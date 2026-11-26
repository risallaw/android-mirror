package dev.local.androidmirror.service

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.view.Surface
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import androidx.core.content.edit
import dev.local.androidmirror.BuildConfig
import dev.local.androidmirror.R
import dev.local.androidmirror.capture.DisplaySnapshot
import dev.local.androidmirror.capture.DisplayWatcher
import dev.local.androidmirror.capture.ProjectionSession
import dev.local.androidmirror.control.ControlBridge
import dev.local.androidmirror.core.CoreCallbacks
import dev.local.androidmirror.core.NativeCore
import dev.local.androidmirror.core.Pairings
import dev.local.androidmirror.net.NetworkInfo
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Foreground service (type mediaProjection) that owns one mirroring session:
 * the MediaProjection, its single VirtualDisplay, and the Rust core.
 *
 * Start order (PLAN §6, Android 14+): startForeground → getMediaProjection →
 * registerCallback → createVirtualDisplay once with a null surface → NativeCore
 * → nativeSetDisplay. Receivers reconnecting reuse the session; a new consent is
 * only needed after Stop.
 */
class MirrorService : Service(), CoreCallbacks {
    private val main = Handler(Looper.getMainLooper())

    /**
     * Runs blocking work off the main thread, in order: core start (it waits for a previous
     * core to release the pairing store) and destroy, preferences, interface scans.
     */
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "mirror-ctl")
    }

    /** The core started on the worker, until the worker closes it (worker thread only). */
    private var workerCore: NativeCore? = null

    // Main-thread state; `session` is also read by Rust threads via the callbacks.
    private val gate = SessionGate<Intent>()
    private var projection: MediaProjection? = null

    @Volatile
    private var session: ProjectionSession? = null
    private var core: NativeCore? = null

    /** Counts starts, so a core start finishing after its session was stopped is ignored. */
    private var generation = 0
    private var watcher: DisplayWatcher? = null

    // No partial wake lock (AUTO decision): with the screen off there is nothing to mirror, and
    // Android vitals flag foreground services that keep the CPU up; if the phone sleeps the Mac
    // reconnects when it wakes. The Wi-Fi lock only lowers latency while it is awake.
    private var wifiLock: WifiManager.WifiLock? = null
    private val networkCallbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private var apReceiver: BroadcastReceiver? = null
    private var activeSessionId = 0L
    private var destroyed = false

    /** The latest start delivered, so a stop never ends the service under a newer start. */
    private var lastStartId = 0

    /** Network callbacks fire in bursts (and on every signal-strength change): one scan per burst. */
    private val addressRefresh = Coalesced({ main.postDelayed(it, ADDRESS_REFRESH_DELAY_MS) }, ::refreshAddress)

    /** What the notification shows (see [MirrorStatus.notificationFields]); null while none is up. */
    private var notified: MirrorStatus? = null

    private val statusListener: (MirrorStatus) -> Unit = { status ->
        val shown = status.notificationFields()
        // Only once startForeground posted it: a plain notify would outlive stopForeground.
        val posted = notified
        if (posted != null && gate.active && (status.running || status.phase == Phase.STOPPING) && shown != posted) {
            notified = shown
            Notifications.update(this, status)
        }
    }

    private val clearPairingMessage = Runnable { MirrorState.update { it.copy(pairingMessage = null) } }

    private val projectionCallback = object : MediaProjection.Callback() {
        override fun onStop() {
            // "Stop sharing" chip, device lock on Android 15 QPR1+, or another capture.
            Log.i(TAG, "projection stopped by the system")
            main.post { shutdown(null, projectionRevoked = true) }
        }

        override fun onCapturedContentResize(width: Int, height: Int) {
            main.post { watcher?.schedule() }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        MirrorState.observe(statusListener)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        when (intent?.action) {
            ACTION_START -> when (gate.start(intent)) {
                SessionGate.Start.NOW -> startMirroring(intent)
                // A startForegroundService must be answered with startForeground even when its
                // start is ignored or deferred, or the system crashes the app when we stop.
                SessionGate.Start.RUNNING -> {
                    Log.w(TAG, "already running; ignoring start")
                    enterForeground()
                }
                SessionGate.Start.AFTER_STOP -> {
                    Log.i(TAG, "start requested while stopping; starting once stopped")
                    enterForeground()
                }
            }
            ACTION_STOP -> if (!shutdown(null) && !gate.active) stopSelfResult(startId)
            ACTION_NEW_PIN -> if (gate.active) newPin() else stopSelfResult(startId)
            ACTION_REFRESH_ADDRESS -> if (gate.active) addressRefresh.request() else stopSelfResult(startId)
            else -> if (!gate.active) stopSelfResult(startId)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        destroyed = true
        MirrorState.remove(statusListener)
        main.removeCallbacks(clearPairingMessage)
        shutdown(null)
        worker.shutdown()
        super.onDestroy()
    }

    // ---------------------------------------------------------------------
    // Session lifecycle (main thread)
    // ---------------------------------------------------------------------

    /** Post the notification and become a foreground service; false if the system refused. */
    private fun enterForeground(): Boolean = try {
        ServiceCompat.startForeground(
            this,
            Notifications.ID,
            Notifications.build(this, MirrorState.current),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION,
        )
        true
    } catch (e: RuntimeException) {
        Log.e(TAG, "startForeground failed", e)
        false
    }

    /** Runs only after [SessionGate.start] said NOW. */
    private fun startMirroring(intent: Intent) {
        // The paired list stays shown while starting (the UI keeps it current while idle).
        MirrorState.update { MirrorStatus(phase = Phase.STARTING, paired = it.paired, pairedUnreadable = it.pairedUnreadable) }
        // 1. Foreground first: getMediaProjection requires it on Android 14+.
        if (!enterForeground()) {
            fail(getString(R.string.error_foreground))
            return
        }
        notified = MirrorState.current.notificationFields()
        // 2. Projection from the (single-use) consent result.
        val resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, 0)
        val data = IntentCompat.getParcelableExtra(intent, EXTRA_DATA, Intent::class.java)
        val mpm = getSystemService(MediaProjectionManager::class.java)
        val proj = data?.let { runCatching { mpm.getMediaProjection(resultCode, it) }.getOrNull() }
        if (proj == null) {
            fail(getString(R.string.error_projection))
            return
        }
        projection = proj
        // 3. Callback before createVirtualDisplay (required on 14+).
        proj.registerCallback(projectionCallback, main)
        // 4. The one VirtualDisplay, null surface until a client streams.
        val snapshot = DisplaySnapshot.query(this)
        val s = ProjectionSession(proj)
        session = s
        try {
            s.create(snapshot, main)
        } catch (e: RuntimeException) {
            Log.e(TAG, "createVirtualDisplay failed", e)
            fail(getString(R.string.error_projection))
            return
        }
        // 5. Rust core: listener + encoder (encoder starts per client). Started on the worker: it
        // waits for a previous core to finish closing, and reads preferences and interfaces.
        val gen = ++generation
        worker.execute {
            // The address first: once the core starts, a Mac can connect at any moment.
            val ip = NetworkInfo.lanIpv4(this)
            // NativeCore() loads the library: a missing one is a start error, not a crash.
            val c = runCatching { NativeCore(this).takeIf { Pairings.start(it, configJson()) } }
                .onFailure { Log.e(TAG, "native core failed", it) }
                .getOrNull()
            workerCore = c
            main.post { coreStarted(gen, c, snapshot, ip) }
        }
    }

    private fun coreStarted(gen: Int, c: NativeCore?, snapshot: DisplaySnapshot, ip: String?) {
        // Stopped meanwhile: the shutdown queued behind the start closes the core.
        if (gen != generation || gate.stopping || !gate.active) return
        if (c == null) {
            fail(getString(R.string.error_core))
            return
        }
        core = c
        // Tell the core whether the Accessibility service is already on.
        ControlBridge.attachCore(c)
        c.setDisplay(snapshot.width, snapshot.height, snapshot.rotation, snapshot.dpi)
        watcher = DisplayWatcher(this, ::onDisplayChanged, ::onScreenChanged).also { it.start(snapshot) }
        registerNetworkCallback()
        // The PIN is read here, not on the worker: a rotation reported in between
        // (onPinChanged) must not be overwritten with the older PIN.
        MirrorState.update { coreReady(it, ip, c.port(), c.pin()) }
        refreshPaired()
        Log.i(TAG, "mirroring ready on port ${c.port()}")
    }

    private fun fail(message: String) {
        Log.e(TAG, message)
        shutdown(message)
    }

    /**
     * Tear everything down; false if no session is active or one is already being torn down.
     * The native core is destroyed on the worker thread (it blocks and upcalls onSurfaceGone),
     * then the VirtualDisplay and projection are released on the main thread.
     */
    private fun shutdown(error: String?, projectionRevoked: Boolean = false): Boolean {
        if (!gate.beginShutdown()) return false
        // Shown at once: the core can take a while to close.
        MirrorState.update(::stoppingStatus)
        watcher?.stop()
        watcher = null
        unregisterNetworkCallback()
        releaseWifiLock()
        main.removeCallbacks(clearPairingMessage)
        activeSessionId = 0L
        core = null
        ControlBridge.detachCore()
        val s = session
        val p = projection
        projection = null
        worker.execute {
            val c = workerCore
            workerCore = null
            runCatching {
                if (c != null) {
                    if (projectionRevoked) c.projectionRevoked()
                    Pairings.close(c)
                }
            }.onFailure { Log.e(TAG, "native destroy failed", it) }
            main.post { shutdownFinished(s, p, error) }
        }
        return true
    }

    private fun shutdownFinished(s: ProjectionSession?, p: MediaProjection?, error: String?) {
        session = null
        notified = null
        s?.release()
        p?.let {
            it.unregisterCallback(projectionCallback)
            it.stop()
        }
        MirrorState.update {
            MirrorStatus(
                phase = if (error != null) Phase.ERROR else Phase.IDLE,
                error = error,
                paired = it.paired,
                pairedUnreadable = it.pairedUnreadable,
            )
        }
        // The closed core may have saved pairings the list has not shown yet.
        refreshPaired()
        val next = gate.shutdownDone()
        if (next != null && !destroyed && gate.start(next) == SessionGate.Start.NOW) {
            startMirroring(next)
            return
        }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelfResult(lastStartId)
    }

    /**
     * "New PIN": rotate it on the worker (in order with the core's start and close there), apply
     * it here. The PIN
     * view's live region announces the new PIN; no toast repeats it.
     */
    private fun newPin() {
        val c = core ?: return
        if (!live || MirrorState.current.newPinPending) return
        val gen = generation
        MirrorState.update { it.copy(newPinPending = true) }
        worker.execute {
            val result = runCatching { c.newPin() }.onFailure { Log.e(TAG, "new PIN failed", it) }.getOrNull()
            main.post {
                // A stale or failed result only ends the pending state.
                val shown = newPinToShow(newPinResultApplies(gen, generation, live, c, core), result?.pin, c::pin)
                MirrorState.update { withNewPin(it, shown, result?.resets ?: 0) }
                // A message kept (counted after the New PIN) keeps its own clear timer.
                if (MirrorState.current.pairingMessage == null) main.removeCallbacks(clearPairingMessage)
            }
        }
    }

    /** Main thread: whether core events still belong to the session on screen (see [SessionGate.eventsLive]). */
    private val live: Boolean get() = gate.eventsLive

    private fun refreshPaired() = Pairings.refresh(filesDir) { list -> MirrorState.update { it.withPaired(list) } }

    private fun onDisplayChanged(d: DisplaySnapshot) {
        Log.i(TAG, "display changed: ${d.width}x${d.height} rot ${d.rotation} dpi ${d.dpi}")
        session?.setDensity(d.dpi)
        core?.setDisplay(d.width, d.height, d.rotation, d.dpi)
    }

    private fun onScreenChanged(on: Boolean) {
        core?.setScreenState(on)
    }

    /**
     * Re-scan the address when the network changes. The default network alone is not enough: with
     * a VPN up, a Wi-Fi roam or new lease changes only the VPN's capabilities, and the address
     * shown comes from the Wi-Fi under it; so every Wi-Fi / Ethernet network is watched too.
     * Hotspot and tethering are no network at all: a broadcast receiver and the app resuming re-scan.
     */
    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val lan = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            // A LAN without internet access can still reach the Mac.
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        runCatching { addressCallback().also { cm.registerDefaultNetworkCallback(it, main) } }
            .onSuccess { networkCallbacks += it }
            .onFailure { Log.w(TAG, "Default network callback failed", it) }
        runCatching { addressCallback().also { cm.registerNetworkCallback(lan, it, main) } }
            .onSuccess { networkCallbacks += it }
            .onFailure { Log.w(TAG, "LAN network callback failed", it) }
        // Hotspot is no network: its on/off is only announced by this broadcast. The action is a
        // hidden but widely used constant (WifiManager.WIFI_AP_STATE_CHANGED_ACTION). It is a system
        // broadcast, which a RECEIVER_NOT_EXPORTED receiver still gets.
        if (apReceiver == null) {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) = addressRefresh.request()
            }
            runCatching {
                ContextCompat.registerReceiver(
                    this, receiver, IntentFilter(WIFI_AP_STATE_CHANGED), ContextCompat.RECEIVER_NOT_EXPORTED,
                )
            }.onSuccess { apReceiver = receiver }
                .onFailure { Log.w(TAG, "Hotspot receiver failed", it) }
        }
    }

    private fun addressCallback() = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = addressRefresh.request()

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = addressRefresh.request()

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = addressRefresh.request()

        override fun onLost(network: Network) = addressRefresh.request()
    }

    private fun unregisterNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java)
        networkCallbacks.forEach { cb -> runCatching { cm?.unregisterNetworkCallback(cb) } }
        networkCallbacks.clear()
        apReceiver?.let { r -> runCatching { unregisterReceiver(r) } }
        apReceiver = null
    }

    /** Main thread. A changed address drops the client so it reconnects to the new one. */
    private fun refreshAddress() {
        if (core == null) return
        val gen = generation
        // The interface scan can be slow; it runs on the worker, the result is applied here.
        runCatching {
            worker.execute {
                val ip = NetworkInfo.lanIpv4(this)
                main.post { addressChanged(gen, ip) }
            }
        }
    }

    private fun addressChanged(gen: Int, ip: String?) {
        val c = core ?: return
        if (gen != generation) return
        val old = MirrorState.current.ip
        if (ip == old) return
        Log.i(TAG, "LAN address changed: $old -> $ip")
        if (old != null) c.networkChanged()
        MirrorState.update { it.copy(ip = ip) }
    }

    private fun acquireWifiLock() {
        if (wifiLock?.isHeld == true) return
        val wm = applicationContext.getSystemService(WifiManager::class.java) ?: return
        wifiLock = runCatching {
            wm.createWifiLock(WifiManager.WIFI_MODE_FULL_LOW_LATENCY, "AndroidMirror:stream").apply {
                setReferenceCounted(false)
                acquire()
            }
        }.onFailure { Log.w(TAG, "wifi lock failed", it) }.getOrNull()
    }

    private fun releaseWifiLock() {
        wifiLock?.let { if (it.isHeld) it.release() }
        wifiLock = null
    }

    private fun configJson(): String = JSONObject()
        .put("deviceName", deviceName())
        .put("deviceId", deviceId())
        .put("model", android.os.Build.MODEL)
        .put("sdkInt", android.os.Build.VERSION.SDK_INT)
        .put("filesDir", filesDir.absolutePath)
        // The core accepts loopback peers when "debug" is set. Any app on the phone can reach
        // 127.0.0.1 and burn PIN tries, so a debug build needs an explicit opt-in too, which only
        // adb can give (run-as works for debuggable apps only):
        // adb shell run-as dev.local.androidmirror touch files/allow_loopback
        .put("debug", BuildConfig.DEBUG && File(filesDir, LOOPBACK_OPT_IN).exists())
        .toString()

    private fun deviceName(): String =
        Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME)
            ?.takeIf { it.isNotBlank() } ?: android.os.Build.MODEL

    private fun deviceId(): String {
        val prefs = getSharedPreferences("mirror", Context.MODE_PRIVATE)
        prefs.getString("device_id", null)?.let { return it }
        val id = UUID.randomUUID().toString()
        prefs.edit { putString("device_id", id) }
        return id
    }

    // ---------------------------------------------------------------------
    // CoreCallbacks (Rust threads)
    // ---------------------------------------------------------------------

    override fun onSurfaceReady(surface: Surface, width: Int, height: Int) {
        val s = session
        if (s == null) {
            surface.release()
            return
        }
        s.onSurfaceReady(surface, width, height)
    }

    override fun onSurfaceGone() {
        session?.onSurfaceGone()
    }

    override fun onSurfaceRefresh() {
        // Throwing tells the core to restart the codec at once (see CoreCallbacks).
        (session ?: throw IllegalStateException("no projection session")).refreshSurface()
    }

    override fun onClientState(state: Int, sessionId: Long, name: String?, peer: String?, reason: Int) {
        Log.i(TAG, "client ${peerText(name)} (${peerText(peer)}) session $sessionId state $state reason $reason")
        main.post {
            if (!live) return@post
            val (next, tracked) = applyClientState(MirrorState.current, activeSessionId, state, sessionId, name)
            activeSessionId = tracked
            if (tracked == 0L) releaseWifiLock() else acquireWifiLock()
            MirrorState.update { next }
        }
    }

    override fun onStreamInfo(width: Int, height: Int, fps: Int, encoder: String) {
        Log.i(TAG, "encoder $encoder ${width}x$height @$fps fps")
        val info = getString(R.string.stream_info, width, height, fps)
        main.post { if (live) MirrorState.update { it.copy(streamInfo = info) } }
    }

    override fun onError(message: String) {
        Log.w(TAG, "core error: $message")
        main.post { if (live) MirrorState.update { it.copy(error = message) } }
    }

    override fun onPinChanged(pin: String) {
        // [pin] itself is not used: the server reports outside its lock, so it can be older than a
        // "New PIN" applied meanwhile; the core's current PIN (read under its lock) is shown instead.
        main.post {
            val c = core ?: return@post // not up yet: coreStarted reads the PIN
            if (!live) return@post
            val current = c.pin()
            MirrorState.update { if (it.running) it.copy(pin = current) else it }
        }
    }

    override fun onPaired(clientId: String, clientName: String) {
        Log.i(TAG, "paired ${peerText(clientName)}")
        main.post {
            if (!live) return@post
            main.removeCallbacks(clearPairingMessage)
            MirrorState.update { it.copy(pairingMessage = null) }
            // Through the pairings thread, in order with removals (see Pairings.refresh).
            refreshPaired()
        }
    }

    override fun onPairingFailed(peer: String, attemptsLeft: Int, lockedForMs: Long, resets: Long) {
        val message = if (lockedForMs > 0) {
            getString(R.string.pin_locked, lockoutText(lockedForMs), peerText(peer))
        } else {
            getString(
                R.string.pin_wrong,
                peerText(peer),
                resources.getQuantityString(R.plurals.tries_left, attemptsLeft, attemptsLeft),
            )
        }
        main.post {
            if (!pairingFailureApplies(live, resets, MirrorState.current.pinResets)) return@post
            MirrorState.update { it.copy(pairingMessage = message, pairingMessageResets = resets) }
            // Shown until it is no longer true: the lockout ends, or a minute after a wrong PIN.
            main.removeCallbacks(clearPairingMessage)
            main.postDelayed(clearPairingMessage, maxOf(lockedForMs, PAIRING_MESSAGE_MS))
        }
    }

    /** e.g. "1 hour 30 minutes" (see [lockoutParts]). */
    private fun lockoutText(ms: Long): String {
        val (h, m, sec) = lockoutParts(ms)
        return listOf(R.plurals.duration_hours to h, R.plurals.duration_minutes to m, R.plurals.duration_seconds to sec)
            .filter { it.second > 0 }
            .joinToString(" ") { (id, n) -> resources.getQuantityString(id, n.toInt(), n.toInt()) }
    }

    // Control input: forwarded to the Accessibility service on the main thread.
    override fun onGesture(kind: Int, xs: FloatArray, ys: FloatArray, durationMs: Long) =
        ControlBridge.onGesture(kind, xs, ys, durationMs)

    override fun onScroll(x: Float, y: Float, dx: Float, dy: Float) =
        ControlBridge.onScroll(x, y, dx, dy)

    override fun onGlobalAction(action: Int) = ControlBridge.onGlobalAction(action)

    override fun onText(text: String) = ControlBridge.onText(text)

    override fun onKey(key: Int) = ControlBridge.onKey(key)

    /** Gestures arrive whole (see onGesture); live touch is not used yet. */
    override fun onTouchLive(phase: Int, x: Float, y: Float) = Unit

    companion object {
        private const val TAG = "MirrorService"
        private const val ACTION_START = "dev.local.androidmirror.action.START"
        private const val ACTION_STOP = "dev.local.androidmirror.action.STOP"
        private const val ACTION_NEW_PIN = "dev.local.androidmirror.action.NEW_PIN"
        private const val EXTRA_RESULT_CODE = "resultCode"
        private const val EXTRA_DATA = "data"
        private const val PAIRING_MESSAGE_MS = 60_000L
        private const val ACTION_REFRESH_ADDRESS = "dev.local.androidmirror.action.REFRESH_ADDRESS"
        private const val ADDRESS_REFRESH_DELAY_MS = 300L
        private const val WIFI_AP_STATE_CHANGED = "android.net.wifi.WIFI_AP_STATE_CHANGED"

        /** In a debug build, this file in filesDir lets loopback peers connect (see [configJson]). */
        private const val LOOPBACK_OPT_IN = "allow_loopback"

        /**
         * Start a session with a fresh consent result (never reuse one). Called from the visible
         * app, so a plain start is allowed and preferred: a startForegroundService whose
         * startForeground then fails makes the system crash the app when the service stops.
         */
        fun start(context: Context, resultCode: Int, data: Intent) {
            val i = Intent(context, MirrorService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_RESULT_CODE, resultCode)
                .putExtra(EXTRA_DATA, data)
            try {
                context.startService(i)
            } catch (_: IllegalStateException) {
                // Not in the foreground after all (background start restriction).
                ContextCompat.startForegroundService(context, i)
            }
        }

        fun stopIntent(context: Context): Intent =
            Intent(context, MirrorService::class.java).setAction(ACTION_STOP)

        fun stop(context: Context) {
            context.startService(stopIntent(context))
        }

        /**
         * Re-scan the LAN address of the running session. For hotspot and tethering, which no
         * network callback reports: called when the app comes to the front.
         */
        fun refreshAddress(context: Context) {
            context.startService(Intent(context, MirrorService::class.java).setAction(ACTION_REFRESH_ADDRESS))
        }

        /** Replace the pairing PIN of the running session (also ends a PIN lockout). */
        fun newPin(context: Context) {
            context.startService(Intent(context, MirrorService::class.java).setAction(ACTION_NEW_PIN))
        }
    }
}
