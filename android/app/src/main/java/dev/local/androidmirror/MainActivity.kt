package dev.local.androidmirror

import android.Manifest
import android.content.ClipData
import android.content.ActivityNotFoundException
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.media.projection.MediaProjectionConfig
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.net.Uri
import android.app.Dialog
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.fragment.app.DialogFragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dev.local.androidmirror.control.ControlBridge
import dev.local.androidmirror.core.NativeCore
import dev.local.androidmirror.core.PairedMac
import dev.local.androidmirror.core.Pairings
import dev.local.androidmirror.core.removeSucceeded
import dev.local.androidmirror.net.NetworkInfo
import dev.local.androidmirror.service.MirrorService
import dev.local.androidmirror.service.MirrorState
import dev.local.androidmirror.service.MirrorStatus
import dev.local.androidmirror.service.Phase
import dev.local.androidmirror.service.groupPin
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    private lateinit var statusDot: View
    private lateinit var statusTitle: TextView
    private lateinit var statusDetail: TextView
    private lateinit var addressText: TextView
    private lateinit var addressHint: TextView
    private lateinit var copyButton: MaterialButton
    private lateinit var startStopButton: MaterialButton

    private lateinit var pinCard: View
    private lateinit var pinText: TextView
    private lateinit var newPinButton: MaterialButton
    private lateinit var pairingMessage: TextView
    private lateinit var pairedEmpty: TextView
    private lateinit var pairedList: LinearLayout
    private lateinit var controlDot: View
    private lateinit var controlStatus: TextView
    private lateinit var controlDetail: TextView
    private lateinit var clipboardNote: TextView
    private lateinit var inputDroppedNote: TextView
    private lateinit var restrictedHelp: View
    private lateinit var appInfoButton: View

    private val dot = GradientDrawable().apply { shape = GradientDrawable.OVAL }
    private val controlDotDrawable = GradientDrawable().apply { shape = GradientDrawable.OVAL }

    private val render: (MirrorStatus) -> Unit = { render(it) }
    private val renderControl: (Boolean) -> Unit = { renderControl(it) }

    /** Last list rendered, to rebuild rows only when it changes. */
    private var shownPaired: List<PairedMac>? = null

    /** Macs being removed (a second confirmation of the same one is ignored). */
    private val removing = mutableSetOf<String>()

    /** The phone's LAN address shown while idle, looked up off the main thread in [onResume]. */
    private var idleIp: String? = null

    /** Whether a control note was on screen since [onStart] (then it counts as seen). */
    private var notesShown = false
    private val io = Executors.newSingleThreadExecutor { r -> Thread(r, "main-io") }

    private val consentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val data = result.data
            if (result.resultCode == RESULT_OK && data != null) {
                MirrorService.start(this, result.resultCode, data)
            } else {
                Toast.makeText(this, R.string.consent_declined, Toast.LENGTH_SHORT).show()
            }
        }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Mirroring works without the notification; continue either way.
            requestConsent()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val root = findViewById<View>(R.id.root)
        val content = findViewById<View>(R.id.content)
        val basePadding = content.paddingTop
        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            // The scroll view stops below the status bar (content scrolled up is clipped there
            // instead of running under the clock); at the bottom the content scrolls behind the
            // navigation bar but can be scrolled clear of it.
            root.updatePadding(left = bars.left, top = bars.top, right = bars.right)
            content.updatePadding(bottom = basePadding + bars.bottom)
            insets
        }

        statusDot = findViewById(R.id.status_dot)
        statusDot.background = dot
        statusTitle = findViewById(R.id.status_title)
        statusDetail = findViewById(R.id.status_detail)
        addressText = findViewById(R.id.address_text)
        addressHint = findViewById(R.id.address_hint)
        copyButton = findViewById(R.id.copy_button)
        startStopButton = findViewById(R.id.start_stop_button)

        pinCard = findViewById(R.id.pin_card)
        pinText = findViewById(R.id.pin_text)
        newPinButton = findViewById(R.id.new_pin_button)
        newPinButton.setOnClickListener { MirrorService.newPin(this) }
        pairingMessage = findViewById(R.id.pairing_message)
        pairedEmpty = findViewById(R.id.paired_empty)
        pairedList = findViewById(R.id.paired_list)
        controlDot = findViewById(R.id.control_dot)
        controlDot.background = controlDotDrawable
        controlStatus = findViewById(R.id.control_status)
        controlDetail = findViewById(R.id.control_detail)
        clipboardNote = findViewById(R.id.clipboard_note)
        inputDroppedNote = findViewById(R.id.input_dropped_note)
        restrictedHelp = findViewById(R.id.control_restricted_help)
        appInfoButton = findViewById(R.id.app_info_button)

        findViewById<View>(R.id.accessibility_button).setOnClickListener {
            openSettings(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
        appInfoButton.setOnClickListener {
            openSettings(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)))
        }

        findViewById<TextView>(R.id.version_text).text = runCatching { NativeCore.nativeVersion() }
            .getOrElse { getString(R.string.core_unavailable, (it.cause ?: it).message) }

        startStopButton.setOnClickListener {
            if (MirrorState.current.running) MirrorService.stop(this) else startFlow()
        }
        copyButton.setOnClickListener { copyAddress() }
    }

    override fun onStart() {
        super.onStart()
        notesShown = false
        MirrorState.observe(render)
        ControlBridge.observe(renderControl)
        ControlBridge.loadNotes(this)
        // Also while idle: the list comes from the store file then (see Pairings).
        Pairings.refresh(filesDir) { list -> MirrorState.update { it.withPaired(list) } }
    }

    override fun onResume() {
        super.onResume()
        // On every return to the app: hotspot and tethering (often switched on in Settings) change
        // the address without any network callback.
        if (MirrorState.current.running) MirrorService.refreshAddress(this)
        // Unused while a session runs: the service publishes the address then.
        if (MirrorState.current.run { running && phase != Phase.STARTING }) return
        val app = applicationContext
        io.execute {
            val ip = NetworkInfo.lanIpv4(app)
            runOnUiThread {
                idleIp = ip
                render(MirrorState.current)
            }
        }
    }

    override fun onStop() {
        MirrorState.remove(render)
        ControlBridge.remove(renderControl)
        if (notesShown) ControlBridge.acknowledgeNotes(this)
        super.onStop()
    }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }

    private fun startFlow() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestConsent()
        }
    }

    private fun requestConsent() {
        val mpm = getSystemService(MediaProjectionManager::class.java)
        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Whole screen only: the receiver mirrors the device, not one app.
            mpm.createScreenCaptureIntent(MediaProjectionConfig.createConfigForDefaultDisplay())
        } else {
            mpm.createScreenCaptureIntent()
        }
        consentLauncher.launch(intent)
    }

    private fun copyAddress() {
        val address = MirrorState.current.address ?: return
        val cm = getSystemService(ClipboardManager::class.java)
        cm.setPrimaryClip(ClipData.newPlainText(getString(R.string.app_name), address))
        // Android 13+ shows its own clipboard confirmation.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            Toast.makeText(this, getString(R.string.copied, address), Toast.LENGTH_SHORT).show()
        }
    }

    private fun openSettings(intent: Intent) {
        try {
            startActivity(intent)
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, R.string.settings_unavailable, Toast.LENGTH_SHORT).show()
        }
    }

    private fun renderControl(on: Boolean) {
        controlDotDrawable.setColor(color(if (on) R.color.status_live else R.color.status_idle))
        controlStatus.setText(if (on) R.string.control_on else R.string.control_off)
        // The live region announces this, so it says what is on, not just "On".
        controlStatus.contentDescription = getString(if (on) R.string.control_on_description else R.string.control_off_description)
        controlDetail.setText(if (on) R.string.control_on_detail else R.string.control_off_detail)
        // Android 13+ blocks accessibility for sideloaded apps until "Allow restricted settings".
        val help = if (!on && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) View.VISIBLE else View.GONE
        restrictedHelp.visibility = help
        appInfoButton.visibility = help
        clipboardNote.visibility = if (ControlBridge.clipboardUsed) View.VISIBLE else View.GONE
        inputDroppedNote.visibility = if (ControlBridge.inputDropped) View.VISIBLE else View.GONE
        if (ControlBridge.clipboardUsed || ControlBridge.inputDropped) notesShown = true
    }

    private fun renderPairing(s: MirrorStatus) {
        pinCard.visibility = if (s.showPin) View.VISIBLE else View.GONE
        if (s.showPin) {
            newPinButton.isEnabled = !s.newPinPending
            pinText.text = groupPin(s.pin)
            // Read digit by digit, not as "one hundred twenty-three thousand…".
            pinText.contentDescription = getString(R.string.pin_description, s.pin.toList().joinToString(" "))
        }
        pairingMessage.text = s.pairingMessage
        pairingMessage.visibility = if (s.pairingMessage != null) View.VISIBLE else View.GONE

        val paired = s.paired.orEmpty()
        if (paired != shownPaired) {
            shownPaired = paired
            pairedList.removeAllViews()
            val inflater = LayoutInflater.from(this)
            for (mac in paired) {
                val row = inflater.inflate(R.layout.item_paired, pairedList, false)
                row.findViewById<TextView>(R.id.paired_name).text = mac.displayName
                row.findViewById<TextView>(R.id.paired_date).apply {
                    val at = mac.pairedAt
                    visibility = if (at != null) View.VISIBLE else View.GONE
                    if (at != null) {
                        text = getString(
                            R.string.paired_on,
                            DateUtils.formatDateTime(context, at, DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_MONTH or DateUtils.FORMAT_SHOW_YEAR),
                        )
                    }
                }
                row.findViewById<View>(R.id.paired_remove).apply {
                    contentDescription = getString(R.string.action_remove_description, mac.displayName)
                    setOnClickListener { confirmRemove(mac) }
                }
                pairedList.addView(row)
            }
        }
        // Nothing while the list loads (no flash of "no Mac paired"); an unreadable store says so.
        when {
            s.pairedUnreadable -> pairedEmpty.setText(R.string.paired_unreadable)
            s.paired?.isEmpty() == true -> pairedEmpty.setText(R.string.paired_empty)
        }
        pairedEmpty.visibility = if (s.pairedUnreadable || s.paired?.isEmpty() == true) View.VISIBLE else View.GONE
    }

    private fun confirmRemove(mac: PairedMac) {
        if (mac.clientId in removing) return
        val tag = "remove:${mac.clientId}"
        // A double tap opens one dialog. A fragment, so it is dismissed with the activity (no
        // leaked window) and comes back after a rotation.
        if (supportFragmentManager.findFragmentByTag(tag) != null) return
        RemoveMacDialog.of(mac).show(supportFragmentManager, tag)
    }

    /** Works mirroring or not (a connected Mac is disconnected); see [Pairings]. */
    internal fun remove(clientId: String, name: String) {
        // A confirmation for a Mac already being removed must not report that removal's
        // success as a failure.
        if (!removing.add(clientId)) return
        if (MirrorState.current.paired?.none { it.clientId == clientId } == true) {
            removing -= clientId
            return
        }
        val app = applicationContext
        Pairings.remove(filesDir, clientId) { removed, list ->
            removing -= clientId
            MirrorState.update { it.withPaired(list) }
            if (!removeSucceeded(removed, clientId, list)) {
                Toast.makeText(app, app.getString(R.string.remove_failed, name), Toast.LENGTH_LONG).show()
            }
        }
    }

    /** "Remove <Mac>?"; its arguments survive a rotation. */
    class RemoveMacDialog : DialogFragment() {
        override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
            val args = requireArguments()
            val id = args.getString(ARG_ID).orEmpty()
            val name = args.getString(ARG_NAME).orEmpty()
            return MaterialAlertDialogBuilder(requireContext())
                .setTitle(getString(R.string.remove_confirm_title, name))
                .setMessage(R.string.remove_confirm_message)
                .setPositiveButton(R.string.action_remove) { _, _ -> (activity as? MainActivity)?.remove(id, name) }
                .setNegativeButton(R.string.action_cancel, null)
                .create()
        }

        companion object {
            private const val ARG_ID = "clientId"
            private const val ARG_NAME = "name"

            fun of(mac: PairedMac) = RemoveMacDialog().apply {
                arguments = Bundle().apply {
                    putString(ARG_ID, mac.clientId)
                    putString(ARG_NAME, mac.displayName)
                }
            }
        }
    }

    private fun color(id: Int) = ContextCompat.getColor(this, id)

    private fun render(s: MirrorStatus) {
        val client = s.clientName ?: getString(R.string.unknown_client)
        // While the PIN card is hidden (a Mac is connected), pairing problems show here: someone
        // trying PINs during a session is worth seeing.
        val warning = s.error.takeIf { s.phase != Phase.ERROR } ?: s.pairingMessage.takeIf { !s.showPin }
        val (dotColor, title, detail) = when (s.phase) {
            Phase.IDLE -> Triple(R.color.status_idle, getString(R.string.status_idle), getString(R.string.status_idle_detail))
            Phase.STARTING -> Triple(R.color.status_wait, getString(R.string.status_starting), getString(R.string.status_starting_detail))
            Phase.WAITING -> Triple(
                R.color.status_wait,
                getString(R.string.status_waiting),
                if (s.ip == null) getString(R.string.status_no_wifi_detail) else getString(R.string.status_waiting_detail),
            )
            Phase.STOPPING -> Triple(R.color.status_idle, getString(R.string.status_stopping), getString(R.string.status_stopping_detail))
            Phase.CONNECTING -> Triple(R.color.status_wait, getString(R.string.status_connecting, client), getString(R.string.status_connecting_detail))
            Phase.STREAMING -> Triple(
                R.color.status_live,
                getString(R.string.status_streaming, client),
                s.streamInfo ?: getString(R.string.status_streaming_detail),
            )
            Phase.ERROR -> Triple(R.color.status_error, getString(R.string.status_error), s.error ?: getString(R.string.status_error_detail))
        }
        dot.setColor(color(dotColor))
        renderPairing(s)
        statusTitle.text = title
        statusDetail.text = if (warning != null) getString(R.string.detail_with_warning, detail, warning) else detail

        val address = s.address
        when {
            address != null -> {
                addressText.text = address
                addressText.setTextColor(color(R.color.text_primary))
                addressHint.text = getString(R.string.address_hint)
            }
            s.running && s.phase != Phase.STARTING -> {
                addressText.text = getString(R.string.address_no_wifi)
                addressText.setTextColor(color(R.color.text_secondary))
                addressHint.text = getString(R.string.address_hint_no_wifi)
            }
            else -> {
                addressText.text = idleIp ?: getString(R.string.address_placeholder)
                addressText.setTextColor(color(R.color.text_secondary))
                addressHint.text = getString(R.string.address_hint_idle)
            }
        }
        copyButton.isEnabled = address != null

        if (s.running || s.phase == Phase.STOPPING) {
            startStopButton.setText(R.string.action_stop_mirroring)
            startStopButton.backgroundTintList = ColorStateList.valueOf(color(R.color.stop_bg))
            startStopButton.setTextColor(color(R.color.stop_text))
            // Stop works while STARTING too (the notification offers it then as well).
            setStartStopEnabled(s.phase != Phase.STOPPING)
        } else {
            startStopButton.setText(R.string.action_start_mirroring)
            startStopButton.backgroundTintList = ColorStateList.valueOf(color(R.color.start_bg))
            startStopButton.setTextColor(color(R.color.start_text))
            setStartStopEnabled(true)
        }
    }

    /** The custom tint has no disabled state of its own: dim it like Material's disabled buttons. */
    private fun setStartStopEnabled(enabled: Boolean) {
        startStopButton.isEnabled = enabled
        startStopButton.alpha = if (enabled) 1f else DISABLED_ALPHA
    }

    private companion object {
        const val DISABLED_ALPHA = 0.38f
    }
}
