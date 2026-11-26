package dev.local.androidmirror.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.local.androidmirror.MainActivity
import dev.local.androidmirror.R

/** The foreground-service notification. */
object Notifications {
    const val ID = 1
    private const val CHANNEL = "mirroring"

    /** Set once the channel exists, so later updates skip the binder lookup. */
    @Volatile
    private var channelReady = false

    private fun ensureChannel(context: Context) {
        if (channelReady) return
        val nm = context.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) != null) {
            channelReady = true
            return
        }
        val channel = NotificationChannel(
            CHANNEL,
            context.getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.notification_channel_desc)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
        channelReady = true
    }

    fun build(context: Context, status: MirrorStatus): Notification {
        ensureChannel(context)
        val (title, text) = when (status.phase) {
            Phase.STREAMING -> context.getString(
                R.string.notif_streaming,
                status.clientName ?: context.getString(R.string.unknown_client),
            ) to (status.streamInfo ?: status.address.orEmpty())
            Phase.CONNECTING -> context.getString(
                R.string.notif_connecting,
                status.clientName ?: context.getString(R.string.unknown_client),
            ) to status.address.orEmpty()
            Phase.STARTING -> context.getString(R.string.notif_starting) to ""
            Phase.STOPPING -> context.getString(R.string.notif_stopping) to ""
            else -> if (status.address != null) {
                context.getString(R.string.notif_ready, status.address) to
                    context.getString(R.string.notif_ready_text)
            } else {
                context.getString(R.string.notif_ready_no_wifi) to
                    context.getString(R.string.status_no_wifi_detail)
            }
        }
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_mirror)
            .setColor(ContextCompat.getColor(context, R.color.brand_teal))
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            // Never put the pairing PIN here; it lives only in the app UI.
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(
                NotificationCompat.Builder(context, CHANNEL)
                    .setSmallIcon(R.drawable.ic_stat_mirror)
                    .setColor(ContextCompat.getColor(context, R.color.brand_teal))
                    .setContentTitle(context.getString(R.string.notif_public))
                    .build(),
            )
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        if (offersStop(status.phase)) {
            val stop = PendingIntent.getService(
                context,
                1,
                MirrorService.stopIntent(context),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            builder.addAction(0, context.getString(R.string.action_stop), stop)
        }
        return builder.build()
    }

    fun update(context: Context, status: MirrorStatus) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        context.getSystemService(NotificationManager::class.java).notify(ID, build(context, status))
    }
}

/** Whether the notification offers Stop: not while stopping, when it would do nothing. */
internal fun offersStop(phase: Phase): Boolean = phase != Phase.STOPPING
