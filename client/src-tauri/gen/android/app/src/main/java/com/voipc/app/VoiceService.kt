package com.voipc.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

class VoiceService : Service() {

    companion object {
        const val CHANNEL_ID = "voipc_voice"
        const val NOTIFICATION_ID = 1
        const val ACTION_MUTE = "com.voipc.app.ACTION_MUTE"
        const val ACTION_DEAFEN = "com.voipc.app.ACTION_DEAFEN"
        const val ACTION_DISCONNECT = "com.voipc.app.ACTION_DISCONNECT"
        const val EXTRA_CHANNEL_NAME = "channel_name"
    }

    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_MUTE, ACTION_DEAFEN, ACTION_DISCONNECT -> {
                // Forward action to the WebView via a broadcast or Tauri event
                val actionIntent = Intent(intent.action).apply {
                    setPackage(packageName)
                }
                sendBroadcast(actionIntent)
                // Not stopSelf() on ACTION_DISCONNECT: that action leaves the
                // voice channel (the server connections stay), and the web
                // side stops this service once the leave has happened. Stopping
                // here would drop the foreground service even when the leave
                // failed and the call is still running.
                return START_NOT_STICKY
            }
        }

        val channelName = intent?.getStringExtra(EXTRA_CHANNEL_NAME) ?: "voice channel"
        val notification = buildNotification(channelName)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // The microphone type is what keeps the capture alive with the
            // screen locked or another app in front; without it Android 11+
            // hands the call silence (H4-02). Only with the permission:
            // Android 14 throws for a microphone-type start without it, and
            // MainActivity starts this again once it is granted.
            var types = ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
            if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED) {
                types = types or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            }
            startForeground(NOTIFICATION_ID, notification, types)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // Acquire partial wake lock to keep CPU running for voice processing.
        // Every start lands here (a channel switch, the permission upgrade),
        // so the previous one goes first rather than piling up.
        wakeLock?.let { if (it.isHeld) it.release() }
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "VoIPC::VoiceCall"
        ).apply {
            acquire(30 * 60 * 1000L) // 30 min max
        }

        // Not sticky: the call lives in the activity's process. A service
        // Android restarts on its own after that process died has no call to
        // hold, and would show "In voice" over nothing (H4-14).
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        wakeLock?.let {
            if (it.isHeld) it.release()
        }
        wakeLock = null
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Voice Call",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Active voice call notification"
            setShowBadge(false)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(channelName: String): Notification {
        // Tap notification to return to app
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPending = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Disconnect action
        val disconnectIntent = Intent(this, VoiceService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPending = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VoIPC")
            .setContentText("In voice: #$channelName")
            .setSmallIcon(android.R.drawable.ic_lock_silent_mode_off)
            .setOngoing(true)
            .setContentIntent(openPending)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Leave voice",
                disconnectPending
            )
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .build()
    }
}
