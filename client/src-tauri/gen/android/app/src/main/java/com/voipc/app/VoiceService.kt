package com.voipc.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
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
                if (intent.action == ACTION_DISCONNECT) {
                    stopSelf()
                }
                return START_STICKY
            }
        }

        val channelName = intent?.getStringExtra(EXTRA_CHANNEL_NAME) ?: "voice channel"
        val notification = buildNotification(channelName)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // Acquire partial wake lock to keep CPU running for voice processing
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "VoIPC::VoiceCall"
        ).apply {
            acquire(30 * 60 * 1000L) // 30 min max (re-acquired on service restart)
        }

        return START_STICKY
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
            .setContentText("Connected to #$channelName")
            .setSmallIcon(android.R.drawable.ic_lock_silent_mode_off)
            .setOngoing(true)
            .setContentIntent(openPending)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Disconnect",
                disconnectPending
            )
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .build()
    }
}
