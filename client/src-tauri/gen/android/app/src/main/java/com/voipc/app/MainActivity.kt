package com.voipc.app

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.media.AudioManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : TauriActivity() {

    companion object {
        private const val REQUEST_RECORD_AUDIO = 1001
        private const val REQUEST_POST_NOTIFICATIONS = 1002
    }

    // Whether volume key PTT is enabled (toggled from WebView via JS bridge)
    private var volumeKeyPttEnabled = false
    private var volumeKeyPttActive = false
    private var webViewRef: WebView? = null
    private var audioManager: AudioManager? = null

    // JS interface exposed as window.__VoIPC in the WebView
    inner class VoIPCBridge {
        @JavascriptInterface
        fun startVoiceService(channelName: String) {
            this@MainActivity.startVoiceService(channelName)
        }

        @JavascriptInterface
        fun stopVoiceService() {
            this@MainActivity.stopVoiceService()
        }

        @JavascriptInterface
        fun setVolumeKeyPtt(enabled: Boolean) {
            this@MainActivity.volumeKeyPttEnabled = enabled
        }

        @JavascriptInterface
        fun setSpeakerphone(enabled: Boolean) {
            this@MainActivity.audioManager?.let { am ->
                @Suppress("DEPRECATION")
                am.isSpeakerphoneOn = enabled
                am.mode = if (enabled) AudioManager.MODE_NORMAL else AudioManager.MODE_IN_COMMUNICATION
            }
        }
    }

    // Listen for actions from VoiceService notification
    private val actionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                VoiceService.ACTION_DISCONNECT -> {
                    evaluateJs("window.__voipc_disconnect && window.__voipc_disconnect()")
                }
                VoiceService.ACTION_MUTE -> {
                    evaluateJs("window.__voipc_toggle_mute && window.__voipc_toggle_mute()")
                }
                VoiceService.ACTION_DEAFEN -> {
                    evaluateJs("window.__voipc_toggle_deafen && window.__voipc_toggle_deafen()")
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager

        // Enable speakerphone by default for VoIP use
        audioManager?.let { am ->
            @Suppress("DEPRECATION")
            am.isSpeakerphoneOn = true
            am.mode = AudioManager.MODE_NORMAL
        }

        // Request RECORD_AUDIO permission at startup (required for Oboe mic capture)
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.RECORD_AUDIO),
                REQUEST_RECORD_AUDIO
            )
        }

        // Request POST_NOTIFICATIONS permission (required on Android 13+ for foreground service notification)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_POST_NOTIFICATIONS
            )
        }

        // Register broadcast receiver for notification actions
        val filter = IntentFilter().apply {
            addAction(VoiceService.ACTION_DISCONNECT)
            addAction(VoiceService.ACTION_MUTE)
            addAction(VoiceService.ACTION_DEAFEN)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(actionReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(actionReceiver, filter)
        }

        // Add JS interface to WebView after Tauri creates it (delayed to ensure WebView exists)
        Handler(Looper.getMainLooper()).postDelayed({
            val wv = findWebView(window.decorView)
            if (wv != null) {
                webViewRef = wv
                wv.addJavascriptInterface(VoIPCBridge(), "__VoIPC")
                // Security hardening: disable unnecessary WebView features
                wv.settings.setGeolocationEnabled(false)
                wv.settings.mediaPlaybackRequiresUserGesture = true
                wv.settings.javaScriptCanOpenWindowsAutomatically = false
            }
        }, 500)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
        when (requestCode) {
            REQUEST_RECORD_AUDIO -> {
                if (granted) {
                    android.util.Log.i("VoIPC", "RECORD_AUDIO permission granted")
                } else {
                    android.util.Log.w("VoIPC", "RECORD_AUDIO permission denied — microphone will not work")
                    evaluateJs("window.__voipc_permission_denied && window.__voipc_permission_denied('RECORD_AUDIO')")
                }
            }
            REQUEST_POST_NOTIFICATIONS -> {
                if (granted) {
                    android.util.Log.i("VoIPC", "POST_NOTIFICATIONS permission granted")
                } else {
                    android.util.Log.w("VoIPC", "POST_NOTIFICATIONS permission denied — call notification won't show")
                    evaluateJs("window.__voipc_permission_denied && window.__voipc_permission_denied('POST_NOTIFICATIONS')")
                }
            }
        }
    }

    override fun onDestroy() {
        unregisterReceiver(actionReceiver)
        super.onDestroy()
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        if (volumeKeyPttEnabled && keyCode == KeyEvent.KEYCODE_VOLUME_DOWN) {
            if (!volumeKeyPttActive) {
                volumeKeyPttActive = true
                evaluateJs("window.__voipc_ptt_press && window.__voipc_ptt_press()")
            }
            return true // Consume the event
        }
        return super.onKeyDown(keyCode, event)
    }

    override fun onKeyUp(keyCode: Int, event: KeyEvent?): Boolean {
        if (volumeKeyPttEnabled && keyCode == KeyEvent.KEYCODE_VOLUME_DOWN) {
            if (volumeKeyPttActive) {
                volumeKeyPttActive = false
                evaluateJs("window.__voipc_ptt_release && window.__voipc_ptt_release()")
            }
            return true
        }
        return super.onKeyUp(keyCode, event)
    }

    private fun evaluateJs(js: String) {
        runOnUiThread {
            (webViewRef ?: findWebView(window.decorView))?.evaluateJavascript(js, null)
        }
    }

    private fun findWebView(view: View): WebView? {
        if (view is WebView) return view
        if (view is ViewGroup) {
            for (i in 0 until view.childCount) {
                val result = findWebView(view.getChildAt(i))
                if (result != null) return result
            }
        }
        return null
    }

    // Start the foreground voice service
    fun startVoiceService(channelName: String) {
        val intent = Intent(this, VoiceService::class.java).apply {
            putExtra(VoiceService.EXTRA_CHANNEL_NAME, channelName)
        }
        startForegroundService(intent)
    }

    // Stop the foreground voice service
    fun stopVoiceService() {
        stopService(Intent(this, VoiceService::class.java))
    }
}
