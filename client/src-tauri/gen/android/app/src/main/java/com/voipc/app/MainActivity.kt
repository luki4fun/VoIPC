package com.voipc.app

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.media.AudioPlaybackConfiguration
import android.media.AudioRecordingConfiguration
import android.os.Build
import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.WindowInsetsControllerCompat

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
    // The loudspeaker rather than the earpiece, the default for a VoIP app
    private var speakerOn = true
    // The channel the voice service is up for; null while not in a call
    private var voiceChannel: String? = null

    // Android 12+ drops MODE_IN_COMMUNICATION again while the app that set it
    // has no call audio running — between talkers, with push-to-talk up. Set it
    // again the moment ours starts, so the echo canceller has its mode.
    private fun reassertCallMode() {
        val am = audioManager ?: return
        if (voiceChannel != null && am.mode != AudioManager.MODE_IN_COMMUNICATION) applyCallAudio()
    }
    private val playbackCallback = object : AudioManager.AudioPlaybackCallback() {
        override fun onPlaybackConfigChanged(configs: MutableList<AudioPlaybackConfiguration>) {
            reassertCallMode()
        }
    }
    private val recordingCallback = object : AudioManager.AudioRecordingCallback() {
        override fun onRecordingConfigChanged(configs: MutableList<AudioRecordingConfiguration>) {
            reassertCallMode()
        }
    }

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

        /**
         * Which way round the status- and navigation-bar icons should be
         * drawn, for the palette the user has chosen.
         *
         * The bars are transparent and the page paints its own background into
         * them, so the icons are the only part Android still owns — and white
         * icons on the Slate light palette are invisible.
         */
        @JavascriptInterface
        fun setSystemBarsLight(light: Boolean) {
            this@MainActivity.runOnUiThread {
                WindowInsetsControllerCompat(window, window.decorView).apply {
                    isAppearanceLightStatusBars = light
                    isAppearanceLightNavigationBars = light
                }
            }
        }

        @JavascriptInterface
        fun setSpeakerphone(enabled: Boolean) {
            this@MainActivity.runOnUiThread {
                this@MainActivity.speakerOn = enabled
                if (this@MainActivity.voiceChannel != null) this@MainActivity.applyCallAudio()
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
        // Transparent bars with no scrim and light icons, rather than the
        // `enableEdgeToEdge()` default, which is `SystemBarStyle.auto(...)`:
        // that reads the *system* day/night setting at onCreate and paints a
        // 90%-white scrim across the navigation bar of a dark app, with dark
        // status icons that vanish against it. The page paints its own
        // background into both strips and keeps its content out of them with
        // env(safe-area-inset-*), so there is nothing here for Android to
        // improve. `setSystemBarsLight` flips the icons when a light palette
        // is chosen; this is the starting point, and the default palette
        // is dark.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
        )
        super.onCreate(savedInstanceState)

        audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        audioManager?.registerAudioPlaybackCallback(playbackCallback, null)
        audioManager?.registerAudioRecordingCallback(recordingCallback, null)

        // The microphone is asked for on joining voice (startVoiceService),
        // not at every cold start: a "don't ask again" answered here, before
        // the page had loaded, reached no handler and was never shown (H4-18).

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
        // Not exported on every API level: below 33 a plain registerReceiver
        // lets any installed app send ACTION_MUTE, which toggles — unmutes.
        // ContextCompat guards the old levels with a signature permission.
        ContextCompat.registerReceiver(this, actionReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

    }

    // Called by wry as it creates the WebView, before the first page load: an
    // interface added after a load only shows up on the next one. It was a
    // 500 ms timer, which a slow cold start could beat, leaving the call with
    // no foreground service and no speaker control (H4-15).
    override fun onWebViewCreate(webView: WebView) {
        webViewRef = webView
        webView.addJavascriptInterface(VoIPCBridge(), "__VoIPC")
        // Security hardening: disable unnecessary WebView features
        webView.settings.setGeolocationEnabled(false)
        webView.settings.mediaPlaybackRequiresUserGesture = true
        webView.settings.javaScriptCanOpenWindowsAutomatically = false
    }

    /**
     * The call's audio routing, for as long as the call lasts. The platform's
     * echo cancellation only runs in MODE_IN_COMMUNICATION, so the loudspeaker
     * is chosen as the communication device rather than by dropping to
     * MODE_NORMAL, which played the speaker straight into the microphone (H3-01).
     */
    private fun applyCallAudio() {
        val am = audioManager ?: return
        am.mode = AudioManager.MODE_IN_COMMUNICATION
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (speakerOn) {
                am.availableCommunicationDevices
                    .firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
                    ?.let { am.setCommunicationDevice(it) }
            } else {
                am.clearCommunicationDevice()
            }
        } else {
            @Suppress("DEPRECATION")
            am.isSpeakerphoneOn = speakerOn
        }
    }

    private fun releaseCallAudio() {
        val am = audioManager ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            am.clearCommunicationDevice()
        } else {
            @Suppress("DEPRECATION")
            am.isSpeakerphoneOn = false
        }
        am.mode = AudioManager.MODE_NORMAL
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
                    // Started before the answer, the service holds no
                    // microphone type yet, and the capture the join opened
                    // failed: restart both now.
                    voiceChannel?.let { startVoiceService(it) }
                    evaluateJs("window.__voipc_mic_granted && window.__voipc_mic_granted()")
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
        audioManager?.unregisterAudioPlaybackCallback(playbackCallback)
        audioManager?.unregisterAudioRecordingCallback(recordingCallback)
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

    // Start the foreground voice service, and ask for the microphone the
    // first time a call needs it
    fun startVoiceService(channelName: String) {
        runOnUiThread {
            voiceChannel = channelName
            applyCallAudio()
            val intent = Intent(this, VoiceService::class.java).apply {
                putExtra(VoiceService.EXTRA_CHANNEL_NAME, channelName)
            }
            startForegroundService(intent)
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.RECORD_AUDIO),
                    REQUEST_RECORD_AUDIO
                )
            }
        }
    }

    // Stop the foreground voice service
    fun stopVoiceService() {
        runOnUiThread {
            if (voiceChannel != null) releaseCallAudio()
            voiceChannel = null
            stopService(Intent(this, VoiceService::class.java))
        }
    }
}
