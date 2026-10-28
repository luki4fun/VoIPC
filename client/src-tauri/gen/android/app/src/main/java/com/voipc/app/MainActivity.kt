package com.voipc.app

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.content.res.Resources
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.media.AudioPlaybackConfiguration
import android.media.AudioRecordingConfiguration
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import org.json.JSONObject
import java.io.File

class MainActivity : TauriActivity() {

    companion object {
        private const val REQUEST_RECORD_AUDIO = 1001
        private const val REQUEST_POST_NOTIFICATIONS = 1002

        /**
         * Each palette's page background (--bg-primary in theme.ts) and
         * whether it is light. A copy, so the window can show it before the
         * page has loaded; an id this table does not know falls back to the
         * system's mode, as the page itself would.
         */
        private val PALETTE_BACKGROUNDS = mapOf(
            "voipc-night" to ("#1c1f24" to false),
            "voipc-day" to ("#ffffff" to true),
            "voipc-dark" to ("#1a1a2e" to false),
            "slate-dark" to ("#313338" to false),
            "slate-light" to ("#ffffff" to true),
            "amoled" to ("#000000" to false),
            // Renamed in 0.11 (theme.ts RENAMED_PALETTES)
            "discord-dark" to ("#313338" to false),
            "discord-light" to ("#ffffff" to true),
        )

        /** The splash for the next start, per palette (themes.xml Launch.*). */
        private val LAUNCH_THEMES = mapOf(
            "voipc-night" to R.style.Theme_voipc_client_Launch_voipc_night,
            "voipc-day" to R.style.Theme_voipc_client_Launch_voipc_day,
            "voipc-dark" to R.style.Theme_voipc_client_Launch_voipc_dark,
            "slate-dark" to R.style.Theme_voipc_client_Launch_slate_dark,
            "slate-light" to R.style.Theme_voipc_client_Launch_slate_light,
            "amoled" to R.style.Theme_voipc_client_Launch_amoled,
            "discord-dark" to R.style.Theme_voipc_client_Launch_slate_dark,
            "discord-light" to R.style.Theme_voipc_client_Launch_slate_light,
        )
    }

    /** The palette id somebody chose, from settings.json; null when none was. */
    private var chosenPalette: String? = null

    /**
     * What the window shows before the page paints, and which way round the
     * bar icons go: the stored palette's own background when somebody chose
     * one, else the system mode's default (VoIPC day or night, which is also
     * what values[-night]/colors.xml says). A dark palette on a phone in light
     * mode used to open on a second of white with white icons on it.
     * Null colour: keep the theme's window background.
     */
    private fun launchLook(): Pair<Int?, Boolean> {
        val systemLight = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) !=
            Configuration.UI_MODE_NIGHT_YES
        val stored = try {
            // config::data_dir() is Tauri's app_data_dir(); look in both places
            // it can resolve to rather than depend on which one that is
            val file = listOf(File(filesDir, "settings.json"), File(dataDir, "settings.json"))
                .firstOrNull { it.isFile }
            val prefs = file?.let { JSONObject(it.readText()).optJSONObject("ui_prefs") }
            // palette_chosen is recorded since 1.1.0; absent with a palette
            // stored means it was chosen (ui-prefs.ts sanitizeUiPrefs)
            if (prefs == null || !prefs.optBoolean("palette_chosen", true)) null
            else {
                chosenPalette = prefs.optString("palette", "").ifEmpty { null }
                val known = PALETTE_BACKGROUNDS[prefs.optString("palette", "")]
                val own = prefs.optJSONObject("palette_overrides")?.optString("--bg-primary", "")
                    ?.takeIf { it.matches(Regex("#[0-9a-fA-F]{6}")) }
                when {
                    known == null -> null
                    own != null -> own to known.second
                    else -> known
                }
            }
        } catch (e: Exception) {
            null
        }
        return if (stored != null) Color.parseColor(stored.first) to stored.second else null to systemLight
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
    // What the window opened in (launchLook), for the WebView to keep showing
    // until the page paints
    private var launchBackground: Int? = null

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

    // A file the page asked to save (VoIPCBridge.saveFile): it waits in
    // `save-out` until the system's "save to" picker answers, is copied to
    // where the person chose, and goes. One at a time: a second ask while the
    // picker is open is refused, so no answer lands on the wrong file.
    @Volatile private var pendingSave: File? = null
    private var pendingSaveMime = "application/octet-stream"
    private val saveDocument = registerForActivityResult(
        object : ActivityResultContracts.CreateDocument("application/octet-stream") {
            override fun createIntent(context: Context, input: String): Intent =
                super.createIntent(context, input).setType(pendingSaveMime)
        }
    ) { uri -> finishSave(uri) }

    private fun finishSave(uri: Uri?) {
        val file = pendingSave ?: return
        if (uri == null) {
            // The person backed out of the picker
            file.delete()
            pendingSave = null
            evaluateJs("window.__voipc_saved && window.__voipc_saved(null)")
            return
        }
        // Off the UI thread: up to 64 MiB to a provider that may be slow
        Thread {
            val ok = runCatching {
                contentResolver.openOutputStream(uri)?.use { out -> file.inputStream().use { it.copyTo(out) } } != null
            }.getOrDefault(false)
            // A document left half written is no copy of the file
            if (!ok) runCatching { DocumentsContract.deleteDocument(contentResolver, uri) }
            file.delete()
            pendingSave = null
            evaluateJs("window.__voipc_saved && window.__voipc_saved($ok)")
        }.start()
    }

    // JS interface exposed as window.__VoIPC in the WebView
    inner class VoIPCBridge {
        /**
         * Save a file the page has put in `save-out` (files.rs `save_file`),
         * where the system's own picker lets the person choose. Only a path in
         * there is taken, so the page can copy nothing else of the app's out.
         * Never opened or run.
         */
        @JavascriptInterface
        fun saveFile(path: String, name: String, mime: String) {
            val file = File(path).canonicalFile
            val home = File(applicationInfo.dataDir).canonicalPath + File.separator
            val inSaveOut = file.parentFile?.name == "save-out" && file.path.startsWith(home) && file.isFile
            if (!inSaveOut || pendingSave != null) {
                if (inSaveOut) file.delete()
                evaluateJs("window.__voipc_saved && window.__voipc_saved(false)")
                return
            }
            this@MainActivity.runOnUiThread {
                pendingSave = file
                pendingSaveMime = mime.takeIf { Regex("""^[\w.+-]+/[\w.+-]+$""").matches(it) }
                    ?: "application/octet-stream"
                saveDocument.launch(name)
            }
        }

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
        // improve. `setSystemBarsLight` flips the icons when the palette
        // changes; this is the starting point, from the stored palette
        // (launchLook), so the icons already suit the first frame.
        val (launchColour, launchLight) = launchLook()
        val bars = if (launchLight) SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
            else SystemBarStyle.dark(Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = bars, navigationBarStyle = bars)
        launchColour?.let { window.setBackgroundDrawable(ColorDrawable(it)) }
        launchBackground = launchColour
        super.onCreate(savedInstanceState)

        // The splash Android draws before any of this runs comes from the theme
        // alone: tell it the palette's for next time (Android 13+), or let it
        // follow the system's mode again when no palette was chosen
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            splashScreen.setSplashScreenTheme(chosenPalette?.let { LAUNCH_THEMES[it] } ?: Resources.ID_NULL)
        }

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

        // The on-screen keyboard. Edge to edge, the window no longer shrinks
        // for it (adjustResize is a no-op once the app draws behind the
        // system bars), and the page is exactly the window's height — so the
        // message box at the bottom sat under the keyboard. The content view
        // is padded by the keyboard's height instead, less the navigation
        // bar's, which the page already keeps clear itself with
        // env(safe-area-inset-bottom). The insets go on to the WebView
        // unchanged, so those env() values stay right.
        val content = findViewById<View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
            val nav = insets.getInsets(WindowInsetsCompat.Type.navigationBars()).bottom
            view.setPadding(0, 0, 0, if (ime > nav) ime - nav else 0)
            insets
        }

        // Back closes what is open on the page, topmost first — a menu, a
        // dialog, the stream or mixer view, a drawer (stores/back-stack.ts).
        // Only with nothing open does it leave, and then by putting the app
        // in the background rather than finishing it: finishing used to end
        // the call along with the activity. TauriActivity turns wry's own
        // handler off (handleBackNavigation = false), so this is the only one.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val webView = webViewRef ?: findWebView(window.decorView)
                if (webView == null) {
                    moveTaskToBack(true)
                    return
                }
                webView.evaluateJavascript(
                    "(window.__voipc_back ? window.__voipc_back() : false) === true",
                ) { handled ->
                    if (handled != "true") moveTaskToBack(true)
                }
            }
        })
    }

    // Called by wry as it creates the WebView, before the first page load: an
    // interface added after a load only shows up on the next one. It was a
    // 500 ms timer, which a slow cold start could beat, leaving the call with
    // no foreground service and no speaker control (H4-15).
    override fun onWebViewCreate(webView: WebView) {
        webViewRef = webView
        // A WebView paints its own default (white, or black in night mode)
        // until the page's first frame: the same colour as the window instead,
        // or the window's own showing through, so a cold start does not flash
        webView.setBackgroundColor(launchBackground ?: Color.TRANSPARENT)
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
