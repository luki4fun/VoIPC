import { writable } from 'svelte/store';
import { addNotification } from './notifications';
import { leaveVoice, startTransmit, stopTransmit, toggleDeafen, toggleMute } from './voice';
import { back } from './back-stack';

/** true in the browser build (web client), false in the Tauri app (desktop/Android). */
export const isWeb: boolean = __WEB__;

/** true when running on Android (Tauri mobile) or, on the web client, in a
 *  mobile browser — both get the phone layout. */
export const isMobile = writable(false);

/** Whether volume key PTT is enabled */
export const volumeKeyPtt = writable(false);

/** The currently active mobile tab */
export type MobileTab = 'channels' | 'chat' | 'mixer' | 'room' | 'users';
export const mobileTab = writable<MobileTab>('chat');

/**
 * "Show the chat", for whichever shell is on screen.
 *
 * The two say it differently — the classic layout has tabs and the modern one a
 * drawer over the chat — and picking a channel has to do it in both: on a phone
 * the channel list covers what you just asked to read, so a tap that changes
 * nothing visible reads as a tap that did nothing. A counter rather than a flag
 * because it is an event: asking twice has to arrive twice.
 */
export const showChatRequested = writable(0);

export function showChatPane(): void {
  mobileTab.set('chat');
  showChatRequested.update((n) => n + 1);
}

// Detect platform on init.
// Primary: check user agent for "Android" (always present in Android WebView).
// Secondary: check for our Kotlin JS bridge (__VoIPC) injected by MainActivity.kt.
if (typeof window !== 'undefined') {
  const isAndroid = /android/i.test(navigator.userAgent)
    || typeof (window as any).__VoIPC !== 'undefined';
  // Web: any phone gets the phone layout (iPhone Safari has no "Android" in
  // its UA; iPadOS masquerades as a Mac, hence the coarse-pointer fallback)
  const isPhoneBrowser = isWeb && (
    /iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent)
    || (window.matchMedia?.('(pointer: coarse)').matches && window.innerWidth < 900)
  );
  isMobile.set(isAndroid || isPhoneBrowser);

  // Register global JS bridge functions for Android native → WebView communication.
  // These are called from MainActivity.kt via evaluateJavascript(). The web
  // client has no native side, so an Android browser gets none of them.
  if (isAndroid && !isWeb) {
    // System Back (MainActivity.kt): close the topmost open layer. True when
    // something took the press; false sends the app to the background.
    (window as any).__voipc_back = () => back();

    // Volume key PTT press/release.
    //
    // Through the shared actions, which also set `isTransmitting` — invoking
    // the commands directly opened the microphone without anything in the UI
    // knowing, so the voice bar showed nothing and the voice-activation
    // auto-start could not tell the mic was already open.
    (window as any).__voipc_ptt_press = () => {
      void startTransmit();
    };
    (window as any).__voipc_ptt_release = () => {
      void stopTransmit();
    };

    // Notification action: the call notification's button. It is the call's,
    // so it ends the call — leaving voice, not the server, and not the other
    // servers that are open.
    (window as any).__voipc_disconnect = () => {
      void leaveVoice();
    };

    // Notification actions: toggle mute / deafen. The result has to be fed back
    // into the stores — the button and our own row in the member list both read
    // them, and nothing else in the app learns about a toggle made from the
    // notification shade.
    (window as any).__voipc_toggle_mute = () => {
      void toggleMute();
    };

    (window as any).__voipc_toggle_deafen = () => {
      void toggleDeafen();
    };

    // The microphone was granted on joining (MainActivity asks then, not at
    // start). The capture the join opened before the answer failed; closing
    // it lets voice activation open it again, now with the permission.
    (window as any).__voipc_mic_granted = () => {
      void stopTransmit();
    };

    // Permission denial feedback from MainActivity
    (window as any).__voipc_permission_denied = (permission: string) => {
      if (permission === 'RECORD_AUDIO') {
        addNotification("Microphone permission denied \u2014 voice won't work. Grant in Settings \u2192 Apps \u2192 VoIPC.", "error");
      } else if (permission === 'POST_NOTIFICATIONS') {
        addNotification("Notification permission denied \u2014 active call indicator won't show.", "warning");
      }
    };
  }
}
