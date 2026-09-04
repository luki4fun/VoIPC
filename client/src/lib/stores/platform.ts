import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';
import { addNotification } from './notifications';

/** true in the browser build (web client), false in the Tauri app (desktop/Android). */
export const isWeb: boolean = __WEB__;

/** true when running on Android (Tauri mobile) or, on the web client, in a
 *  mobile browser — both get the phone layout. */
export const isMobile = writable(false);

/** Whether volume key PTT is enabled */
export const volumeKeyPtt = writable(false);

/** The currently active mobile tab */
export type MobileTab = 'channels' | 'chat' | 'users';
export const mobileTab = writable<MobileTab>('chat');

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
    // Volume key PTT press/release
    (window as any).__voipc_ptt_press = () => {
      invoke('start_transmit').catch(() => {});
    };
    (window as any).__voipc_ptt_release = () => {
      invoke('stop_transmit').catch(() => {});
    };

    // Notification action: disconnect
    (window as any).__voipc_disconnect = () => {
      invoke('disconnect').catch(() => {});
    };

    // Notification action: toggle mute
    (window as any).__voipc_toggle_mute = () => {
      invoke('toggle_mute').catch(() => {});
    };

    // Notification action: toggle deafen
    (window as any).__voipc_toggle_deafen = () => {
      invoke('toggle_deafen').catch(() => {});
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
