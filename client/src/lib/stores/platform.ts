import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';
import { addNotification } from './notifications';

/** true when running on Android (Tauri mobile). This is a Tauri app, not a web app,
 *  so the only mobile platform is Android. */
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
  isMobile.set(isAndroid);

  // Register global JS bridge functions for Android native → WebView communication.
  // These are called from MainActivity.kt via evaluateJavascript().
  if (isAndroid) {
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
