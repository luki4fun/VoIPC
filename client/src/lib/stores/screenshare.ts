import { writable } from "svelte/store";

export interface ScreenShareInfo {
  user_id: number;
  username: string;
  resolution: number;
}

// Active screen shares in the current channel
export const activeScreenShares = writable<ScreenShareInfo[]>([]);

// Who we're currently watching (null = not watching)
export const watchingUserId = writable<number | null>(null);

// Whether the screen share viewer is popped out into a separate window
export const poppedOut = writable<boolean>(false);

// Module-level reference to the pop-out window (not reactive)
let popoutWindowRef: any = null;
export function setPopoutWindow(win: any) { popoutWindowRef = win; }
export function getPopoutWindow(): any { return popoutWindowRef; }

// Whether we are sharing our screen
export const isSharingScreen = writable<boolean>(false);

// Our viewer count (when sharing)
export const viewerCount = writable<number>(0);

// Current frame as data URL (base64 JPEG)
export const currentFrame = writable<string | null>(null);

// Settings chosen when starting share (needed for start_screen_capture later)
export const shareResolution = writable<number>(720);
export const shareFps = writable<number>(30);

// Whether the source picker modal is open
export const showSourcePicker = writable<boolean>(false);

// Screen audio toggle state (sharer side)
export const screenAudioEnabled = writable<boolean>(true);

// Screen audio activity indicators
export const screenAudioSending = writable<boolean>(false);
export const screenAudioReceiving = writable<boolean>(false);

// Screen share video stats (computed by polling in App.svelte)
export const senderFps = writable<number>(0);
export const senderBitrate = writable<number>(0);      // kbps
export const receiverFps = writable<number>(0);
export const receiverBitrate = writable<number>(0);     // kbps
export const receiverResolution = writable<string>("");  // "1280x720"
export const receiverFramesDropped = writable<number>(0);

export function addScreenShare(info: ScreenShareInfo) {
  activeScreenShares.update((shares) => {
    // Replace if already exists (shouldn't happen, but be safe)
    const filtered = shares.filter((s) => s.user_id !== info.user_id);
    return [...filtered, info];
  });
}

export function removeScreenShare(userId: number) {
  activeScreenShares.update((shares) =>
    shares.filter((s) => s.user_id !== userId)
  );
}

export function resetScreenShareState() {
  // Close pop-out window if open
  if (popoutWindowRef) {
    popoutWindowRef.close().catch(() => {});
    popoutWindowRef = null;
  }
  poppedOut.set(false);
  activeScreenShares.set([]);
  watchingUserId.set(null);
  isSharingScreen.set(false);
  viewerCount.set(0);
  currentFrame.set(null);
  shareResolution.set(720);
  shareFps.set(30);
  showSourcePicker.set(false);
  screenAudioEnabled.set(true);
  screenAudioSending.set(false);
  screenAudioReceiving.set(false);
  senderFps.set(0);
  senderBitrate.set(0);
  receiverFps.set(0);
  receiverBitrate.set(0);
  receiverResolution.set("");
  receiverFramesDropped.set(0);
}
