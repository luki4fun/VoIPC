import { derived, writable } from "svelte/store";
import { uiPrefs } from "./ui-prefs.js";

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

// ── Our own share, as we send it ───────────────────────────────────────────

/** The native preview of our own share, a JPEG data URL (`screenshare-preview`).
 *  The browser shows its MediaStream instead and never sets this. */
export const previewFrame = writable<string | null>(null);

/** Our preview enlarged into the stream view, where a watched share goes. */
export const previewStage = writable(false);

/**
 * What the stream view shows: a share we watch, our own preview, or nothing.
 *
 * The one answer every layout reads — the modern overlay, its swipe guard and
 * the classic centre column — so none of them can disagree about whether the
 * view is open. Watching wins: there is one view, and while somebody else's
 * share is in it our own preview stays the floating card.
 */
export const streamStage = derived(
  [watchingUserId, poppedOut, previewStage, isSharingScreen],
  ([$watching, $popped, $stage, $sharing]): "watch" | "preview" | null =>
    $watching !== null && !$popped ? "watch" : $stage && $sharing ? "preview" : null,
);

/** Is our own preview on screen anywhere — the floating card or the stream
 *  view? Native capture runs for it and renders it only then. */
export const previewShown = derived(
  [isSharingScreen, streamStage, uiPrefs],
  ([$sharing, $stage, $prefs]) => $sharing && ($stage === "preview" || $prefs.share_preview),
);

// A share's preview ends with it
isSharingScreen.subscribe((sharing) => {
  if (!sharing) {
    previewStage.set(false);
    previewFrame.set(null);
  }
});

// Settings chosen when starting share (needed for start_screen_capture later)
export const shareResolution = writable<number>(720);
export const shareFps = writable<number>(30);

// Whether the source picker modal is open
export const showSourcePicker = writable<boolean>(false);

// Whether the picker is in "switch" mode (already sharing, switching source)
export const pickerSwitchMode = writable<boolean>(false);

// Current capture source tracking
export const currentSourceType = writable<string>("display");
export const currentSourceId = writable<string>("0");

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
  previewFrame.set(null);
  previewStage.set(false);
  shareResolution.set(720);
  shareFps.set(30);
  showSourcePicker.set(false);
  pickerSwitchMode.set(false);
  currentSourceType.set("display");
  currentSourceId.set("0");
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
