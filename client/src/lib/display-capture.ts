// What the browser client asks getDisplayMedia for, and why it is not the same
// everywhere.
//
// Firefox has never shipped audio capture for getDisplayMedia — Mozilla bug
// 1541425 has been open since 2019 — and asking for it anyway is not free: the
// picker then offers browser tabs and nothing else, so a Firefox user cannot
// share a screen or a window at all. VoIPC therefore asks without audio there,
// and the share dialog says so rather than quietly downgrading.

/**
 * Whether this browser can put the shared screen's sound in the stream.
 *
 * ponytail: user-agent sniffing. There is no feature test for a constraint the
 * browser accepts and then ignores, and `getDisplayMedia` cannot be probed
 * without opening a picker in the user's face. Ceiling: a Firefox fork that
 * rewrites its user agent gets the Chromium request, and at worst is back to
 * being offered tabs only.
 */
export function canShareDisplayAudio(
  ua: string = globalThis.navigator?.userAgent ?? "",
): boolean {
  return !/firefox|fxios/i.test(ua);
}

export interface DisplayCaptureQuality {
  width: number;
  height: number;
  fps: number;
}

/** The constraints handed to `navigator.mediaDevices.getDisplayMedia`. */
export function displayConstraints(
  quality: DisplayCaptureQuality,
  ua?: string,
): MediaStreamConstraints {
  return {
    video: {
      width: { ideal: quality.width },
      height: { ideal: quality.height },
      frameRate: { ideal: quality.fps },
    },
    audio: canShareDisplayAudio(ua),
  };
}
