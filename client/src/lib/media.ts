// What the page may show of a file somebody else made, and how.
//
// A picture is never handed to the browser's or the WebView's own decoder as
// it came: a crafted one (libwebp's CVE-2023-4863, say) runs code there. It
// is decoded by memory-safe Rust (crates/voipc-media: natively on the
// desktop and Android, as wasm in a worker in the browser) and only the PNG
// written for it is drawn (`pictureUrl`). Video and sound cannot be made
// safe that way; they play through the system's decoders only where the
// person allows it (`playsMedia`). image-sinks.test.ts checks that no other
// code makes an object URL a picture could be drawn from.

import { invoke } from "@tauri-apps/api/core";
import type { FileBlob, FileConv } from "./types";
import type { UiPrefs } from "./ui-prefs";
import { isAndroidApp, isWeb } from "./stores/platform";

/** crates/voipc-media `Profile`. */
export const PROFILE = { emote: 0, sticker: 1, photo: 2 } as const;

/** A file's picture as the PNG it may be shown as, from the file's own copy
 *  (desktop: `files.rs file_image`; browser: `web/backend/files.ts`). Throws
 *  why it is not shown. */
export async function fileImage(server: string, conv: FileConv, file: FileBlob, op?: string): Promise<Uint8Array> {
  return new Uint8Array(await invoke<ArrayBuffer>("file_image", { server, conv, file, profile: PROFILE.photo, op }));
}

/** An object URL for a PNG the sanitizer wrote; nothing else is drawn. */
export function pictureUrl(png: Uint8Array): string {
  return URL.createObjectURL(new Blob([png as Uint8Array<ArrayBuffer>], { type: "image/png" }));
}

/** An object URL for a video or a sound, typed by its sniffed kind. */
export function playableUrl(bytes: Uint8Array, mime: string): string {
  if (!/^(video|audio)\//.test(mime)) throw new Error(`not a video or a sound: ${mime}`);
  return URL.createObjectURL(new Blob([bytes as Uint8Array<ArrayBuffer>], { type: mime }));
}

/**
 * The desktop app on Linux: its WebKitGTK web process runs unsandboxed
 * (checked 2026-10-29, WebKitGTK 2.54: same mount namespace, no seccomp), so a
 * video's decoder (GStreamer) holds what the app holds. Its sandbox cannot be
 * turned on reliably (bubblewrap needs user namespaces some distributions
 * restrict), so there video and sound play inline only once asked for.
 */
export const LINUX_APP = !isWeb && !isAndroidApp && typeof navigator !== "undefined" && /Linux/.test(navigator.userAgent);

/** Whether a loaded video or sound plays here: the person's answer, else on
 *  everywhere but the Linux desktop app. */
export function playsMedia(prefs: Pick<UiPrefs, "play_media">): boolean {
  return prefs.play_media ?? !LINUX_APP;
}
