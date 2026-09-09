// Per-browser getDisplayMedia constraints. Pure functions only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { canShareDisplayAudio, displayConstraints } from "./display-capture.ts";

const CHROME =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0";
const FIREFOX_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) FxiOS/133.0 Mobile/15E148 Safari/605.1.15";
const SAFARI =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

test("only Firefox is refused screen audio", () => {
  assert.equal(canShareDisplayAudio(CHROME), true);
  assert.equal(canShareDisplayAudio(SAFARI), true);
  assert.equal(canShareDisplayAudio(FIREFOX), false);
  assert.equal(canShareDisplayAudio(FIREFOX_IOS), false);
  // Chrome's own UA carries "like Gecko" — that must not read as Firefox
  assert.ok(CHROME.includes("like Gecko"));
});

test("an unknown browser is asked for audio", () => {
  // The desktop webview and anything we have not heard of: assume it works,
  // the worst case is an audio track the browser never fills.
  assert.equal(canShareDisplayAudio(""), true);
  assert.equal(canShareDisplayAudio("SomeNewBrowser/1.0"), true);
});

test("quality survives, audio follows the browser", () => {
  const quality = { width: 1280, height: 720, fps: 30 };

  const chrome = displayConstraints(quality, CHROME);
  assert.equal(chrome.audio, true);
  assert.deepEqual(chrome.video, {
    width: { ideal: 1280 },
    height: { ideal: 720 },
    frameRate: { ideal: 30 },
  });

  const firefox = displayConstraints(quality, FIREFOX);
  assert.equal(firefox.audio, false);
  // Firefox loses only the audio: the picker must still be asked for the same
  // resolution and frame rate, or a screen share there would look different
  assert.deepEqual(firefox.video, chrome.video);
});
