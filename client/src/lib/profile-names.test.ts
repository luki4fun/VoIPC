// Every place that shows a member by name goes through MemberName: a place that
// forgets shows `bob` in one list and `Robert @bob` in the next, and someone who
// picked a name that place cannot be told apart by what they are called elsewhere.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const SHOWN_IN = [
  "components/modern/MemberList.svelte",
  "components/modern/ChannelSidebar.svelte",
  "components/modern/UserPanel.svelte",
  "components/stage/SpeakerTile.svelte",
  "components/chat/MessageList.svelte",
  "components/UserContextMenu.svelte",
];

test("the member rows use MemberName", () => {
  for (const file of SHOWN_IN) {
    const text = readFileSync(new URL(`./${file}`, import.meta.url), "utf8");
    assert.match(text, /<MemberName\b/, file);
  }
});

test("a chat header does not take a shared message's word for whose account it is", () => {
  const text = readFileSync(new URL("./components/chat/MessageList.svelte", import.meta.url), "utf8");
  assert.match(text, /msg\.kind === "shared" \? null : msg\.account/);
});
