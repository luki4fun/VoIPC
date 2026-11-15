// A read of a stored log reaches the desktop's disk only with the posts it read (Round C): the
// backend holds its cursors until a save that took the stores after them says so.

import { test } from "node:test";
import assert from "node:assert/strict";

const { invoked } = await import("./node-stores.mjs");
const { chatUnlocked, flushChatSave, noteReadUpto } = await import("./chat.ts");
const { chatHistoryDisabled } = await import("./settings.ts");

const calls = (command: string) =>
  (invoked() as [string, Record<string, unknown>][]).filter(([c]) => c === command).map(([, a]) => a);

test("a save carries the last read filed before it, and history off sends the read at once", async () => {
  chatUnlocked.set(true);
  chatHistoryDisabled.set(false);

  noteReadUpto(3);
  await flushChatSave();
  assert.equal(calls("save_chat_messages").at(-1)?.readUpto, 3, "a read alone asks for a save");

  // Out of order or not a number: nothing moves
  noteReadUpto(2);
  noteReadUpto(Number.NaN);
  const saves = calls("save_chat_messages").length;
  await flushChatSave();
  assert.equal(calls("save_chat_messages").length, saves, "no save was asked for");

  noteReadUpto(5);
  await flushChatSave();
  assert.equal(calls("save_chat_messages").at(-1)?.readUpto, 5);

  // History off keeps no posts to wait for
  chatHistoryDisabled.set(true);
  noteReadUpto(7);
  assert.deepEqual(calls("log_read_saved").at(-1), { upto: 7 });
  await flushChatSave();
  assert.equal(calls("save_chat_messages").at(-1)?.readUpto, 5, "and no save");
  chatHistoryDisabled.set(false);
});
