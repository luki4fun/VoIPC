// What 1.6.0's and 1.11.0's front ends kept in a desktop history's `extra`
// (client/src-tauri/tests/fixtures/<version>/expected.json, written once by
// those versions and never regenerated) still reads back here: every field,
// and what this version does not know is kept for the next save.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fromArchived, toArchived } from "./chat-rules.ts";
import type { ChatMessage } from "./types.ts";

type Archived = ChatMessage & { extra?: string | null };

function messages(version: string): Archived[] {
  const path = join(import.meta.dirname, "../../src-tauri/tests/fixtures", version, "expected.json");
  const archive = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  const chats = { ...(archive.channels as object), ...(archive.dms as object) } as Record<string, Archived[]>;
  return Object.values(chats).flat();
}

for (const version of ["1.6.0", "1.11.0"]) {
  test(`a ${version} history's extra fields all read back and save again`, () => {
    const all = messages(version);
    const withExtra = all.filter((m) => typeof m.extra === "string");
    assert.ok(withExtra.length >= 3, "the fixture holds messages with extra fields");
    for (const m of withExtra) {
      const stored = JSON.parse(m.extra as string) as Record<string, unknown>;
      const back = fromArchived(m);
      const kept = back.extra_kept ? (JSON.parse(back.extra_kept) as Record<string, unknown>) : {};
      for (const [k, v] of Object.entries(stored)) {
        if (k in kept) assert.deepEqual(kept[k], v, `${m.id}: ${k} kept as it was`);
        else assert.deepEqual((back as unknown as Record<string, unknown>)[k], v, `${m.id}: ${k} read back`);
      }
      assert.deepEqual(JSON.parse(toArchived(back).extra ?? "{}"), stored, `${m.id}: saved again as it was`);
    }
  });
}

test("a 1.11 history's field from a later version is kept, not read", () => {
  const future = messages("1.11.0").find((m) => m.content === "a later 1.x kept something here");
  assert.ok(future);
  const back = fromArchived(future);
  assert.ok(!("later_field" in back));
  assert.deepEqual(JSON.parse(back.extra_kept ?? "{}"), { later_field: { a: 1 } });
});
