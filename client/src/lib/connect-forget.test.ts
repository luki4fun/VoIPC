// R3 F10: a server given up on (the reconnect budget spent, a key refused) left what its
// sessions kept for a reconnect in memory until the app quit. Each such path goes through
// `removeServer`, and `disconnect` without `keepSessions` is what wipes it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("a server taken off the list has its kept sessions forgotten", () => {
  const code = readFileSync(new URL("./connect.ts", import.meta.url), "utf8");
  const start = code.indexOf("function removeServer(");
  const body = code.slice(start, code.indexOf("\n}\n", start));
  assert.match(body, /if \(!told\) invoke\("disconnect", \{ server \}\)/);
  // Only a close that disconnects it itself says so
  assert.deepEqual([...code.matchAll(/removeServer\(server, true\)/g)].length, 1);
  assert.match(code, /removeServer\(server, true\);\n  try \{\n    await invoke\("disconnect", \{ server \}\);/);
  assert.doesNotMatch(body, /keepSessions: true/, "and keeps nothing");
});
