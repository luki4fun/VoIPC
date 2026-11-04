import assert from "node:assert/strict";
import { test } from "node:test";

import { buildJoinLink, parseJoinFragment, parseJoinLink } from "./invite.ts";

test("a link to sign up with: its code, whole, and the channel it opens", () => {
  const code = "A".repeat(43);
  assert.deepEqual(parseJoinFragment(`#join=${code}`), { code, channel: null });
  assert.deepEqual(parseJoinFragment(`join=${code}&channel=welcome`), { code, channel: "welcome" });
  for (const bad of ["#join=short", `#join=${code}x`, "#channel=x", "#join=", `#join=${"A".repeat(42)}!`]) {
    assert.equal(parseJoinFragment(bad), null, bad);
  }
  const link = buildJoinLink("ivy.l4f.cc", 9987, code, "the lobby");
  assert.equal(link, `https://ivy.l4f.cc:9987/#join=${code}&channel=the%20lobby`);
  assert.deepEqual(parseJoinLink(link), { host: "ivy.l4f.cc", port: 9987, code, channel: "the lobby" });
  assert.deepEqual(parseJoinLink(buildJoinLink("::1", 9987, code)), { host: "::1", port: 9987, code, channel: null });
  assert.equal(parseJoinLink(`http://ivy.l4f.cc/#join=${code}`), null, "https only");
  assert.equal(parseJoinLink("not a link"), null);
});
