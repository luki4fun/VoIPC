import assert from "node:assert/strict";
import { test } from "node:test";

import { badgeStyle, badgesInOrder, colorOf, hexOf, sectionsOf } from "./member-sections.ts";

const styles = [
  { badge: "Lead", color: 0xff8800, section: true },
  { badge: "Crew", color: null, section: true },
  { badge: "Online", color: null, section: true },
];
const m = (name: string, ...badges: string[]) => ({ name, badges });
const names = (s: { members: { name: string }[] }) => s.members.map((x) => x.name);

test("everybody stands under their top group, top groups first", () => {
  const out = sectionsOf(
    [m("a", "Crew"), m("b"), m("c", "Crew", "Lead"), m("d", "Lead")],
    styles,
    "In voice",
  );
  assert.deepEqual(
    out.map((s) => s.label),
    ["Lead", "Crew", "In voice"],
  );
  assert.deepEqual(names(out[0]), ["c", "d"]);
  assert.deepEqual(names(out[1]), ["a"]);
  assert.deepEqual(names(out[2]), ["b"]);
});

test("a badge called like the fallback section does not collide with it", () => {
  const out = sectionsOf([m("a", "Online"), m("b")], styles, "Online");
  assert.deepEqual(
    out.map((s) => s.label),
    ["Online", "Online"],
  );
  assert.equal(new Set(out.map((s) => s.key)).size, 2);
});

test("a badge the server did not name, and an old relay naming none, mean no section", () => {
  assert.deepEqual(
    sectionsOf([m("a", "Ghost"), m("b")], styles, "In voice").map((s) => s.key),
    ["rest"],
  );
  assert.deepEqual(
    sectionsOf([m("a", "Lead")], [], "In voice").map((s) => s.label),
    ["In voice"],
  );
  assert.deepEqual(sectionsOf([], styles, "In voice"), []);
});

test("two groups with one badge draw one badge: a repeat would stop the keyed list", () => {
  assert.deepEqual(badgesInOrder(["Crew", "Lead", "Crew"], styles), ["Lead", "Crew"]);
});

test("a row's badges go by the server's order, what it did not name last", () => {
  assert.deepEqual(badgesInOrder(["Ghost", "Crew", "Lead"], styles), ["Lead", "Crew", "Ghost"]);
});

test("a colour is written out as six hex digits whatever the number", () => {
  assert.equal(hexOf(0xff8800), "#ff8800");
  assert.equal(hexOf(7), "#000007");
  assert.equal(hexOf(0x1ff8800), "#ff8800");
  assert.equal(colorOf("#FF8800"), 0xff8800);
  assert.equal(colorOf("red; background: url(x)"), null);
});

test("a badge with no colour keeps the theme's look, one with a colour its readable ink", () => {
  assert.equal(badgeStyle("Crew", styles), "");
  assert.equal(badgeStyle("Ghost", styles), "");
  assert.match(badgeStyle("Lead", styles), /^background: #ff8800; color: #[0-9a-f]{6};$/);
});

test("a group whose section is turned off keeps its badge, and its people stand with the next", () => {
  const off = [
    { badge: "Lead", color: 0xff8800, section: false },
    { badge: "Crew", color: null, section: true },
  ];
  const out = sectionsOf([m("a", "Lead"), m("b", "Lead", "Crew"), m("c")], off, "In voice");
  assert.deepEqual(
    out.map((s) => [s.label, names(s)]),
    [
      ["Crew", ["b"]],
      ["In voice", ["a", "c"]],
    ],
  );
  assert.deepEqual(badgesInOrder(["Crew", "Lead"], off), ["Lead", "Crew"], "the order of badges stays");
  assert.match(badgeStyle("Lead", off), /#ff8800/, "and its colour");
});
