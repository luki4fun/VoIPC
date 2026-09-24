// Per-server stores: what a component reads is the server on screen, what a
// handler writes is the server the event came from, and the two never leak
// into each other.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get, writable } from "svelte/store";
import { dropServer, scoped, serverAddress } from "./scoped.ts";

test("the bare store follows the server on screen", () => {
  const names = scoped<string[]>(() => []);
  names.of("a:1").set(["alice"]);
  names.of("b:2").set(["bob"]);

  const seen: string[][] = [];
  const stop = names.subscribe((v) => seen.push(v));
  serverAddress.set("a:1");
  assert.deepEqual(get(names), ["alice"]);
  serverAddress.set("b:2");
  assert.deepEqual(get(names), ["bob"]);
  // A write to the server on screen reaches a live subscriber too
  names.of("b:2").update((l) => [...l, "bea"]);
  assert.deepEqual(seen.at(-1), ["bob", "bea"]);
  stop();
  serverAddress.set("");
  assert.deepEqual(get(names), [], "no server on screen reads as the initial value");
});

test("of() keeps servers apart", () => {
  const id = scoped(() => 0);
  id.of("a:1").set(7);
  assert.equal(get(id.of("b:2")), 0, "writing one server leaves the other alone");
  assert.equal(get(id.of("a:1")), 7);
  assert.equal(id.of("a:1"), id.of("a:1"), "one store per server, not one per call");
});

test("the bare store has no setter", () => {
  const s = scoped(() => 1) as unknown as Record<string, unknown>;
  assert.equal(s.set, undefined);
  assert.equal(s.update, undefined);
});

test("at() follows another store's server", async () => {
  const id = scoped(() => 0);
  const which = writable<string | null>(null);
  const followed = id.at(which);
  id.of("a:1").set(5);
  assert.equal(get(followed), 0);
  which.set("a:1");
  assert.equal(get(followed), 5);
  // A server that gets its store only later is picked up when it does — a
  // microtask later, since `of` must not write reactive state where it reads
  which.set("c:3");
  const seen: number[] = [];
  const stop = followed.subscribe((v) => seen.push(v));
  id.of("c:3").set(9);
  await Promise.resolve();
  assert.equal(seen.at(-1), 9);
  stop();
});

test("all() lists every server and tracks their values", async () => {
  const unread = scoped(() => 0);
  unread.of("a:1").set(1);
  unread.of("b:2").set(2);
  const every = unread.all();
  let last = new Map<string, number>();
  const stop = every.subscribe((m) => (last = m));
  assert.deepEqual([...last], [["a:1", 1], ["b:2", 2]]);
  unread.of("b:2").set(3);
  assert.equal(last.get("b:2"), 3);
  unread.of("c:3").set(4);
  await Promise.resolve();
  assert.equal(last.get("c:3"), 4);
  stop();
});

test("drop forgets a server, and a live view of it reads empty", async () => {
  const names = scoped<string[]>(() => []);
  names.of("a:1").set(["alice"]);
  serverAddress.set("a:1");
  let last: string[] = ["?"];
  const stop = names.subscribe((v) => (last = v));
  names.drop("a:1");
  assert.deepEqual(last, []);
  assert.equal(get(names.all()).has("a:1"), false);
  // Coming back is a fresh start, and the view picks the new store up
  names.of("a:1").set(["again"]);
  await Promise.resolve();
  assert.deepEqual(last, ["again"]);
  stop();
  serverAddress.set("");
});

test("dropServer forgets a server in every scoped store at once", () => {
  const a = scoped(() => 0);
  const b = scoped(() => "");
  a.of("x:1").set(1);
  b.of("x:1").set("one");
  b.of("y:2").set("two");
  dropServer("x:1");
  assert.equal(get(a.all()).has("x:1"), false);
  assert.equal(get(b.all()).has("x:1"), false);
  assert.equal(get(b.of("y:2")), "two", "other servers are untouched");
});

test("of() for a new server writes nothing any view is subscribed to, there and then", async () => {
  // The shape of the bug that froze the desktop window at startup: a helper
  // read a server's value through of() while Svelte was evaluating a $derived,
  // of() created the store, and creating it wrote the registry every view
  // derives from — a write Svelte refuses inside a derived (state_unsafe_mutation).
  const names = scoped<string[]>(() => []);
  serverAddress.set("n:1");
  let emitted = 0;
  const stop = names.subscribe(() => emitted++);
  const before = emitted;
  names.of("n:1");
  assert.equal(emitted, before, "nothing emitted synchronously");
  await Promise.resolve();
  names.of("n:1").set(["later"]);
  assert.deepEqual(get(names), ["later"], "and the view finds the store once told");
  stop();
  serverAddress.set("");
});
