// The file size checks that run before wasm-bindgen copies a file into wasm
// memory (S-024). Pure functions only: the module itself is never loaded.

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkOpenInput, checkSealInput, MAX_FILE_BLOB, MAX_FILE_PLAIN, sealedLen } from "./wasm.ts";

/** A byte array of `length`, without allocating it. */
const bytes = (length: number) => ({ length }) as Uint8Array;

test("sealed lengths are voipc_crypto's", () => {
  assert.equal(sealedLen(0), 32 + 16);
  assert.equal(sealedLen(1), 32 + 1 + 16);
  assert.equal(sealedLen(64 * 1024), 32 + 64 * 1024 + 16);
  assert.equal(sealedLen(64 * 1024 + 1), 32 + 64 * 1024 + 1 + 2 * 16);
  // file.rs asserts the same
  assert.equal(MAX_FILE_BLOB, MAX_FILE_PLAIN + 32 + 1024 * 16);
});

test("a file too large for wasm is refused before it is copied there", () => {
  assert.doesNotThrow(() => checkSealInput(bytes(MAX_FILE_PLAIN)));
  assert.throws(() => checkSealInput(bytes(MAX_FILE_PLAIN + 1)), { name: "TooLarge" });
  assert.doesNotThrow(() => checkOpenInput(MAX_FILE_PLAIN, bytes(MAX_FILE_BLOB)));
  assert.throws(() => checkOpenInput(MAX_FILE_PLAIN + 1, bytes(100)), { name: "TooLarge" });
  assert.throws(() => checkOpenInput(10, bytes(MAX_FILE_BLOB + 1)), { name: "Malformed" });
  // A gigabyte claimed by a blob of a few bytes is refused by the size alone
  assert.throws(() => checkOpenInput(2 ** 30, bytes(48)), { name: "TooLarge" });
});
