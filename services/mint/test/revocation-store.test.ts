import { test } from "node:test";
import assert from "node:assert/strict";
import { RevocationStore } from "../src/revocation-store.js";

const VALID_HASH = "a".repeat(64);

test("revoke()/list(): a revoked hash shows up in list()", () => {
  const store = new RevocationStore();
  store.revoke(VALID_HASH);
  assert.deepEqual(store.list(), [VALID_HASH]);
});

test("revoke(): idempotent — revoking the same hash twice doesn't duplicate it", () => {
  const store = new RevocationStore();
  store.revoke(VALID_HASH);
  store.revoke(VALID_HASH);
  assert.deepEqual(store.list(), [VALID_HASH]);
});

test("list(): empty for a fresh store", () => {
  assert.deepEqual(new RevocationStore().list(), []);
});

test("revoke(): rejects anything that isn't a 64-char lowercase hex hash", () => {
  const store = new RevocationStore();
  for (const bad of ["not-a-hash", "A".repeat(64), "a".repeat(63), "a".repeat(65), ""]) {
    assert.throws(() => store.revoke(bad), RangeError, `expected RangeError for ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(store.list(), [], "no partial/invalid entries leaked into the store");
});

test("list(): reflects multiple distinct revoked hashes", () => {
  const store = new RevocationStore();
  const hashB = "b".repeat(64);
  store.revoke(VALID_HASH);
  store.revoke(hashB);
  assert.deepEqual([...store.list()].sort(), [VALID_HASH, hashB].sort());
});
