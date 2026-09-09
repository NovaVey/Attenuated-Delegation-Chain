import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRevocationList, REVOCATION_LIST_VERSION } from "../src/list.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

test("buildRevocationList: sorts and deduplicates the revoked hashes", () => {
  const list = buildRevocationList([HASH_B, HASH_A, HASH_B], { issuedAt: 1000 });
  assert.deepEqual(list.revoked, [HASH_A, HASH_B]);
});

test("buildRevocationList: defaults issuedAt to the real clock and ttlSeconds to DEFAULT_TTL_SECONDS", () => {
  const before = Math.floor(Date.now() / 1000);
  const list = buildRevocationList([]);
  const after = Math.floor(Date.now() / 1000);
  assert.ok(list.issuedAt >= before && list.issuedAt <= after);
  assert.equal(list.ttlSeconds, 60);
  assert.equal(list.v, REVOCATION_LIST_VERSION);
});

test("buildRevocationList: rejects a hash that isn't 64-char lowercase hex", () => {
  assert.throws(() => buildRevocationList(["not-a-hash"], { issuedAt: 1000 }), RangeError);
  assert.throws(() => buildRevocationList(["A".repeat(64)], { issuedAt: 1000 }), RangeError, "uppercase must be rejected");
  assert.throws(() => buildRevocationList(["a".repeat(63)], { issuedAt: 1000 }), RangeError, "too short");
  assert.throws(() => buildRevocationList([""], { issuedAt: 1000 }), RangeError, "empty string");
});

test("buildRevocationList: rejects an invalid ttlSeconds", () => {
  assert.throws(() => buildRevocationList([], { issuedAt: 1000, ttlSeconds: 0 }), RangeError);
  assert.throws(() => buildRevocationList([], { issuedAt: 1000, ttlSeconds: -5 }), RangeError);
  assert.throws(() => buildRevocationList([], { issuedAt: 1000, ttlSeconds: 1.5 }), RangeError);
});

test("buildRevocationList: rejects a negative issuedAt", () => {
  assert.throws(() => buildRevocationList([], { issuedAt: -1 }), RangeError);
});

test("buildRevocationList: an empty revoked set is valid (nothing revoked yet)", () => {
  const list = buildRevocationList([], { issuedAt: 1000 });
  assert.deepEqual(list.revoked, []);
});
