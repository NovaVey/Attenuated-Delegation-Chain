import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "@adc/core";
import { buildRevocationList, REVOCATION_LIST_VERSION, type RevocationListPayload } from "../src/list.js";
import { signRevocationList, revocationSignInput } from "../src/sign.js";
import { verifySignedRevocationList } from "../src/verify.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

function freshRoot() {
  const { secretKey, publicKey } = generateKeypair();
  return { rootSecretKey: secretKey, rootPublicKey: publicKey };
}

test("real round trip: a list signed with the root key verifies under its public key and yields the exact revoked set", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const list = buildRevocationList([HASH_A, HASH_B], { issuedAt: 1_000, ttlSeconds: 60 });
  const signed = signRevocationList(list, rootSecretKey);

  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_010 });

  assert.equal(result.ok, true);
  if (!result.ok) throw new Error("unreachable");
  assert.deepEqual([...result.revokedHashes].sort(), [HASH_A, HASH_B]);
  assert.equal(result.payload.issuedAt, 1_000);
});

test("an empty revoked list still signs and verifies (nothing revoked yet is a valid, signed statement)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([], { issuedAt: 1_000 }), rootSecretKey);
  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_010 });
  assert.equal(result.ok, true);
});

test("wrong root public key: BAD_SIGNATURE", () => {
  const { rootSecretKey } = freshRoot();
  const { rootPublicKey: wrongKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_000 }), rootSecretKey);

  const result = verifySignedRevocationList(signed, wrongKey, { now: 1_010 });

  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "BAD_SIGNATURE");
});

test("tampering with the payload after signing (adding a hash) is caught: BAD_SIGNATURE", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_000 }), rootSecretKey);

  const tampered = { ...signed, payload: { ...signed.payload, revoked: [...signed.payload.revoked, HASH_B] } };

  const result = verifySignedRevocationList(tampered, rootPublicKey, { now: 1_010 });
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "BAD_SIGNATURE");
});

test("tampering with issuedAt after signing (trying to make a stale list look fresh) is caught: BAD_SIGNATURE", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_000, ttlSeconds: 60 }), rootSecretKey);

  const tampered = { ...signed, payload: { ...signed.payload, issuedAt: 1_000_000 } };

  const result = verifySignedRevocationList(tampered, rootPublicKey, { now: 1_000_010 });
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "BAD_SIGNATURE");
});

test("removing a revoked hash after signing (trying to un-revoke something) is caught: BAD_SIGNATURE", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A, HASH_B], { issuedAt: 1_000 }), rootSecretKey);

  const tampered = { ...signed, payload: { ...signed.payload, revoked: [HASH_A] } };

  const result = verifySignedRevocationList(tampered, rootPublicKey, { now: 1_010 });
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "BAD_SIGNATURE");
});

test("a corrupted signature string is caught: BAD_SIGNATURE, not a thrown error", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_000 }), rootSecretKey);
  const corrupted = { ...signed, signature: signed.signature.slice(0, -4) + "xxxx" };

  const result = verifySignedRevocationList(corrupted, rootPublicKey, { now: 1_010 });
  assert.equal(result.ok, false);
});

test("a genuinely non-base64url signature string denies MALFORMED, not a thrown error", () => {
  const { rootPublicKey } = freshRoot();
  const bad = { payload: { v: REVOCATION_LIST_VERSION, issuedAt: 1000, ttlSeconds: 60, revoked: [] }, signature: "!!!not-base64url!!!" };
  const result = verifySignedRevocationList(bad, rootPublicKey, { now: 1010 });
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "MALFORMED");
});

// --- freshness -------------------------------------------------------------

test("exactly at the TTL boundary (no skew needed): still allowed", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([], { issuedAt: 1_000, ttlSeconds: 60 }), rootSecretKey);
  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_060, clockSkewSeconds: 0 });
  assert.equal(result.ok, true);
});

test("one second past TTL with zero skew: EXPIRED", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([], { issuedAt: 1_000, ttlSeconds: 60 }), rootSecretKey);
  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_061, clockSkewSeconds: 0 });
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "EXPIRED");
});

test("past TTL but still within the clock-skew allowance: still allowed", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([], { issuedAt: 1_000, ttlSeconds: 60 }), rootSecretKey);
  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_090, clockSkewSeconds: 60 });
  assert.equal(result.ok, true);
});

test("past TTL AND past the skew allowance: EXPIRED", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([], { issuedAt: 1_000, ttlSeconds: 60 }), rootSecretKey);
  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_500, clockSkewSeconds: 60 });
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "EXPIRED");
});

test("a suspiciously future-dated issuedAt (beyond skew tolerance) is rejected, not treated as extra-fresh", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  // issuedAt far in the future relative to `now` — a legitimately-clocked
  // signer would never produce this.
  const signed = signRevocationList(buildRevocationList([], { issuedAt: 100_000, ttlSeconds: 60 }), rootSecretKey);
  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_000, clockSkewSeconds: 60 });
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "EXPIRED");
});

test("a mildly future issuedAt within skew tolerance (ordinary clock drift) is still accepted", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([], { issuedAt: 1_030, ttlSeconds: 60 }), rootSecretKey);
  const result = verifySignedRevocationList(signed, rootPublicKey, { now: 1_000, clockSkewSeconds: 60 });
  assert.equal(result.ok, true);
});

// --- malformed shapes (untrusted input from the wire) -----------------------

test("null/non-object input denies MALFORMED, never throws", () => {
  const { rootPublicKey } = freshRoot();
  for (const bad of [null, undefined, "a string", 42, [], true]) {
    const result = verifySignedRevocationList(bad, rootPublicKey);
    assert.equal(result.ok, false);
    assert.equal((result as { code: string }).code, "MALFORMED");
  }
});

test("missing/wrong-typed fields deny MALFORMED, never throw", () => {
  const { rootPublicKey } = freshRoot();
  const cases: unknown[] = [
    {},
    { signature: "abc" }, // no payload
    { payload: {}, signature: "abc" }, // payload missing every field
    { payload: { v: "wrong-version", issuedAt: 1, ttlSeconds: 1, revoked: [] }, signature: "abc" },
    { payload: { v: REVOCATION_LIST_VERSION, issuedAt: "not-a-number", ttlSeconds: 1, revoked: [] }, signature: "abc" },
    { payload: { v: REVOCATION_LIST_VERSION, issuedAt: 1, ttlSeconds: -1, revoked: [] }, signature: "abc" },
    { payload: { v: REVOCATION_LIST_VERSION, issuedAt: 1, ttlSeconds: 1, revoked: "not-an-array" }, signature: "abc" },
    { payload: { v: REVOCATION_LIST_VERSION, issuedAt: 1, ttlSeconds: 1, revoked: ["not-a-valid-hash"] }, signature: "abc" },
    { payload: { v: REVOCATION_LIST_VERSION, issuedAt: 1, ttlSeconds: 1, revoked: [] }, signature: "" },
    { payload: { v: REVOCATION_LIST_VERSION, issuedAt: 1, ttlSeconds: 1, revoked: [] } }, // no signature at all
  ];
  for (const bad of cases) {
    const result = verifySignedRevocationList(bad, rootPublicKey);
    assert.equal(result.ok, false, `expected denial for ${JSON.stringify(bad)}`);
    assert.equal((result as { code: string }).code, "MALFORMED", `expected MALFORMED for ${JSON.stringify(bad)}`);
  }
});

test("an issuedAt/ttlSeconds beyond Number.MAX_SAFE_INTEGER denies MALFORMED rather than reaching canonicalEncode() and throwing", () => {
  // Regression test for an adversarial-review finding: Number.isInteger()
  // alone (not Number.isSafeInteger()) let an out-of-safe-range value
  // through parseShape(), reaching canonicalEncode() (via
  // revocationSignInput, called BEFORE the signature is even checked) and
  // throwing a RangeError there — an unauthenticated crash, since no
  // valid signature was needed to trigger it: any response body shape
  // alone was enough. No real signer would ever produce such a value
  // (buildRevocationList()'s own isSafePositiveInt() already prevents
  // it), so this is purely about untrusted wire input.
  const { rootPublicKey } = freshRoot();
  const unsafeValues = [Number.MAX_SAFE_INTEGER + 1, Number.MAX_SAFE_INTEGER + 2, 2 ** 60, Infinity, NaN];
  for (const unsafe of unsafeValues) {
    const badIssuedAt = {
      payload: { v: REVOCATION_LIST_VERSION, issuedAt: unsafe, ttlSeconds: 60, revoked: [] },
      signature: "irrelevant-should-never-be-checked",
    };
    const r1 = verifySignedRevocationList(badIssuedAt, rootPublicKey);
    assert.equal(r1.ok, false, `expected denial for issuedAt=${unsafe}`);
    assert.equal((r1 as { code: string }).code, "MALFORMED", `expected MALFORMED for issuedAt=${unsafe}`);

    const badTtl = {
      payload: { v: REVOCATION_LIST_VERSION, issuedAt: 1000, ttlSeconds: unsafe, revoked: [] },
      signature: "irrelevant-should-never-be-checked",
    };
    const r2 = verifySignedRevocationList(badTtl, rootPublicKey);
    assert.equal(r2.ok, false, `expected denial for ttlSeconds=${unsafe}`);
    assert.equal((r2 as { code: string }).code, "MALFORMED", `expected MALFORMED for ttlSeconds=${unsafe}`);
  }
});

test("revocationSignInput()/signRevocationList() reject a non-string entry in payload.revoked rather than silently signing it", () => {
  // Defense-in-depth: buildRevocationList() is the only real caller in
  // this codebase and already validates every entry, but revocationSignInput
  // and signRevocationList are public API of their own — a hand-built
  // RevocationListPayload (bypassing buildRevocationList) with a non-string
  // entry would otherwise be accepted by canonicalEncode()'s CanonicalValue
  // union and get silently signed as part of a well-formed-looking but
  // semantically-wrong list.
  const { secretKey } = generateKeypair();
  const malformedPayload = {
    v: REVOCATION_LIST_VERSION,
    issuedAt: 1000,
    ttlSeconds: 60,
    revoked: ["a".repeat(64), 12345],
  } as unknown as RevocationListPayload;

  assert.throws(() => revocationSignInput(malformedPayload), TypeError);
  assert.throws(() => signRevocationList(malformedPayload, secretKey), TypeError);
});

test("extra, unexpected top-level or payload fields are ignored, not rejected (forward-compatible, matching signing's own field allowlist)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_000 }), rootSecretKey);
  const withExtra = { ...signed, payload: { ...signed.payload, extra: "ignored" }, alsoExtra: true };
  const result = verifySignedRevocationList(withExtra, rootPublicKey, { now: 1_010 });
  assert.equal(result.ok, true);
});
