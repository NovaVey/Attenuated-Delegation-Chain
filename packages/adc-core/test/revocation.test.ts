import { test } from "node:test";
import assert from "node:assert/strict";
import { attenuate, blockSignatureHash, encodeToken, generateKeypair, mintRoot, seal, verify } from "../src/index.js";

function freshRoot() {
  const root = generateKeypair();
  return { rootSecretKey: root.secretKey, rootPublicKey: root.publicKey };
}

function code(result: { ok: boolean }): string | undefined {
  return (result as { ok: false; code?: string }).code;
}

// ---------------------------------------------------------------------
// blockSignatureHash
// ---------------------------------------------------------------------

test("blockSignatureHash: sha256 hex of the raw signature, deterministic, distinct for distinct signatures", () => {
  const a = new Uint8Array(64).fill(1);
  const b = new Uint8Array(64).fill(2);
  assert.equal(blockSignatureHash(a), blockSignatureHash(a));
  assert.notEqual(blockSignatureHash(a), blockSignatureHash(b));
  assert.match(blockSignatureHash(a), /^[0-9a-f]{64}$/);
});

// ---------------------------------------------------------------------
// verify() with no revocation opts: unaffected
// ---------------------------------------------------------------------

test("no revokedHashes option at all: verify() behaves exactly as before, never denies ADC_REVOKED", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const wire = encodeToken(mintRoot(rootSecretKey));
  const result = verify(wire, rootPublicKey);
  assert.equal(result.ok, true);
});

test("an empty revokedHashes set: no effect, same as omitting it", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const wire = encodeToken(mintRoot(rootSecretKey));
  const result = verify(wire, rootPublicKey, {}, { revokedHashes: new Set() });
  assert.equal(result.ok, true);
});

test("a revokedHashes set containing an unrelated hash: no effect", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const wire = encodeToken(mintRoot(rootSecretKey));
  const result = verify(wire, rootPublicKey, {}, { revokedHashes: new Set(["deadbeef".repeat(8)]) });
  assert.equal(result.ok, true);
});

// ---------------------------------------------------------------------
// Root revocation kills every descendant, for free
// ---------------------------------------------------------------------

test("revoking the root (block 0) denies the root token itself with ADC_REVOKED", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const root = mintRoot(rootSecretKey);
  const rootHash = blockSignatureHash(root.sigs[0]!);

  const result = verify(encodeToken(root), rootPublicKey, {}, { revokedHashes: new Set([rootHash]) });

  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_REVOKED");
});

test("revoking the root hash denies every descendant, without the list ever naming them individually", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const root = mintRoot(rootSecretKey);
  const rootHash = blockSignatureHash(root.sigs[0]!);
  const revoked = new Set([rootHash]);

  let token = root;
  for (let hop = 0; hop < 5; hop++) {
    token = attenuate(token, { caveats: [] });
    const result = verify(encodeToken(token), rootPublicKey, {}, { revokedHashes: revoked });
    assert.equal(result.ok, false, `hop ${hop + 1} should be denied — its wire bytes still contain block 0's revoked signature`);
    assert.equal(code(result), "ADC_REVOKED");
  }

  // Sealing doesn't change this either — same blocks/sigs, only the proof differs.
  const sealedResult = verify(encodeToken(seal(token)), rootPublicKey, {}, { revokedHashes: revoked });
  assert.equal(sealedResult.ok, false);
  assert.equal(code(sealedResult), "ADC_REVOKED");
});

// ---------------------------------------------------------------------
// Revoking a non-root block: scoped to that block and its descendants only
// ---------------------------------------------------------------------

test("revoking an intermediate (non-root) block denies that hop and its descendants, but not the root alone or a sibling branch", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const root = mintRoot(rootSecretKey);
  const hop1 = attenuate(root, { caveats: [] });
  const hop2 = attenuate(hop1, { caveats: [] });

  const hop1Hash = blockSignatureHash(hop1.sigs[hop1.sigs.length - 1]!);
  const revoked = new Set([hop1Hash]);

  // The root by itself never touched hop1's block/signature — unaffected.
  const rootResult = verify(encodeToken(root), rootPublicKey, {}, { revokedHashes: revoked });
  assert.equal(rootResult.ok, true);

  // hop1 itself: denied.
  const hop1Result = verify(encodeToken(hop1), rootPublicKey, {}, { revokedHashes: revoked });
  assert.equal(hop1Result.ok, false);
  assert.equal(code(hop1Result), "ADC_REVOKED");

  // hop2, a descendant of hop1: also denied — hop2's wire bytes still
  // contain hop1's own block and signature.
  const hop2Result = verify(encodeToken(hop2), rootPublicKey, {}, { revokedHashes: revoked });
  assert.equal(hop2Result.ok, false);
  assert.equal(code(hop2Result), "ADC_REVOKED");

  // A SIBLING branch attenuated from the same root, never passing through
  // the revoked hop1 block at all: unaffected. (attenuate() always mints a
  // fresh keypair per call, so this sibling's own block/signature differ
  // from hop1's even though both attenuate the same root.)
  const sibling = attenuate(root, { caveats: [] });
  const siblingResult = verify(encodeToken(sibling), rootPublicKey, {}, { revokedHashes: revoked });
  assert.equal(siblingResult.ok, true);
});

// ---------------------------------------------------------------------
// Reason code and message
// ---------------------------------------------------------------------

test("ADC_REVOKED names the exact block index that matched", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const root = mintRoot(rootSecretKey);
  const hop1 = attenuate(root, { caveats: [] });
  const hop1Hash = blockSignatureHash(hop1.sigs[hop1.sigs.length - 1]!);

  const result = verify(encodeToken(hop1), rootPublicKey, {}, { revokedHashes: new Set([hop1Hash]) });
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.match(result.reason, /block 1/);
});

// ---------------------------------------------------------------------
// Ordering: revocation (step 4) runs before caveat evaluation (step 5)
// ---------------------------------------------------------------------

test("a token that is BOTH revoked AND would independently fail a caveat check denies ADC_REVOKED, not the caveat's own code", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  // Expired well outside the default clock-skew window — this caveat
  // alone would deny with ADC_EXPIRED if revocation didn't run first.
  const root = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: 1_000 }] });
  const rootHash = blockSignatureHash(root.sigs[0]!);

  const result = verify(encodeToken(root), rootPublicKey, { now: 999_999 }, { revokedHashes: new Set([rootHash]) });

  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_REVOKED", "revocation (step 4) must be checked before caveat evaluation (step 5)");
});

test("conversely, an unrevoked but expired token still correctly denies ADC_EXPIRED (revocation isn't masking other checks)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const root = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: 1_000 }] });
  const result = verify(encodeToken(root), rootPublicKey, { now: 999_999 }, { revokedHashes: new Set() });
  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_EXPIRED");
});
