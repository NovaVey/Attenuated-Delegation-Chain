import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mintRoot,
  attenuate,
  seal,
  verify,
  encodeToken,
  decodeBlock,
  generateKeypair,
  AdcError,
} from "../src/index.js";
import { bytesEqual } from "../src/bytes.js";

/**
 * Regression tests for findings from the Phase 1 adversarial review,
 * confirmed real and fixed in src/. Each test is named after the defect
 * it would have caught before the fix.
 */

function freshRoot() {
  const root = generateKeypair();
  return { rootSecretKey: root.secretKey, rootPublicKey: root.publicKey };
}

test("attenuate() rejects a nextKeypair whose secret doesn't derive its declared public key", () => {
  const { rootSecretKey } = freshRoot();
  const token = mintRoot(rootSecretKey);
  const unrelated = generateKeypair();
  const mismatched = { secretKey: generateKeypair().secretKey, publicKey: unrelated.publicKey };

  assert.throws(() => attenuate(token, { nextKeypair: mismatched }), AdcError);
  try {
    attenuate(token, { nextKeypair: mismatched });
    assert.fail("expected attenuate() to throw");
  } catch (err) {
    assert.equal((err as AdcError).code, "ADC_MALFORMED");
  }
});

test("mintRoot() rejects a nextKeypair whose secret doesn't derive its declared public key", () => {
  const { rootSecretKey } = freshRoot();
  const unrelated = generateKeypair();
  const mismatched = { secretKey: generateKeypair().secretKey, publicKey: unrelated.publicKey };

  assert.throws(() => mintRoot(rootSecretKey, { nextKeypair: mismatched }), AdcError);
});

test("mintRoot()/attenuate() reject a wrong-length nextKeypair.secretKey", () => {
  const { rootSecretKey } = freshRoot();
  const bogus = { secretKey: new Uint8Array(31), publicKey: generateKeypair().publicKey };
  assert.throws(() => mintRoot(rootSecretKey, { nextKeypair: bogus }), AdcError);
});

test("the returned proof secret is not aliased to a caller-supplied nextKeypair buffer", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const kp = generateKeypair();
  const kpSecretCopy = Uint8Array.from(kp.secretKey);

  const token = mintRoot(rootSecretKey, { nextKeypair: kp });

  // Ordinary key hygiene: caller zeroes their own copy once they believe
  // it's safely embedded in the returned token.
  kp.secretKey.fill(0);

  assert.equal(token.proof.type, "attenuable");
  if (token.proof.type === "attenuable") {
    assert.ok(bytesEqual(token.proof.secretKey, kpSecretCopy), "returned proof secret must be unaffected by caller mutating their own buffer");
  }
  assert.equal(verify(encodeToken(token), rootPublicKey).ok, true, "token must still verify after caller zeroes their local copy");
});

test("seal() rejects a hand-constructed token with a blocks/sigs count mismatch", () => {
  const { rootSecretKey } = freshRoot();
  const token = mintRoot(rootSecretKey);
  const corrupt = { ...token, sigs: [...token.sigs, token.sigs[0]!] };
  assert.throws(() => seal(corrupt), AdcError);
  try {
    seal(corrupt);
    assert.fail("expected seal() to throw");
  } catch (err) {
    assert.equal((err as AdcError).code, "ADC_MALFORMED");
  }
});

test("prevSignature binding: splicing a grandchild across two same-nk siblings is denied, even though the verify key at that position is identical", () => {
  // This isolates docs/PLAN.md 1.3's "include the previous signature"
  // requirement from the ordinary next-key chain-mismatch check: both
  // siblings below share the exact same `nk` (via the nextKeypair testing
  // hook), so if prevSignature were NOT part of the signed input, this
  // splice would verify. It must not.
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const shared = attenuate(mintRoot(rootSecretKey)); // depth 1

  const kp = generateKeypair();
  // max_depth is evaluated purely from the wire structure (ctx.depth), not
  // from any fact — a large, harmless value here just needs to differ
  // between the two siblings (so their block bytes and signatures differ)
  // without pulling caveat-fact requirements into a test that isn't about
  // caveats at all.
  const siblingA = attenuate(shared, { nextKeypair: kp, caveats: [{ kind: "max_depth", depth: 100 }] });
  const siblingB = attenuate(shared, { nextKeypair: kp, caveats: [{ kind: "max_depth", depth: 101 }] });

  // Sanity: identical verify key at this position (both use kp.publicKey
  // as their `nk`), but distinct block content and therefore distinct
  // signatures — the two siblings are not accidentally identical tokens.
  const nkA = decodeBlock(siblingA.blocks[siblingA.blocks.length - 1]!).nextPublicKey;
  const nkB = decodeBlock(siblingB.blocks[siblingB.blocks.length - 1]!).nextPublicKey;
  assert.ok(bytesEqual(nkA, nkB), "sanity: siblings must share the same nk for this test to isolate prevSignature");
  assert.ok(
    !bytesEqual(siblingA.sigs[siblingA.sigs.length - 1]!, siblingB.sigs[siblingB.sigs.length - 1]!),
    "sanity: siblings must have distinct signatures (distinct caveats)",
  );
  assert.equal(verify(encodeToken(siblingA), rootPublicKey).ok, true);
  assert.equal(verify(encodeToken(siblingB), rootPublicKey).ok, true);

  const grandchildA = attenuate(siblingA);
  assert.equal(verify(encodeToken(grandchildA), rootPublicKey).ok, true);

  // Graft grandchildA's own (block, sig) — signed with prevSignature =
  // siblingA's last sig — onto siblingB, whose last sig differs.
  const franken = {
    version: "adc1" as const,
    blocks: [...siblingB.blocks, grandchildA.blocks[grandchildA.blocks.length - 1]!],
    sigs: [...siblingB.sigs, grandchildA.sigs[grandchildA.sigs.length - 1]!],
    proof: grandchildA.proof,
  };

  const result = verify(encodeToken(franken), rootPublicKey);
  assert.equal(result.ok, false);
  assert.equal((result as { ok: false; code: string }).code, "ADC_SIG_INVALID");
});

test("a corrupted sealing signature is denied with ADC_PROOF_INVALID", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = attenuate(attenuate(mintRoot(rootSecretKey)));
  const sealed = seal(token);
  assert.equal(sealed.proof.type, "sealed");
  if (sealed.proof.type !== "sealed") throw new Error("unreachable");

  const corruptSignature = Uint8Array.from(sealed.proof.signature);
  corruptSignature[0] = corruptSignature[0]! ^ 0xff;
  const corrupted = { ...sealed, proof: { type: "sealed" as const, signature: corruptSignature } };

  const result = verify(encodeToken(corrupted), rootPublicKey);
  assert.equal(result.ok, false);
  assert.equal((result as { ok: false; code: string }).code, "ADC_PROOF_INVALID");
});

test("flipping any single byte of a sealed token breaks verification (drives the sealed proof-check branch)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = attenuate(attenuate(mintRoot(rootSecretKey)));
  const wire = encodeToken(seal(token));
  assert.equal(verify(wire, rootPublicKey).ok, true, "sanity: original sealed token verifies");

  const bytes = Buffer.from(wire, "utf8");
  let flippedCount = 0;
  for (let i = 0; i < bytes.length; i++) {
    const mutated = Buffer.from(bytes);
    mutated[i] = mutated[i]! ^ 0x01;
    const mutatedWire = mutated.toString("utf8");
    if (mutatedWire === wire) continue;

    let result;
    try {
      result = verify(mutatedWire, rootPublicKey);
    } catch (err) {
      assert.fail(`verify() threw on mutated sealed token (byte ${i}): ${(err as Error).message}`);
    }
    assert.equal(result.ok, false, `mutating byte ${i} of a sealed token should invalidate it`);
    flippedCount++;
  }
  assert.ok(flippedCount > 0, "sanity: the mutation loop actually ran");
});

test("maxDepth is enforced before decoding block/sig payloads (ADC_DEPTH_EXCEEDED, not ADC_MALFORMED, even when those payloads are garbage)", () => {
  const { rootPublicKey } = freshRoot();
  // 5 blocks (12 segments) of pure garbage — not valid base64url, and
  // wouldn't decode to a real block/sig even if it were. If the depth cap
  // were checked only after decoding, this would fail with ADC_MALFORMED
  // (from the garbage content) rather than ADC_DEPTH_EXCEEDED.
  const segments = ["adc1"];
  for (let i = 0; i < 5; i++) segments.push("###not-base64###", "###not-base64###");
  segments.push("kAAAA");
  const wire = segments.join(".");

  const result = verify(wire, rootPublicKey, {}, { maxDepth: 2 });
  assert.equal(result.ok, false);
  assert.equal((result as { ok: false; code: string }).code, "ADC_DEPTH_EXCEEDED");
});
