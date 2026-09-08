// Generator for test/fixtures/golden-vectors.json. Deterministic: every
// secret key is a fixed, hand-chosen byte pattern (no RNG), so re-running
// this script reproduces byte-identical output. Not part of the test
// suite itself — the committed fixture is what pins the format; this
// script documents how it was produced and lets it be regenerated if the
// format ever intentionally changes (which should also bump the version
// tag).
//
// Run from packages/adc-core after `npm run build`:
//   node scripts/gen-golden-vectors.mjs
import { mintRoot, attenuate, seal, verify, encodeToken, decodeToken, getPublicKey } from "@adc/core";
import { writeFileSync } from "node:fs";

function detSecret(tag) {
  // 32 deterministic bytes derived from a small tag, distinct per call site.
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (tag * 37 + i * 11 + 1) % 256;
  return out;
}

const rootSecretKey = detSecret(0);
const rootPublicKey = getPublicKey(rootSecretKey);

const nextKeypairs = [1, 2, 3, 4].map((tag) => {
  const secretKey = detSecret(tag);
  const publicKey = getPublicKey(secretKey);
  return { secretKey, publicKey };
});

function b64(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

const vectors = [];
let sealedWireDepth2;

let token = mintRoot(rootSecretKey, { nextKeypair: nextKeypairs[0] });
for (let depth = 0; depth <= 3; depth++) {
  const wire = encodeToken(token);
  const result = verify(wire, rootPublicKey);
  if (!result.ok) throw new Error(`generator produced a token that fails to verify at depth ${depth}: ${result.code}`);
  vectors.push({
    description: `attenuable token at depth ${depth}`,
    depth,
    proofType: "attenuable",
    wire,
  });

  if (depth === 2) {
    sealedWireDepth2 = encodeToken(seal(token));
    const sealedResult = verify(sealedWireDepth2, rootPublicKey);
    if (!sealedResult.ok) throw new Error(`generator produced a sealed token that fails to verify at depth ${depth}`);
    vectors.push({
      description: `sealed token at depth ${depth}`,
      depth,
      proofType: "sealed",
      wire: sealedWireDepth2,
    });
  }

  if (depth < 3) token = attenuate(token, { nextKeypair: nextKeypairs[depth + 1] });
}

// Negative vectors: pin that specific, deliberately-corrupted mutations of
// the positive vectors above are DENIED with a specific reason code — not
// just "some byte-flip somewhere is denied" (roundtrip.test.ts's fuzz
// loops already cover that generally, against freshly generated keys each
// run), but that these exact, committed-to-the-repo bytes stay denied.
// Catches a regression that silently widens acceptance, which a
// fixture of purely positive vectors cannot.
// Corrupts raw signature/proof BYTES and re-encodes, rather than flipping
// a byte in the base64url text directly — a text-level flip can land on a
// character outside the base64url alphabet (e.g. 'z' XOR 0x01 = '{') and
// fail with ADC_MALFORMED for the wrong reason instead of the one this
// vector is meant to pin.
function corruptBytes(bytes, index, mask = 0xff) {
  const copy = Uint8Array.from(bytes);
  copy[index] = copy[index] ^ mask;
  return copy;
}

const depth0Wire = vectors[0].wire;
const negativeVectors = [];

// Corrupt block0's signature (a signature-chain failure).
{
  const parsed = decodeToken(depth0Wire);
  const corrupted = { ...parsed, sigs: [corruptBytes(parsed.sigs[0], 0), ...parsed.sigs.slice(1)] };
  const wire = encodeToken(corrupted);
  const result = verify(wire, rootPublicKey);
  if (result.ok || result.code !== "ADC_SIG_INVALID") {
    throw new Error(`negative vector 'corrupted block0 signature' did not produce ADC_SIG_INVALID: ${JSON.stringify(result)}`);
  }
  negativeVectors.push({ description: "depth-0 vector with block0's signature corrupted", wire, expectedCode: result.code });
}

// Drop the final ('proof') segment entirely — a truncation.
{
  const wire = depth0Wire.slice(0, depth0Wire.lastIndexOf("."));
  const result = verify(wire, rootPublicKey);
  if (result.ok || result.code !== "ADC_MALFORMED") {
    throw new Error(`negative vector 'truncated proof segment' did not produce ADC_MALFORMED: ${JSON.stringify(result)}`);
  }
  negativeVectors.push({ description: "depth-0 vector with the proof segment truncated off", wire, expectedCode: result.code });
}

// Corrupt the sealed depth-2 vector's sealing signature (the proof-check
// branch specific to sealed tokens).
{
  const parsed = decodeToken(sealedWireDepth2);
  if (parsed.proof.type !== "sealed") throw new Error("expected a sealed proof");
  const corrupted = { ...parsed, proof: { type: "sealed", signature: corruptBytes(parsed.proof.signature, 0) } };
  const wire = encodeToken(corrupted);
  const result = verify(wire, rootPublicKey);
  if (result.ok || result.code !== "ADC_PROOF_INVALID") {
    throw new Error(`negative vector 'corrupted sealing signature' did not produce ADC_PROOF_INVALID: ${JSON.stringify(result)}`);
  }
  negativeVectors.push({ description: "sealed depth-2 vector with the sealing signature corrupted", wire, expectedCode: result.code });
}

const fixture = {
  formatVersion: "adc1",
  rootSecretKeyB64: b64(rootSecretKey),
  rootPublicKeyB64: b64(rootPublicKey),
  nextSecretKeysB64: nextKeypairs.map((kp) => b64(kp.secretKey)),
  vectors,
  negativeVectors,
};

writeFileSync(
  new URL("../test/fixtures/golden-vectors.json", import.meta.url),
  JSON.stringify(fixture, null, 2) + "\n",
);
console.log("wrote golden-vectors.json with", vectors.length, "positive vectors and", negativeVectors.length, "negative vectors");
