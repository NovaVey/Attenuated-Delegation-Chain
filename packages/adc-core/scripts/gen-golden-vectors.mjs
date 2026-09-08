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
import { mintRoot, attenuate, seal, verify, encodeToken, getPublicKey } from "@adc/core";
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
    const sealedWire = encodeToken(seal(token));
    const sealedResult = verify(sealedWire, rootPublicKey);
    if (!sealedResult.ok) throw new Error(`generator produced a sealed token that fails to verify at depth ${depth}`);
    vectors.push({
      description: `sealed token at depth ${depth}`,
      depth,
      proofType: "sealed",
      wire: sealedWire,
    });
  }

  if (depth < 3) token = attenuate(token, { nextKeypair: nextKeypairs[depth + 1] });
}

const fixture = {
  formatVersion: "adc1",
  rootSecretKeyB64: b64(rootSecretKey),
  rootPublicKeyB64: b64(rootPublicKey),
  nextSecretKeysB64: nextKeypairs.map((kp) => b64(kp.secretKey)),
  vectors,
};

writeFileSync(
  new URL("../test/fixtures/golden-vectors.json", import.meta.url),
  JSON.stringify(fixture, null, 2) + "\n",
);
console.log("wrote golden-vectors.json with", vectors.length, "vectors");
