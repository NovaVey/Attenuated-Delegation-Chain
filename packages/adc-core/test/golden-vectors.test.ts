import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mintRoot, attenuate, seal, verify, encodeToken } from "../src/index.js";
import { getPublicKey } from "../src/crypto.js";

/**
 * Pins the wire format: these vectors were generated once (see
 * scripts/gen-golden-vectors.mjs) from fixed, non-random key material and
 * committed to fixtures/golden-vectors.json. This test independently
 * re-derives the same tokens from the same fixed secrets and asserts
 * byte-for-byte equality with the committed wire strings — any accidental
 * drift in canonical encoding, signature input layout, or wire joining
 * fails here before anything downstream depends on the format.
 */

const fixturePath = fileURLToPath(new URL("./fixtures/golden-vectors.json", import.meta.url));
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  formatVersion: string;
  rootSecretKeyB64: string;
  rootPublicKeyB64: string;
  nextSecretKeysB64: string[];
  vectors: { description: string; depth: number; proofType: "attenuable" | "sealed"; wire: string }[];
  negativeVectors: { description: string; wire: string; expectedCode: string }[];
};

function fromB64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function keypairFor(secretB64: string) {
  const secretKey = fromB64(secretB64);
  return { secretKey, publicKey: getPublicKey(secretKey) };
}

test("golden vectors: fixture is non-trivial", () => {
  assert.equal(fixture.formatVersion, "adc1");
  assert.ok(fixture.vectors.length >= 5);
  assert.ok(fixture.negativeVectors.length >= 3);
});

test("golden vectors: every committed negative vector is denied with its pinned reason code", () => {
  // Unlike roundtrip.test.ts's byte-flip fuzz loops (which mutate freshly
  // generated tokens each run), these are specific, committed-to-the-repo
  // corrupted byte strings — this catches a regression that silently
  // widens acceptance of a known-bad token, not just "some mutation
  // somewhere is denied".
  const rootPublicKey = fromB64(fixture.rootPublicKeyB64);
  for (const v of fixture.negativeVectors) {
    const result = verify(v.wire, rootPublicKey);
    assert.equal(result.ok, false, `${v.description} should be denied`);
    assert.equal((result as { ok: false; code: string }).code, v.expectedCode, v.description);
  }
});

test("golden vectors: every committed wire string verifies against the committed root public key", () => {
  const rootPublicKey = fromB64(fixture.rootPublicKeyB64);
  for (const v of fixture.vectors) {
    const result = verify(v.wire, rootPublicKey);
    assert.equal(result.ok, true, `${v.description} should verify`);
    assert.equal((result as { ok: true; depth: number }).depth, v.depth);
  }
});

test("golden vectors: re-minting from the same fixed secrets reproduces the exact committed bytes", () => {
  const rootSecretKey = fromB64(fixture.rootSecretKeyB64);

  const byDepth = new Map<number, { attenuable?: string; sealed?: string }>();
  for (const v of fixture.vectors) {
    const entry = byDepth.get(v.depth) ?? {};
    entry[v.proofType] = v.wire;
    byDepth.set(v.depth, entry);
  }

  let token = mintRoot(rootSecretKey, { nextKeypair: keypairFor(fixture.nextSecretKeysB64[0]!) });

  for (let depth = 0; depth <= 3; depth++) {
    const expected = byDepth.get(depth)!;
    assert.equal(encodeToken(token), expected.attenuable, `depth ${depth} attenuable wire mismatch`);
    if (expected.sealed) {
      assert.equal(encodeToken(seal(token)), expected.sealed, `depth ${depth} sealed wire mismatch`);
    }
    if (depth < 3) {
      token = attenuate(token, { nextKeypair: keypairFor(fixture.nextSecretKeysB64[depth + 1]!) });
    }
  }
});
