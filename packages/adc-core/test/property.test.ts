import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { mintRoot, attenuate, verify, encodeToken, generateKeypair } from "../src/index.js";
import { canonicalEncode, type CanonicalValue } from "../src/canonical.js";
import { utf8Decode } from "../src/bytes.js";

// A small recursive arbitrary over the CanonicalValue shape actually used
// by block payloads (docs/PLAN.md 1.4: object keys sorted, integers only,
// no floats).
const canonicalValueArb: fc.Arbitrary<CanonicalValue> = fc.letrec((tie) => ({
  value: fc.oneof(
    { depthSize: "small" },
    fc.string(),
    fc.integer(),
    fc.boolean(),
    fc.array(tie("value") as fc.Arbitrary<CanonicalValue>, { maxLength: 4 }),
    fc.dictionary(fc.string({ minLength: 1, maxLength: 8 }), tie("value") as fc.Arbitrary<CanonicalValue>, {
      maxKeys: 4,
    }),
  ),
})).value as fc.Arbitrary<CanonicalValue>;

test("property: canonicalEncode is deterministic regardless of object key insertion order", () => {
  fc.assert(
    fc.property(fc.dictionary(fc.string({ minLength: 1, maxLength: 6 }), canonicalValueArb, { maxKeys: 5 }), (obj) => {
      const shuffled: Record<string, CanonicalValue> = {};
      for (const key of Object.keys(obj).sort().reverse()) shuffled[key] = obj[key]!;
      assert.equal(utf8Decode(canonicalEncode(obj)), utf8Decode(canonicalEncode(shuffled)));
    }),
    { numRuns: 200 },
  );
});

test("property: honest mint+attenuate chains of any depth 0-10 always verify with the right depth", () => {
  const { secretKey: rootSecretKey, publicKey: rootPublicKey } = generateKeypair();
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 10 }), (depth) => {
      let token = mintRoot(rootSecretKey);
      for (let i = 0; i < depth; i++) token = attenuate(token);
      const result = verify(encodeToken(token), rootPublicKey);
      assert.equal(result.ok, true);
      assert.equal((result as { ok: true; depth: number }).depth, depth);
    }),
    { numRuns: 30 },
  );
});

test("property: mutating one random byte of a valid token is always denied, never thrown", () => {
  const { secretKey: rootSecretKey, publicKey: rootPublicKey } = generateKeypair();
  let token = mintRoot(rootSecretKey);
  for (let i = 0; i < 4; i++) token = attenuate(token);
  const wire = encodeToken(token);
  const bytes = Buffer.from(wire, "utf8");

  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: bytes.length - 1 }),
      fc.integer({ min: 1, max: 255 }),
      (index, xorMask) => {
        const mutated = Buffer.from(bytes);
        mutated[index] = mutated[index]! ^ xorMask;
        const mutatedWire = mutated.toString("utf8");
        if (mutatedWire === wire) return; // byte change didn't survive the utf8 round-trip identically

        let result;
        try {
          result = verify(mutatedWire, rootPublicKey);
        } catch (err) {
          assert.fail(`verify() threw: ${(err as Error).message}`);
        }
        assert.equal(result.ok, false);
      },
    ),
    { numRuns: 300 },
  );
});

test("property: two independently minted roots never cross-verify", () => {
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 5 }), (depth) => {
      const a = generateKeypair();
      const b = generateKeypair();
      let token = mintRoot(a.secretKey);
      for (let i = 0; i < depth; i++) token = attenuate(token);
      const result = verify(encodeToken(token), b.publicKey);
      assert.equal(result.ok, false);
      assert.equal((result as { ok: false; code: string }).code, "ADC_SIG_INVALID");
    }),
    { numRuns: 20 },
  );
});
