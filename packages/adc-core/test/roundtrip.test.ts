import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mintRoot,
  attenuate,
  seal,
  verify,
  encodeToken,
  decodeToken,
  generateKeypair,
  AdcError,
} from "../src/index.js";

function freshRoot() {
  const root = generateKeypair();
  return { rootSecretKey: root.secretKey, rootPublicKey: root.publicKey };
}

test("round-trip: depths 0 through 8 verify and report the right depth", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();

  let token = mintRoot(rootSecretKey);
  for (let depth = 0; depth <= 8; depth++) {
    const wire = encodeToken(token);
    const result = verify(wire, rootPublicKey);
    assert.equal(result.ok, true, `depth ${depth} should verify`);
    assert.equal((result as { ok: true; depth: number }).depth, depth);

    // decode(encode(x)) round-trips to the same wire string.
    assert.equal(encodeToken(decodeToken(wire)), wire);

    if (depth < 8) token = attenuate(token);
  }
});

test("sealed token at each depth still verifies", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey);
  for (let depth = 0; depth <= 4; depth++) {
    const sealedWire = encodeToken(seal(token));
    const result = verify(sealedWire, rootPublicKey);
    assert.equal(result.ok, true);
    if (depth < 4) token = attenuate(token);
  }
});

test("flipping any single byte in the token breaks verification", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey);
  token = attenuate(token);
  token = attenuate(token);
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey).ok, true, "sanity: original token verifies");

  const bytes = Buffer.from(wire, "utf8");
  let flippedCount = 0;
  for (let i = 0; i < bytes.length; i++) {
    for (const bit of [0x01, 0x40, 0x80]) {
      const mutated = Buffer.from(bytes);
      mutated[i] = mutated[i]! ^ bit;
      const mutatedWire = mutated.toString("utf8");
      if (mutatedWire === wire) continue; // e.g. flipping a bit that round-trips identically through encoding

      let result;
      try {
        result = verify(mutatedWire, rootPublicKey);
      } catch (err) {
        // verify() must never throw on token input; a thrown error here is
        // itself a bug in the implementation, not an acceptable "deny".
        assert.fail(
          `verify() threw on mutated token (byte ${i}, bit 0x${bit.toString(16)}): ${(err as Error).message}`,
        );
      }
      assert.equal(
        result.ok,
        false,
        `mutating byte ${i} (bit 0x${bit.toString(16)}) should invalidate the token`,
      );
      flippedCount++;
    }
  }
  assert.ok(flippedCount > 0, "sanity: the mutation loop actually ran");
});

test("sealed token cannot be attenuated", () => {
  const { rootSecretKey } = freshRoot();
  const token = attenuate(mintRoot(rootSecretKey));
  const sealed = seal(token);

  assert.throws(() => attenuate(sealed), AdcError);
  assert.throws(() => seal(sealed), AdcError);
});

test("truncating the wire string to any strict prefix fails to verify", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey);
  for (let i = 0; i < 3; i++) token = attenuate(token);
  const wire = encodeToken(token);

  for (let len = 0; len < wire.length; len++) {
    const prefix = wire.slice(0, len);
    let result;
    try {
      result = verify(prefix, rootPublicKey);
    } catch (err) {
      assert.fail(`verify() threw on truncated token (len ${len}): ${(err as Error).message}`);
    }
    assert.equal(result.ok, false, `prefix of length ${len} should not verify`);
  }

  // The full string is the one length that must verify — sanity check
  // that the loop above wasn't vacuously true because nothing verifies.
  assert.equal(verify(wire, rootPublicKey).ok, true);
});

test("swapping a block between two tokens that share a prefix fails", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();

  // Both chains share an identical block0 and block1 (chainA is attenuated
  // once, then forked into two independent continuations).
  const shared = attenuate(mintRoot(rootSecretKey));
  const chainA = attenuate(attenuate(shared)); // shared -> a2 -> a3
  const chainB = attenuate(shared); // shared -> b2 (sibling of a2)

  assert.equal(verify(encodeToken(chainA), rootPublicKey).ok, true);
  assert.equal(verify(encodeToken(chainB), rootPublicKey).ok, true);

  // Splice chainB's block (b2, at index 2) into chainA's position 2,
  // keeping chainA's later block (a3) which was actually signed with the
  // secret embedded in a2's `nk` — not b2's.
  const franken = {
    version: "adc1" as const,
    blocks: [chainA.blocks[0]!, chainA.blocks[1]!, chainB.blocks[2]!, chainA.blocks[3]!],
    sigs: [chainA.sigs[0]!, chainA.sigs[1]!, chainB.sigs[2]!, chainA.sigs[3]!],
    proof: chainA.proof,
  };
  const result = verify(encodeToken(franken), rootPublicKey);
  assert.equal(result.ok, false);
  assert.equal((result as { ok: false; code: string }).code, "ADC_SIG_INVALID");
});

test("excising an interior block from a valid chain fails (prevSignature binding)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey);
  for (let i = 0; i < 3; i++) token = attenuate(token);
  assert.equal(verify(encodeToken(token), rootPublicKey).ok, true);

  // Remove block index 1 (and its sig), leaving block2's signature (which
  // was made with the secret embedded in block1's nk, over prevSignature =
  // sig1) directly following block0.
  const excised = {
    version: "adc1" as const,
    blocks: [token.blocks[0]!, token.blocks[2]!, token.blocks[3]!],
    sigs: [token.sigs[0]!, token.sigs[2]!, token.sigs[3]!],
    proof: token.proof,
  };
  const result = verify(encodeToken(excised), rootPublicKey);
  assert.equal(result.ok, false);
  assert.equal((result as { ok: false; code: string }).code, "ADC_SIG_INVALID");
});

test("wrong root public key is denied", () => {
  const { rootSecretKey } = freshRoot();
  const other = generateKeypair();
  const wire = encodeToken(mintRoot(rootSecretKey));
  const result = verify(wire, other.publicKey);
  assert.equal(result.ok, false);
  assert.equal((result as { ok: false; code: string }).code, "ADC_SIG_INVALID");
});

test("depth exceeding maxDepth is denied structurally", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey);
  for (let i = 0; i < 5; i++) token = attenuate(token);
  const wire = encodeToken(token); // depth 5

  const result = verify(wire, rootPublicKey, {}, { maxDepth: 4 });
  assert.equal(result.ok, false);
  assert.equal((result as { ok: false; code: string }).code, "ADC_DEPTH_EXCEEDED");

  assert.equal(verify(wire, rootPublicKey, {}, { maxDepth: 5 }).ok, true);
});

test("malformed wire strings are denied, never thrown", () => {
  const { rootPublicKey } = freshRoot();
  const inputs = [
    "",
    "not-a-token",
    "adc1",
    "adc1.",
    "adc1..",
    "adc2.AA.AA.kAA",
    "adc1.AA.AA.xAA", // unknown proof prefix
    "adc1.####.AA.kAA", // invalid base64url
  ];
  for (const input of inputs) {
    let result;
    try {
      result = verify(input, rootPublicKey);
    } catch (err) {
      assert.fail(`verify() threw on '${input}': ${(err as Error).message}`);
    }
    assert.equal(result.ok, false, `'${input}' should be denied`);
    assert.equal((result as { ok: false; code: string }).code, "ADC_MALFORMED");
  }
});
