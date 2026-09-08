import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalEncode } from "../src/canonical.js";
import { b64urlDecode, b64urlEncode, bytesEqual, u32be, readU32be, utf8Decode } from "../src/bytes.js";
import { buildSignInput, DOMAIN_TAG, ALG_TAG_ED25519 } from "../src/signing.js";
import { encodeBlock, decodeBlock, ALG_ED25519 } from "../src/block.js";
import { encodeToken, decodeToken } from "../src/wire.js";
import { generateKeypair, sign, verifySignature, PUBLIC_KEY_LEN, SIGNATURE_LEN } from "../src/crypto.js";

test("canonicalEncode sorts object keys regardless of insertion order", () => {
  const a = canonicalEncode({ b: 1, a: 2, c: 3 });
  const b = canonicalEncode({ c: 3, a: 2, b: 1 });
  assert.equal(utf8Decode(a), utf8Decode(b));
  assert.equal(utf8Decode(a), '{"a":2,"b":1,"c":3}');
});

test("canonicalEncode produces no insignificant whitespace", () => {
  const bytes = canonicalEncode({ nk: "x", c: [{ kind: "scope" }], alg: "ed25519" });
  assert.doesNotMatch(utf8Decode(bytes), /\s/);
});

test("canonicalEncode rejects non-integer numbers", () => {
  assert.throws(() => canonicalEncode({ x: 1.5 } as never), TypeError);
});

test("canonicalEncode rejects -0", () => {
  assert.throws(() => canonicalEncode({ x: -0 } as never), RangeError);
});

test("canonicalEncode nested arrays and objects round-trip through JSON.parse", () => {
  const value = { c: [{ kind: "scope", ids: ["a", "b"] }], alg: "ed25519", nk: "xyz" };
  const bytes = canonicalEncode(value);
  assert.deepEqual(JSON.parse(utf8Decode(bytes)), value);
});

test("b64url encode/decode round-trips and is unpadded", () => {
  for (const len of [0, 1, 2, 3, 4, 5, 31, 32, 64]) {
    const bytes = new Uint8Array(len).map((_, i) => i % 256);
    const encoded = b64urlEncode(bytes);
    assert.doesNotMatch(encoded, /=/);
    assert.ok(bytesEqual(b64urlDecode(encoded), bytes));
  }
});

test("b64urlDecode rejects invalid alphabet and non-canonical input", () => {
  assert.throws(() => b64urlDecode("not valid!"), SyntaxError);
  assert.throws(() => b64urlDecode("A"), SyntaxError); // length % 4 === 1 is never valid
});

test("u32be round-trips and rejects out-of-range values", () => {
  for (const n of [0, 1, 255, 256, 65535, 0xffffffff]) {
    assert.equal(readU32be(u32be(n), 0), n);
  }
  assert.throws(() => u32be(-1), RangeError);
  assert.throws(() => u32be(1.5), RangeError);
  assert.throws(() => u32be(0x100000000), RangeError);
});

test("buildSignInput layout matches docs/PLAN.md 1.3 byte-for-byte", () => {
  const blockBytes = new Uint8Array([1, 2, 3]);
  const nextPubKey = new Uint8Array(32).fill(7);
  const prevSignature = new Uint8Array(64).fill(9);

  const input = buildSignInput({ blockBytes, nextPubKey, prevSignature });

  let offset = 0;
  assert.ok(bytesEqual(input.slice(offset, offset + 6), DOMAIN_TAG));
  offset += 6;
  assert.equal(input[offset], 0x00);
  offset += 1;
  assert.equal(readU32be(input, offset), blockBytes.length);
  offset += 4;
  assert.ok(bytesEqual(input.slice(offset, offset + blockBytes.length), blockBytes));
  offset += blockBytes.length;
  assert.equal(input[offset], ALG_TAG_ED25519);
  offset += 1;
  assert.ok(bytesEqual(input.slice(offset, offset + 32), nextPubKey));
  offset += 32;
  assert.ok(bytesEqual(input.slice(offset, offset + 64), prevSignature));
  offset += 64;
  assert.equal(input.length, offset);
});

test("buildSignInput omits prevSignature entirely for block 0 (not zero-padded)", () => {
  const blockBytes = new Uint8Array([1, 2, 3]);
  const nextPubKey = new Uint8Array(32).fill(7);
  const input = buildSignInput({ blockBytes, nextPubKey });
  // 6 (domain) + 1 (0x00) + 4 (len) + 3 (block) + 1 (algTag) + 32 (nk) = 47, no trailing prevSig bytes
  assert.equal(input.length, 47);
});

test("buildSignInput is sensitive to every field (no field can be omitted without changing the input)", () => {
  const base = { blockBytes: new Uint8Array([1, 2, 3]), nextPubKey: new Uint8Array(32).fill(1), prevSignature: new Uint8Array(64).fill(2) };
  const baseline = buildSignInput(base);

  const diffBlock = buildSignInput({ ...base, blockBytes: new Uint8Array([1, 2, 4]) });
  const diffNk = buildSignInput({ ...base, nextPubKey: new Uint8Array(32).fill(9) });
  const diffPrev = buildSignInput({ ...base, prevSignature: new Uint8Array(64).fill(9) });

  assert.ok(!bytesEqual(baseline, diffBlock));
  assert.ok(!bytesEqual(baseline, diffNk));
  assert.ok(!bytesEqual(baseline, diffPrev));
});

test("block encode/decode round-trips alg, nk, and caveats", () => {
  const kp = generateKeypair();
  const caveats = [{ kind: "scope", ids: ["a", "b"] }];
  const bytes = encodeBlock({ alg: ALG_ED25519, nextPublicKey: kp.publicKey, caveats });
  const decoded = decodeBlock(bytes);
  assert.equal(decoded.alg, ALG_ED25519);
  assert.ok(bytesEqual(decoded.nextPublicKey, kp.publicKey));
  assert.deepEqual(decoded.caveats, caveats);
});

test("decodeBlock rejects unknown extra fields", () => {
  const bytes = canonicalEncode({ alg: "ed25519", nk: "AAAA", c: [], extra: 1 });
  assert.throws(() => decodeBlock(bytes), SyntaxError);
});

test("decodeBlock rejects unsupported alg", () => {
  const bytes = canonicalEncode({ alg: "ed448", nk: "AAAA", c: [] });
  assert.throws(() => decodeBlock(bytes), SyntaxError);
});

test("decodeBlock rejects wrong-length nk", () => {
  const bytes = canonicalEncode({ alg: "ed25519", nk: b64urlEncode(new Uint8Array(31)), c: [] });
  assert.throws(() => decodeBlock(bytes), SyntaxError);
});

test("wire encode/decode preserves exact raw block and sig bytes", () => {
  const blocks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])];
  const sigs = [new Uint8Array(SIGNATURE_LEN).fill(1), new Uint8Array(SIGNATURE_LEN).fill(2)];
  const token = {
    version: "adc1" as const,
    blocks,
    sigs,
    proof: { type: "attenuable" as const, secretKey: new Uint8Array(32).fill(3) },
  };
  const wire = encodeToken(token);
  const decoded = decodeToken(wire);
  assert.equal(decoded.blocks.length, 2);
  assert.ok(bytesEqual(decoded.blocks[0]!, blocks[0]!));
  assert.ok(bytesEqual(decoded.blocks[1]!, blocks[1]!));
  assert.ok(bytesEqual(decoded.sigs[0]!, sigs[0]!));
  assert.ok(bytesEqual(decoded.sigs[1]!, sigs[1]!));
  assert.equal(decoded.proof.type, "attenuable");
});

test("sign/verify basic correctness", () => {
  const kp = generateKeypair();
  const msg = new TextEncoder().encode("hello");
  const sig = sign(kp.secretKey, msg);
  assert.equal(sig.length, SIGNATURE_LEN);
  assert.equal(kp.publicKey.length, PUBLIC_KEY_LEN);
  assert.equal(verifySignature(kp.publicKey, msg, sig), true);
  assert.equal(verifySignature(kp.publicKey, new TextEncoder().encode("goodbye"), sig), false);
});

test("verifySignature never throws on malformed inputs", () => {
  assert.equal(verifySignature(new Uint8Array(32), new Uint8Array(0), new Uint8Array(64)), false);
  assert.equal(verifySignature(new Uint8Array(1), new Uint8Array(0), new Uint8Array(1)), false);
  assert.equal(verifySignature(new Uint8Array(32).fill(0xff), new Uint8Array(3), new Uint8Array(64).fill(0xff)), false);
});

test("verifySignature rejects the ZIP215 degenerate low-order (pubkey, sig) pair for arbitrary messages", () => {
  // Regression test for a real Ed25519 edge case: under cofactored
  // (ZIP215) verification — @noble/curves's default — certain low-order
  // public keys combined with a matching low-order signature verify
  // against *every* message, because the cofactor multiplication
  // annihilates the low-order component before the equality check. That
  // would let anyone forge a "sealed" proof for a token whose last
  // block's `nk` happens to be such a point, without ever holding the
  // real secret. crypto.ts pins `{ zip215: false }` (strict RFC8032) to
  // close this off; this test asserts the all-0xff pair — a known
  // instance of the degenerate combination — is rejected regardless of
  // which message it's checked against.
  const degeneratePublicKey = new Uint8Array(32).fill(0xff);
  const degenerateSignature = new Uint8Array(64).fill(0xff);
  for (const msg of [new Uint8Array(0), new Uint8Array(3), new TextEncoder().encode("anything")]) {
    assert.equal(verifySignature(degeneratePublicKey, msg, degenerateSignature), false);
  }
});
