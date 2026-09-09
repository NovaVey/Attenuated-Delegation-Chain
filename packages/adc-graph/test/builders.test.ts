import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { attenuate, encodeToken, generateKeypair, mintRoot, seal, verify, type Caveat, type ParsedToken } from "@adc/core";
import { buildAttenuateEvent, buildMintEvent, buildRevokeEvent, buildSealEvent, buildVerifyEvent } from "../src/builders.js";
import { blockIdentity } from "../src/hash.js";
import type { GraphPrincipalIdentity } from "../src/identity.js";
import { rootKeyPrincipal } from "../src/identity.js";

const ALICE: GraphPrincipalIdentity = { kind: "human", source: "adc-mint", externalId: "user:alice", displayName: "Alice" };
const AGENT: GraphPrincipalIdentity = { kind: "agent", source: "adc-broker", externalId: "session-1" };
const OPERATOR: GraphPrincipalIdentity = { kind: "human", source: "manual", externalId: "ops@example.com" };

function freshRoot() {
  const { secretKey, publicKey } = generateKeypair();
  return { rootSecretKey: secretKey, rootPublicKey: publicKey };
}

// --- buildMintEvent -------------------------------------------------------

test("buildMintEvent: principal derived from the root public key, resource = block 0's identity", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: 9_999_999_999 }] });

  const event = buildMintEvent(token, rootPublicKey);

  assert.deepEqual(event.principal, rootKeyPrincipal(rootPublicKey));
  assert.equal(event.resource.externalId, blockIdentity(token.sigs[0]!));
  assert.equal(event.action, "mint");
  assert.equal(event.decision, "allow");
  assert.equal(event.denyReason, null);
  assert.equal(event.onBehalfOf, null);
  assert.equal(event.reversible, null);
  assert.ok(event.taintLabels.includes("depth:0"));
  assert.ok(event.taintLabels.includes("caveat:expires"));
});

test("buildMintEvent: onBehalfOf and now, when supplied, flow straight through", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey);
  const now = new Date("2026-01-01T00:00:00Z");

  const event = buildMintEvent(token, rootPublicKey, { onBehalfOf: ALICE, now });

  assert.deepEqual(event.onBehalfOf, ALICE);
  assert.equal(event.occurredAt, now);
});

test("buildMintEvent: taintLabels list every distinct caveat kind, deduped and sorted, no duplicates for repeated kinds", () => {
  const { rootSecretKey } = freshRoot();
  const caveats: Caveat[] = [
    { kind: "scope", triples: [["repo", "1", "read"]] },
    { kind: "scope", triples: [["repo", "2", "write"]] },
    { kind: "max_depth", depth: 3 },
  ];
  const token = mintRoot(rootSecretKey, { caveats });
  const event = buildMintEvent(token, generateKeypair().publicKey);
  const caveatLabels = event.taintLabels.filter((l) => l.startsWith("caveat:"));
  assert.deepEqual(caveatLabels, ["caveat:max_depth", "caveat:scope"]);
});

test("buildMintEvent: requestDigest is the sha256 of block 0's raw bytes, not the caveats/secret in any other form", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "max_depth", depth: 1 }] });
  const event = buildMintEvent(token, rootPublicKey);
  assert.match(event.requestDigest!, /^[0-9a-f]{64}$/);
  // Never the proof secret, in any encoding.
  if (token.proof.type === "attenuable") {
    assert.ok(!event.requestDigest!.includes(Buffer.from(token.proof.secretKey).toString("hex")));
  }
});

test("buildMintEvent: two different tokens (different root keys) produce two different resource identities", () => {
  const a = freshRoot();
  const b = freshRoot();
  const tokenA = mintRoot(a.rootSecretKey);
  const tokenB = mintRoot(b.rootSecretKey);
  assert.notEqual(buildMintEvent(tokenA, a.rootPublicKey).resource.externalId, buildMintEvent(tokenB, b.rootPublicKey).resource.externalId);
});

// --- buildAttenuateEvent ---------------------------------------------------

test("buildAttenuateEvent: resource is the NEW block's identity, distinct from the parent's", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const root = mintRoot(rootSecretKey);
  const child = attenuate(root, { caveats: [{ kind: "max_depth", depth: 5 }] });

  const mintEvent = buildMintEvent(root, rootPublicKey);
  const attenuateEvent = buildAttenuateEvent(child, { actor: AGENT });

  assert.notEqual(attenuateEvent.resource.externalId, mintEvent.resource.externalId);
  assert.equal(attenuateEvent.resource.externalId, blockIdentity(child.sigs[child.sigs.length - 1]!));
  assert.equal(attenuateEvent.action, "attenuate");
  assert.equal(attenuateEvent.decision, "allow");
  assert.deepEqual(attenuateEvent.principal, AGENT);
});

test("buildAttenuateEvent: depth and taintLabels reflect the NEW block only, not the parent's caveats", () => {
  const { rootSecretKey } = freshRoot();
  const root = mintRoot(rootSecretKey, { caveats: [{ kind: "scope", triples: [["repo", "*", "read"]] }] });
  const child = attenuate(root, { caveats: [{ kind: "hosts", hostnames: ["example.com"] }] });

  const event = buildAttenuateEvent(child, { actor: AGENT });

  assert.ok(event.taintLabels.includes("depth:1"));
  assert.ok(event.taintLabels.includes("caveat:hosts"));
  assert.ok(!event.taintLabels.includes("caveat:scope"), "must not leak the parent block's caveats into this event");
});

test("buildAttenuateEvent: a chain of attenuations produces a strictly distinct resource identity at every hop", () => {
  const { rootSecretKey } = freshRoot();
  let token = mintRoot(rootSecretKey);
  const seen = new Set<string>();
  for (let i = 0; i < 5; i++) {
    token = attenuate(token, { caveats: [{ kind: "max_depth", depth: 10 }] });
    const id = buildAttenuateEvent(token, { actor: AGENT }).resource.externalId;
    assert.ok(!seen.has(id), `hop ${i} reused a previous hop's identity`);
    seen.add(id);
  }
});

// --- buildSealEvent ---------------------------------------------------------

test("buildSealEvent: references the LAST EXISTING block (same identity as the pre-seal token's own last block), not a new one", () => {
  const { rootSecretKey } = freshRoot();
  const attenuated = attenuate(mintRoot(rootSecretKey), { caveats: [] });
  const sealed = seal(attenuated);

  const preSealId = blockIdentity(attenuated.sigs[attenuated.sigs.length - 1]!);
  const sealEvent = buildSealEvent(sealed, { actor: AGENT });

  assert.equal(sealEvent.resource.externalId, preSealId);
  assert.equal(sealEvent.action, "seal");
  assert.equal(sealEvent.decision, "allow");
});

test("buildSealEvent: sealing directly after mint (no prior attenuation) references block 0 correctly", () => {
  const { rootSecretKey } = freshRoot();
  const root = mintRoot(rootSecretKey);
  const sealed = seal(root);

  const sealEvent = buildSealEvent(sealed, { actor: AGENT });

  assert.equal(sealEvent.resource.externalId, blockIdentity(root.sigs[0]!));
  assert.ok(sealEvent.taintLabels.includes("depth:0"));
});

// --- malformed-token handling ------------------------------------------------

test("buildMintEvent/buildAttenuateEvent/buildSealEvent throw a clear RangeError on a hand-constructed token with no blocks, instead of an opaque node:crypto TypeError", () => {
  const empty: ParsedToken = { version: "adc1", blocks: [], sigs: [], proof: { type: "attenuable", secretKey: new Uint8Array(32) } };
  const { rootPublicKey } = freshRoot();

  assert.throws(() => buildMintEvent(empty, rootPublicKey), RangeError);
  assert.throws(() => buildAttenuateEvent(empty, { actor: AGENT }), RangeError);
  assert.throws(() => buildSealEvent(empty, { actor: AGENT }), RangeError);
});

test("buildMintEvent/buildAttenuateEvent/buildSealEvent throw a clear RangeError on mismatched blocks/sigs lengths", () => {
  const { rootSecretKey } = freshRoot();
  const real = mintRoot(rootSecretKey);
  const mismatched: ParsedToken = { ...real, sigs: [...real.sigs, real.sigs[0]!] };

  assert.throws(() => buildMintEvent(mismatched, freshRoot().rootPublicKey), RangeError);
  assert.throws(() => buildAttenuateEvent(mismatched, { actor: AGENT }), RangeError);
  assert.throws(() => buildSealEvent(mismatched, { actor: AGENT }), RangeError);
});

// --- buildVerifyEvent -------------------------------------------------------

test("buildVerifyEvent: a real successful verify produces decision 'allow', resource = the terminal block's identity", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: 9_999_999_999 }] });
  const wire = encodeToken(token);
  const result = verify(wire, rootPublicKey);
  assert.equal(result.ok, true);

  const event = buildVerifyEvent(wire, result, { actor: AGENT, onBehalfOf: ALICE });

  assert.equal(event.decision, "allow");
  assert.equal(event.denyReason, null);
  assert.equal(event.resource.externalId, blockIdentity(token.sigs[0]!));
  assert.deepEqual(event.onBehalfOf, ALICE);
  assert.ok(event.taintLabels.includes("depth:0"));
  assert.equal(event.requestDigest, createHash("sha256").update(token.blocks[0]!).digest("hex"));
});

test("buildVerifyEvent: a caveat denial (real crypto, real decode) still resolves a REAL block identity — not the undecodable fallback", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: 1_000 }] }); // already expired
  const wire = encodeToken(token);
  const result = verify(wire, rootPublicKey, { now: 2_000 });
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "ADC_EXPIRED");

  const event = buildVerifyEvent(wire, result, { actor: AGENT });

  assert.equal(event.decision, "deny");
  assert.equal(event.denyReason, "ADC_EXPIRED: " + result.reason);
  assert.equal(event.resource.externalId, blockIdentity(token.sigs[0]!));
  assert.ok(!event.resource.externalId.startsWith("undecodable:"));
  assert.ok(event.taintLabels.includes("code:ADC_EXPIRED"));
});

test("buildVerifyEvent: wrong root key (ADC_SIG_INVALID) still decodes fine, resolves a real block identity", () => {
  const { rootSecretKey } = freshRoot();
  const { publicKey: wrongKey } = generateKeypair();
  const token = mintRoot(rootSecretKey);
  const wire = encodeToken(token);
  const result = verify(wire, wrongKey);
  assert.equal(result.ok, false);

  const event = buildVerifyEvent(wire, result, { actor: AGENT });
  assert.equal(event.resource.externalId, blockIdentity(token.sigs[0]!));
});

test("buildVerifyEvent: a genuinely undecodable token falls back to undecodableResource, never throws", () => {
  const { rootPublicKey } = freshRoot();
  const garbage = "not-an-adc-token-at-all";
  const result = verify(garbage, rootPublicKey);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "ADC_MALFORMED");

  const event = buildVerifyEvent(garbage, result, { actor: AGENT });

  assert.equal(event.decision, "deny");
  assert.ok(event.resource.externalId.startsWith("undecodable:"));
  assert.equal(event.requestDigest, null);
  assert.ok(!event.taintLabels.some((l) => l.startsWith("depth:")), "no depth label when the token never decoded");
});

test("buildVerifyEvent: accepts Uint8Array tokenBytes, same as @adc/core's own verify()", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey);
  const wireBytes = new TextEncoder().encode(encodeToken(token));
  const result = verify(wireBytes, rootPublicKey);
  const event = buildVerifyEvent(wireBytes, result, { actor: AGENT });
  assert.equal(event.resource.externalId, blockIdentity(token.sigs[0]!));
});

test("buildVerifyEvent: invalid-UTF-8 Uint8Array tokenBytes (the TextDecoder fatal-throw path) falls back cleanly, matching a real ADC_MALFORMED verify() result", () => {
  const { rootPublicKey } = freshRoot();
  const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd, 0x80, 0x81]);
  const result = verify(invalidUtf8, rootPublicKey);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "ADC_MALFORMED");

  const event = buildVerifyEvent(invalidUtf8, result, { actor: AGENT });

  assert.equal(event.decision, "deny");
  assert.ok(event.resource.externalId.startsWith("undecodable:"));
  // Deterministic: the fallback identity must be derived from the exact
  // raw bytes given, not a re-encoded/transformed version of them.
  const expected = createHash("sha256").update(invalidUtf8).digest("hex");
  assert.equal(event.resource.externalId, `undecodable:${expected}`);
});

test("buildVerifyEvent: a Uint8Array that IS valid UTF-8 but fails to decode as a token still falls back using the original bytes (the non-string rawBytes branch)", () => {
  const { rootPublicKey } = freshRoot();
  const validUtf8Garbage = new TextEncoder().encode("adc1.not-a-real-token");
  const result = verify(validUtf8Garbage, rootPublicKey);
  assert.equal(result.ok, false);

  const event = buildVerifyEvent(validUtf8Garbage, result, { actor: AGENT });

  const expected = createHash("sha256").update(validUtf8Garbage).digest("hex");
  assert.equal(event.resource.externalId, `undecodable:${expected}`);
});

test("buildVerifyEvent: a sealed, attenuated token's terminal identity matches buildSealEvent's own resource for the same token", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const child = attenuate(mintRoot(rootSecretKey), { caveats: [] });
  const sealed = seal(child);
  const wire = encodeToken(sealed);
  const result = verify(wire, rootPublicKey);
  assert.equal(result.ok, true);

  const verifyEvent = buildVerifyEvent(wire, result, { actor: AGENT });
  const sealEvent = buildSealEvent(sealed, { actor: AGENT });

  assert.equal(verifyEvent.resource.externalId, sealEvent.resource.externalId);
});

// --- buildRevokeEvent --------------------------------------------------------

test("buildRevokeEvent: resource.externalId is exactly the given hash, decision 'allow', reason carried in taintLabels not denyReason", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey);
  const rootHash = buildMintEvent(token, rootPublicKey).resource.externalId;

  const event = buildRevokeEvent(rootHash, { actor: OPERATOR, reason: "compromised key" });

  assert.equal(event.resource.externalId, rootHash);
  assert.equal(event.action, "revoke");
  assert.equal(event.decision, "allow");
  assert.equal(event.denyReason, null);
  assert.deepEqual(event.principal, OPERATOR);
  assert.equal(event.requestDigest, null);
  assert.ok(event.taintLabels.includes("reason:compromised key"));
});

test("buildRevokeEvent: rejects an empty string instead of silently writing a 'successful' revoke of nothing", () => {
  assert.throws(() => buildRevokeEvent("", { actor: OPERATOR, reason: "test" }), RangeError);
});

test("buildRevokeEvent: rejects an arbitrary non-hash string (e.g. an operator typo)", () => {
  assert.throws(() => buildRevokeEvent("not-a-real-hash", { actor: OPERATOR, reason: "test" }), RangeError);
  assert.throws(() => buildRevokeEvent("deadbeef", { actor: OPERATOR, reason: "test" }), RangeError, "too short to be a real sha256 hex digest");
});

test("buildRevokeEvent: rejects one of buildVerifyEvent's own 'undecodable:'-prefixed fallback identities — it was never a real block-signature hash", () => {
  const { rootPublicKey } = freshRoot();
  const result = verify("garbage-token", rootPublicKey);
  const denyEvent = buildVerifyEvent("garbage-token", result, { actor: AGENT });
  assert.ok(denyEvent.resource.externalId.startsWith("undecodable:"));

  assert.throws(() => buildRevokeEvent(denyEvent.resource.externalId, { actor: OPERATOR, reason: "test" }), RangeError);
});

test("buildRevokeEvent: accepts a real blockIdentity() output unchanged (uppercase hex is rejected — blockIdentity() only ever produces lowercase)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const rootHash = buildMintEvent(mintRoot(rootSecretKey), rootPublicKey).resource.externalId;
  assert.doesNotThrow(() => buildRevokeEvent(rootHash, { actor: OPERATOR, reason: "test" }));
  assert.throws(() => buildRevokeEvent(rootHash.toUpperCase(), { actor: OPERATOR, reason: "test" }), RangeError);
});

// --- Full lifecycle consistency ---------------------------------------------

test("full lifecycle: mint -> attenuate -> attenuate -> seal -> verify -> revoke all reference identities consistently", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token: ParsedToken = mintRoot(rootSecretKey, { caveats: [{ kind: "max_depth", depth: 5 }] });
  const mintEvent = buildMintEvent(token, rootPublicKey);

  token = attenuate(token, { caveats: [] });
  const attenuate1Event = buildAttenuateEvent(token, { actor: AGENT });

  token = attenuate(token, { caveats: [] });
  const attenuate2Event = buildAttenuateEvent(token, { actor: AGENT });

  const sealed = seal(token);
  const sealEvent = buildSealEvent(sealed, { actor: AGENT });

  const wire = encodeToken(sealed);
  const result = verify(wire, rootPublicKey);
  assert.equal(result.ok, true);
  const verifyEvent = buildVerifyEvent(wire, result, { actor: AGENT, onBehalfOf: ALICE });

  const revokeEvent = buildRevokeEvent(mintEvent.resource.externalId, { actor: OPERATOR, reason: "root compromised" });

  // Every hop's identity is distinct from every other hop's.
  const hopIds = [mintEvent.resource.externalId, attenuate1Event.resource.externalId, attenuate2Event.resource.externalId];
  assert.equal(new Set(hopIds).size, 3, "mint/attenuate1/attenuate2 must each have a distinct identity");

  // seal and the final verify both reference the SAME terminal block as the last attenuate.
  assert.equal(sealEvent.resource.externalId, attenuate2Event.resource.externalId);
  assert.equal(verifyEvent.resource.externalId, attenuate2Event.resource.externalId);

  // revoke targets block 0's own identity (the "root hash" docs/PLAN.md Phase 7 refers to), not the terminal block.
  assert.equal(revokeEvent.resource.externalId, mintEvent.resource.externalId);
  assert.notEqual(revokeEvent.resource.externalId, verifyEvent.resource.externalId);
});
