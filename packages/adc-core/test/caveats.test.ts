import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mintRoot,
  attenuate,
  verify,
  encodeToken,
  encodeBlock,
  generateKeypair,
  AdcError,
  DEFAULT_CLOCK_SKEW_SECONDS,
} from "../src/index.js";
import { buildSignInput } from "../src/signing.js";
import { sign } from "../src/crypto.js";
import { ALG_ED25519 } from "../src/block.js";

function freshRoot() {
  const root = generateKeypair();
  return { rootSecretKey: root.secretKey, rootPublicKey: root.publicKey };
}

function code(result: { ok: boolean }): string | undefined {
  return (result as { ok: false; code?: string }).code;
}

// ---------------------------------------------------------------------
// scope
// ---------------------------------------------------------------------

test("scope: permits an exact (resourceKind, resourceId, relation) match", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, {
    caveats: [{ kind: "scope", triples: [["repo", "123", "read"]] }],
  });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "123", relation: "read" }).ok, true);
  assert.equal(code(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "123", relation: "write" })), "ADC_SCOPE");
  assert.equal(code(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "456", relation: "read" })), "ADC_SCOPE");
  assert.equal(code(verify(wire, rootPublicKey, { resourceKind: "issue", resourceId: "123", relation: "read" })), "ADC_SCOPE");
});

test("scope: '*' resourceId matches any resourceId", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, {
    caveats: [{ kind: "scope", triples: [["repo", "*", "read"]] }],
  });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "any-id-at-all", relation: "read" }).ok, true);
  assert.equal(code(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "any-id-at-all", relation: "write" })), "ADC_SCOPE");
});

test("scope: denies when the required facts are not supplied", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "scope", triples: [["repo", "*", "read"]] }] });
  const result = verify(encodeToken(token), rootPublicKey, {});
  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_SCOPE");
});

test("scope narrows across attenuation: a later, tighter scope caveat is enforced even though the root allowed more", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey, {
    caveats: [{ kind: "scope", triples: [["repo", "*", "read"], ["repo", "*", "write"]] }],
  });
  token = attenuate(token, { caveats: [{ kind: "scope", triples: [["repo", "*", "read"]] }] });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "1", relation: "read" }).ok, true);
  assert.equal(code(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "1", relation: "write" })), "ADC_SCOPE");
});

test("scope: an earlier, tighter scope caveat still binds even when a later block adds a looser one of the same kind", () => {
  // The harder direction: a regression that evaluated only the newest
  // block's scope caveat per kind (discarding earlier same-kind caveats
  // instead of ANDing every instance) would pass the test above but fail
  // this one.
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey, { caveats: [{ kind: "scope", triples: [["repo", "*", "read"]] }] });
  token = attenuate(token, {
    caveats: [{ kind: "scope", triples: [["repo", "*", "read"], ["repo", "*", "write"]] }],
  });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "1", relation: "read" }).ok, true);
  // block0's caveat never granted "write" — it must still be denied even
  // though block1's (later, broader) caveat alone would have allowed it.
  assert.equal(code(verify(wire, rootPublicKey, { resourceKind: "repo", resourceId: "1", relation: "write" })), "ADC_SCOPE");
});

// ---------------------------------------------------------------------
// sinks
// ---------------------------------------------------------------------

test("sinks: permits only listed sink classes", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "sinks", classes: ["exec:shell", "write:fs"] }] });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { sink: "exec:shell" }).ok, true);
  assert.equal(verify(wire, rootPublicKey, { sink: "write:fs" }).ok, true);
  assert.equal(code(verify(wire, rootPublicKey, { sink: "net:email" })), "ADC_SINK");
  assert.equal(code(verify(wire, rootPublicKey, {})), "ADC_SINK");
});

// ---------------------------------------------------------------------
// taint_max
// ---------------------------------------------------------------------

test("taint_max: permits at or below the ceiling, denies above it", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "taint_max", level: "DERIVED" }] });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { taintLevel: "TRUSTED" }).ok, true);
  assert.equal(verify(wire, rootPublicKey, { taintLevel: "DERIVED" }).ok, true, "boundary: exactly at the ceiling");
  assert.equal(code(verify(wire, rootPublicKey, { taintLevel: "RAW_UNTRUSTED" })), "ADC_TAINT");
  assert.equal(code(verify(wire, rootPublicKey, {})), "ADC_TAINT");
});

test("taint_max narrows across attenuation: the tightest ceiling in the chain wins", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey, { caveats: [{ kind: "taint_max", level: "RAW_UNTRUSTED" }] });
  token = attenuate(token, { caveats: [{ kind: "taint_max", level: "TRUSTED" }] });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { taintLevel: "TRUSTED" }).ok, true);
  assert.equal(code(verify(wire, rootPublicKey, { taintLevel: "DERIVED" })), "ADC_TAINT");
});

test("taint_max: an earlier, tighter ceiling still binds even when a later block adds a looser one", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey, { caveats: [{ kind: "taint_max", level: "TRUSTED" }] });
  token = attenuate(token, { caveats: [{ kind: "taint_max", level: "RAW_UNTRUSTED" }] });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { taintLevel: "TRUSTED" }).ok, true);
  // block0's ceiling (TRUSTED) must still bind even though block1's
  // (later, looser) ceiling alone would have permitted DERIVED.
  assert.equal(code(verify(wire, rootPublicKey, { taintLevel: "DERIVED" })), "ADC_TAINT");
});

// ---------------------------------------------------------------------
// expires
// ---------------------------------------------------------------------

test("expires: boundary cases at exactly the expiry, just inside skew, and just past skew", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const at = 1_000_000;
  const skew = 60;
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at }] });
  const wire = encodeToken(token);

  const exact = verify(wire, rootPublicKey, { now: at }, { clockSkewSeconds: skew });
  assert.equal(exact.ok, true, "now == at should be permitted");
  assert.equal((exact as { usedClockSkew: boolean }).usedClockSkew, false);

  const beforeExpiry = verify(wire, rootPublicKey, { now: at - 1 }, { clockSkewSeconds: skew });
  assert.equal(beforeExpiry.ok, true);
  assert.equal((beforeExpiry as { usedClockSkew: boolean }).usedClockSkew, false);

  const withinSkew = verify(wire, rootPublicKey, { now: at + skew }, { clockSkewSeconds: skew });
  assert.equal(withinSkew.ok, true, "now == at + skew should be permitted (boundary)");
  assert.equal((withinSkew as { usedClockSkew: boolean }).usedClockSkew, true);

  const pastSkew = verify(wire, rootPublicKey, { now: at + skew + 1 }, { clockSkewSeconds: skew });
  assert.equal(pastSkew.ok, false);
  assert.equal(code(pastSkew), "ADC_EXPIRED");
});

test("expires: the real DEFAULT_CLOCK_SKEW_SECONDS value governs the skew boundary when opts is omitted, not just an explicitly-passed override", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const at = 1_000_000;
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at }] });
  const wire = encodeToken(token);

  // opts is omitted entirely here (only 3 args) — this must fall back to
  // the real DEFAULT_CLOCK_SKEW_SECONDS, not some other value.
  const withinDefaultSkew = verify(wire, rootPublicKey, { now: at + DEFAULT_CLOCK_SKEW_SECONDS });
  assert.equal(withinDefaultSkew.ok, true, "boundary: now == at + DEFAULT_CLOCK_SKEW_SECONDS should be permitted");
  assert.equal((withinDefaultSkew as { usedClockSkew: boolean }).usedClockSkew, true);

  const pastDefaultSkew = verify(wire, rootPublicKey, { now: at + DEFAULT_CLOCK_SKEW_SECONDS + 1 });
  assert.equal(pastDefaultSkew.ok, false);
  assert.equal(code(pastDefaultSkew), "ADC_EXPIRED");
});

test("expires: the minimum across blocks governs, not the newest block's value", () => {
  // A longer (looser) expires added in a later block must NOT override an
  // earlier, tighter one — docs/PLAN.md 1.5: "Expiry is the minimum across
  // all blocks, not the value in the newest one."
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const tight = 1_000_000;
  const loose = 9_000_000;
  let token = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: tight }] });
  token = attenuate(token, { caveats: [{ kind: "expires", at: loose }] });
  const wire = encodeToken(token);

  // Comfortably past the tight expiry (well beyond any skew) but nowhere
  // near the loose one.
  const result = verify(wire, rootPublicKey, { now: tight + 10_000 }, { clockSkewSeconds: 60 });
  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_EXPIRED");

  // Still valid before the tight expiry.
  assert.equal(verify(wire, rootPublicKey, { now: tight - 1 }).ok, true);
});

test("expires: 'now' defaults to the real wall clock when omitted", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const farFuture = Math.floor(Date.now() / 1000) + 1_000_000;
  const farPast = 1; // 1970-01-01T00:00:01Z

  const futureToken = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: farFuture }] });
  assert.equal(verify(encodeToken(futureToken), rootPublicKey).ok, true);

  const pastToken = mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: farPast }] });
  const result = verify(encodeToken(pastToken), rootPublicKey);
  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_EXPIRED");
});

// ---------------------------------------------------------------------
// max_depth (caveat form; distinct from opts.maxDepth's structural cap)
// ---------------------------------------------------------------------

test("max_depth caveat: boundary at exactly the limit and one over", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey, { caveats: [{ kind: "max_depth", depth: 2 }] });
  token = attenuate(token);
  token = attenuate(token); // depth 2 now
  assert.equal(verify(encodeToken(token), rootPublicKey).ok, true, "boundary: exactly at max_depth");

  const overToken = attenuate(token); // depth 3
  const result = verify(encodeToken(overToken), rootPublicKey);
  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_DEPTH_EXCEEDED");
});

test("max_depth caveat and opts.maxDepth structural cap both apply", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey, { caveats: [{ kind: "max_depth", depth: 10 }] });
  token = attenuate(token);
  token = attenuate(token); // depth 2
  const wire = encodeToken(token);

  // Caveat allows depth 10, but the verifier's own structural cap is 1.
  const result = verify(wire, rootPublicKey, {}, { maxDepth: 1 });
  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_DEPTH_EXCEEDED");
});

// ---------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------

test("hosts: permits only listed hostnames, case-insensitively", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "hosts", hostnames: ["api.example.com"] }] });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { host: "api.example.com" }).ok, true);
  assert.equal(verify(wire, rootPublicKey, { host: "API.EXAMPLE.COM" }).ok, true);
  assert.equal(code(verify(wire, rootPublicKey, { host: "evil.example.com" })), "ADC_HOST");
  assert.equal(code(verify(wire, rootPublicKey, {})), "ADC_HOST");
});

// ---------------------------------------------------------------------
// aud
// ---------------------------------------------------------------------

test("aud: permits only the named verifier", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const token = mintRoot(rootSecretKey, { caveats: [{ kind: "aud", verifier: "broker-prod-1" }] });
  const wire = encodeToken(token);

  assert.equal(verify(wire, rootPublicKey, { audience: "broker-prod-1" }).ok, true);
  assert.equal(code(verify(wire, rootPublicKey, { audience: "broker-prod-2" })), "ADC_AUDIENCE");
  assert.equal(code(verify(wire, rootPublicKey, {})), "ADC_AUDIENCE");
});

// ---------------------------------------------------------------------
// composition across caveats and blocks
// ---------------------------------------------------------------------

test("every caveat in every block must be satisfied (AND across all instances)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let token = mintRoot(rootSecretKey, {
    caveats: [
      { kind: "scope", triples: [["repo", "*", "read"]] },
      { kind: "sinks", classes: ["net:email"] },
    ],
  });
  token = attenuate(token, { caveats: [{ kind: "taint_max", level: "DERIVED" }] });
  const wire = encodeToken(token);

  const allFacts = { resourceKind: "repo", resourceId: "1", relation: "read", sink: "net:email", taintLevel: "DERIVED" as const };
  assert.equal(verify(wire, rootPublicKey, allFacts).ok, true);

  assert.equal(code(verify(wire, rootPublicKey, { ...allFacts, relation: "write" })), "ADC_SCOPE");
  assert.equal(code(verify(wire, rootPublicKey, { ...allFacts, sink: "exec:shell" })), "ADC_SINK");
  assert.equal(code(verify(wire, rootPublicKey, { ...allFacts, taintLevel: "RAW_UNTRUSTED" })), "ADC_TAINT");
});

// ---------------------------------------------------------------------
// mint/attenuate-time validation
// ---------------------------------------------------------------------

test("mintRoot()/attenuate() reject structurally invalid caveats at construction time", () => {
  const { rootSecretKey } = freshRoot();
  const token = mintRoot(rootSecretKey);

  assert.throws(() => mintRoot(rootSecretKey, { caveats: [{ kind: "taint_max", level: "BOGUS" as never }] }), AdcError);
  assert.throws(() => mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: -1 }] }), AdcError);
  assert.throws(() => mintRoot(rootSecretKey, { caveats: [{ kind: "hosts", hostnames: ["not a hostname!"] }] }), AdcError);
  assert.throws(() => attenuate(token, { caveats: [{ kind: "aud", verifier: "" }] }), AdcError);

  try {
    mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: -1 }] });
    assert.fail("expected throw");
  } catch (err) {
    assert.equal((err as AdcError).code, "ADC_MALFORMED");
  }
});

test("mintRoot()/attenuate() reject -0 in expires.at/max_depth.depth with the documented AdcError, not an untyped RangeError", () => {
  // Regression test: -0 satisfies a naive "non-negative integer" check
  // (Number.isInteger(-0), Number.isSafeInteger(-0), and -0 >= 0 are all
  // true in JS) but canonical.ts's stringify() explicitly rejects -0 in
  // numeric fields. Before this was pinned in isNonNegativeSafeInteger,
  // parseCaveat/validateCaveats let -0 through silently and mintRoot()/
  // attenuate() instead threw a raw, unwrapped RangeError deep inside
  // encodeBlock() — breaking the documented "malformed caveats always
  // surface as AdcError('ADC_MALFORMED', ...)" contract.
  const { rootSecretKey } = freshRoot();

  assert.throws(() => mintRoot(rootSecretKey, { caveats: [{ kind: "expires", at: -0 }] }), AdcError);
  assert.throws(() => mintRoot(rootSecretKey, { caveats: [{ kind: "max_depth", depth: -0 }] }), AdcError);

  try {
    mintRoot(rootSecretKey, { caveats: [{ kind: "max_depth", depth: -0 }] });
    assert.fail("expected throw");
  } catch (err) {
    assert.ok(err instanceof AdcError, `expected AdcError, got ${(err as Error).constructor.name}`);
    assert.equal((err as AdcError).code, "ADC_MALFORMED");
  }
});

// ---------------------------------------------------------------------
// unrecognized caveat kind (closed vocabulary is enforced by rejection)
// ---------------------------------------------------------------------

test("verify() denies a token carrying an unrecognized caveat kind (fails closed, never silently ignored)", () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const kp = generateKeypair();
  // Hand-construct a block bypassing mintRoot()'s typed/validated caveats
  // API — this simulates a token minted by some future version of the
  // format with a caveat kind this verifier doesn't know about, or a
  // hostile token. It must never be silently ignored: that would widen
  // effective authority instead of narrowing it.
  const blockBytes = encodeBlock({
    alg: ALG_ED25519,
    nextPublicKey: kp.publicKey,
    caveats: [{ kind: "future_kind_v9", payload: "whatever" } as never],
  });
  const toSign = buildSignInput({ blockBytes, nextPubKey: kp.publicKey });
  const sig = sign(rootSecretKey, toSign);
  const token = {
    version: "adc1" as const,
    blocks: [blockBytes],
    sigs: [sig],
    proof: { type: "attenuable" as const, secretKey: kp.secretKey },
  };

  const result = verify(encodeToken(token), rootPublicKey);
  assert.equal(result.ok, false);
  assert.equal(code(result), "ADC_MALFORMED");
});
