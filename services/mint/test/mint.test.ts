import { test } from "node:test";
import assert from "node:assert/strict";
import { verify, generateKeypair } from "@adc/core";
import { mintWithBounding } from "../src/mint.js";
import { FakeRbaClient } from "../src/rba/fake.js";

const ALICE = { ns: "user", id: "alice" };

function freshRoot() {
  const { secretKey, publicKey } = generateKeypair();
  return { rootSecretKey: secretKey, rootPublicKey: publicKey };
}

test("mints a real, verifiable token when there are no scope caveats", async () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const rba = new FakeRbaClient();
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: ALICE,
    caveats: [{ kind: "expires", at: 9_999_999_999 }],
  });
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error("unreachable");
  const result = verify(outcome.token, rootPublicKey);
  assert.equal(result.ok, true);
  assert.equal(outcome.depth, 0);
});

test("mints a real, verifiable token when the requested scope IS granted", async () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: ALICE,
    caveats: [{ kind: "scope", triples: [["repo", "123", "read"]] }],
  });
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error("unreachable");
  const result = verify(outcome.token, rootPublicKey, { resourceKind: "repo", resourceId: "123", relation: "read" });
  assert.equal(result.ok, true);
});

test("refuses to mint (no token produced) when the requested scope is NOT granted", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient(); // no grants
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: ALICE,
    caveats: [{ kind: "scope", triples: [["repo", "123", "admin"]] }],
  });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "scope_not_granted");
});

test("refuses to mint when RBA is unreachable (fails closed, not open)", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  rba.setUnavailable(true);
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: ALICE,
    caveats: [{ kind: "scope", triples: [["repo", "123", "read"]] }],
  });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "rba_unavailable");
});

test("malformed request body: missing subject", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  const outcome = await mintWithBounding(rootSecretKey, rba, { caveats: [] });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "invalid_request");
  assert.equal(rba.calls.length, 0, "must not call RBA before the request even validates");
});

test("malformed request body: caveats is not an array", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  const outcome = await mintWithBounding(rootSecretKey, rba, { subject: ALICE, caveats: "not-an-array" });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "invalid_request");
});

test("malformed request body: an unrecognized caveat kind is rejected before any RBA call, not silently dropped", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: ALICE,
    caveats: [{ kind: "totally_unknown_kind" }],
  });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "invalid_request");
  assert.equal(rba.calls.length, 0);
});

test("malformed request body: a structurally invalid scope triple never reaches bounding logic (no crash, clean 'invalid_request')", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  // Not a 3-tuple — would break naive destructuring in bounding.ts if it
  // reached there unvalidated.
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: ALICE,
    caveats: [{ kind: "scope", triples: [["repo", "read"]] }],
  });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "invalid_request");
  assert.equal(rba.calls.length, 0);
});

test("malformed request body: subject with an extra field is rejected (matches @adc/core's own exact-keys discipline)", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: { ns: "user", id: "alice", extra: "field" },
    caveats: [],
  });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "invalid_request");
});

test("request body with unexpected top-level fields is rejected", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  const outcome = await mintWithBounding(rootSecretKey, rba, { subject: ALICE, caveats: [], extra: true });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.code, "invalid_request");
});

test("null / non-object request bodies are rejected, not thrown", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  for (const bad of [null, undefined, "a string", 42, []]) {
    const outcome = await mintWithBounding(rootSecretKey, rba, bad);
    assert.equal(outcome.ok, false);
    if (outcome.ok) throw new Error("unreachable");
    assert.equal(outcome.code, "invalid_request");
  }
});

test("scope bounding runs BEFORE minting: a rejected mint never touches the root secret key's signing path (no token is ever produced)", async () => {
  const { rootSecretKey } = freshRoot();
  const rba = new FakeRbaClient();
  const outcome = await mintWithBounding(rootSecretKey, rba, {
    subject: ALICE,
    caveats: [{ kind: "scope", triples: [["repo", "*", "read"]] }],
  });
  assert.equal(outcome.ok, false);
  // The outcome type itself has no `token` field when ok is false — this
  // assertion is really just documenting the invariant the type already
  // enforces at compile time.
  assert.equal("token" in outcome, false);
});
