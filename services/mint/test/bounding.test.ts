import { test } from "node:test";
import assert from "node:assert/strict";
import type { Caveat } from "@adc/core";
import { boundScopeCaveats } from "../src/bounding.js";
import { FakeRbaClient } from "../src/rba/fake.js";
import type { CheckResponse, NamespaceRelation, RbaClient, ScopeQueryResponse, Subject } from "../src/rba/client.js";

const ALICE = { ns: "user", id: "alice" };

test("no scope caveats at all: ok without ever calling RBA", async () => {
  const rba = new FakeRbaClient();
  const caveats: Caveat[] = [{ kind: "expires", at: 1000 }, { kind: "aud", verifier: "broker-prod" }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.deepEqual(result, { ok: true });
  assert.equal(rba.calls.length, 0);
});

test("wildcard triple: granted via /scope", async () => {
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "*", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.deepEqual(result, { ok: true });
  assert.equal(rba.calls.length, 1);
  assert.equal(rba.calls[0]!.kind, "scopeQuery");
});

test("wildcard triple: not granted anywhere -> rejected with 'not_granted'", async () => {
  const rba = new FakeRbaClient(); // no grants at all
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "*", "write"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.deepEqual(result.failures, [{ kind: "not_granted", resourceKind: "repo", resourceId: "*", relation: "write" }]);
});

test("point triple: granted via /check", async () => {
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "123", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.deepEqual(result, { ok: true });
  assert.equal(rba.calls.length, 1);
  assert.equal(rba.calls[0]!.kind, "check");
});

test("point triple: subject holds it on a DIFFERENT resourceId -> still rejected (no bleed-through)", async () => {
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "999", relation: "read" }]);
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "123", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.deepEqual(result.failures, [{ kind: "not_granted", resourceKind: "repo", resourceId: "123", relation: "read" }]);
});

test("point triple: granted for a DIFFERENT subject -> still rejected (no bleed-through across subjects)", async () => {
  const bob = { ns: "user", id: "bob" };
  const rba = new FakeRbaClient([{ subject: bob, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "123", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
});

test("ALL-OR-NOTHING: one ungranted triple among several rejects the whole mint, not just that triple", async () => {
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  const caveats: Caveat[] = [
    { kind: "scope", triples: [["repo", "123", "read"], ["repo", "123", "write"]] }, // write not granted
  ];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0]!.kind, "not_granted");
  assert.equal((result.failures[0] as { relation: string }).relation, "write");
});

test("multiple scope caveats (e.g. across a hypothetical multi-caveat mint) are all checked together", async () => {
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  const caveats: Caveat[] = [
    { kind: "scope", triples: [["repo", "123", "read"]] },
    { kind: "scope", triples: [["issue", "*", "comment"]] }, // not granted
  ];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
});

test("truncated (unconfirmed) scope scan is treated as not granted, never as granted", async () => {
  const rba = new FakeRbaClient();
  rba.simulateScopeTruncated("repo", "read");
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "*", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.deepEqual(result.failures, [{ kind: "not_granted", resourceKind: "repo", resourceId: "*", relation: "read" }]);
});

test("a per-target RBA error is reported distinctly and still rejects the mint", async () => {
  const rba = new FakeRbaClient();
  rba.simulateScopeError("repo", "read");
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "*", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0]!.kind, "rba_error");
});

test("a malformed /scope response missing an entry for a requested target fails closed, never silently treated as granted", async () => {
  // Regression test: bounding.ts used to iterate response.grants
  // directly, so a target genuinely granted but simply absent from a
  // short/malformed response would never appear in failures — the mint
  // would proceed as if that target had never been requested at all.
  // RBA's own contract guarantees one entry per target, but this must
  // not depend on that contract holding.
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "1", relation: "read" }]);
  rba.simulateDroppedScopeTarget("repo", "read");
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "*", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0]!.kind, "rba_unavailable");
});

test("RBA unreachable (network failure) fails closed: rejected, never treated as granted", async () => {
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "123", relation: "read" }]);
  rba.setUnavailable(true);
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "123", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0]!.kind, "rba_unavailable");
});

test("duplicate triples (same wildcard target repeated) cost exactly one RBA call, not one per occurrence", async () => {
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "1", relation: "read" }]);
  const caveats: Caveat[] = [
    { kind: "scope", triples: [["repo", "*", "read"]] },
    { kind: "scope", triples: [["repo", "*", "read"]] }, // exact duplicate
  ];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.deepEqual(result, { ok: true });
  assert.equal(rba.calls.length, 1);
  const args = rba.calls[0]!.args as { targets: unknown[] };
  assert.equal(args.targets.length, 1);
});

test("more than 50 distinct wildcard targets is rejected client-side, without ever calling RBA", async () => {
  const rba = new FakeRbaClient();
  const triples: [string, string, string][] = [];
  for (let i = 0; i < 51; i++) triples.push([`kind${i}`, "*", "read"]);
  const caveats: Caveat[] = [{ kind: "scope", triples }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.deepEqual(result.failures, [{ kind: "too_many_targets", scope: "wildcard", count: 51, max: 50 }]);
  assert.equal(rba.calls.length, 0);
});

test("more than 50 distinct point targets is rejected client-side, without ever calling RBA", async () => {
  // Unlike wildcard targets (batched into one /scope call), point checks
  // are one /check call each, fired concurrently — this cap bounds that
  // fan-out; it isn't an RBA-imposed limit like SCOPE_QUERY_MAX_TARGETS.
  const rba = new FakeRbaClient();
  const triples: [string, string, string][] = [];
  for (let i = 0; i < 51; i++) triples.push(["repo", `id${i}`, "read"]);
  const caveats: Caveat[] = [{ kind: "scope", triples }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.deepEqual(result.failures, [{ kind: "too_many_targets", scope: "point", count: 51, max: 50 }]);
  assert.equal(rba.calls.length, 0);
});

test("both a wildcard and a point triple in the same mint are both checked", async () => {
  const rba = new FakeRbaClient([
    { subject: ALICE, resourceKind: "repo", resourceId: "1", relation: "read" }, // grounds the wildcard
    { subject: ALICE, resourceKind: "issue", resourceId: "42", relation: "comment" },
  ]);
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "*", "read"], ["issue", "42", "comment"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.deepEqual(result, { ok: true });
  assert.equal(rba.calls.length, 2);
});

// ---------------------------------------------------------------------
// Hardening: a malformed `granted`/`allowed` value that is truthy but not
// literally `=== true` must still deny, not accidentally grant. These
// bypass FakeRbaClient's normal (correctly-typed) responses with a
// minimal hand-rolled RbaClient returning deliberately malformed values
// cast through `as unknown as ...` — TypeScript itself would never let
// legitimate code construct these, which is exactly why they're worth a
// test: only a bug or a compromised/misbehaving RBA deployment could
// produce them, and bounding.ts must not trust `granted`/`allowed`
// merely being truthy.
// ---------------------------------------------------------------------

test("a /scope response with a non-boolean truthy 'granted' value still denies (strict === true, not a truthiness check)", async () => {
  const rba: RbaClient = {
    async scopeQuery(subject: Subject, targets: readonly NamespaceRelation[]): Promise<ScopeQueryResponse> {
      return {
        subject,
        grants: targets.map((t) => ({
          namespace: t.namespace,
          relationOrPermission: t.relationOrPermission,
          granted: "false" as unknown as boolean, // malformed: a truthy string, not the boolean false
          truncated: false,
        })),
      };
    },
    async check(): Promise<CheckResponse> {
      throw new Error("not used in this test");
    },
  };
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "*", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.failures[0]!.kind, "not_granted");
});

test("a /check response with a non-boolean truthy 'allowed' value still denies", async () => {
  const rba: RbaClient = {
    async scopeQuery(): Promise<ScopeQueryResponse> {
      throw new Error("not used in this test");
    },
    async check(subject: Subject, relation: string, object: Subject): Promise<CheckResponse> {
      return { subject, relation, object, depth: 0, allowed: "false" as unknown as boolean };
    },
  };
  const caveats: Caveat[] = [{ kind: "scope", triples: [["repo", "1", "read"]] }];
  const result = await boundScopeCaveats(caveats, ALICE, rba);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.failures[0]!.kind, "not_granted");
});
