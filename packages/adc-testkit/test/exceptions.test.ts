import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { falseDenyKey, isKnownFalseDeny, loadExceptions } from "../src/exceptions.js";
import type { ChainSpec } from "../src/reference.js";
import type { Tuple } from "../src/universe.js";

const SAMPLE_SPEC: ChainSpec = { hops: [{ caveats: [{ kind: "aud", verifier: "broker-prod" }] }] };
const SAMPLE_QUERY: Tuple = {
  resourceKind: "repo",
  resourceId: "1",
  relation: "read",
  sink: "net:email",
  host: "api.example.com",
  taintLevel: "TRUSTED",
  now: 1000,
  audience: "broker-prod",
};

test("falseDenyKey is deterministic for the same case", () => {
  const a = falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 60);
  const b = falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 60);
  assert.equal(a, b);
});

test("falseDenyKey is deterministic regardless of object key insertion order", () => {
  const reorderedQuery: Tuple = {
    audience: SAMPLE_QUERY.audience,
    now: SAMPLE_QUERY.now,
    taintLevel: SAMPLE_QUERY.taintLevel,
    host: SAMPLE_QUERY.host,
    sink: SAMPLE_QUERY.sink,
    relation: SAMPLE_QUERY.relation,
    resourceId: SAMPLE_QUERY.resourceId,
    resourceKind: SAMPLE_QUERY.resourceKind,
  };
  assert.equal(falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 60), falseDenyKey(SAMPLE_SPEC, reorderedQuery, 60));
});

test("falseDenyKey differs when the query differs", () => {
  const otherQuery: Tuple = { ...SAMPLE_QUERY, relation: "write" };
  assert.notEqual(falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 60), falseDenyKey(SAMPLE_SPEC, otherQuery, 60));
});

test("falseDenyKey differs when the chain spec differs", () => {
  const otherSpec: ChainSpec = { hops: [{ caveats: [{ kind: "aud", verifier: "broker-staging" }] }] };
  assert.notEqual(falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 60), falseDenyKey(otherSpec, SAMPLE_QUERY, 60));
});

test("falseDenyKey differs when clockSkewSeconds differs", () => {
  assert.notEqual(falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 60), falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 61));
});

test("isKnownFalseDeny matches a key present in the exceptions list, and rejects one that isn't", () => {
  const key = falseDenyKey(SAMPLE_SPEC, SAMPLE_QUERY, 60);
  const exceptions = { falseDenies: [{ key, reason: "test fixture" }] };
  assert.equal(isKnownFalseDeny(key, exceptions), true);
  assert.equal(isKnownFalseDeny("not-a-real-key", exceptions), false);
  assert.equal(isKnownFalseDeny(key, { falseDenies: [] }), false);
});

test("loadExceptions reads and parses a real file from disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "adc-testkit-exceptions-"));
  const path = join(dir, "exceptions.json");
  try {
    writeFileSync(path, JSON.stringify({ falseDenies: [{ key: "abc123", reason: "example" }] }));
    const loaded = loadExceptions(path);
    assert.deepEqual(loaded, { falseDenies: [{ key: "abc123", reason: "example" }] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadExceptions throws (rather than silently returning an empty list) when the file is missing", () => {
  // Regression test: loadExceptions() used to fall back to
  // { falseDenies: [] } for a missing file, which is indistinguishable
  // from a legitimate empty exceptions.json — a broken path would never
  // surface as a failure as long as there happened to be zero false
  // denies to match against it.
  const dir = mkdtempSync(join(tmpdir(), "adc-testkit-exceptions-missing-"));
  try {
    assert.throws(() => loadExceptions(join(dir, "does-not-exist.json")), /not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadExceptions rejects a file whose falseDenies field isn't an array", () => {
  const dir = mkdtempSync(join(tmpdir(), "adc-testkit-exceptions-bad-"));
  const path = join(dir, "exceptions.json");
  try {
    writeFileSync(path, JSON.stringify({ falseDenies: "not an array" }));
    assert.throws(() => loadExceptions(path), SyntaxError);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the real, committed exceptions.json loads successfully and is currently empty", () => {
  const exceptions = loadExceptions();
  assert.deepEqual(exceptions, { falseDenies: [] });
});
