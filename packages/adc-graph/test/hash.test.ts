import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { blockIdentity, blockResource, undecodableResource } from "../src/hash.js";

test("blockIdentity: sha256 hex of the raw signature bytes", () => {
  const sig = new Uint8Array(64).fill(7);
  const expected = createHash("sha256").update(sig).digest("hex");
  assert.equal(blockIdentity(sig), expected);
  assert.equal(blockIdentity(sig).length, 64);
  assert.match(blockIdentity(sig), /^[0-9a-f]{64}$/);
});

test("blockIdentity: two different signatures produce two different identities", () => {
  const a = new Uint8Array(64).fill(1);
  const b = new Uint8Array(64).fill(2);
  assert.notEqual(blockIdentity(a), blockIdentity(b));
});

test("blockIdentity: the same signature always produces the same identity", () => {
  const sig = new Uint8Array(64).fill(9);
  assert.equal(blockIdentity(sig), blockIdentity(sig));
});

test("blockResource: kind/source/externalId shape", () => {
  const sig = new Uint8Array(64).fill(3);
  const resource = blockResource(sig);
  assert.equal(resource.kind, "adc-block");
  assert.equal(resource.source, "adc");
  assert.equal(resource.externalId, blockIdentity(sig));
});

test("undecodableResource: prefixed distinctly from a real block identity, never collides with one", () => {
  const rawBytes = new TextEncoder().encode("not a real token");
  const resource = undecodableResource(rawBytes);
  assert.equal(resource.kind, "adc-block");
  assert.equal(resource.source, "adc");
  assert.ok(resource.externalId.startsWith("undecodable:"));
  // A bare blockIdentity() output is a 64-char hex string with no prefix —
  // confirm the two output shapes can never be confused.
  assert.ok(!/^[0-9a-f]{64}$/.test(resource.externalId));
});

test("undecodableResource: deterministic for the same raw bytes, distinct for different ones", () => {
  const a = new TextEncoder().encode("garbage-a");
  const b = new TextEncoder().encode("garbage-b");
  assert.equal(undecodableResource(a).externalId, undecodableResource(a).externalId);
  assert.notEqual(undecodableResource(a).externalId, undecodableResource(b).externalId);
});
