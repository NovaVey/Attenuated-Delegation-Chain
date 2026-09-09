import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "@adc/core";
import { rootKeyPrincipal, toBase64Url, ADC_RESOURCE_SOURCE, ADC_BLOCK_RESOURCE_KIND } from "../src/identity.js";

test("rootKeyPrincipal: derives kind/source/externalId from the public key, never the secret", () => {
  const { secretKey, publicKey } = generateKeypair();
  const identity = rootKeyPrincipal(publicKey);
  assert.equal(identity.kind, "service");
  assert.equal(identity.source, "adc-mint");
  assert.equal(identity.externalId, toBase64Url(publicKey));
  assert.equal(identity.displayName, null);
  // The secret key's bytes must never appear anywhere in the identity.
  const secretB64 = toBase64Url(secretKey);
  assert.notEqual(identity.externalId, secretB64);
  assert.ok(!JSON.stringify(identity).includes(secretB64));
});

test("rootKeyPrincipal: accepts an explicit displayName", () => {
  const { publicKey } = generateKeypair();
  const identity = rootKeyPrincipal(publicKey, "root authority");
  assert.equal(identity.displayName, "root authority");
});

test("rootKeyPrincipal: two different public keys produce two different externalIds", () => {
  const a = generateKeypair();
  const b = generateKeypair();
  assert.notEqual(rootKeyPrincipal(a.publicKey).externalId, rootKeyPrincipal(b.publicKey).externalId);
});

test("rootKeyPrincipal: the same public key always produces the same externalId (idempotent, matches Principal-Graph's upsert-by-(source,external_id) expectation)", () => {
  const { publicKey } = generateKeypair();
  assert.equal(rootKeyPrincipal(publicKey).externalId, rootKeyPrincipal(publicKey).externalId);
});

test("toBase64Url: produces a URL-safe string with no padding, decodes back to the original bytes", () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const encoded = toBase64Url(bytes);
  assert.ok(!encoded.includes("+"));
  assert.ok(!encoded.includes("/"));
  assert.ok(!encoded.includes("="));
  assert.deepEqual(new Uint8Array(Buffer.from(encoded, "base64url")), bytes);
});

test("resource constants are stable string literals (a real Principal-Graph adapter matches these exactly)", () => {
  assert.equal(ADC_RESOURCE_SOURCE, "adc");
  assert.equal(ADC_BLOCK_RESOURCE_KIND, "adc-block");
});
