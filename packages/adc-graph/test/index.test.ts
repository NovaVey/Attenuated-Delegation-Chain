import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair, mintRoot } from "@adc/core";
import * as adcGraph from "../src/index.js";

/**
 * Regression guard: index.ts is the package's real public entry point
 * (package.json main/exports both point at dist/src/index.js), but no
 * OTHER test file imports from it — every other test imports directly
 * from a submodule. That leaves a real gap `tsc` alone doesn't close: a
 * value (function/const) accidentally placed in an `export type {...}`
 * clause instead of a plain `export {...}` one compiles cleanly and
 * type-checks cleanly, but silently omits the runtime binding from the
 * built JS — a downstream consumer gets a `ReferenceError` at import
 * time, undetected by this repo's own typecheck/build steps. Actually
 * *calling* every export here, through the public entry point, is what
 * catches that class of mistake.
 */
test("every exported value is actually callable/usable through the public entry point, not just type-visible", () => {
  assert.equal(typeof adcGraph.buildMintEvent, "function");
  assert.equal(typeof adcGraph.buildAttenuateEvent, "function");
  assert.equal(typeof adcGraph.buildSealEvent, "function");
  assert.equal(typeof adcGraph.buildVerifyEvent, "function");
  assert.equal(typeof adcGraph.buildRevokeEvent, "function");
  assert.equal(typeof adcGraph.rootKeyPrincipal, "function");
  assert.equal(typeof adcGraph.toBase64Url, "function");
  assert.equal(typeof adcGraph.blockIdentity, "function");
  assert.equal(typeof adcGraph.blockResource, "function");
  assert.equal(typeof adcGraph.undecodableResource, "function");
  assert.equal(typeof adcGraph.isBlockIdentity, "function");
  assert.equal(typeof adcGraph.createInMemoryGraphSink, "function");
  assert.equal(typeof adcGraph.ADC_RESOURCE_SOURCE, "string");
  assert.equal(typeof adcGraph.ADC_BLOCK_RESOURCE_KIND, "string");
  assert.ok(adcGraph.BLOCK_IDENTITY_PATTERN instanceof RegExp);
});

test("end-to-end through the public entry point only: mint an event, record it in the reference sink", () => {
  const { secretKey, publicKey } = generateKeypair();
  const token = mintRoot(secretKey);
  const sink = adcGraph.createInMemoryGraphSink();

  const event = adcGraph.buildMintEvent(token, publicKey);
  sink.record(event);

  assert.equal(sink.events.length, 1);
  assert.equal(sink.events[0]!.action, "mint");
  assert.equal(adcGraph.isBlockIdentity(event.resource.externalId), true);
});
