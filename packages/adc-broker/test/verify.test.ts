import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeToken, generateKeypair, mintRoot, type Caveat } from "@adc/core";
import { verifyCall } from "../src/verify.js";
import type { CallFactSets } from "../src/facts.js";

const NOW = 1_800_000_000;

function mint(caveats: readonly Caveat[]) {
  const { secretKey, publicKey } = generateKeypair();
  const token = encodeToken(mintRoot(secretKey, { caveats }));
  return { token, publicKey };
}

function factSets(overrides: Partial<CallFactSets> = {}): CallFactSets {
  return {
    base: { taintLevel: "TRUSTED", now: NOW },
    sinks: [],
    hosts: [],
    ...overrides,
  };
}

test("no sinks/hosts caveats at all: a bare base-facts check passes for a token with only expires", () => {
  const { token, publicKey } = mint([{ kind: "expires", at: NOW + 1000 }]);
  const result = verifyCall(token, publicKey, factSets());
  assert.equal(result.ok, true);
});

test("a sinks caveat covering the tool's one declared capability: allow", () => {
  const { token, publicKey } = mint([{ kind: "sinks", classes: ["exec:shell"] }]);
  const result = verifyCall(token, publicKey, factSets({ sinks: ["exec:shell"] }));
  assert.equal(result.ok, true);
});

test("a sinks caveat missing one of TWO declared capabilities: deny (fail-closed across all variations)", () => {
  const { token, publicKey } = mint([{ kind: "sinks", classes: ["exec:shell"] }]);
  const result = verifyCall(token, publicKey, factSets({ sinks: ["exec:shell", "write:fs"] }));
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "ADC_SINK");
});

test("a hosts caveat permitting one detected host but not a second: deny", () => {
  const { token, publicKey } = mint([{ kind: "hosts", hostnames: ["good.example.com"] }]);
  const result = verifyCall(token, publicKey, factSets({ hosts: ["good.example.com", "bad.example.com"] }));
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "ADC_HOST");
});

test("a hosts caveat permitting every detected host: allow", () => {
  const { token, publicKey } = mint([{ kind: "hosts", hostnames: ["a.example.com", "b.example.com"] }]);
  const result = verifyCall(token, publicKey, factSets({ hosts: ["a.example.com", "b.example.com"] }));
  assert.equal(result.ok, true);
});

test("taint_max ceiling respected via base facts, independent of sinks/hosts variations", () => {
  const { token, publicKey } = mint([{ kind: "taint_max", level: "DERIVED" }, { kind: "sinks", classes: ["exec:shell"] }]);
  const allowed = verifyCall(
    token,
    publicKey,
    factSets({ base: { taintLevel: "DERIVED", now: NOW }, sinks: ["exec:shell"] }),
  );
  assert.equal(allowed.ok, true);

  const denied = verifyCall(
    token,
    publicKey,
    factSets({ base: { taintLevel: "RAW_UNTRUSTED", now: NOW }, sinks: ["exec:shell"] }),
  );
  assert.equal(denied.ok, false);
  if (denied.ok) throw new Error("unreachable");
  assert.equal(denied.code, "ADC_TAINT");
});

test("expired token denies regardless of sinks/hosts being otherwise satisfied", () => {
  // Well outside the default 60s clock-skew window, so this is a genuine
  // expiry, not a skew-tolerated near-miss.
  const { token, publicKey } = mint([{ kind: "expires", at: NOW - 1000 }, { kind: "sinks", classes: ["exec:shell"] }]);
  const result = verifyCall(token, publicKey, factSets({ sinks: ["exec:shell"] }));
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "ADC_EXPIRED");
});

test("multiple sink variations: the FIRST denial found is returned, not silently masked by a later allow", () => {
  const { token, publicKey } = mint([{ kind: "sinks", classes: ["write:fs"] }]);
  // "exec:shell" is checked first (declaration order) and isn't covered.
  const result = verifyCall(token, publicKey, factSets({ sinks: ["exec:shell", "write:fs"] }));
  assert.equal(result.ok, false);
});

test("a token with no caveats at all permits every fact variation", () => {
  const { token, publicKey } = mint([]);
  const result = verifyCall(token, publicKey, factSets({ sinks: ["exec:shell", "net:email"], hosts: ["x.example.com"] }));
  assert.equal(result.ok, true);
});

test("wrong root public key denies with ADC_SIG_INVALID regardless of facts", () => {
  const { token } = mint([]);
  const { publicKey: wrongKey } = generateKeypair();
  const result = verifyCall(token, wrongKey, factSets());
  assert.equal(result.ok, false);
  if (result.ok) throw new Error("unreachable");
  assert.equal(result.code, "ADC_SIG_INVALID");
});
