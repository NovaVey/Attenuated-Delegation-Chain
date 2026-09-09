import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveCallFacts, type FactsSourceTool } from "../src/facts.js";

const NOW = 1_800_000_000;

function tool(capabilities: FactsSourceTool["capabilities"]["capabilities"], destinationKeys?: readonly string[]): FactsSourceTool {
  return { capabilities: { capabilities }, ...(destinationKeys ? { destinationKeys } : {}) };
}

test("NONE-sinkClass tool (no capabilities): sinks and hosts both empty", () => {
  const facts = deriveCallFacts(tool([]), { anything: "https://example.com" }, "CLEAN", NOW);
  assert.deepEqual(facts.sinks, []);
  assert.deepEqual(facts.hosts, []);
  assert.deepEqual(facts.base, { taintLevel: "TRUSTED", now: NOW });
});

test("EXEC-sinkClass tool: sinks carries the declared capability, hosts stays empty regardless of args", () => {
  const facts = deriveCallFacts(tool(["exec:shell"]), { cmd: "curl https://evil.example" }, "CLEAN", NOW);
  assert.deepEqual(facts.sinks, ["exec:shell"]);
  assert.deepEqual(facts.hosts, [], "host detection is EXFIL-only, mirroring taint-tracked-tool-broker's own destinationKeys convention");
});

test("MUTATE-sinkClass tool: hosts stays empty even when args contain a URL-shaped string", () => {
  const facts = deriveCallFacts(tool(["write:fs"]), { path: "/tmp/x", note: "see https://example.com" }, "CLEAN", NOW);
  assert.deepEqual(facts.hosts, []);
});

test("EXFIL-sinkClass tool: hosts derived from a genuine http(s) URL in args", () => {
  const facts = deriveCallFacts(tool(["net:api-call"]), { url: "https://api.example.com/v1/widgets" }, "CLEAN", NOW);
  assert.deepEqual(facts.sinks, ["net:api-call"]);
  assert.deepEqual(facts.hosts, ["api.example.com"]);
});

test("EXFIL-sinkClass tool: hosts derived from a genuine email address in args (net:email)", () => {
  const facts = deriveCallFacts(tool(["net:email"]), { to: "alice@example.com", body: "hi" }, "CLEAN", NOW);
  assert.deepEqual(facts.hosts, ["example.com"]);
});

test("EXFIL-sinkClass tool: a benign string that merely contains a URL-looking substring is not flagged unless it IS the URL", () => {
  const facts = deriveCallFacts(tool(["net:api-call"]), { note: "see https://example.com for details" }, "CLEAN", NOW);
  // Matches taint-tracked-tool-broker's own findOutboundHosts semantics —
  // this is its behavior, not something adc-broker adds or removes.
  assert.deepEqual(facts.hosts, []);
});

test("destinationKeys narrows the scan to just the named key's subtree", () => {
  const facts = deriveCallFacts(
    tool(["net:api-call"], ["url"]),
    { url: "https://real-destination.example", notes: "https://decoy.example" },
    "CLEAN",
    NOW,
  );
  assert.deepEqual(facts.hosts, ["real-destination.example"]);
});

test("a tool declaring multiple sink capabilities carries all of them", () => {
  const facts = deriveCallFacts(tool(["exec:shell", "write:fs"]), {}, "CLEAN", NOW);
  assert.deepEqual(facts.sinks, ["exec:shell", "write:fs"]);
});

test("taint level and now flow through unchanged (mapped) into base facts", () => {
  const facts = deriveCallFacts(tool([]), {}, "RAW_UNTRUSTED", 42);
  assert.deepEqual(facts.base, { taintLevel: "RAW_UNTRUSTED", now: 42 });
});

test("now defaults to the current wall clock when omitted", () => {
  const before = Math.floor(Date.now() / 1000);
  const facts = deriveCallFacts(tool([]), {}, "CLEAN");
  const after = Math.floor(Date.now() / 1000);
  assert.ok(facts.base.now >= before && facts.base.now <= after);
});
