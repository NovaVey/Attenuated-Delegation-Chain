import { test } from "node:test";
import assert from "node:assert/strict";
import { createBroker, ToolCallBlockedError, type AuditEvent, type SinkCapability, type ToolExecutor } from "taint-tracked-tool-broker";
import { encodeToken, generateKeypair, mintRoot, type Caveat } from "@adc/core";
import { wrapWithAdcGate, AdcGateError } from "../src/gate.js";

function mintToken(caveats: readonly Caveat[]) {
  const { secretKey, publicKey } = generateKeypair();
  const token = encodeToken(mintRoot(secretKey, { caveats }));
  return { token, publicKey };
}

function execTool(): ToolExecutor<{ cmd: string }, { ran: true }> & { calls: number } {
  const tool = {
    name: "shell_exec",
    capabilities: { capabilities: ["exec:shell"] as SinkCapability[] },
    calls: 0,
    async execute() {
      tool.calls++;
      return { ran: true as const };
    },
  };
  return tool;
}

function sourceTool(): ToolExecutor<Record<string, never>, { text: string }> {
  return {
    name: "fetch_url",
    capabilities: { capabilities: [] },
    isSource: true,
    async execute() {
      return { text: "untrusted content from the wire" };
    },
  };
}

function emailTool(): ToolExecutor<{ to: string }, { sent: true }> & { calls: number } {
  const tool = {
    name: "send_email",
    capabilities: { capabilities: ["net:email"] as SinkCapability[] },
    calls: 0,
    async execute() {
      tool.calls++;
      return { sent: true as const };
    },
  };
  return tool;
}

test("ADC deny happens BEFORE the taint gate: broker.call() is never reached, no AuditEvent is produced", async () => {
  const events: AuditEvent[] = [];
  const broker = createBroker({ auditSink: { record: (e) => events.push(e) } });
  const tool = execTool();
  // Token authorizes a DIFFERENT sink than the one this tool declares.
  const { token, publicKey } = mintToken([{ kind: "sinks", classes: ["write:fs"] }]);

  const wrapped = wrapWithAdcGate(broker, tool, { rootPublicKey: publicKey, getToken: () => token });

  await assert.rejects(() => wrapped.execute({ cmd: "rm -rf /" }), (err: unknown) => {
    assert.ok(err instanceof AdcGateError);
    assert.equal(err.code, "ADC_SINK");
    assert.equal(err.toolName, "shell_exec");
    return true;
  });

  assert.equal(tool.calls, 0, "the underlying tool must never execute on ADC denial");
  assert.equal(events.length, 0, "the broker's own gate/audit path must never run — ADC denial happens strictly before broker.call()");
});

test("missing token: denies with ADC_MALFORMED before the gate, tool never runs", async () => {
  const broker = createBroker();
  const tool = execTool();
  const { publicKey } = mintToken([]);

  const wrapped = wrapWithAdcGate(broker, tool, { rootPublicKey: publicKey, getToken: () => undefined });

  await assert.rejects(() => wrapped.execute({ cmd: "ls" }), (err: unknown) => {
    assert.ok(err instanceof AdcGateError);
    assert.equal(err.code, "ADC_MALFORMED");
    return true;
  });
  assert.equal(tool.calls, 0);
});

test("both ADC and the taint gate pass: the real tool executes and returns its real result", async () => {
  const broker = createBroker();
  const tool = execTool();
  const { token, publicKey } = mintToken([{ kind: "sinks", classes: ["exec:shell"] }]);

  const wrapped = wrapWithAdcGate(broker, tool, { rootPublicKey: publicKey, getToken: () => token });
  const result = await wrapped.execute({ cmd: "ls" });

  assert.deepEqual(result, { ran: true });
  assert.equal(tool.calls, 1);
});

test("regression: an EXFIL-class tool call (host fact derived + sink fact) with an ordinary sinks caveat is allowed, not wrongly denied", async () => {
  // End-to-end coverage for the critical cross-product bug found in review
  // (see verify.test.ts's own regression tests for the unit-level case):
  // an EXFIL tool call detects a host in its args, so BOTH factSets.sinks
  // and factSets.hosts are non-empty here — exactly the case the old
  // sink-only/host-only decomposition got wrong.
  const broker = createBroker();
  const tool = emailTool();
  const { token, publicKey } = mintToken([{ kind: "sinks", classes: ["net:email"] }]);
  const wrapped = wrapWithAdcGate(broker, tool, { rootPublicKey: publicKey, getToken: () => token });

  const result = await wrapped.execute({ to: "alice@example.com" });

  assert.deepEqual(result, { sent: true });
  assert.equal(tool.calls, 1);
});

test("ADC passes but the taint gate (real defaultPolicy) blocks: throws the BROKER's ToolCallBlockedError, not AdcGateError", async () => {
  const broker = createBroker();
  const source = sourceTool();
  const wrappedSource = broker.wrap(source);
  // Raise the scope watermark to RAW_UNTRUSTED via a real untrusted source
  // call — defaultPolicy's MATRIX unconditionally BLOCKs RAW_UNTRUSTED x
  // EXEC (policy/default-policy.ts), regardless of private-data exposure.
  await wrappedSource.execute({});
  assert.equal(broker.scope.watermark.level, "RAW_UNTRUSTED");

  const tool = execTool();
  // Broadly-scoped token: ADC verification alone would allow this call.
  const { token, publicKey } = mintToken([{ kind: "sinks", classes: ["exec:shell"] }]);
  const wrapped = wrapWithAdcGate(broker, tool, { rootPublicKey: publicKey, getToken: () => token });

  await assert.rejects(() => wrapped.execute({ cmd: "ls" }), (err: unknown) => {
    assert.ok(err instanceof ToolCallBlockedError);
    assert.ok(!(err instanceof AdcGateError), "must not be conflated with an ADC denial");
    return true;
  });
  assert.equal(tool.calls, 0, "a taint-gate BLOCK must still prevent execution");
});

test("AdcGateError and ToolCallBlockedError are never instances of one another (distinct reason-code identity, docs/PLAN.md Phase 5)", () => {
  const adcErr = new AdcGateError("t", "ADC_SCOPE", "denied");
  assert.ok(!(adcErr instanceof ToolCallBlockedError));
});

test("NONE-sinkClass tool: dispatched straight through with no ADC check at all, even with no token", async () => {
  const broker = createBroker();
  const source = sourceTool();
  const { publicKey } = mintToken([]);

  const wrapped = wrapWithAdcGate(broker, source, { rootPublicKey: publicKey, getToken: () => undefined });
  const result = await wrapped.execute({});

  assert.deepEqual(result, { text: "untrusted content from the wire" });
});

test("live taint level flows into the ADC check: a taint_max caveat below the current watermark denies", async () => {
  const broker = createBroker();
  const source = sourceTool();
  await broker.wrap(source).execute({}); // raises watermark to RAW_UNTRUSTED

  const tool = execTool();
  const { token, publicKey } = mintToken([
    { kind: "sinks", classes: ["exec:shell"] },
    { kind: "taint_max", level: "DERIVED" }, // ceiling below live RAW_UNTRUSTED
  ]);
  const wrapped = wrapWithAdcGate(broker, tool, { rootPublicKey: publicKey, getToken: () => token });

  await assert.rejects(() => wrapped.execute({ cmd: "ls" }), (err: unknown) => {
    assert.ok(err instanceof AdcGateError);
    assert.equal(err.code, "ADC_TAINT");
    return true;
  });
  assert.equal(tool.calls, 0);
});

test("registers the tool with the broker exactly once (via broker.wrap at wrap-time), not per call", async () => {
  const broker = createBroker();
  let wrapCalls = 0;
  const realWrap = broker.wrap.bind(broker);
  broker.wrap = ((executor) => {
    wrapCalls++;
    return realWrap(executor);
  }) as typeof broker.wrap;

  const tool = execTool();
  const { token, publicKey } = mintToken([{ kind: "sinks", classes: ["exec:shell"] }]);
  const wrapped = wrapWithAdcGate(broker, tool, { rootPublicKey: publicKey, getToken: () => token });
  assert.equal(wrapCalls, 1, "broker.wrap() must run at wrap time");

  await wrapped.execute({ cmd: "one" });
  await wrapped.execute({ cmd: "two" });

  assert.equal(wrapCalls, 1, "broker.wrap() must NOT run again per call");
  assert.equal(tool.calls, 2);
});
