import { test } from "node:test";
import assert from "node:assert/strict";
import { createBroker, type AuditEvent, type ToolExecutor } from "taint-tracked-tool-broker";
import { encodeToken, generateKeypair, mintRoot } from "@adc/core";
import { redactAdcTokens, createAdcAuditRedactor } from "../src/redact.js";

function mintToken(): string {
  const { secretKey } = generateKeypair();
  return encodeToken(mintRoot(secretKey, { caveats: [] }));
}

test("redacts a top-level string token", () => {
  const token = mintToken();
  assert.equal(redactAdcTokens(token), "[redacted:adc-token]");
});

test("redacts a token embedded inside a longer string (e.g. a Bearer header value)", () => {
  const token = mintToken();
  const redacted = redactAdcTokens(`Bearer ${token}`);
  assert.equal(redacted, "Bearer [redacted:adc-token]");
});

test("finds and redacts a token nested at any depth, under any key name", () => {
  const token = mintToken();
  const input = {
    foo: { bar: [{ whateverKeyName: token }, "unrelated"] as unknown[] },
    top: "fine",
  };
  const redacted = redactAdcTokens(input);
  const bar = redacted.foo.bar as [{ whateverKeyName: string }, string];
  assert.equal(bar[0].whateverKeyName, "[redacted:adc-token]");
  assert.equal(bar[1], "unrelated");
  assert.equal(redacted.top, "fine");
});

test("leaves ordinary strings, numbers, booleans, null untouched", () => {
  const input = { a: "just some text", b: 42, c: true, d: null, e: undefined };
  assert.deepEqual(redactAdcTokens(input), input);
});

test("regression: a Map's entries (keys and values) are walked and redacted, not silently erased into {}", () => {
  // Map/Set hold entries in an internal slot, not an own-enumerable
  // property — Object.entries() sees nothing, so the generic plain-object
  // branch used to silently flatten a Map into {}, destroying non-token
  // data sitting alongside a token in the same Map. The broker's default
  // cloneArgs is structuredClone, which preserves Map/Set intact, so a
  // real tool's args snapshot can legitimately carry one.
  const token = mintToken();
  const input = { headers: new Map<string, string>([["Authorization", `Bearer ${token}`], ["X-Trace", "abc123"]]) };
  const redacted = redactAdcTokens(input);
  assert.ok(redacted.headers instanceof Map, "must still be a Map, not flattened into a plain object");
  assert.equal(redacted.headers.get("Authorization"), "Bearer [redacted:adc-token]");
  assert.equal(redacted.headers.get("X-Trace"), "abc123", "non-token entries in the same Map must survive");
});

test("regression: a Map key that is itself a token is redacted too, not just values", () => {
  const token = mintToken();
  const input = new Map<string, string>([[token, "some value"]]);
  const redacted = redactAdcTokens(input);
  assert.equal(redacted.has(token), false);
  assert.equal(redacted.get("[redacted:adc-token]"), "some value");
});

test("regression: a Set's values are walked and redacted, not silently erased into {}", () => {
  const token = mintToken();
  const input = { tags: new Set([token, "unrelated"]) };
  const redacted = redactAdcTokens(input);
  assert.ok(redacted.tags instanceof Set);
  assert.deepEqual([...redacted.tags], ["[redacted:adc-token]", "unrelated"]);
});

test("a Date is passed through unchanged, not flattened into {} (it can never hold a string token anyway)", () => {
  const input = { at: new Date(1_700_000_000_000) };
  const redacted = redactAdcTokens(input);
  assert.ok(redacted.at instanceof Date);
  assert.equal(redacted.at.getTime(), 1_700_000_000_000);
});

test("guards against a circular object instead of hanging forever (structuredClone, the broker's default cloneArgs, supports circular refs)", () => {
  const token = mintToken();
  const circular: { self?: unknown; secret: string } = { secret: token };
  circular.self = circular;
  const redacted = redactAdcTokens(circular);
  assert.equal(redacted.secret, "[redacted:adc-token]");
  assert.equal(redacted.self, redacted, "the cycle itself is preserved, not infinitely unrolled");
});

test("regression: a token whose last base64url character is '-' is redacted in full, no stray trailing character left behind", () => {
  // Base64url's alphabet includes "-" and "_", which are NOT \w characters
  // in JS regex — a naive \b-bounded pattern fails to match right at a
  // trailing "-", leaving it outside the placeholder. Try every possible
  // trailing character deliberately, not just "-", so this doesn't rely on
  // hitting the unlucky case by chance.
  for (const lastChar of ["-", "_", "a", "9"]) {
    const fakeToken = `adc1.YWJj.ZGVm${lastChar}`;
    const input = `Bearer ${fakeToken} extra`;
    const redacted = redactAdcTokens(input);
    assert.equal(redacted, "Bearer [redacted:adc-token] extra", `failed for trailing char '${lastChar}'`);
  }
});

test("does not mistake an unrelated dotted string for a token", () => {
  const input = "adc1 is a great vitamin, adc1.notactuallyatoken stays as one segment";
  // A single 'adc1.<segment>' with only ONE dot-separated segment after the
  // tag doesn't match (a real token has at least two: block + sig) — the
  // regex requires `{2,}` repetitions of `.segment`.
  assert.equal(redactAdcTokens(input), input);
});

test("createAdcAuditRedactor: end-to-end through a real createBroker(), the token never reaches the audit sink", async () => {
  const token = mintToken();
  const events: AuditEvent[] = [];

  const broker = createBroker({
    auditSink: { record: (event) => events.push(event) },
    policy: () => ({ action: "ALLOW" }),
    redactAuditArgs: createAdcAuditRedactor(),
  });

  const tool: ToolExecutor<{ url: string; adcToken: string }, { ok: true }> = {
    name: "call_api",
    capabilities: { capabilities: ["net:api-call"] },
    async execute() {
      return { ok: true };
    },
  };

  const wrapped = broker.wrap(tool);
  await wrapped.execute({ url: "https://api.example.com", adcToken: token });

  assert.equal(events.length, 1);
  const recordedArgs = events[0]!.call.args as { url: string; adcToken: string };
  assert.equal(recordedArgs.url, "https://api.example.com", "non-token fields pass through unchanged");
  assert.equal(recordedArgs.adcToken, "[redacted:adc-token]");
  assert.ok(!JSON.stringify(events).includes(token), "the raw token string must not appear anywhere in the audited event");
});

test("createAdcAuditRedactor composes with a caller-supplied andThen, applied after token redaction", () => {
  const token = mintToken();
  const redactor = createAdcAuditRedactor((call) => ({ ...(call.args as object), extra: "andThen ran" }));
  const result = redactor(
    { id: "1", toolName: "t", sessionId: "s", args: { adcToken: token, keep: "me" } },
    // Minimal TaintContext stand-in — createAdcAuditRedactor never reads
    // taint itself, only passes it through to andThen.
    {} as never,
  ) as { adcToken: string; keep: string; extra: string };
  assert.equal(result.adcToken, "[redacted:adc-token]");
  assert.equal(result.keep, "me");
  assert.equal(result.extra, "andThen ran");
});
