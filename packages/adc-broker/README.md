# @adc/broker

The [Taint-Tracked-Tool-Broker](https://github.com/NovaVey/Taint-Tracked-Tool-Broker)
("TTTB") adapter — [`docs/PLAN.md`](../../docs/PLAN.md) Phase 5: "Verification
runs before the taint gate. Both must pass. Denial reason codes stay
distinct so 'no authority' is never confused with 'tainted.' The adapter
injects facts from broker state: the sink class about to be hit, the
destination host, the live taint level, the current time."

TTTB is a real, published library (`taint-tracked-tool-broker` on npm,
`^1.4.0` here — see [its README](https://github.com/NovaVey/Taint-Tracked-Tool-Broker#readme)),
not a service, so this package depends on it directly rather than hand-rolling
a client against a wire contract, unlike `services/mint`'s RBA integration.

## Why the adapter wraps the call site, not the tool

TTTB's own dispatch order (`broker.ts`) is:

```
call() → dispatch() → dispatchGated() → gateDecision() [taint gate] → (approval wait) → finalizeGated() → tool.execute()
```

The registered tool's `execute()` only ever runs *after* the taint gate has
already decided. TTTB exposes no middleware/hook registry and no seam that
runs before `gateDecision()` — the only pluggable pieces (`policy`,
`approvalChannel`, `redactAuditArgs`, ...) all run as part of, or after, the
gate. So "verification runs before the taint gate" cannot be satisfied by
wrapping the tool's own `execute()` and registering that with the broker —
by the time that runs, the gate has already decided.

`wrapWithAdcGate()` therefore sits one layer above `broker.call()`/
`broker.wrap()`'s own drop-in `execute()`: it verifies the ADC token first,
and only calls into the broker (and therefore the taint gate) if that
verification passes. A denial never reaches `broker.call()` at all — no
`AuditEvent` is produced for it, and the broker's own gate never runs.

```ts
import { createBroker } from "taint-tracked-tool-broker";
import { wrapWithAdcGate, createAdcAuditRedactor, AdcGateError } from "@adc/broker";

const broker = createBroker({
  auditSink: myAuditSink,
  redactAuditArgs: createAdcAuditRedactor(),
});

const shellExec = wrapWithAdcGate(broker, {
  name: "shell_exec",
  capabilities: { capabilities: ["exec:shell"] },
  async execute({ cmd }) { /* ... */ },
}, {
  rootPublicKey,
  getToken: () => currentSessionToken, // or read it out of args — see AdcGateOptions
});

await shellExec.execute({ cmd: "..." }); // ADC-denied → AdcGateError, broker never touches it
                                          // ADC-allowed, taint-gate-denied → ToolCallBlockedError
                                          // both pass → the real tool runs
```

## Fact derivation

| ADC fact | source | notes |
| --- | --- | --- |
| `sink` | `tool.capabilities.capabilities` | Verified once per declared `SinkCapability` — a tool declaring more than one must have ALL of them covered by any `sinks` caveat present, fail-closed. |
| `host` | TTTB's own `findOutboundHosts(args, { destinationKeys })` | Only computed for an `EXFIL`-class tool, mirroring `ToolExecutor.destinationKeys`'s own "only ever consulted for an EXFIL-class tool" convention. Verified once per detected hostname. |
| `taintLevel` | `broker.scope.watermark.level`, mapped via `adcTaintLevel()` | TTTB's `CLEAN`/`DERIVED_UNTRUSTED`/`RAW_UNTRUSTED` map onto `@adc/core`'s `TRUSTED`/`DERIVED`/`RAW_UNTRUSTED` — same 3-level ordering, different names (`taint.test.ts` asserts the ordering stays in sync). |
| `now` | wall clock (or an explicit override, for tests) | |

`resourceKind`/`resourceId`/`relation` (the `scope` caveat) and `audience`
(`aud`) are deliberately **not** derived here — `docs/PLAN.md` Phase 5 only
names sink/host/taint/time as broker-state facts, and TTTB has no generic
concept of "which RBA resource this call concerns." A tool that needs
`scope`/`aud` gating supplies those facts itself, directly against
`@adc/core`'s `verify()`.

A `sinks`/`hosts` caveat is checked against **every** declared capability /
detected host independently — not a merged or best-case fact — since
`@adc/core`'s `Facts` only holds one `sink`/`host` value at a time and each
caveat kind only reads its own fact. See `verify.ts`'s doc comment for why
this is exactly equivalent to evaluating the true, possibly multi-valued
fact set a call could exercise.

## NONE-sinkClass tools are never ADC-gated

A tool declaring no sink capabilities is, per TTTB's own `SinkClass` doc
comment, "not policy-gated at all" — there is no taint gate for ADC
verification to run before, and no honest sink/host fact a source-only call
could supply. `wrapWithAdcGate()` mirrors this exactly: such a tool is
dispatched straight through, even with no token presented. A `scope`-bounded
token limiting *which* content a source tool may fetch is a legitimate use
of ADC, but needs resource facts this generic, broker-state-only adapter
can't derive — see `gate.ts`'s doc comment for the worked-through reasoning.

## Redacting the token

TTTB ships zero default audit redaction (`redactAuditArgs` is a pure
integrator-supplied seam — see its own `docs/audit-redaction.md`). Per
`docs/PLAN.md` 1.2, an attenuable ADC token's proof field is live
signing-key material and "must never be logged, never land in an audit
sink, and never be treated as an opaque token id." `createAdcAuditRedactor()`
recursively scans `call.args` for anything shaped like an ADC token
(`adc1.<b64url>. ...`) and replaces it with a fixed placeholder — a
value-*shape* match, not a key-name one, so it catches a forwarded token
regardless of which argument key carries it. Compose it with an
integrator's own key-denylist/sinkClass-based pattern via its `andThen`
parameter.

## Known limitation: `taint_max` staleness across an approval wait

A `REQUIRE_APPROVAL` verdict from TTTB's own gate can wait on human
timescales before the underlying tool actually executes. TTTB's own gate
re-reads the watermark immediately before executing for exactly this reason
(`revalidateBeforeExecute()`); this adapter has no hook into that re-check,
since ADC verification runs as one atomic step strictly before
`broker.call()` is ever invoked, not inside it. A concurrent call that
raises the watermark during another call's approval wait will not
retroactively invalidate an ADC `taint_max` verdict already returned for
that waiting call. `sinks`/`hosts`/`expires` caveats are unaffected — their
facts don't depend on the watermark. See `gate.ts`'s doc comment.

## Testing strategy

No fake broker — every test in this package runs against the real,
published `taint-tracked-tool-broker`, including `gate.test.ts`'s
end-to-end assertions that an ADC denial produces zero `AuditEvent`s (the
broker's own gate never runs) and that a taint-gate denial throws TTTB's
own `ToolCallBlockedError`, never `AdcGateError` — the two error classes
are never `instanceof` one another.

- `test/taint.test.ts` — the taint-level mapping, plus an order-preservation
  property check that fails loudly if either library ever reorders/adds a
  level.
- `test/facts.test.ts` — fact derivation per sink class, `destinationKeys`
  narrowing, and that a non-EXFIL tool never triggers host detection even
  when its args happen to contain a URL-looking string.
- `test/verify.test.ts` — the multi-variation fail-closed verification
  logic, against real minted tokens.
- `test/gate.test.ts` — the end-to-end wrapper: verification-before-the-gate,
  missing-token handling, both-pass execution, ADC-pass/gate-deny, the
  distinct error classes, and NONE-sinkClass bypass.
- `test/redact.test.ts` — token redaction, including a real
  `createBroker({ redactAuditArgs: createAdcAuditRedactor() })` round trip
  asserting the raw token string never appears anywhere in a recorded
  `AuditEvent`.

## Running

```
npm run build   # builds @adc/core first if needed — see prebuild
npm test        # node:test over dist/test/*.test.js, no network required
```
