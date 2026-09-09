import { sinkClassOf, type ToolCallBroker, type ToolExecutor } from "taint-tracked-tool-broker";
import type { ReasonCode, VerifyOptions } from "@adc/core";
import { deriveCallFacts } from "./facts.js";
import { verifyCall } from "./verify.js";

export interface AdcGateOptions {
  readonly rootPublicKey: Uint8Array;
  /** Returns the ADC token to verify for this call, or `undefined` if none
   * was supplied. Receives the call's `args` so a deployment that forwards
   * the token as part of the tool's own arguments (e.g. a `net:api-call`
   * tool presenting delegated authority to an internal API downstream) can
   * read it from there; a deployment that instead binds one token to the
   * whole broker session can ignore `args` and close over a fixed value.
   * Either way, redact it before it reaches an audit sink — see redact.ts. */
  readonly getToken: (args: unknown) => string | Uint8Array | undefined;
  readonly verifyOptions?: VerifyOptions;
}

/**
 * Thrown when ADC verification denies a gated call, before the broker's
 * own taint gate ever runs (docs/PLAN.md Phase 5: "Verification runs
 * before the taint gate. Both must pass. Denial reason codes stay distinct
 * so 'no authority' is never confused with 'tainted.'"). Deliberately a
 * different class from taint-tracked-tool-broker's own
 * `ToolCallBlockedError` — an integrator's `catch` (or their own
 * `AuditSink`/logging) can `instanceof`-distinguish "this call had no ADC
 * authority" from "this call was blocked by the taint gate" without
 * inspecting a shared error shape's fields.
 */
export class AdcGateError extends Error {
  readonly code: ReasonCode;
  readonly toolName: string;

  constructor(toolName: string, code: ReasonCode, reason: string) {
    super(`ADC denied call to "${toolName}": ${reason} (${code})`);
    this.name = "AdcGateError";
    this.code = code;
    this.toolName = toolName;
  }
}

/**
 * Wraps `executor` so that, for a gated call, an ADC token is verified —
 * against facts derived from the broker's own live state: the tool's
 * declared sink capabilities, any destination host detected in `args`, the
 * current taint watermark, and the current time (facts.ts) — strictly
 * before the call ever reaches `broker.call()`/the taint gate.
 *
 * Registers `executor` with `broker` exactly once, at wrap time (via
 * `broker.wrap()`), not per call — the returned object is a drop-in
 * replacement for `executor` itself, matching `broker.wrap()`'s own
 * contract, so it can be handed to whatever code already calls
 * `broker.wrap(executor)` today with no other change.
 *
 * A NONE-sinkClass tool (no declared capabilities — a pure source/read
 * tool) is dispatched straight through with no ADC check at all: TTTB's
 * own `SinkClass` doc comment is explicit that "Empty ⇒ sinkClass NONE —
 * the tool is not policy-gated at all," so there is no taint gate for
 * verification to run "before," and no sink/host fact a source-only call
 * could honestly supply in the first place (a `scope`-caveated token
 * bounding *which* content a source tool may fetch is a real, valid use of
 * ADC, but it needs resourceKind/resourceId/relation facts this generic,
 * broker-state-only adapter has no way to derive — an integrator who wants
 * that gates the specific source tool's own `execute()` directly, calling
 * `@adc/core`'s `verify()` with the facts that tool's own request actually
 * names).
 *
 * **Known limitation: a `taint_max` caveat is checked against the
 * watermark at the START of this call, not the instant execution actually
 * happens.** `sinks`/`hosts` facts come from `args`, which the broker
 * snapshots before any wait, so they can't drift — but `taintLevel` is
 * read live from `broker.scope.watermark.level` before ever calling
 * `gated.execute()`, and a `REQUIRE_APPROVAL` verdict from the broker's
 * own gate can wait on human timescales before the underlying tool
 * actually runs. taint-tracked-tool-broker's own gate re-reads the
 * watermark immediately before executing for exactly this reason
 * (`revalidateBeforeExecute()`, broker.ts) — this adapter has no hook into
 * that re-check, since ADC verification runs as one atomic step strictly
 * before `broker.call()`/`gated.execute()` is ever invoked, not inside it.
 * A concurrent call that raises the watermark during another call's
 * approval wait will not retroactively invalidate an ADC `taint_max`
 * verdict already returned for that waiting call. `sinks`/`hosts`/`expires`
 * caveats are unaffected (their facts don't depend on the watermark).
 */
export function wrapWithAdcGate<T extends ToolExecutor>(broker: ToolCallBroker, executor: T, opts: AdcGateOptions): T {
  const gated = broker.wrap(executor);
  const sinkClass = sinkClassOf(executor.capabilities.capabilities);

  if (sinkClass === "NONE") {
    return gated;
  }

  // Widened to ToolExecutor (A=R=unknown) for the wrapper body: T's own
  // A/R may be narrower than unknown, and this function's job is to
  // interpose on execute()'s *value*, not to re-derive T's specific
  // argument/result types. Cast back to T at the return — the returned
  // object's shape (same fields as `gated`, execute replaced) is what
  // actually has to satisfy T, and it does.
  const gatedUntyped = gated as ToolExecutor;

  const wrapped: ToolExecutor = {
    ...gatedUntyped,
    execute: async (args: unknown) => {
      const token = opts.getToken(args);
      if (token === undefined) {
        // No REASON_CODE means "absent" specifically; ADC_MALFORMED is the
        // closest fit — "not a valid token," which an absent one certainly
        // isn't — and matches @adc/core's own verify() treatment of
        // unparseable input.
        throw new AdcGateError(executor.name, "ADC_MALFORMED", "no ADC token supplied for a gated call");
      }
      const liveTaintLevel = broker.scope.watermark.level;
      const facts = deriveCallFacts(executor, args, liveTaintLevel);
      const result = verifyCall(token, opts.rootPublicKey, facts, opts.verifyOptions);
      if (!result.ok) {
        throw new AdcGateError(executor.name, result.code, result.reason);
      }
      return gatedUntyped.execute(args);
    },
  };
  return wrapped as T;
}
