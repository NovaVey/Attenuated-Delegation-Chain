import { findOutboundHosts, sinkClassOf, type SinkCapability, type TaintLevel as BrokerTaintLevel } from "taint-tracked-tool-broker";
import type { TaintLevel as AdcTaintLevel } from "@adc/core";
import { adcTaintLevel } from "./taint.js";

/** The shape of a tool declaration this package actually reads from —
 * structurally a `taint-tracked-tool-broker` `ToolExecutor`, but named and
 * scoped narrowly here so `deriveCallFacts` doesn't need the tool's
 * `execute`/`isSource`/etc. fields just to compute facts. */
export interface FactsSourceTool {
  readonly capabilities: { readonly capabilities: readonly SinkCapability[] };
  readonly destinationKeys?: readonly string[];
}

/**
 * The fact *variations* a single gated call could exercise, derived from
 * broker state (docs/PLAN.md Phase 5: "The adapter injects facts from
 * broker state: the sink class about to be hit, the destination host, the
 * live taint level, the current time").
 *
 * `@adc/core`'s `Facts` holds one `sink` and one `host` value at a time,
 * but a real tool can declare more than one `SinkCapability` and a real
 * call's arguments can reference more than one destination host —
 * `verifyCall` (verify.ts) is what turns this into "every variation must
 * independently pass"; this module only computes what those variations
 * are.
 */
export interface CallFactSets {
  /** Facts common to every variation: the live taint level and the
   * verification instant. Never includes `sink`/`host` — those vary. */
  readonly base: { readonly taintLevel: AdcTaintLevel; readonly now: number };
  /** Every `SinkCapability` the tool declares. Empty for a NONE-sinkClass
   * tool (never reached by `wrapWithAdcGate`, which skips ADC entirely for
   * those — see gate.ts — but kept honest here regardless). */
  readonly sinks: readonly SinkCapability[];
  /** Every destination hostname `findOutboundHosts` finds in `args`.
   * Always empty for a non-EXFIL tool: destination-host detection is only
   * meaningful for an EXFIL-class call, mirroring
   * `ToolExecutor.destinationKeys`'s own doc comment ("Only ever consulted
   * for an EXFIL-class tool") in taint-tracked-tool-broker. */
  readonly hosts: readonly string[];
}

/**
 * Computes `CallFactSets` for one gated call. Never itself decides
 * allow/deny — see verify.ts for that.
 *
 * Throws `taint-tracked-tool-broker`'s own `ArgsTooDeepError` if `args`
 * nests deeper than its fixed safety bound (via `findOutboundHosts`) — the
 * same fail-closed structural rejection the broker's own gate would apply
 * to this call regardless (errors.ts's `ArgsTooDeepError` doc comment:
 * "the call is BLOCKed and audited, never silently allowed through on a
 * partial/incomplete scan"); this just surfaces it slightly earlier, since
 * ADC verification runs before the broker's own gate does.
 */
export function deriveCallFacts(
  tool: FactsSourceTool,
  args: unknown,
  liveTaintLevel: BrokerTaintLevel,
  now: number = Math.floor(Date.now() / 1000),
): CallFactSets {
  const sinkClass = sinkClassOf(tool.capabilities.capabilities);
  const hosts = sinkClass === "EXFIL" ? findOutboundHosts(args, { destinationKeys: tool.destinationKeys }) : [];
  return {
    base: { taintLevel: adcTaintLevel(liveTaintLevel), now },
    sinks: tool.capabilities.capabilities,
    hosts,
  };
}
