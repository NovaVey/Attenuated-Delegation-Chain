import type { TaintLevel as BrokerTaintLevel } from "taint-tracked-tool-broker";
import type { TaintLevel as AdcTaintLevel } from "@adc/core";

/**
 * Maps the broker's live taint watermark onto ADC's own `taint_max` scale.
 *
 * The two libraries independently define a totally-ordered, 3-level trust
 * lattice with the same shape but different names:
 *
 *   taint-tracked-tool-broker:  CLEAN(0) < DERIVED_UNTRUSTED(1) < RAW_UNTRUSTED(2)
 *   @adc/core (docs/PLAN.md 1.5): TRUSTED(0) < DERIVED(1) < RAW_UNTRUSTED(2)
 *
 * This is a direct ordinal correspondence (see taint.test.ts's own
 * order-preservation check, which fails loudly if either library ever adds
 * or reorders a level), not a coincidence: docs/PLAN.md 1.5 says the
 * caveat vocabulary "imports its string space from RBA namespaces... Sink
 * classes import from the broker" — `taint_max` is the one caveat kind
 * whose levels are @adc/core's OWN closed enum rather than an imported
 * namespace (see `@adc/core`'s `TAINT_LEVELS` doc comment), precisely
 * because a token must remain verifiable even by a party that never links
 * against this broker's exact type — this map is what lets a broker
 * integrator use it anyway.
 */
const BROKER_TO_ADC_TAINT_LEVEL: Record<BrokerTaintLevel, AdcTaintLevel> = {
  CLEAN: "TRUSTED",
  DERIVED_UNTRUSTED: "DERIVED",
  RAW_UNTRUSTED: "RAW_UNTRUSTED",
};

export function adcTaintLevel(level: BrokerTaintLevel): AdcTaintLevel {
  const mapped = BROKER_TO_ADC_TAINT_LEVEL[level];
  if (mapped === undefined) {
    // Defensive only — TypeScript's Record already makes this unreachable
    // for any value that type-checks as BrokerTaintLevel. Guards against a
    // future taint-tracked-tool-broker major version adding a level this
    // map hasn't been updated for, which would otherwise silently produce
    // `undefined` as a taintLevel fact — @adc/core's evaluateCaveat treats
    // an undefined fact as "deny" for a taint_max caveat, but failing loud
    // here at the source is clearer than a caveat evaluator's generic
    // deny reason.
    throw new RangeError(`unrecognized broker taint level '${String(level)}' — @adc/broker's taint.ts needs updating`);
  }
  return mapped;
}
