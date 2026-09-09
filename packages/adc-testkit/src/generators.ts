import fc from "fast-check";
import type { Caveat, TaintLevel } from "@adc/core";
import {
  AUDIENCES,
  CLOCK_VALUE_MAX,
  CLOCK_VALUE_MIN,
  HOSTS,
  RELATIONS,
  RESOURCES,
  SINKS,
  TAINT_UNIVERSE,
  type Tuple,
} from "./universe.js";
import type { ChainSpec } from "./reference.js";

/**
 * fast-check arbitraries, all grounded in universe.ts's constants (not
 * independently random strings) so generated caveats actually interact
 * with generated queries often enough to exercise real boundaries, rather
 * than almost always missing each other in a vast, disjoint random space.
 * Every produced Caveat is structurally valid per @adc/core's parseCaveat
 * — the fuzzer is testing caveat SEMANTICS, not caveat rejection — so
 * mintRoot()/attenuate() never throw on generated input.
 */

// Drawn as a PAIR, not resourceKind and resourceId independently: universe.ts's
// allTuples() only ever iterates the exact (kind, id) pairs listed in
// RESOURCES, so a query or scope triple generated with resourceKind and
// resourceId chosen independently could land on a combination (e.g.
// kind="doc", id="3", which RESOURCES never lists) that the materialized
// universe (reference-invariants.test.ts's monotone-decrease check) never
// exercises — a silent coverage gap between what gets fuzzed and what the
// universe actually covers. Pairing keeps every generated resource
// reference inside the same finite universe allTuples() iterates.
const resourcePairArb = fc.constantFrom(...RESOURCES);
const relationArb = fc.constantFrom(...RELATIONS);

const scopeTripleArb = fc
  .tuple(resourcePairArb, fc.boolean(), relationArb)
  .map(
    ([[resourceKind, resourceId], wildcardId, relation]) =>
      [resourceKind, wildcardId ? "*" : resourceId, relation] as const,
  );

const scopeCaveatArb: fc.Arbitrary<Caveat> = fc
  .array(scopeTripleArb, { minLength: 0, maxLength: 4 })
  .map((triples) => ({ kind: "scope", triples }) as Caveat);

const sinksCaveatArb: fc.Arbitrary<Caveat> = fc
  .subarray([...SINKS], { minLength: 0, maxLength: SINKS.length })
  .map((classes) => ({ kind: "sinks", classes }) as Caveat);

const taintMaxCaveatArb: fc.Arbitrary<Caveat> = fc
  .constantFrom(...TAINT_UNIVERSE)
  .map((level: TaintLevel) => ({ kind: "taint_max", level }) as Caveat);

const expiresCaveatArb: fc.Arbitrary<Caveat> = fc
  .integer({ min: CLOCK_VALUE_MIN, max: CLOCK_VALUE_MAX })
  .map((at) => ({ kind: "expires", at }) as Caveat);

// Depth caveats range a bit past the max chain depth generators.ts
// produces (see chainSpecArb below) so some fuzzed max_depth caveats are
// the binding constraint and some are slack, in both directions.
const maxDepthCaveatArb: fc.Arbitrary<Caveat> = fc
  .integer({ min: 0, max: 12 })
  .map((depth) => ({ kind: "max_depth", depth }) as Caveat);

const hostsCaveatArb: fc.Arbitrary<Caveat> = fc
  .subarray([...HOSTS], { minLength: 0, maxLength: HOSTS.length })
  .map((hostnames) => ({ kind: "hosts", hostnames }) as Caveat);

const audCaveatArb: fc.Arbitrary<Caveat> = fc
  .constantFrom(...AUDIENCES)
  .map((verifier) => ({ kind: "aud", verifier }) as Caveat);

export const caveatArb: fc.Arbitrary<Caveat> = fc.oneof(
  scopeCaveatArb,
  sinksCaveatArb,
  taintMaxCaveatArb,
  expiresCaveatArb,
  maxDepthCaveatArb,
  hostsCaveatArb,
  audCaveatArb,
);

const hopArb = fc.record({
  caveats: fc.array(caveatArb, { minLength: 0, maxLength: 3 }),
});

/** Chains of depth 0 through 8 — docs/PLAN.md 3's "random attenuation
 * chains to depth 8" (hops.length = depth + 1, so 1 to 9 hops). */
export const chainSpecArb: fc.Arbitrary<ChainSpec> = fc
  .array(hopArb, { minLength: 1, maxLength: 9 })
  .map((hops) => ({ hops }));

export const queryArb: fc.Arbitrary<Tuple> = fc
  .tuple(
    resourcePairArb, // a query never asks about '*' — that's only meaningful in a caveat's own triples
    relationArb,
    fc.constantFrom(...SINKS),
    fc.constantFrom(...HOSTS),
    fc.constantFrom(...TAINT_UNIVERSE),
    fc.integer({ min: CLOCK_VALUE_MIN, max: CLOCK_VALUE_MAX }),
    fc.constantFrom(...AUDIENCES),
  )
  .map(([[resourceKind, resourceId], relation, sink, host, taintLevel, now, audience]) => ({
    resourceKind,
    resourceId,
    relation,
    sink,
    host,
    taintLevel,
    now,
    audience,
  }));
