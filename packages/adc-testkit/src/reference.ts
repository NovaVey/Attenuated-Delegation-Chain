import type { Caveat, TaintLevel } from "@adc/core";
import { allTuples, tupleKey, TAINT_UNIVERSE, type Tuple } from "./universe.js";

/**
 * An independently-written reference evaluator for the caveat vocabulary
 * (docs/PLAN.md 1.5), used to differentially fuzz-test @adc/core's real
 * verify() (test/differential.test.ts). Deliberately does NOT import or
 * call @adc/core's evaluateCaveat — reusing that would make every
 * "comparison" tautological. This module was written from the spec text,
 * not from reading caveats.ts's implementation, and uses different
 * control-flow shapes (materialized sets, early-continue loops) than that
 * module's predicate-and-short-circuit style on purpose: two independent
 * mistakes are less likely to be the *same* mistake than one mistake
 * tested against its own assumptions.
 *
 * A ChainSpec is this package's own abstract chain representation — a
 * list of hops, each carrying the caveats added at that hop (hop 0 =
 * root/block 0). generators.ts produces these; mint.ts turns one into a
 * real, signed @adc/core token via the real mintRoot()/attenuate() so the
 * differential test exercises the real wire format too, not just this
 * evaluator's idea of the semantics.
 */
export interface ChainSpec {
  readonly hops: readonly { readonly caveats: readonly Caveat[] }[];
}

export function depthOf(spec: ChainSpec): number {
  return spec.hops.length - 1;
}

const TAINT_RANK: Record<TaintLevel, number> = Object.fromEntries(
  TAINT_UNIVERSE.map((level, i) => [level, i]),
) as Record<TaintLevel, number>;

/** Whether ONE caveat, in isolation, permits one tuple at one depth. */
function caveatPermits(caveat: Caveat, tuple: Tuple, depth: number, clockSkewSeconds: number): boolean {
  switch (caveat.kind) {
    case "scope": {
      for (const [resourceKind, resourceId, relation] of caveat.triples) {
        if (relation !== tuple.relation) continue;
        if (resourceKind !== tuple.resourceKind) continue;
        if (resourceId === "*" || resourceId === tuple.resourceId) return true;
      }
      return false;
    }

    case "sinks": {
      const permittedSinks = new Set(caveat.classes);
      return permittedSinks.has(tuple.sink);
    }

    case "taint_max": {
      // Materialize the permitted taint-level SET (every level ranked at
      // or below the ceiling), then test membership — rather than
      // comparing ranks directly — to keep this a genuinely different
      // code path from caveats.ts's index comparison.
      const ceilingRank = TAINT_RANK[caveat.level];
      const permittedLevels = new Set(TAINT_UNIVERSE.filter((level) => TAINT_RANK[level] <= ceilingRank));
      return permittedLevels.has(tuple.taintLevel);
    }

    case "expires": {
      const validUntil = caveat.at + clockSkewSeconds;
      return tuple.now <= validUntil;
    }

    case "max_depth":
      return depth <= caveat.depth;

    case "hosts": {
      const permittedHosts = new Set(caveat.hostnames.map((h) => h.toLowerCase()));
      return permittedHosts.has(tuple.host.toLowerCase());
    }

    case "aud":
      return caveat.verifier === tuple.audience;
  }
}

function allCaveatsThrough(spec: ChainSpec, hopIndex: number): Caveat[] {
  const caveats: Caveat[] = [];
  for (let i = 0; i <= hopIndex; i++) {
    for (const c of spec.hops[i]!.caveats) caveats.push(c);
  }
  return caveats;
}

/**
 * Whether the chain (through `hopIndex`, i.e. depth = hopIndex) permits
 * one query tuple: every caveat added at or before this hop must permit
 * it (docs/PLAN.md 1.6 step 5 — no special-cased cross-block
 * aggregation, same AND-across-every-instance composition as
 * caveats.ts's evaluateCaveat, arrived at independently from the same
 * spec text).
 */
export function referenceAllowsAtHop(
  spec: ChainSpec,
  hopIndex: number,
  query: Tuple,
  clockSkewSeconds: number,
): boolean {
  const depth = hopIndex;
  for (const caveat of allCaveatsThrough(spec, hopIndex)) {
    if (!caveatPermits(caveat, query, depth, clockSkewSeconds)) return false;
  }
  return true;
}

export function referenceAllows(spec: ChainSpec, query: Tuple, clockSkewSeconds: number): boolean {
  return referenceAllowsAtHop(spec, depthOf(spec), query, clockSkewSeconds);
}

/**
 * Materializes the FULL permitted tuple set at a given hop by testing
 * every tuple in the finite universe — "the reference evaluator ... has
 * to materialize the permitted set at each hop and intersect" (1.5).
 * Used to check Claim 2 (monotone decrease) directly as a subset
 * relation between consecutive hops' materialized sets, not just via
 * scattered single-query comparisons.
 */
export function permittedSetAtHop(spec: ChainSpec, hopIndex: number, clockSkewSeconds: number): Set<string> {
  const permitted = new Set<string>();
  for (const tuple of allTuples()) {
    if (referenceAllowsAtHop(spec, hopIndex, tuple, clockSkewSeconds)) {
      permitted.add(tupleKey(tuple));
    }
  }
  return permitted;
}
