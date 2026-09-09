import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { chainSpecArb } from "../src/generators.js";
import { permittedSetAtHop, depthOf } from "../src/reference.js";
import { CLOCK_SKEW_SECONDS } from "../src/universe.js";
import { FUZZ_SEED } from "./fuzz-config.js";

/**
 * Claim 2 (monotone decrease), checked directly against the reference
 * evaluator's fully materialized permitted set at each hop — "the
 * reference evaluator ... has to materialize the permitted set at each
 * hop and intersect" (docs/PLAN.md 1.5) — rather than via scattered
 * single-query comparisons. This is the more expensive, more direct
 * check; differential.test.ts's monotone-decrease test covers the same
 * claim on the real verifier via single-query prefixes, which is cheap
 * enough to run with more chains. Kept to a modest chain count here since
 * materializing all ~27,648 universe tuples at every hop of every chain
 * is real work.
 */
test("Claim 2 (monotone decrease): the reference evaluator's materialized permitted set only shrinks as depth increases", () => {
  fc.assert(
    fc.property(chainSpecArb, (spec) => {
      const depth = depthOf(spec);
      let previous = permittedSetAtHop(spec, 0, CLOCK_SKEW_SECONDS);
      for (let hop = 1; hop <= depth; hop++) {
        const current = permittedSetAtHop(spec, hop, CLOCK_SKEW_SECONDS);
        for (const key of current) {
          assert.ok(
            previous.has(key),
            `monotone decrease violated: tuple ${key} is permitted at hop ${hop} but was not permitted at hop ${hop - 1}.\nspec=${JSON.stringify(spec)}`,
          );
        }
        previous = current;
      }
    }),
    { numRuns: 25, seed: FUZZ_SEED },
  );
});
