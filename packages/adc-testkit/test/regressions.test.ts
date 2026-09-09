import { test } from "node:test";

/**
 * Permanent regression tests for shrunk counterexamples found by the
 * differential fuzzer (docs/PLAN.md 3: "Every shrunk counterexample is
 * committed as a permanent regression test"). When differential.test.ts,
 * reference-invariants.test.ts, or non-removability.test.ts fails with a
 * shrunk (spec, query) counterexample, after root-causing and fixing the
 * underlying bug, copy the minimal case here as an explicit, hardcoded
 * test — so it's checked on every run regardless of the fuzz seed, run
 * count, or generator changes, not only when the randomized search
 * happens to rediscover it.
 *
 * Empty as of writing: the initial differential fuzz run (500 chains ×
 * 20 queries), the monotone-decrease checks, and the non-removability
 * property tests all passed with zero false grants and zero unexpected
 * false denies. See packages/adc-testkit/README.md for the published
 * line and its seed.
 */
test("regressions placeholder (no counterexamples found yet)", () => {
  // Intentionally empty. Add a case here, don't delete this test, the
  // next time the fuzzer finds one.
});
