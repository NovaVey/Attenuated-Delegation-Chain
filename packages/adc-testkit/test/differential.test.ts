import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { generateKeypair, verify, encodeToken } from "@adc/core";
import { chainSpecArb, queryArb } from "../src/generators.js";
import { referenceAllows, type ChainSpec } from "../src/reference.js";
import { mintChain } from "../src/mint.js";
import { falseDenyKey, isKnownFalseDeny, loadExceptions } from "../src/exceptions.js";
import { CLOCK_SKEW_SECONDS, type Tuple } from "../src/universe.js";
import { FUZZ_SEED } from "./fuzz-config.js";

/**
 * The differential fuzzer — docs/PLAN.md 3. Compares @adc/core's real
 * verify() (on a real, signed token built by mintChain()) against
 * reference.ts's independently-written evaluator (on the same abstract
 * ChainSpec), for many random chains × many random queries per chain.
 *
 * Verdicts are asymmetric (1.5/3):
 *   - FALSE GRANT (verifier allows, reference denies): always a hard
 *     failure. There is no exception list for this — it would mean the
 *     real verifier is granting authority the closed vocabulary's own
 *     semantics say it shouldn't.
 *   - FALSE DENY (verifier denies, reference allows): also fails, UNLESS
 *     the exact case is pre-approved in exceptions.json with a written
 *     reason (none are, as of writing — see that file).
 *
 * Both cases throw inside the fc.property callback (not accumulated and
 * reported after the fact), so fast-check's automatic shrinking finds a
 * minimal counterexample for either kind of disagreement. Per 3, any
 * shrunk counterexample that this test's evolution needs to remember gets
 * copied into test/regressions.test.ts as a permanent, hardcoded case.
 */

// Ed25519 signing/verification dominates cost here (each chain does up to
// 9 real mint/attenuate signs, each query a full real verify()), so these
// are sized for CI to stay in the tens of seconds rather than minutes,
// not for the largest number that would technically fit in a CI budget.
// Bump them (and re-run once) if this package's own README needs a
// larger published line for some reason.
const CHAINS_PER_RUN = 150;
const QUERIES_PER_CHAIN = 20;

function checkOneCase(
  rootPublicKey: Uint8Array,
  wire: string,
  spec: ChainSpec,
  query: Tuple,
  exceptions: ReturnType<typeof loadExceptions>,
): void {
  const verifierResult = verify(wire, rootPublicKey, query, { clockSkewSeconds: CLOCK_SKEW_SECONDS });
  const referenceResult = referenceAllows(spec, query, CLOCK_SKEW_SECONDS);

  if (verifierResult.ok && !referenceResult) {
    assert.fail(
      "FALSE GRANT: verify() allowed a query the reference evaluator denies.\n" +
        `spec=${JSON.stringify(spec)}\n` +
        `query=${JSON.stringify(query)}\n` +
        `verifierResult=${JSON.stringify(verifierResult)}`,
    );
  }

  if (!verifierResult.ok && referenceResult) {
    const key = falseDenyKey(spec, query, CLOCK_SKEW_SECONDS);
    if (!isKnownFalseDeny(key, exceptions)) {
      assert.fail(
        `UNEXPECTED FALSE DENY (key ${key}): verify() denied a query the reference evaluator allows, and this case is not in exceptions.json.\n` +
          `spec=${JSON.stringify(spec)}\n` +
          `query=${JSON.stringify(query)}\n` +
          `verifierResult=${JSON.stringify(verifierResult)}\n` +
          `If this is a genuine, unavoidable case, add {"key": "${key}", "reason": "<why>"} to exceptions.json. If it's a bug, fix it instead.`,
      );
    }
  }
}

test(`differential: ${CHAINS_PER_RUN} chains × ${QUERIES_PER_CHAIN} queries, 0 false grants, seed=${FUZZ_SEED}`, () => {
  const { secretKey: rootSecretKey, publicKey: rootPublicKey } = generateKeypair();
  const exceptions = loadExceptions();
  let checked = 0;

  fc.assert(
    fc.property(chainSpecArb, fc.array(queryArb, { minLength: QUERIES_PER_CHAIN, maxLength: QUERIES_PER_CHAIN }), (spec, queries) => {
      const tokens = mintChain(rootSecretKey, spec);
      const wire = encodeToken(tokens[tokens.length - 1]!);
      for (const query of queries) {
        checked++;
        checkOneCase(rootPublicKey, wire, spec, query, exceptions);
      }
    }),
    { numRuns: CHAINS_PER_RUN, seed: FUZZ_SEED },
  );

  // Only reached if fc.assert completed all CHAINS_PER_RUN runs without
  // any case (false grant, or false deny outside exceptions.json) making
  // checkOneCase throw.
  console.log(
    `differential fuzz: ${CHAINS_PER_RUN} chains × ${QUERIES_PER_CHAIN} queries = ${checked} checks, 0 false grants, seed=${FUZZ_SEED}`,
  );
  assert.equal(checked, CHAINS_PER_RUN * QUERIES_PER_CHAIN);
});

test("Claim 2 (monotone decrease) on the real verifier: once a query is denied at some depth, it stays denied at every deeper hop of the same chain", () => {
  fc.assert(
    fc.property(chainSpecArb, queryArb, (spec, query) => {
      const { secretKey: rootSecretKey, publicKey: rootPublicKey } = generateKeypair();
      const tokens = mintChain(rootSecretKey, spec);

      let deniedFromHereOn = false;
      for (const token of tokens) {
        const result = verify(encodeToken(token), rootPublicKey, query, { clockSkewSeconds: CLOCK_SKEW_SECONDS });
        if (deniedFromHereOn) {
          assert.equal(
            result.ok,
            false,
            `monotone decrease violated: query was denied at an earlier hop but allowed at a later one.\nspec=${JSON.stringify(spec)}\nquery=${JSON.stringify(query)}`,
          );
        }
        if (!result.ok) deniedFromHereOn = true;
      }
    }),
    { numRuns: 150, seed: FUZZ_SEED },
  );
});
