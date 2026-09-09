# @adc/testkit

Reference evaluator, generators, and differential fuzzer for `@adc/core`.
Dev-only — not published, no runtime integration surface, exists purely to
back the soundness claims in [`docs/PLAN.md`](../../docs/PLAN.md) sections
3 and 4.

## What this tests

`@adc/core`'s `verify()` evaluates caveats by walking every block and
AND-ing every caveat instance's predicate against the supplied facts. That
composition is *claimed* (in `caveats.ts`'s own doc comments) to give the
right answer for cross-block narrowing and "minimum across blocks"
semantics — but a doc comment is not a proof, and a bug in that
implementation's understanding of its own semantics wouldn't be caught by
tests written from the same understanding.

So this package's `src/reference.ts` is a **second, independently-written
evaluator** of the same closed vocabulary — read from `docs/PLAN.md` 1.5's
spec text, not from reading `caveats.ts`'s source, using different code
shapes (materialized sets, early-continue loops) than that module's
predicate-and-short-circuit style. `test/differential.test.ts` mints real,
signed tokens with `@adc/core`'s real `mintRoot()`/`attenuate()`, verifies
them with the real `verify()`, and compares the result against
`reference.ts` on the same logical chain, for many random chains × many
random queries. Two independent implementations disagreeing is a much
stronger signal than one implementation failing its own tests.

## The universe

`src/universe.ts` defines the finite test universe the reference evaluator
materializes permitted sets over. Per `docs/PLAN.md` 3's suggestion —
"8 resources × 6 relations × 3 sinks × 4 hosts × 3 taint levels × a
discrete clock" — plus one **extension**: a 2-value `audience` axis, since
those six suggested axes don't touch the `aud` caveat kind at all. Leaving
a whole caveat kind outside the fuzzed universe would leave exactly the
kind of soundness gap this phase exists to close, so "suggested" is
treated as a floor here, not a ceiling. Total: 8×6×3×4×3×4×2 = 27,648
tuples.

Every axis is a small, hand-picked, closed set (not independently random
strings), and `src/generators.ts`'s caveat arbitraries draw from these
same constants — so generated caveats actually interact with generated
queries often enough to exercise real boundaries, rather than almost
always missing each other in a vast, disjoint random space.

## The published line

```
150 chains × 20 queries = 3,000 checks, 0 false grants, seed=20260101
```

(`test/differential.test.ts`, printed on every successful run.) Verdicts
are asymmetric, per `docs/PLAN.md` 3:

- **False grant** (verifier allows, reference denies) — always a hard
  failure. There is no exception list for this.
- **False deny** (verifier denies, reference allows) — also fails, unless
  the exact case is pre-approved in [`exceptions.json`](./exceptions.json)
  with a written reason. That file is empty as of writing — every case the
  fuzzer has found agrees.

Both kinds of disagreement throw inside the `fc.property` callback (not
accumulated and reported after the fact), so fast-check's shrinking finds
a minimal counterexample for either. Per `docs/PLAN.md` 3 ("every shrunk
counterexample is committed as a permanent regression test"), any case
that's ever found gets hand-copied into `test/regressions.test.ts` as an
explicit, hardcoded test after the underlying bug is fixed (or the
exception is deliberately accepted) — so it's checked on every run
regardless of seed, run count, or generator changes, not only when the
randomized search happens to rediscover it. Empty as of writing.

The run count (150×20) is sized so the full package test suite finishes
in well under a minute, dominated by real Ed25519 signing/verification
(each chain mints up to 9 real blocks; each query is a full real
`verify()` call) — not the largest number that would technically fit a CI
budget. Bump `CHAINS_PER_RUN`/`QUERIES_PER_CHAIN` in
`test/differential.test.ts` and re-run to publish a larger line.

## Claims covered

- **Claim 1 (attenuation soundness)** and its asymmetric-verdict
  methodology are exactly what `test/differential.test.ts` is.
- **Claim 2 (monotone decrease)** — authority at hop N+1 ⊆ authority at
  hop N — is checked two ways: directly against the reference evaluator's
  fully materialized permitted set at each hop (`test/reference-invariants.test.ts`,
  a genuine subset check over all 27,648 tuples, at every hop, of every
  fuzzed chain — kept to fewer runs since this is real work), and against
  the real verifier via single-query chain prefixes (`test/differential.test.ts`'s
  second test, cheap enough to run with more chains).
- **Claim 3 (non-removability)** — docs/PLAN.md 4 has the written
  argument (plus its documented residual: an intermediate delegator
  replaying their own earlier, broader token is not "stripping," and no
  signature scheme removes that — it's an expiry/revocation problem).
  `test/non-removability.test.ts` is the property-test half: no
  truncation of a real token's wire string to any prefix verifies, and no
  tampering with an earlier block's caveats (without that block's signing
  predecessor's secret) verifies — both across many randomly generated
  chain shapes, not just `@adc/core`'s own hand-picked hardening cases.
  These tests call `verify()` with no facts on chains carrying random
  caveats, so a *caveat-content* denial (e.g. `ADC_SCOPE`) on the
  pristine, untampered token is expected and not itself a signal; the
  sanity check that guards against a genuinely broken test is that the
  pristine token is never *structurally* denied (`ADC_MALFORMED`,
  `ADC_SIG_INVALID`, `ADC_PROOF_INVALID`).
- **Claim 4 (revocation liveness)** is Phase 7 — not yet implemented, out
  of scope here.

## Running

```
npm run build   # tsc (also builds @adc/core first if needed — see prebuild)
npm test        # node:test over dist/test/*.test.js, ~50-65s
```

## A note on independence

Node's test runner (`node --test dist/test/*.test.js`) gives each matched
file its own isolated module graph — importing one `*.test.js` file from
another re-evaluates its top-level code, including every top-level
`test(...)` registration, in the importer's graph too. Shared constants
used across test files (e.g. the fuzz seed) live in
`test/fuzz-config.ts`, which is deliberately not named `*.test.ts`, so
importing it doesn't silently re-run another file's fuzzer.
