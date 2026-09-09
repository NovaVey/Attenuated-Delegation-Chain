/**
 * Shared fuzz configuration, factored out of differential.test.ts.
 *
 * Deliberately NOT named `*.test.ts`: this package's test script runs
 * `node --test dist/test/*.test.js`, and Node's test runner gives each
 * matched file its own isolated module graph — importing a `*.test.js`
 * file from another `*.test.js` file re-evaluates its top-level code
 * (including every top-level `test(...)` registration) in the importer's
 * graph too. Importing differential.test.js's FUZZ_SEED from here used
 * to silently re-run its 500-chain fuzzer an extra time per importer.
 */
export const FUZZ_SEED = 20260101;
