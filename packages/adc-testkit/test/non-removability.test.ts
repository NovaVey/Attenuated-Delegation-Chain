import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
  generateKeypair,
  verify,
  encodeToken,
  decodeBlock,
  encodeBlock,
  type ParsedToken,
  type VerifyResult,
} from "@adc/core";
import { chainSpecArb } from "../src/generators.js";
import { mintChain } from "../src/mint.js";
import { FUZZ_SEED } from "./fuzz-config.js";

/**
 * These tests call verify() with no facts, on chains carrying randomly
 * generated caveats — so a fuzzed chain legitimately denying with a
 * caveat-content code (ADC_SCOPE, ADC_SINK, ...) is expected, not a bug
 * (e.g. an empty `sinks.classes` array permits no sink at all). What
 * "sanity: the token isn't already broken before we tamper with it"
 * actually needs to rule out is a *structural* denial — proof this
 * package minted something malformed. Never true for a real, freshly
 * minted, untampered token; asserted here rather than assumed.
 */
// ADC_DEPTH_EXCEEDED is deliberately excluded: it can come from a
// caveat-content max_depth restriction as legitimately as from the
// structural opts.maxDepth cap, and these tests call verify() with no
// opts (default maxDepth=32, well above chainSpecArb's max depth of 8),
// so it can never be the structural cap firing here anyway.
const STRUCTURAL_CODES = new Set(["ADC_MALFORMED", "ADC_SIG_INVALID", "ADC_PROOF_INVALID"]);

function assertStructurallySound(result: VerifyResult, message: string): void {
  if (!result.ok) {
    assert.ok(!STRUCTURAL_CODES.has(result.code), `${message} (got structural denial ${result.code}: ${result.reason})`);
  }
}

/**
 * Claim 3 (non-removability) — docs/PLAN.md section 4's precise
 * statement: "No holder can strip a caveat added at or before their own
 * hop, and no downstream holder can truncate the chain to any prefix,
 * because either operation requires a secret key that appears in no
 * token that holder ever received." Section 4 has the written argument
 * (and its documented residual — replaying an earlier, broader token is
 * not "stripping," it's a separate expiry/revocation concern). This file
 * is the property-test half of that claim: adc-core/test/roundtrip.test.ts
 * and hardening.test.ts already prove it for hand-picked chains; these
 * tests prove it holds across many randomly generated chain shapes.
 */

test("no truncation of a real token's wire string to any strict prefix verifies, across randomly generated chains", () => {
  fc.assert(
    fc.property(chainSpecArb, (spec) => {
      const { secretKey: rootSecretKey, publicKey: rootPublicKey } = generateKeypair();
      const tokens = mintChain(rootSecretKey, spec);
      const wire = encodeToken(tokens[tokens.length - 1]!);

      assertStructurallySound(verify(wire, rootPublicKey), "sanity: the pristine, untampered full token must not be structurally denied");

      // Every strict prefix of the wire string must fail. Full exhaustion
      // (every byte length, as adc-core's own hardening test does) would
      // multiply badly with fc's own run count here, so sample instead:
      // the empty string, one byte in, one byte short, and the midpoint.
      const lengthsToTry = new Set([0, 1, wire.length - 1, Math.floor(wire.length / 2)]);
      for (const len of lengthsToTry) {
        if (len < 0 || len >= wire.length) continue;
        const prefix = wire.slice(0, len);
        let result;
        try {
          result = verify(prefix, rootPublicKey);
        } catch (err) {
          assert.fail(`verify() threw on a truncated token (len ${len}): ${(err as Error).message}`);
        }
        assert.equal(result.ok, false, `prefix of length ${len} (of ${wire.length}) should not verify`);
      }
    }),
    { numRuns: 100, seed: FUZZ_SEED },
  );
});

test("no tampering with an earlier block's caveats (without that block's signing predecessor's secret) verifies, across randomly generated chains", () => {
  fc.assert(
    fc.property(chainSpecArb, fc.nat(), (spec, pick) => {
      const depth = spec.hops.length - 1;
      if (depth < 1) return; // need at least one "earlier" block to tamper with

      const { secretKey: rootSecretKey, publicKey: rootPublicKey } = generateKeypair();
      const tokens = mintChain(rootSecretKey, spec);
      const finalToken = tokens[tokens.length - 1]!;
      assertStructurallySound(
        verify(encodeToken(finalToken), rootPublicKey),
        "sanity: the pristine, untampered full token must not be structurally denied",
      );

      const targetIndex = pick % depth; // any block strictly before the last

      const original = decodeBlock(finalToken.blocks[targetIndex]!);
      // Guaranteed to differ from the original bytes regardless of what
      // that block originally carried — the specific mutation doesn't
      // matter, only that block content changed without re-signing.
      const tamperedBytes = encodeBlock({
        alg: original.alg,
        nextPublicKey: original.nextPublicKey,
        caveats: [...original.caveats, { kind: "aud", verifier: "tampered-by-test" }],
      });
      assert.notDeepEqual(tamperedBytes, finalToken.blocks[targetIndex], "sanity: tampering must actually change the block bytes");

      const tampered: ParsedToken = {
        version: finalToken.version,
        blocks: finalToken.blocks.map((b, i) => (i === targetIndex ? tamperedBytes : b)),
        sigs: finalToken.sigs,
        proof: finalToken.proof,
      };

      const result = verify(encodeToken(tampered), rootPublicKey);
      assert.equal(result.ok, false, `tampering with block ${targetIndex} (of depth ${depth}) should invalidate the token`);
    }),
    { numRuns: 100, seed: FUZZ_SEED },
  );
});
