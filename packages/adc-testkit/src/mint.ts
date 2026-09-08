import { mintRoot, attenuate, type ParsedToken } from "@adc/core";
import type { ChainSpec } from "./reference.js";

/**
 * Builds a real, signed @adc/core token from a ChainSpec, using the real
 * mintRoot()/attenuate() — the differential fuzzer compares the real
 * verify() on this actual wire-format token against reference.ts's
 * evaluator on the same ChainSpec, so the comparison covers the real
 * signing/encoding path too, not just an abstract semantics check.
 *
 * Returns one ParsedToken per hop (index i = the token at depth i), so
 * callers can check Claim 2 (monotone decrease) against the real verifier
 * across real chain prefixes, not just the reference evaluator's
 * materialized sets.
 */
export function mintChain(rootSecretKey: Uint8Array, spec: ChainSpec): ParsedToken[] {
  if (spec.hops.length === 0) {
    throw new RangeError("ChainSpec must have at least one hop (the root)");
  }
  const tokens: ParsedToken[] = [];
  let token = mintRoot(rootSecretKey, { caveats: spec.hops[0]!.caveats });
  tokens.push(token);
  for (let i = 1; i < spec.hops.length; i++) {
    token = attenuate(token, { caveats: spec.hops[i]!.caveats });
    tokens.push(token);
  }
  return tokens;
}
