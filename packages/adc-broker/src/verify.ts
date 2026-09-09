import { verify as coreVerify, type Facts, type VerifyOptions, type VerifyResult } from "@adc/core";
import type { CallFactSets } from "./facts.js";

/**
 * Verifies `token` against every fact variation `factSets` describes,
 * requiring ALL of them to independently pass — fail-closed.
 *
 * **Every variation must carry BOTH `sink` and `host` together whenever
 * both axes are non-empty — a cross product, not two separate lists.**
 * It's true that each ADC caveat kind only ever reads its own fact
 * (`sinks` reads `facts.sink`, `hosts` reads `facts.host`; see
 * `@adc/core`'s `evaluateCaveat`), but `verify()` requires EVERY caveat in
 * the token to pass against EACH fact-set used, and `evaluateCaveat` fails
 * closed when its own required fact is simply absent — so a fact-set
 * carrying `host` but not `sink` would make a token's own `sinks` caveat
 * (if it has one) deny outright, regardless of whether that `host` is
 * actually permitted, and vice versa. A single-axis decomposition (fixed
 * in review before this shipped) denied almost every real EXFIL call for a
 * token with an ordinary `sinks` caveat, precisely because the host-only
 * variation always left `sink` undefined. The cross product avoids this:
 * every variation supplies every fact this call could actually have, so a
 * caveat that doesn't care about one axis simply doesn't notice it's
 * fixed at a particular value for that variation.
 *
 * Only collapses to a single axis (no cross product) when the OTHER axis
 * is empty — e.g. a non-EXFIL tool never has a `host` fact to cross with,
 * so its sink variations are checked alone; there is no missing-`host`
 * problem because there was never a `host` fact to have supplied. When
 * BOTH axes are empty (docs/PLAN.md 1.5's `expires`/`max_depth`-only
 * token, or a call with no sink at all — unreachable from
 * `wrapWithAdcGate`, which never ADC-checks a NONE-sinkClass tool, but
 * kept correct here regardless since this function is independently
 * exported/tested), the token is verified once against the bare `base`
 * facts.
 *
 * Re-verifies the full Ed25519 signature chain on every variation in the
 * loop, denying (and stopping) at the first failure. That repeats work for
 * the (uncommon) multi-capability or multi-host call — cross-product size
 * is `sinks.length * hosts.length` in the worst case — but correctness
 * matters far more than shaving a handful of local Ed25519 verifications;
 * there is no network round trip here to amortize against, and a real
 * tool declaring many capabilities or a call touching many hosts at once
 * is not the common case this needs to be fast for.
 */
export function verifyCall(
  token: string | Uint8Array,
  rootPublicKey: Uint8Array,
  factSets: CallFactSets,
  opts?: VerifyOptions,
): VerifyResult {
  const variations: Facts[] = [];
  if (factSets.sinks.length > 0 && factSets.hosts.length > 0) {
    for (const sink of factSets.sinks) {
      for (const host of factSets.hosts) {
        variations.push({ ...factSets.base, sink, host });
      }
    }
  } else if (factSets.sinks.length > 0) {
    for (const sink of factSets.sinks) {
      variations.push({ ...factSets.base, sink });
    }
  } else if (factSets.hosts.length > 0) {
    for (const host of factSets.hosts) {
      variations.push({ ...factSets.base, host });
    }
  } else {
    variations.push({ ...factSets.base });
  }

  let result: VerifyResult | undefined;
  for (const facts of variations) {
    result = coreVerify(token, rootPublicKey, facts, opts);
    if (!result.ok) return result;
  }
  // variations always has at least one entry (every branch above pushes
  // at least one), so a loop that never hit the early return always
  // assigns `result` at least once.
  return result!;
}
