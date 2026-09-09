import { verify as coreVerify, type Facts, type VerifyOptions, type VerifyResult } from "@adc/core";
import type { CallFactSets } from "./facts.js";

/**
 * Verifies `token` against every fact variation `factSets` describes,
 * requiring ALL of them to independently pass — fail-closed.
 *
 * Each ADC caveat kind only ever reads its own fact (`sinks` reads
 * `facts.sink`, `hosts` reads `facts.host`; see `@adc/core`'s
 * `evaluateCaveat`), so evaluating the token once per declared sink
 * capability and once per detected destination host, all sharing the same
 * `base` facts (taint level, time), is exactly equivalent to evaluating it
 * against the true, possibly multi-valued set of facts this call could
 * exercise — without needing `@adc/core`'s `Facts` type to support
 * multi-valued fields itself. `@adc/core` stays a single-fact-set API; the
 * multiplicity is entirely a broker-adapter concern, so it lives here, not
 * in `@adc/core`.
 *
 * When a tool declares no sink capabilities and no destination host was
 * detected (a call `wrapWithAdcGate` would only reach for a gated,
 * non-NONE-sinkClass tool, so this is `hosts` being empty for a
 * non-EXFIL tool, not `sinks` also being empty), the token is still
 * verified once against the bare `base` facts — a token with, say, only an
 * `expires`/`max_depth` caveat and no `sinks`/`hosts` caveat at all must
 * still be checked for those.
 *
 * Re-verifies the full Ed25519 signature chain on every variation in the
 * loop, denying (and stopping) at the first failure. That repeats work for
 * the (uncommon) multi-capability or multi-host call, but correctness — a
 * caveat that narrows one variation must not be missed because an earlier
 * variation already returned `ok: true` — matters far more than shaving a
 * handful of local Ed25519 verifications; there is no network round trip
 * here to amortize against.
 */
export function verifyCall(
  token: string | Uint8Array,
  rootPublicKey: Uint8Array,
  factSets: CallFactSets,
  opts?: VerifyOptions,
): VerifyResult {
  const variations: Facts[] = [
    ...factSets.sinks.map((sink): Facts => ({ ...factSets.base, sink })),
    ...factSets.hosts.map((host): Facts => ({ ...factSets.base, host })),
  ];
  if (variations.length === 0) {
    variations.push({ ...factSets.base });
  }

  let result: VerifyResult | undefined;
  for (const facts of variations) {
    result = coreVerify(token, rootPublicKey, facts, opts);
    if (!result.ok) return result;
  }
  // variations always has at least one entry (the `if` above), so a loop
  // that never hit the early return always assigns `result` at least once.
  return result!;
}
