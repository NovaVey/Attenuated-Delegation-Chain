/**
 * @adc/revocation — signed revocation-list format, signing (for a mint
 * service holding the root key), verification, and a polling client (for
 * a verifier). See docs/PLAN.md Phase 7.
 *
 * `@adc/core`'s own `verify()` performs the actual, offline revocation
 * CHECK against a caller-supplied `Set<string>` (its `revokedHashes`
 * option) — this package is what keeps that set current: fetching,
 * authenticating (via the same root key that mints tokens), and caching
 * a list built and signed by whoever holds the root key (see
 * `services/mint`'s own `/revoke` and `/revocations` routes for the
 * reference signing/serving side).
 */

export {
  buildRevocationList,
  REVOCATION_LIST_VERSION,
  DEFAULT_TTL_SECONDS,
  DEFAULT_POLL_INTERVAL_MS,
  DEFAULT_CLOCK_SKEW_SECONDS,
} from "./list.js";
export type { RevocationListPayload } from "./list.js";

export { signRevocationList, revocationSignInput } from "./sign.js";
export type { SignedRevocationList } from "./sign.js";

export { verifySignedRevocationList } from "./verify.js";
export type { VerifyListResult, VerifyListReasonCode, VerifyListOptions } from "./verify.js";

export { createRevocationClient } from "./client.js";
export type { RevocationClient, RevocationClientOptions } from "./client.js";
