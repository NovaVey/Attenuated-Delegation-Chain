/** Same shape `@adc/core`'s `blockSignatureHash()` always produces: sha256
 * hex, lowercase, 64 characters. Validated here (not imported from
 * `@adc/core`, which has no dependency on this package's own concerns) so
 * a caller building a list from arbitrary/untrusted strings fails loudly
 * on a malformed entry rather than silently shipping garbage into a
 * SIGNED list — signing a bad hash doesn't make it a valid one. */
const BLOCK_HASH_PATTERN = /^[0-9a-f]{64}$/;

export const REVOCATION_LIST_VERSION = "adc-crl1";

/** Matches docs/PLAN.md Phase 7's own worked example:
 * `liveness bound = list TTL + poll interval + clock skew = 60s + 30s +
 * 60s = 150s worst case`. */
export const DEFAULT_TTL_SECONDS = 60;
export const DEFAULT_POLL_INTERVAL_MS = 30_000;
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;

/**
 * The unsigned revocation list — sha256 hex block-signature hashes
 * (`@adc/core`'s `blockSignatureHash()`, the one canonical per-block
 * identity docs/PLAN.md's Phase 6 section defines and this phase reuses
 * verbatim), plus the freshness fields a verifier needs to decide whether
 * to still trust a cached copy.
 */
export interface RevocationListPayload {
  readonly v: typeof REVOCATION_LIST_VERSION;
  /** Unix seconds. When this specific list was signed — see sign.ts. */
  readonly issuedAt: number;
  /** Seconds. A verifier must not trust this list once
   * `now > issuedAt + ttlSeconds` (plus its own clock-skew allowance). */
  readonly ttlSeconds: number;
  /** Sorted, deduplicated. Sorted so two lists built from the same
   * logical revoked set always serialize identically — not load-bearing
   * for the signature (canonical JSON sorts object keys but not array
   * contents), just for a stable diff/log when comparing two fetches. */
  readonly revoked: readonly string[];
}

function isSafePositiveInt(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Builds an unsigned revocation-list payload from a set of block-signature
 * hashes. Deduplicates and sorts `revokedHashes`; validates every entry
 * looks like a real `blockSignatureHash()` output before it can ever reach
 * `sign.ts` — a typo'd or empty-string entry here would otherwise become a
 * permanently-signed, permanently-shippable piece of the trust anchor.
 */
export function buildRevocationList(
  revokedHashes: Iterable<string>,
  opts: { readonly issuedAt?: number; readonly ttlSeconds?: number } = {},
): RevocationListPayload {
  const issuedAt = opts.issuedAt ?? Math.floor(Date.now() / 1000);
  const ttlSeconds = opts.ttlSeconds ?? DEFAULT_TTL_SECONDS;

  if (!isSafePositiveInt(issuedAt)) {
    throw new RangeError(`issuedAt must be a non-negative safe integer (unix seconds), got ${issuedAt}`);
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new RangeError(`ttlSeconds must be a positive integer, got ${ttlSeconds}`);
  }

  const revoked = [...new Set(revokedHashes)].sort();
  for (const hash of revoked) {
    if (!BLOCK_HASH_PATTERN.test(hash)) {
      throw new RangeError(`revoked hash is not a valid blockSignatureHash() output (64-char lowercase hex sha256): ${JSON.stringify(hash)}`);
    }
  }

  return { v: REVOCATION_LIST_VERSION, issuedAt, ttlSeconds, revoked };
}
