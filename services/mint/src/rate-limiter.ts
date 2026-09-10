/**
 * A tiny in-process token-bucket rate limiter — currently used to bound
 * `POST /mint` traffic at this service's own front door, independent of
 * (and in addition to) RBA's own per-API-key limits (`/scope`: 20 req/min,
 * `/check`: 200 req/min — see services/mint/README.md's "Why HTTP, not an
 * imported library" section). RBA's limits protect RBA; this protects
 * this service (and, transitively, RBA) from a runaway or malicious
 * client hammering `POST /mint` before a single RBA call is ever made.
 *
 * `POST /mint` has no caller identity of its own (see README's Known
 * limitations — this is intentional, matching docs/PLAN.md's Phase 4
 * scope), so this is a single, service-wide bucket, not a per-caller one.
 *
 * Token bucket, not a fixed window: a fixed window resets sharply at its
 * boundary, allowing up to 2x the intended rate in a short burst
 * straddling two windows. A token bucket refills continuously, so the
 * allowed rate is smooth over any window, not just aligned ones.
 */

export interface RateLimiterOptions {
  /** Maximum requests allowed per `windowMs`, and the bucket's capacity
   * (a full bucket allows a burst of this many requests instantly). */
  readonly limit: number;
  /** Milliseconds per `limit` requests' worth of refill. */
  readonly windowMs: number;
  /** Injectable for deterministic tests of refill-over-time behavior,
   * matching this codebase's other injectable-clock conventions
   * (@adc/core's Facts.now, @adc/revocation's RevocationClientOptions.now).
   * Defaults to the real wall clock (Date.now()). */
  readonly now?: () => number;
}

export interface RateLimiter {
  /** Attempts to consume one unit of capacity. Returns true (and consumes
   * it) if capacity was available, false (consuming nothing) otherwise.
   * Never throws, never blocks. */
  tryAcquire(): boolean;
}

export function createTokenBucketRateLimiter(opts: RateLimiterOptions): RateLimiter {
  // Not just "> 0": a bucket capacity below 1 can never actually reach the
  // >= 1 threshold tryAcquire() requires to grant a request (its own cap
  // is below the amount it needs to hand out), so it would silently deny
  // every single request forever — found by adversarial review, reachable
  // in practice via a misconfigured MINT_RATE_LIMIT_PER_MINUTE (config.ts
  // now rejects a non-integer there too, for the same reason).
  if (!Number.isFinite(opts.limit) || opts.limit < 1) {
    throw new RangeError(`createTokenBucketRateLimiter: limit must be at least 1, got ${opts.limit}`);
  }
  if (!Number.isFinite(opts.windowMs) || opts.windowMs <= 0) {
    throw new RangeError(`createTokenBucketRateLimiter: windowMs must be a positive number, got ${opts.windowMs}`);
  }

  const { limit, windowMs } = opts;
  const now = opts.now ?? ((): number => Date.now());
  const refillPerMs = limit / windowMs;

  let tokens = limit; // starts full — the first burst up to `limit` is always allowed
  let lastRefill = now();

  return {
    tryAcquire(): boolean {
      const t = now();
      const elapsedMs = t - lastRefill;
      if (elapsedMs > 0) {
        tokens = Math.min(limit, tokens + elapsedMs * refillPerMs);
        lastRefill = t;
      }
      if (tokens >= 1) {
        tokens -= 1;
        return true;
      }
      return false;
    },
  };
}
