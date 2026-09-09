import { DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_POLL_INTERVAL_MS } from "./list.js";
import { verifySignedRevocationList } from "./verify.js";

export interface RevocationClientOptions {
  /** e.g. the mint service's GET /revocations. */
  readonly url: string;
  readonly rootPublicKey: Uint8Array;
  /** Default DEFAULT_POLL_INTERVAL_MS (30s) — matches docs/PLAN.md Phase
   * 7's own worst-case liveness formula. */
  readonly pollIntervalMs?: number;
  readonly clockSkewSeconds?: number;
  /** Injectable for tests (a local mock server) and for a runtime that
   * doesn't have a global `fetch`. Defaults to the global `fetch`. */
  readonly fetchImpl?: typeof fetch;
  /** Called on any fetch/parse/verify failure during a poll — network
   * error, non-2xx, malformed body, bad signature, or an expired list.
   * The client never throws these back into `poll()`'s caller (a
   * verifier's hot path must not break because a background refresh
   * failed) — this is the only way to observe them. Defaults to a no-op. */
  readonly onError?: (err: Error) => void;
  /** Unix seconds. Injectable for deterministic tests of staleness (a
   * real cached list going stale without waiting on a real timer) —
   * matches @adc/core's own Facts.now/VerifyOptions testing convention.
   * Defaults to the real wall clock. */
  readonly now?: () => number;
}

export interface RevocationClient {
  /**
   * The current, verified, non-expired revoked-hash set — or `null` if
   * no valid list has ever been successfully fetched, or the most
   * recently cached one has since gone stale (checked live against the
   * wall clock on every call, independent of whether the last poll
   * attempt succeeded). **Fail closed**: treat `null` as "revocation
   * status unknown," never as "nothing is revoked" — see this package's
   * README for why a verifier should deny rather than silently skip the
   * check when this is `null`.
   */
  getRevokedHashes(): ReadonlySet<string> | null;
  /**
   * One fetch-verify-cache cycle, callable directly — this is what tests
   * use to exercise the client deterministically (no real timers), and
   * what `start()`'s own interval calls internally. Never throws; a
   * failure is reported via `onError` and leaves any still-fresh cached
   * value untouched (see `getRevokedHashes()`'s own doc comment on why a
   * failed refresh doesn't immediately blank a still-valid cache — a
   * transient network blip shouldn't discard a legitimately-still-fresh
   * list).
   */
  poll(): Promise<void>;
  /** Fetches once immediately, then again every `pollIntervalMs`. */
  start(): void;
  /** Stops the interval. Whatever's currently cached remains available
   * from `getRevokedHashes()` until it naturally goes stale. */
  stop(): void;
}

interface CachedList {
  readonly revokedHashes: ReadonlySet<string>;
  /** Unix seconds: `payload.issuedAt + payload.ttlSeconds +
   * clockSkewSeconds` — recomputed at cache time from that specific
   * list's own fields, not a fixed client-wide TTL, so a signer that
   * issues an unusually short- or long-lived list is honored exactly. */
  readonly validUntil: number;
}

export function createRevocationClient(opts: RevocationClientOptions): RevocationClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const clockSkewSeconds = opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const onError = opts.onError ?? ((): void => {});
  const now = opts.now ?? ((): number => Math.floor(Date.now() / 1000));

  let cached: CachedList | undefined;
  let timer: ReturnType<typeof setInterval> | undefined;

  async function poll(): Promise<void> {
    let body: unknown;
    try {
      const res = await fetchImpl(opts.url);
      if (!res.ok) {
        throw new Error(`revocation list fetch failed: HTTP ${res.status}`);
      }
      body = await res.json();
    } catch (err) {
      onError(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    const result = verifySignedRevocationList(body, opts.rootPublicKey, { clockSkewSeconds, now: now() });
    if (!result.ok) {
      onError(new Error(`revocation list rejected: ${result.code}: ${result.reason}`));
      return;
    }

    cached = {
      revokedHashes: result.revokedHashes,
      validUntil: result.payload.issuedAt + result.payload.ttlSeconds + clockSkewSeconds,
    };
  }

  return {
    getRevokedHashes(): ReadonlySet<string> | null {
      if (!cached) return null;
      return now() <= cached.validUntil ? cached.revokedHashes : null;
    },
    poll,
    start(): void {
      if (timer) return; // already started — idempotent, matching this codebase's other lifecycle methods
      void poll();
      timer = setInterval(() => void poll(), pollIntervalMs);
      // Never hold the process open on this timer alone — a verifier
      // embedding this client shouldn't be unable to exit cleanly just
      // because a background poll is scheduled.
      timer.unref?.();
    },
    stop(): void {
      if (timer) {
        clearInterval(timer);
        timer = undefined;
      }
    },
  };
}
