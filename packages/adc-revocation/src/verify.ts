import { b64urlDecode, verifySignature } from "@adc/core";
import { REVOCATION_LIST_VERSION, type RevocationListPayload } from "./list.js";
import { revocationSignInput, type SignedRevocationList } from "./sign.js";

export type VerifyListReasonCode = "MALFORMED" | "BAD_SIGNATURE" | "EXPIRED";

export type VerifyListResult =
  | { readonly ok: true; readonly payload: RevocationListPayload; readonly revokedHashes: ReadonlySet<string> }
  | { readonly ok: false; readonly code: VerifyListReasonCode; readonly reason: string };

export interface VerifyListOptions {
  /** Unix seconds. Defaults to the real wall clock — pass explicitly for
   * deterministic tests, matching @adc/core's own Facts.now convention. */
  readonly now?: number;
  /** Additional allowance, seconds, on top of the list's own `ttlSeconds`
   * before it's considered stale. Default DEFAULT_CLOCK_SKEW_SECONDS
   * (list.ts) — matches @adc/core's own clock-skew default, and the
   * 150s worst-case liveness bound docs/PLAN.md's Phase 7 section states
   * (60s ttl + 30s poll interval + 60s skew). */
  readonly clockSkewSeconds?: number;
}

function deny(code: VerifyListReasonCode, reason: string): VerifyListResult {
  return { ok: false, code, reason };
}

const BLOCK_HASH_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Validates `raw`'s shape before anything else touches it — `raw` is
 * whatever `JSON.parse()` produced from an HTTP response body, i.e.
 * fully untrusted input, exactly like `@adc/core`'s own `verify()`
 * treats its `tokenBytes` argument. Never throws; returns `undefined` on
 * any structural violation so the caller can fold that into a `MALFORMED`
 * deny with a specific reason, the same "deny by default" discipline
 * docs/PLAN.md 1.6 states for token verification.
 */
function parseShape(raw: unknown): { list: SignedRevocationList; reason?: string } | { list?: undefined; reason: string } {
  if (raw === null || typeof raw !== "object") {
    return { reason: "revocation list must be an object" };
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.signature !== "string" || obj.signature.length === 0) {
    return { reason: "'signature' must be a non-empty string" };
  }
  const payload = obj.payload;
  if (payload === null || typeof payload !== "object") {
    return { reason: "'payload' must be an object" };
  }
  const p = payload as Record<string, unknown>;
  if (p.v !== REVOCATION_LIST_VERSION) {
    return { reason: `'payload.v' must be ${JSON.stringify(REVOCATION_LIST_VERSION)}, got ${JSON.stringify(p.v)}` };
  }
  // Number.isSafeInteger, not just Number.isInteger: an out-of-safe-range
  // integer (e.g. 2**53) still passes Number.isInteger, but canonicalEncode()
  // (called below, via revocationSignInput, BEFORE the signature is even
  // checked) throws a RangeError on one — found by adversarial review as an
  // unauthenticated crash: any HTTP response body with an out-of-range
  // issuedAt/ttlSeconds, no valid signature required, could kill a
  // verifier's process. Reject it here, structurally, before it ever
  // reaches canonical encoding.
  if (typeof p.issuedAt !== "number" || !Number.isSafeInteger(p.issuedAt) || p.issuedAt < 0) {
    return { reason: "'payload.issuedAt' must be a non-negative safe integer" };
  }
  if (typeof p.ttlSeconds !== "number" || !Number.isSafeInteger(p.ttlSeconds) || p.ttlSeconds <= 0) {
    return { reason: "'payload.ttlSeconds' must be a positive safe integer" };
  }
  if (!Array.isArray(p.revoked) || !p.revoked.every((h) => typeof h === "string" && BLOCK_HASH_PATTERN.test(h))) {
    return { reason: "'payload.revoked' must be an array of 64-character lowercase hex sha256 hashes" };
  }
  return {
    list: {
      signature: obj.signature,
      payload: { v: REVOCATION_LIST_VERSION, issuedAt: p.issuedAt, ttlSeconds: p.ttlSeconds, revoked: p.revoked },
    },
  };
}

/**
 * Verifies a signed revocation list: shape, signature, and freshness —
 * in that order, matching `@adc/core`'s own step-ordering discipline
 * (structural checks before crypto, crypto before anything that reads
 * the payload's own claims). `raw` is untrusted input (typically an
 * HTTP response body already run through `JSON.parse()`); this never
 * throws on it.
 *
 * A stale list (past `issuedAt + ttlSeconds`, even with the clock-skew
 * allowance) is denied `EXPIRED` regardless of whether its signature is
 * otherwise perfectly valid — a validly-signed OLD list is exactly the
 * failure mode revocation exists to prevent (the whole point is that the
 * signer might have revoked something SINCE that list was issued), so
 * staleness is checked, not just tamper-evidence.
 */
export function verifySignedRevocationList(raw: unknown, rootPublicKey: Uint8Array, opts: VerifyListOptions = {}): VerifyListResult {
  // The whole body is wrapped, not just the individually-guarded steps
  // below: this function's contract (and its callers', especially
  // client.ts's poll(), which calls this on a raw HTTP response with no
  // try/catch of its own) is "never throws on untrusted input." parseShape()
  // already rejects the one concrete way this used to be violated (an
  // out-of-safe-integer-range issuedAt/ttlSeconds reaching canonicalEncode()
  // and throwing before the signature check) — this catch-all is
  // structural insurance against that class of bug recurring, not a
  // substitute for validating at the source.
  try {
    const shape = parseShape(raw);
    if (!shape.list) {
      return deny("MALFORMED", shape.reason);
    }
    const list = shape.list;

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = b64urlDecode(list.signature);
    } catch {
      return deny("MALFORMED", "'signature' is not valid base64url");
    }

    if (!verifySignature(rootPublicKey, revocationSignInput(list.payload), signatureBytes)) {
      return deny("BAD_SIGNATURE", "revocation list signature does not verify under the given root public key");
    }

    const now = opts.now ?? Math.floor(Date.now() / 1000);
    const clockSkewSeconds = opts.clockSkewSeconds ?? 60;

    // A future-dated issuedAt would make this list look artificially
    // *fresher* than it is (inflating the "now <= issuedAt + ttl" check
    // below) — reject it the same way, not just past-expiry. Only the
    // legitimate root-key holder can produce a validly-signed list at all
    // (the signature check above already establishes that), so this is
    // defense against the SIGNER's own clock being wrong, not an external
    // forgery — see this package's README.
    if (now < list.payload.issuedAt - clockSkewSeconds) {
      return deny("EXPIRED", `revocation list is dated in the future: issuedAt ${list.payload.issuedAt}, now ${now}`);
    }
    if (now > list.payload.issuedAt + list.payload.ttlSeconds + clockSkewSeconds) {
      return deny(
        "EXPIRED",
        `revocation list is stale: issued ${list.payload.issuedAt}, ttl ${list.payload.ttlSeconds}s, now ${now}`,
      );
    }

    return { ok: true, payload: list.payload, revokedHashes: new Set(list.payload.revoked) };
  } catch (err) {
    return deny("MALFORMED", `revocation list could not be verified: ${err instanceof Error ? err.message : String(err)}`);
  }
}
