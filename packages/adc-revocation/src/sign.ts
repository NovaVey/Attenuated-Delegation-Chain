import { b64urlEncode, canonicalEncode, sign, type CanonicalValue } from "@adc/core";
import type { RevocationListPayload } from "./list.js";

/**
 * Domain-separation tag, distinct from block signing's own `"adc-v1"`
 * (docs/PLAN.md 1.3) so a revocation-list signature can never be replayed
 * as, or confused with, a block signature or vice versa — same rationale,
 * different byte string. Deliberately doesn't share `buildSignInput()`'s
 * length-prefixed, multi-field layout: that complexity exists specifically
 * to remove concatenation ambiguity between a variable-length field
 * (`blockBytes`) and the *other* fields that follow it in the same
 * message. Here the domain tag is fixed-content and always first, and the
 * canonical JSON payload is both self-delimiting (a complete, balanced
 * JSON value) and always last — there is no subsequent field for a
 * boundary to be ambiguous with, so a length prefix would add complexity
 * with no ambiguity left to remove.
 */
const DOMAIN_TAG = new TextEncoder().encode("adc-crl1\0");

/** The exact bytes signed/verified for a revocation list — exported so
 * verify.ts can reconstruct the identical input independently, the same
 * "verify over the bytes you can derive yourself" discipline
 * docs/PLAN.md 1.4 requires for block signatures. */
export function revocationSignInput(payload: RevocationListPayload): Uint8Array {
  // This function is public, directly-importable API — buildRevocationList()
  // is the only real caller in this codebase and already validates every
  // entry, but that's a property of the current call graph, not a runtime
  // guarantee this function can rely on. A non-string entry would
  // otherwise reach canonicalEncode() (whose CanonicalValue union accepts
  // it) and get silently signed as part of a well-formed-looking but
  // semantically-wrong list.
  const revoked = [...payload.revoked];
  for (const hash of revoked) {
    if (typeof hash !== "string") {
      throw new TypeError(`revocation list payload.revoked must contain only strings, got ${typeof hash}`);
    }
  }

  // Re-typed as a fresh, plain CanonicalValue object rather than passing
  // `payload` directly: `RevocationListPayload` is a specific interface,
  // not a `{[key: string]: CanonicalValue}` index signature, and only
  // fields the type actually declares should ever be signed — silently
  // signing extra/unexpected own-enumerable properties a caller's object
  // happened to carry would be the wrong contract.
  const canonicalPayload: CanonicalValue = {
    v: payload.v,
    issuedAt: payload.issuedAt,
    ttlSeconds: payload.ttlSeconds,
    revoked,
  };
  const body = canonicalEncode(canonicalPayload);
  const out = new Uint8Array(DOMAIN_TAG.length + body.length);
  out.set(DOMAIN_TAG, 0);
  out.set(body, DOMAIN_TAG.length);
  return out;
}

export interface SignedRevocationList {
  readonly payload: RevocationListPayload;
  /** base64url (unpadded, RFC 4648 §5) — the same encoding every ADC wire
   * segment already uses. */
  readonly signature: string;
}

/** Signs `payload` with `rootSecretKey` — the SAME root key that mints
 * tokens (docs/PLAN.md section 0/Phase 4), so a verifier that already
 * trusts a root public key for minting needs no separate PKI setup to
 * also trust its revocations. See this package's README for the explicit
 * tradeoff this reuse makes (a compromised root key can also suppress its
 * own revocations). */
export function signRevocationList(payload: RevocationListPayload, rootSecretKey: Uint8Array): SignedRevocationList {
  const signature = sign(rootSecretKey, revocationSignInput(payload));
  return { payload, signature: b64urlEncode(signature) };
}
