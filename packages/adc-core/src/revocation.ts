import { createHash } from "node:crypto";

/**
 * The canonical identity of one block, defined exactly once here and
 * reused everywhere else in the stack that needs it — docs/PLAN.md Phase
 * 6: "Event identity is the per-block signature hash. This is also the
 * revocation identifier in Phase 7, so define it once here and reuse
 * it." (`packages/adc-graph`'s own block-identity helper delegates to
 * this function rather than recomputing it independently.)
 *
 * sha256 of the raw 64-byte Ed25519 signature, hex-encoded. A block's
 * signature is not secret (unlike an attenuable token's proof field,
 * docs/PLAN.md 1.2, which must never be logged or land in an audit sink)
 * — hashing here is purely for a fixed-length, uniform key shape to use
 * as a lookup/identity value, not for redaction.
 */
export function blockSignatureHash(signature: Uint8Array): string {
  return createHash("sha256").update(signature).digest("hex");
}
