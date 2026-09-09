import { createHash } from "node:crypto";
import { ADC_BLOCK_RESOURCE_KIND, ADC_RESOURCE_SOURCE, type GraphResourceIdentity } from "./identity.js";

/**
 * "Event identity is the per-block signature hash. This is also the
 * revocation identifier in Phase 7, so define it once here and reuse it."
 * (docs/PLAN.md Phase 6.) This is that one definition.
 *
 * sha256 of the raw 64-byte Ed25519 signature, hex-encoded — a genuine
 * hash of the signature (matching the literal "signature hash," not just
 * an encoding of the signature itself), fixed-length regardless of proof
 * type, and consistent with every other stable-key hash already in this
 * codebase family: Principal-Graph's own chain-hash (sha256/hex),
 * adc-testkit's exceptions.ts `falseDenyKey()` (sha256/hex), and
 * services/mint's audit-redaction digest (sha256/hex) all make the same
 * choice. Block 0's identity computed this way is exactly "the root hash"
 * docs/PLAN.md's own Phase 7 section refers to: "revoking a root hash
 * kills every descendant for free, since every descendant token contains
 * block 0's signature."
 *
 * Signatures are not secret (unlike an attenuable token's proof field,
 * docs/PLAN.md 1.2) — hashing here is for a fixed-length, uniform key
 * shape, not for redaction.
 */
export function blockIdentity(signature: Uint8Array): string {
  return createHash("sha256").update(signature).digest("hex");
}

/** The Principal-Graph resource identity for the block `signature`
 * belongs to — see identity.ts's `ADC_BLOCK_RESOURCE_KIND`/
 * `ADC_RESOURCE_SOURCE` for why this is a distinct resource row per
 * block, not per token. */
export function blockResource(signature: Uint8Array): GraphResourceIdentity {
  return {
    kind: ADC_BLOCK_RESOURCE_KIND,
    source: ADC_RESOURCE_SOURCE,
    externalId: blockIdentity(signature),
  };
}

/**
 * Fallback resource identity for a token that failed to decode at all —
 * builders.ts's `buildVerifyEvent()` needs *some* non-null `resource` for
 * every event (Principal-Graph's `EventInput.resourceId` is required,
 * never optional — see this package's README), but a token that fails to
 * even split into segments has no block/signature to hash in the first
 * place. Hashes the raw, undecodable wire bytes instead, prefixed so it
 * can never collide with, or be mistaken for, a real block identity
 * (`blockIdentity()`'s output is a bare 64-character hex string with no
 * prefix) — a reader of the resulting `resource.externalId` can tell
 * apart "this row is a real, addressable block" from "this row exists
 * only because *something* undecodable was presented" at a glance.
 */
export function undecodableResource(rawBytes: Uint8Array): GraphResourceIdentity {
  return {
    kind: ADC_BLOCK_RESOURCE_KIND,
    source: ADC_RESOURCE_SOURCE,
    externalId: `undecodable:${createHash("sha256").update(rawBytes).digest("hex")}`,
  };
}
