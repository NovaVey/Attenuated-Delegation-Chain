import { createHash } from "node:crypto";
import { blockSignatureHash } from "@adc/core";
import { ADC_BLOCK_RESOURCE_KIND, ADC_RESOURCE_SOURCE, type GraphResourceIdentity } from "./identity.js";

/**
 * "Event identity is the per-block signature hash. This is also the
 * revocation identifier in Phase 7, so define it once here and reuse it."
 * (docs/PLAN.md Phase 6.) Phase 7 landed the canonical definition in
 * `@adc/core` itself (`blockSignatureHash()` — `verify()`'s own
 * revocation check needs it internally, and `@adc/core` is the one
 * package every other package in this stack already depends on, never
 * the reverse — docs/PLAN.md section 2), so this is now a thin,
 * intentional alias kept for this package's own already-public API
 * (`blockIdentity` is what Phase 6's tests/README/consumers already
 * name), delegating to that one real definition rather than
 * recomputing it independently. Still sha256 of the raw 64-byte
 * Ed25519 signature, hex-encoded, byte-for-byte identical output to
 * before this delegation — see `@adc/core`'s own `revocation.ts` for
 * the full rationale (fixed-length uniform key shape; signatures aren't
 * secret, so hashing here is never about redaction).
 */
export function blockIdentity(signature: Uint8Array): string {
  return blockSignatureHash(signature);
}

/** The exact shape `blockIdentity()` always produces: sha256 hex, lowercase,
 * 64 characters. Exported so callers that receive a hash from elsewhere
 * (e.g. `buildRevokeEvent`'s caller-supplied `blockSignatureHash` — see
 * builders.ts) can validate it looks like a real block identity before
 * treating it as one, rather than accepting an arbitrary string silently. */
export const BLOCK_IDENTITY_PATTERN = /^[0-9a-f]{64}$/;

export function isBlockIdentity(value: string): boolean {
  return BLOCK_IDENTITY_PATTERN.test(value);
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
