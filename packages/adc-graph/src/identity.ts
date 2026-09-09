/**
 * Principal/resource identity descriptors — deliberately shaped to match
 * Principal-Graph's own `PrincipalSighting`/`ResourceSighting` inputs to
 * `ensurePrincipal()`/`ensureResource()` (that repo's `src/upsert.ts`)
 * field-for-field, so a real Principal-Graph-side adapter consuming a
 * `GraphEvent` (event.ts) can pass `event.principal`/`event.resource`/
 * `event.onBehalfOf` straight into those functions with zero translation
 * — the same "match the real shape exactly" discipline `packages/adc-broker`
 * already applies to `taint-tracked-tool-broker`'s types.
 *
 * Principal-Graph has no importable library surface and no write API
 * (confirmed directly against that repo: it isn't published to npm, and
 * its only inbound HTTP routes are a read-only health/report server) —
 * see this package's README for the full finding. So this package emits
 * plain data shaped to that contract; it cannot call `ensurePrincipal`/
 * `ensureResource` itself, and this file does not import
 * taint-tracked-tool-broker or principal-graph as a dependency.
 */

/** Mirrors Principal-Graph's `principal_kind` — a closed 3-value Postgres
 * enum in that repo's schema, not open text. */
export type GraphPrincipalKind = "human" | "agent" | "service";

export interface GraphPrincipalIdentity {
  readonly kind: GraphPrincipalKind;
  /** Which system is reporting this principal — e.g. 'adc-mint',
   * 'adc-broker'. Free-form in Principal-Graph's own schema; paired with
   * `externalId` as the upsert key `(source, external_id)`, so two
   * different `source` values for the same real-world actor create two
   * distinct rows there — pick one `source` per integration and keep it
   * consistent, the same convention every Principal-Graph adapter follows. */
  readonly source: string;
  /** Stable within `source` — a public key, an RBA subject encoding, ... .
   * Never secret material (see rootKeyPrincipal()'s own doc comment). */
  readonly externalId: string;
  readonly displayName?: string | null;
}

/** Principal-Graph's `resource.kind` is open text (no DB enum), unlike
 * `principal.kind` — see this package's README for the cross-check. */
export interface GraphResourceIdentity {
  readonly kind: string;
  readonly source: string;
  readonly externalId: string;
  readonly displayName?: string | null;
}

/** The `resource.source` every event this package builds uses for the
 * ADC block resource it references — see hash.ts's `blockResource()`. */
export const ADC_RESOURCE_SOURCE = "adc";

/** The `resource.kind` for an ADC delegation-chain block — a new kind
 * Principal-Graph's `resource-vocabulary.ts` has never seen (per this
 * package's README, that file's own header explicitly anticipates a new
 * adapter adding one). One row per BLOCK, not one row per token: mint
 * creates block 0's row, each attenuate creates the new block's own row
 * — see hash.ts. */
export const ADC_BLOCK_RESOURCE_KIND = "adc-block";

/**
 * The root minting authority's principal identity, derived from the root
 * *public* key — never the secret. `kind: 'service'` matches
 * Principal-Graph's existing convention for a non-human, non-interactive
 * actor identified by possessing a key (its own aws-s3.ts adapter uses
 * the identical rule for an IAM role assumed by automation).
 *
 * Unlike the other event kinds, a mint event's principal doesn't need to
 * be supplied by the caller — the root key that signed block 0 already
 * *is* the actor, and it's exactly what the caller already has in hand
 * when calling `mintRoot()`. See builders.ts's `buildMintEvent()`.
 */
export function rootKeyPrincipal(rootPublicKey: Uint8Array, displayName?: string | null): GraphPrincipalIdentity {
  return {
    kind: "service",
    source: "adc-mint",
    externalId: toBase64Url(rootPublicKey),
    displayName: displayName ?? null,
  };
}

/** Minimal, dependency-free base64url — @adc/core doesn't export its own
 * internal encoder, and this package's only dependency is @adc/core, so a
 * small local implementation (rather than widening @adc/core's public
 * surface for a helper only this package needs) is simplest. */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
