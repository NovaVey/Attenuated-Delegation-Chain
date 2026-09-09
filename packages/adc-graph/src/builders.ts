import { createHash } from "node:crypto";
import { decodeBlock, decodeToken, type ParsedToken, type VerifyResult } from "@adc/core";
import type { GraphEvent } from "./event.js";
import { blockResource, isBlockIdentity, undecodableResource } from "./hash.js";
import { ADC_BLOCK_RESOURCE_KIND, ADC_RESOURCE_SOURCE, rootKeyPrincipal, type GraphPrincipalIdentity } from "./identity.js";

/**
 * `blocks`/`sigs` are typed `readonly Uint8Array[]` with no compile-time
 * non-empty or equal-length guarantee — that invariant is only actually
 * upheld at runtime, by `@adc/core`'s own `mintRoot`/`attenuate`/`seal`/
 * `decodeToken`, each of which validates it explicitly (`attenuate()`/
 * `seal()` throw `AdcError("ADC_MALFORMED", ...)` on exactly this check —
 * `packages/adc-core/src/token.ts`). A hand-constructed or otherwise
 * malformed `ParsedToken` reaching this package's builders without going
 * through one of those would previously fail with an opaque, low-level
 * `TypeError` from deep inside `node:crypto` (a non-null-asserted
 * `undefined` reaching `createHash().update()`) instead of a clear,
 * actionable error — this repeats @adc/core's own check so the failure
 * mode matches: loud, immediate, and clearly attributable to a malformed
 * token, not a cryptic crash three calls downstream.
 */
function assertValidToken(token: ParsedToken): void {
  if (token.blocks.length === 0 || token.blocks.length !== token.sigs.length) {
    throw new RangeError(
      `adc-graph: token has an inconsistent block/signature count (blocks: ${token.blocks.length}, sigs: ${token.sigs.length}) — expected both to be equal and at least 1`,
    );
  }
}

interface CommonOpts {
  /** Defaults to the real wall clock — pass explicitly for deterministic
   * tests, matching @adc/core's own Facts.now convention. */
  readonly now?: Date;
  readonly onBehalfOf?: GraphPrincipalIdentity;
}

function resolveOnBehalfOf(opts: { onBehalfOf?: GraphPrincipalIdentity }): GraphPrincipalIdentity | null {
  return opts.onBehalfOf ?? null;
}

function resolveNow(opts: { now?: Date }): Date {
  return opts.now ?? new Date();
}

/** sha256 hex of a block's raw bytes — the requestDigest field's "hash of
 * X, never X itself" discipline, applied to the block being described
 * rather than to TTTB-style call arguments (see event.ts). */
function digestOf(blockBytes: Uint8Array): string {
  return createHash("sha256").update(blockBytes).digest("hex");
}

/** Every distinct caveat kind present in `blockBytes`, plus the chain
 * depth, as free-form human-legible tags — this package's own choice of
 * what's useful for an auditor skimming Principal-Graph's report (not a
 * reuse of taint-tracked-tool-broker's taint-specific label vocabulary,
 * which has no ADC equivalent — see event.ts's own doc comment). Falls
 * back to an empty caveat list (just the depth tag) if the block somehow
 * fails to decode — callers only ever pass an already-successfully-parsed
 * block here, so this is defensive, not an expected path. */
function blockLabels(blockBytes: Uint8Array, depth: number): string[] {
  const labels = [`depth:${depth}`];
  try {
    const { caveats } = decodeBlock(blockBytes);
    const kinds = [...new Set(caveats.map((c) => `caveat:${c.kind}`))].sort();
    labels.push(...kinds);
  } catch {
    // Defensive only (see doc comment) — never actually reachable from
    // buildMintEvent/buildAttenuateEvent/buildSealEvent, which only ever
    // pass a block from a ParsedToken @adc/core itself just produced.
  }
  return labels;
}

/**
 * Builds a 'mint' event for a freshly-minted root token (block 0).
 *
 * The principal is derived from `rootPublicKey` automatically
 * (`rootKeyPrincipal()`, identity.ts) — unlike every other event kind
 * here, mint's actor is unambiguous and already in the caller's hand, so
 * there's no separate `actor` option to get wrong or duplicate.
 */
export function buildMintEvent(token: ParsedToken, rootPublicKey: Uint8Array, opts: CommonOpts = {}): GraphEvent {
  assertValidToken(token);
  const blockBytes = token.blocks[0]!;
  const sig = token.sigs[0]!;
  return {
    occurredAt: resolveNow(opts),
    principal: rootKeyPrincipal(rootPublicKey),
    onBehalfOf: resolveOnBehalfOf(opts),
    resource: blockResource(sig),
    action: "mint",
    decision: "allow",
    denyReason: null,
    taintLabels: blockLabels(blockBytes, 0),
    reversible: null,
    requestDigest: digestOf(blockBytes),
  };
}

interface ActorOpts extends CommonOpts {
  /** Who performed this operation. Unlike mint's root-key principal, this
   * can't be derived from the token alone — attenuation/sealing only
   * requires holding the current proof secret, which the token itself
   * carries no durable identity for (docs/PLAN.md 1.2's own point: the
   * proof field is a capability, not an identifier). The caller supplies
   * whatever identity it has for the actor performing this call, the same
   * way taint-tracked-tool-broker integrators supply `BrokerAuditSinkOptions
   * .agent` up front — there is no way for this package to derive it
   * honestly on its own. */
  readonly actor: GraphPrincipalIdentity;
}

/** Builds an 'attenuate' event for the newly-appended block (the LAST
 * block in `childToken` — attenuate() always appends exactly one). */
export function buildAttenuateEvent(childToken: ParsedToken, opts: ActorOpts): GraphEvent {
  assertValidToken(childToken);
  const lastIndex = childToken.blocks.length - 1;
  const blockBytes = childToken.blocks[lastIndex]!;
  const sig = childToken.sigs[lastIndex]!;
  return {
    occurredAt: resolveNow(opts),
    principal: opts.actor,
    onBehalfOf: resolveOnBehalfOf(opts),
    resource: blockResource(sig),
    action: "attenuate",
    decision: "allow",
    denyReason: null,
    taintLabels: blockLabels(blockBytes, lastIndex),
    reversible: null,
    requestDigest: digestOf(blockBytes),
  };
}

/** Builds a 'seal' event. `sealedToken` is `seal()`'s return value —
 * identical blocks/sigs to the pre-seal token, only `proof` differs, so
 * the resource this event references is the LAST EXISTING block (the one
 * that's now sealed), not a new one: sealing appends no block. */
export function buildSealEvent(sealedToken: ParsedToken, opts: ActorOpts): GraphEvent {
  assertValidToken(sealedToken);
  const lastIndex = sealedToken.blocks.length - 1;
  const blockBytes = sealedToken.blocks[lastIndex]!;
  const sig = sealedToken.sigs[lastIndex]!;
  return {
    occurredAt: resolveNow(opts),
    principal: opts.actor,
    onBehalfOf: resolveOnBehalfOf(opts),
    resource: blockResource(sig),
    action: "seal",
    decision: "allow",
    denyReason: null,
    taintLabels: blockLabels(blockBytes, lastIndex),
    reversible: null,
    requestDigest: digestOf(blockBytes),
  };
}

/**
 * Builds a 'verify' event ('allow' or 'deny', from `result.ok`) for the
 * TERMINAL block of the token actually presented — the specific
 * delegated-credential instance an auditor cares about, not necessarily
 * block 0. See this package's README for why Phase 7's own revocation
 * CHECK (separate from this event's identity) still has to walk every
 * ancestor's hash, not just this one.
 *
 * Accepts the same `tokenBytes` shape `@adc/core`'s own `verify()` does
 * (`string | Uint8Array`) so a caller can pass exactly what it already
 * handed to `verify()`. `VerifyResult` alone carries no block/signature
 * data (docs/PLAN.md 1.6's Deny/Allow results are deliberately minimal),
 * so this independently re-decodes the wire bytes via `@adc/core`'s own
 * `decodeToken()` — the same decoder `verify()` itself uses, so a token
 * that verified (or was denied by a caveat, not a decode failure) always
 * decodes identically here.
 *
 * A token that failed to decode at all (the `ADC_MALFORMED` case, or any
 * decode-time throw) has no block/signature to hash — this event still
 * needs a non-null `resource` (Principal-Graph's own `EventInput
 * .resourceId` is required, never optional), so it falls back to
 * `undecodableResource()` (hash.ts), hashing the raw undecodable bytes
 * instead. That fallback identity is never mistaken for a real block
 * identity — see that function's own doc comment for the distinguishing
 * prefix.
 */
export function buildVerifyEvent(tokenBytes: string | Uint8Array, result: VerifyResult, opts: ActorOpts): GraphEvent {
  const decision: "allow" | "deny" = result.ok ? "allow" : "deny";
  const denyReason = result.ok ? null : `${result.code}: ${result.reason}`;

  let decoded: ParsedToken | undefined;
  let rawBytes: Uint8Array | undefined;
  try {
    const wire = typeof tokenBytes === "string" ? tokenBytes : new TextDecoder("utf-8", { fatal: true }).decode(tokenBytes);
    decoded = decodeToken(wire);
  } catch {
    rawBytes = typeof tokenBytes === "string" ? new TextEncoder().encode(tokenBytes) : tokenBytes;
  }

  const resource = decoded
    ? blockResource(decoded.sigs[decoded.sigs.length - 1]!)
    : undecodableResource(rawBytes!);

  const taintLabels: string[] = [];
  if (decoded) {
    taintLabels.push(`depth:${decoded.blocks.length - 1}`);
  }
  if (!result.ok) {
    taintLabels.push(`code:${result.code}`);
  }

  return {
    occurredAt: resolveNow(opts),
    principal: opts.actor,
    onBehalfOf: resolveOnBehalfOf(opts),
    resource,
    action: "verify",
    decision,
    denyReason,
    taintLabels,
    reversible: null,
    requestDigest: decoded ? digestOf(decoded.blocks[decoded.blocks.length - 1]!) : null,
  };
}

interface RevokeOpts extends CommonOpts {
  readonly actor: GraphPrincipalIdentity;
  /** Free-text reason, carried in `taintLabels` (never `denyReason` —
   * this event's own `decision` is 'allow', the revocation itself
   * succeeding, not a denial; see this package's README). */
  readonly reason: string;
}

/**
 * Builds a 'revoke' event for the block whose signature hash is
 * `blockSignatureHash` — the same identity `blockIdentity()` (hash.ts)
 * computes (a thin delegating alias to `@adc/core`'s own canonical
 * `blockSignatureHash()`, Phase 7's revocation-list lookup key — see
 * hash.ts's own doc comment). Takes the hash directly, not a
 * `ParsedToken`, since a revocation is keyed by hash alone — the operator
 * revoking a credential may never hold the token itself (e.g. revoking a
 * lost/compromised root from an out-of-band report of its known hash).
 *
 * Validates `blockSignatureHash` looks like a real `blockIdentity()`
 * output (64-character lowercase hex) — every OTHER builder derives its
 * resource identity from actual cryptographic bytes via `blockResource()`/
 * `undecodableResource()`; this is the one builder that takes an identity
 * string directly from a caller (an operator transcribing a hash from an
 * incident report, say), which is exactly the path most likely to carry a
 * typo, an empty string, or — since `undecodableResource()`'s own
 * `undecodable:`-prefixed fallback identities are visible in earlier
 * `verify` events an operator might copy from — a fallback identity that
 * was never a real signature hash to begin with. Throws `RangeError`
 * rather than silently writing a "successful" revoke event for a target
 * that was never a real block identity.
 */
export function buildRevokeEvent(blockSignatureHash: string, opts: RevokeOpts): GraphEvent {
  if (!isBlockIdentity(blockSignatureHash)) {
    throw new RangeError(
      `adc-graph: buildRevokeEvent's blockSignatureHash must be a 64-character lowercase hex sha256 digest (blockIdentity()'s own output shape), got ${JSON.stringify(blockSignatureHash)}`,
    );
  }
  return {
    occurredAt: resolveNow(opts),
    principal: opts.actor,
    onBehalfOf: resolveOnBehalfOf(opts),
    resource: { kind: ADC_BLOCK_RESOURCE_KIND, source: ADC_RESOURCE_SOURCE, externalId: blockSignatureHash },
    action: "revoke",
    decision: "allow",
    denyReason: null,
    taintLabels: [`reason:${opts.reason}`],
    reversible: null,
    requestDigest: null,
  };
}
