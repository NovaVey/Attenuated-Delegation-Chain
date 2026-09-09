import type { GraphPrincipalIdentity, GraphResourceIdentity } from "./identity.js";

/**
 * Every field here mirrors Principal-Graph's real `EventInput`
 * (`src/model.ts` in that repo) field-for-field, with exactly one
 * structural difference: `principal`/`onBehalfOf`/`resource` carry
 * identity DESCRIPTORS here (`GraphPrincipalIdentity`/
 * `GraphResourceIdentity`), not the resolved uuids `EventInput` expects
 * (`principalId`/`onBehalfOf: string | null`/`resourceId`) — because only
 * code with a live `ensurePrincipal()`/`ensureResource()` (Postgres access
 * to that repo's own database) can produce those uuids, and this package
 * has neither (see this package's README). A real Principal-Graph-side
 * sink resolves `principal`/`onBehalfOf`/`resource` via those two
 * functions and passes every OTHER field on this type straight through to
 * `EventBatcher.append()`/`appendEvent()` unchanged.
 *
 * Every field is a required key, matching `EventInput`'s own discipline
 * (docs cross-checked directly against that repo's real type): a
 * nullable-*valued* field (`onBehalfOf`, `denyReason`, `reversible`,
 * `requestDigest`) must still be present as `null`, never omitted —
 * `EventInput`'s own TypeScript type rejects a missing key even where the
 * value itself may be null, and this type mirrors that discipline
 * deliberately, not by accident.
 */
export interface GraphEvent {
  readonly occurredAt: Date;
  readonly principal: GraphPrincipalIdentity;
  /** null when the human this credential traces back to isn't known/
   * attributable — never guessed. */
  readonly onBehalfOf: GraphPrincipalIdentity | null;
  readonly resource: GraphResourceIdentity;
  /** Free string in Principal-Graph's own schema (no CHECK constraint,
   * no enum) — 'mint' | 'attenuate' | 'verify' | 'seal' | 'revoke', per
   * builders.ts. None of these collide with any action string already in
   * use elsewhere in the Principal-Graph ecosystem (confirmed against
   * that repo directly — see this package's README). */
  readonly action: string;
  /** Principal-Graph's `decision` is a strictly binary Postgres enum —
   * there is no third "informational" state. A mint/attenuate/seal that
   * completed (no exception thrown) is 'allow', matching the established
   * convention non-gating Principal-Graph producers already use for "yes,
   * this happened" (see this package's README). */
  readonly decision: "allow" | "deny";
  readonly denyReason: string | null;
  /** Free-form, human-legible provenance tags — this package's own
   * choice of what's useful (caveat kinds present, chain depth, a verify
   * denial's reason code), not a reuse of taint-tracked-tool-broker's
   * taint-specific vocabulary (see builders.ts). */
  readonly taintLabels: readonly string[];
  /**
   * Left `null` (unassessed) for every event this package builds — ADC
   * has no established notion of "is this undoable" the way
   * taint-tracked-tool-broker's sinkClass taxonomy gives that repo's own
   * broker-audit-sink.ts adapter one, and Principal-Graph's own
   * non-broker producer (postgres-usage.ts) leaves it null too rather
   * than inventing new semantics — see this package's README.
   */
  readonly reversible: boolean | null;
  /** sha256 hex of the relevant block's raw bytes, matching
   * `EventInput.requestDigest`'s own "hash of X, never X itself"
   * discipline — see builders.ts. */
  readonly requestDigest: string | null;
}

/**
 * The seam a Principal-Graph-side adapter (or a test/reference
 * implementation — see sinks/memory.ts) implements. Mirrors
 * taint-tracked-tool-broker's own `AuditSink` shape (`record(event): void`,
 * synchronous, never throws back into the caller) deliberately — the same
 * "fire-and-forget, a write failure is the sink's problem, never the
 * emitting code's" contract packages/adc-broker's own audit-redaction
 * work already established for this whole system's event-emission
 * adapters.
 */
export interface GraphSink {
  record(event: GraphEvent): void;
}
