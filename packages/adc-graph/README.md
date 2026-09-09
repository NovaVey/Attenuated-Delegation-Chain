# @adc/graph

[Principal-Graph](https://github.com/NovaVey/Principal-Graph) event emitters —
[`docs/PLAN.md`](../../docs/PLAN.md) Phase 6: "Mint, attenuate, verify-allow,
verify-deny, seal, revoke. Event identity is the per-block signature hash.
This is also the revocation identifier in Phase 7, so define it once here
and reuse it."

## Why this package emits data, not writes rows

Principal-Graph is **not published as an npm package and has no write/
ingestion API** — confirmed directly against that repo, not assumed:

- Its own README: *"This isn't published as an npm package yet — clone the
  repo and write your integration alongside it (say, `scripts/wire-broker.ts`,
  next to the scripts already there)."*
- Its only inbound HTTP surface (`src/server.ts`) is `GET /health`,
  `GET /report`, `GET /report.json` — read-only, key-authenticated. No `POST`
  route exists anywhere in that repo.
- Every one of its seven adapters/exporters (`src/adapters/*.ts`,
  `src/exporters/rba.ts`) imports that repo's own modules by relative path
  and writes through a live `pg.Pool` holding real credentials to that
  repo's own Postgres database — there is exactly one demonstrated pattern
  for getting an event into `event`: code compiled into that repo's own
  process, with direct database access. Its own `broker-audit-sink.ts`
  adapter (the closest precedent to what this package feeds) is explicit
  that even *it* requires cloning that repo's source tree.

So `@adc/graph`, living in a sibling repo with neither Postgres credentials
nor Principal-Graph's source as a library, cannot write a single row. What
it *can* do — and what this package is — is produce **plain, correctly-shaped
event data** matching Principal-Graph's real `EventInput` contract
field-for-field, so that a thin adapter living inside a Principal-Graph
checkout (mirroring `src/adapters/broker-audit-sink.ts`'s own shape exactly
— see "A worked reference adapter" below) can resolve identities and pass
the rest straight through to `EventBatcher.append()`/`appendEvent()` with
zero translation.

## Event identity: the per-block signature hash

```ts
import { blockIdentity } from "@adc/graph";

blockIdentity(token.sigs[i]); // sha256(sig_i), hex — this IS the identity
```

sha256 of the raw 64-byte Ed25519 signature, hex-encoded. Chosen because:

- Principal-Graph's own `event` table has **no caller-supplied identity
  column at all** (confirmed directly: `event.id` is server-generated via
  `randomUUID()`, never accepted from a caller; `event.request_digest` is
  semantically "hash of call arguments," nullable, unindexed; Principal-
  Graph's own `hash`/`prev_hash` chain-hash columns are *derived from its
  own row contents* at insert time, computed by that repo, never accepted
  as external input).
- The only real, exploitable identity mechanism Principal-Graph's schema
  provides is `resource`'s `unique (source, external_id)` upsert key (the
  same mechanism `ensureResource()` already uses for every other adapter).
  So this package represents **each ADC block as its own `resource` row**
  — `kind: 'adc-block'`, `source: 'adc'`, `externalId: blockIdentity(sig)`
  — one row per hop, not one row per token.
- `blockIdentity(token.sigs[0])` for a root token's block 0 is exactly "the
  root hash" `docs/PLAN.md`'s own Phase 7 section refers to: "revoking a
  root hash kills every descendant for free, since every descendant token
  contains block 0's signature." **Phase 7 landed the canonical
  definition in `@adc/core` itself** — `blockSignatureHash()` there, since
  `verify()`'s own offline revocation check needs it internally, and
  `@adc/core` is the one package this whole stack already depends on
  (never the reverse). `blockIdentity()` here is now a thin,
  byte-for-byte-identical alias delegating to it, kept for this package's
  already-public API — see `@adc/core`'s own `revocation.ts` and the
  `packages/adc-core` README's "Revocation" section for the real
  definition and `verify()`'s `revokedHashes` option.

A signature is not secret (unlike an attenuable token's proof field,
`docs/PLAN.md` 1.2) — hashing here is for a fixed-length, uniform key
shape, not redaction.

## The six event kinds

| kind | `resource` references | `principal` | notes |
| --- | --- | --- | --- |
| `mint` | block 0 (the root just created) | derived from `rootPublicKey` automatically (`rootKeyPrincipal()`) | the only kind whose principal isn't caller-supplied — the root key that signed block 0 is unambiguous and already in the caller's hand |
| `attenuate` | the newly-appended block (`token.sigs[sigs.length-1]`) | caller-supplied `actor` | attenuation only requires holding the current proof secret, which carries no durable identity of its own (`docs/PLAN.md` 1.2) — this package can't derive "who" honestly |
| `seal` | the **last existing** block (sealing appends no new block) | caller-supplied `actor` | |
| `verify` | the terminal block of the *presented* token (re-decoded independently from `tokenBytes`, matching `@adc/core`'s own `verify()` decode path) | caller-supplied `actor` | `decision` is `'allow'`/`'deny'` from `result.ok`; a token that fails to decode at all falls back to a distinctly-prefixed synthetic identity (`undecodableResource()`) since `resourceId` is a required field |
| `revoke` | the block named by a caller-supplied hash directly, not derived from a `ParsedToken` — a revocation is keyed by hash alone, and the operator revoking a credential (Phase 7's `services/mint` `POST /revoke`, say) may never hold the token itself | caller-supplied `actor` | `decision` is always `'allow'` (the revocation itself succeeded); the human-readable reason rides in `taintLabels`, never `denyReason` — that field is reserved for an actual denial |

`mint`/`attenuate`/`seal`/`revoke` all use `decision: 'allow'` — Principal-
Graph's `decision` is a strictly binary enum with no third "informational"
state, and no producer in that repo has one either; the established
convention for a non-gating "yes, this happened" event (its own
`postgres-usage.ts` adapter) is the same choice.

`reversible` is left `null` on every event this package builds: ADC has no
established notion of "is this undoable" the way `taint-tracked-tool-broker`'s
`sinkClass` taxonomy gives `broker-audit-sink.ts` one, and Principal-Graph's
other non-broker producer leaves it `null` too rather than inventing new
semantics.

## Usage

```ts
import { mintRoot, attenuate, encodeToken, verify } from "@adc/core";
import { buildMintEvent, buildAttenuateEvent, buildVerifyEvent, createInMemoryGraphSink } from "@adc/graph";

const sink = createInMemoryGraphSink(); // swap for a real sink — see below

const token = mintRoot(rootSecretKey, { caveats: [...] });
sink.record(buildMintEvent(token, rootPublicKey, { onBehalfOf: aliceIdentity }));

const child = attenuate(token, { caveats: [...] });
sink.record(buildAttenuateEvent(child, { actor: agentIdentity, onBehalfOf: aliceIdentity }));

const wire = encodeToken(child);
const result = verify(wire, rootPublicKey, facts);
sink.record(buildVerifyEvent(wire, result, { actor: agentIdentity, onBehalfOf: aliceIdentity }));
```

## A worked reference adapter

This is what a real Principal-Graph-side sink for `@adc/graph` events looks
like, mirroring `src/adapters/broker-audit-sink.ts`'s exact shape in that
repo (identity resolution via `ensurePrincipal`/`ensureResource`, batched
writes via `EventBatcher`, fail-open-on-write-failure since `GraphSink
.record()` is synchronous and non-throwing by this package's own contract
— see `event.ts`'s doc comment). **This file is documentation, not shipped
code** — it can't run from this repo (no Postgres access, no import path to
Principal-Graph's internals), so paste it into a Principal-Graph checkout
as `src/adapters/adc-graph-sink.ts` per that repo's own `CONTRIBUTING.md`
adapter conventions (route every upsert through `ensurePrincipal`/
`ensureResource`, never a raw `INSERT`).

### The `on_behalf_of`-without-a-grant trap, and why the adapter below writes `grant_edge` too

Found in adversarial review before this shipped, and worth explaining in
full since it's exactly the kind of gap that's invisible until someone
actually wires this up: every ADC block gets its **own, one-off**
`resource` row (`blockResource()` — a fresh `external_id` per hop, by
design, since event identity is the per-block signature hash). Principal-
Graph's real `on-behalf-of-escalation` policy
(`src/policies.ts::checkOnBehalfOfEscalation`) flags exactly this shape:

> an `allow` event with `on_behalf_of` set, where the human named there
> holds **no live `grant_edge`** on that event's `resource_id` at all.

Since nothing can pre-provision a `grant_edge` for a resource that doesn't
exist until the very moment the event describing it is written, **every
single `onBehalfOf`-carrying `mint`/`attenuate`/`seal`/`verify(allow)`/
`revoke` event this package ever builds would be reported as a privilege
escalation** by a naive adapter that only writes `event` rows — a 100%
false-positive rate on the most important accountability signal this
package can emit, even though nothing escalated: the human legitimately
holds and is exercising their own delegated credential.

The fix is structural, not a suppression: when an event carries
`onBehalfOf`, the adapter also establishes the fact that makes it true —
that the named human holds this specific delegated block — as an ordinary
`grant_edge` row, in the same write. `'can_use'` is a new relation for a
new `'adc-block'` resource kind; add both to Principal-Graph's own
`src/resource-vocabulary.ts` (`'adc-block': ['can_use']`) alongside the
adapter below, per that file's own header ("update this file the moment a
new adapter introduces a resource kind or relation string").

```ts
// principal-graph/src/adapters/adc-graph-sink.ts (reference — not shipped from this repo)
import type { Pool } from "pg";
import { ensurePrincipal, ensureResource } from "../upsert.js";
import { EventBatcher } from "../event-batch.js";
import type { GraphEvent, GraphSink } from "@adc/graph"; // or copy the type — see below

export interface AdcGraphSinkOptions {
  pool: Pool;
}

export function createAdcGraphSink(opts: AdcGraphSinkOptions): GraphSink & { flush(): Promise<void> } {
  const { pool } = opts;
  const batcher = new EventBatcher(pool);
  const pending = new Set<Promise<void>>();

  async function handle(event: GraphEvent): Promise<void> {
    const [principalId, onBehalfOf, resourceId] = await Promise.all([
      ensurePrincipal(pool, event.principal),
      event.onBehalfOf ? ensurePrincipal(pool, event.onBehalfOf) : Promise.resolve(null),
      ensureResource(pool, event.resource),
    ]);

    // See "The on_behalf_of-without-a-grant trap" above: establish the
    // grant this event's own on_behalf_of implies, in the same write,
    // so the on-behalf-of-escalation policy sees a real grant rather than
    // a one-off resource nobody was ever recorded as holding. Idempotent
    // (ON CONFLICT DO NOTHING) — a token's later hops re-derive the same
    // (onBehalfOf, resource) pair fresh each time, never re-granting
    // something already true.
    if (onBehalfOf) {
      await pool.query(
        `insert into grant_edge (principal_id, resource_id, relation, source)
         values ($1, $2, 'can_use', 'adc')
         on conflict (principal_id, resource_id, relation, source) do nothing`,
        [onBehalfOf, resourceId],
      );
    }

    await batcher.append({
      occurredAt: event.occurredAt,
      principalId,
      onBehalfOf,
      resourceId,
      action: event.action,
      decision: event.decision,
      denyReason: event.denyReason,
      taintLabels: [...event.taintLabels],
      reversible: event.reversible,
      requestDigest: event.requestDigest,
    });
  }

  return {
    record(event: GraphEvent): void {
      // Fire-and-forget, tracked so flush() can wait on it — the same
      // "a write failure is logged, never thrown back into the caller"
      // contract broker-audit-sink.ts's own record() uses.
      const task = handle(event).catch((err: unknown) => {
        console.error("principal-graph: failed to record adc-graph event", err);
      });
      pending.add(task);
      void task.finally(() => pending.delete(task));
    },
    async flush(): Promise<void> {
      await Promise.all([...pending]);
    },
  };
}
```

Note the field-for-field pass-through in `batcher.append()` — every
`GraphEvent` field except `principal`/`onBehalfOf`/`resource` (which need
real database access to resolve into row ids) lands on Principal-Graph's
`EventInput` unchanged, by design.

## Testing strategy

No live Principal-Graph, no Postgres — this package has no dependency on
either, so every test runs against real `@adc/core` cryptography only (real
`mintRoot`/`attenuate`/`seal`/`verify`, never a stub), asserting the shape
and content of the `GraphEvent`s this package builds:

- `test/identity.test.ts` — `rootKeyPrincipal()` derives from the public
  key only (never the secret, asserted directly against the raw secret
  bytes), idempotent, deterministic.
- `test/hash.test.ts` — `blockIdentity()`/`blockResource()`/
  `undecodableResource()`/`isBlockIdentity()`: deterministic, collision-free
  between real and fallback identities.
- `test/builders.test.ts` — all six event kinds against real tokens,
  including a full mint → attenuate → attenuate → seal → verify → revoke
  lifecycle asserting every hop's resource identity is distinct except
  where the spec requires them to match (seal and a successful verify both
  reference the same terminal block as the attenuation that produced it;
  revoke targets block 0's identity, not the terminal block); a caveat
  denial and a wrong-root-key denial both still resolve a *real* block
  identity (only a genuinely undecodable token falls back); depth/caveat
  labels never leak a sibling block's data into the wrong event; a
  hand-constructed malformed `ParsedToken` (no blocks, or a blocks/sigs
  length mismatch) is rejected with a clear `RangeError` rather than an
  opaque crash from deep inside `node:crypto`; `buildVerifyEvent`'s
  invalid-UTF-8 and non-decoding `Uint8Array` paths; `buildRevokeEvent`
  rejecting an empty string, a typo'd hash, and one of
  `undecodableResource()`'s own `undecodable:`-prefixed fallback
  identities.
- `test/memory-sink.test.ts` — the reference `GraphSink` implementation.
- `test/index.test.ts` — every export reachable through the package's real
  public entry point (`src/index.ts`) is exercised at runtime, not just
  type-checked — closing a real gap `tsc` alone doesn't catch (a value
  accidentally placed in an `export type {...}` clause instead of a plain
  `export {...}` one compiles and type-checks cleanly but silently drops
  the runtime binding from the built JS).

## Known limitations

- **No live integration test against a real Principal-Graph instance.**
  This package has no Postgres access from this repo — see "Why this
  package emits data, not writes rows" above. The worked reference adapter
  is hand-verified against Principal-Graph's real `EventInput`/
  `ensurePrincipal`/`ensureResource`/`EventBatcher` signatures (cross-checked
  directly against that repo's source), not exercised end-to-end.
- **No idempotent/exactly-once delivery guarantee.** Principal-Graph's own
  `event` table has no caller-supplied dedup key (confirmed directly — see
  "Event identity" above) and `appendEvent()` is a plain `insert`, not an
  upsert; calling a reference adapter's `record()` twice for the same
  logical ADC operation creates two distinct rows. This package emits
  exactly one `GraphEvent` per builder call, so duplication is only a risk
  if the *caller* invokes a builder more than once for the same real
  operation — the same discipline every Principal-Graph event producer
  already relies on (confirmed: the one real precedent for genuine event
  dedup, `postgres-usage.ts`'s time-window check, is a soft, racy heuristic,
  not a hard guarantee).
- **The `on_behalf_of`-without-a-grant trap** (see "A worked reference
  adapter" above) is a real, demonstrated false-positive mechanism in
  Principal-Graph's `on-behalf-of-escalation` policy against a *naive*
  adapter — closed in the reference adapter shown here (it writes a
  `grant_edge` row alongside the event), but only if a real integrator
  actually copies that part too, not just the `event`-only half.
