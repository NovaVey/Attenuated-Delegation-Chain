# @adc/mint-service

The HTTP mint service — [`docs/PLAN.md`](../../docs/PLAN.md) Phase 4:
"Mint consults RBA's scope-bounding query. A root token can never contain a
(resource, relation) pair Alice does not actually hold at mint time. Reject
the whole mint rather than silently trimming."

Holds the root Ed25519 secret key and the only network dependency in this
codebase: a call out to [NovaVey/Relationship-Based-Authorization](https://github.com/NovaVey/Relationship-Based-Authorization)
("RBA") before minting a root token, to confirm the requested `scope`
caveat is actually backed by real grants. Everything else (`@adc/core`'s
`attenuate()`/`seal()`/`verify()`) stays offline — this service exists
*because* minting specifically needs the root key and RBA access,
per `docs/PLAN.md` section 0.

Also the reference **signing and serving side of revocation**
([`docs/PLAN.md`](../../docs/PLAN.md) Phase 7, `POST /revoke` and
`GET /revocations` below): the root key that mints tokens is the same key
that signs the revocation list, so this is the natural place to hold the
revoked-hash store too, rather than standing up a separate service around
the same secret.

## Why HTTP, not an imported library

RBA is a separate, sibling service with no importable library surface —
its own `package.json` has no `main`/`exports` field, only a CLI `bin`
entry, and its README/Dockerfile both point at running it as an HTTP
server. `src/rba/client.ts` is therefore a thin, hand-rolled client
against its wire contract (`docs/openapi.json` in that repo), not a
generated SDK — the exact request/response shapes below were confirmed
directly against that file, not just against README prose.

## The bounding query

A `scope` caveat's triples are `[resourceKind, resourceId | '*', relation]`.
These map to two different RBA endpoints:

| triple shape | RBA endpoint | what it answers |
| --- | --- | --- |
| `resourceId === '*'` | `POST /scope` | "does subject hold `relation` on *any* resource in this namespace" — built by RBA's own maintainers for exactly this use case (see that repo's `docs/DECISIONS.md`, D-186, and `docs/INTEGRATION.md`'s "Bounding a delegation credential's own scope") |
| a specific `resourceId` | `POST /check` | a point check on that exact `(subject, relation, object)` triple |

**All-or-nothing.** Every distinct triple across every `scope` caveat in
the mint request must be confirmed granted, or the whole mint is rejected
— `src/bounding.ts` never mints a narrower token than what was asked for.
A per-target RBA error, an unconfirmed (`truncated: true`) scan, or the
whole RBA call failing (network error, timeout, non-2xx, a malformed
response) are all treated identically to "not granted": fail closed, per
RBA's own documented recommendation for an unreachable check, extended
here to every other way a call can fail to produce a trustworthy answer.
Only `scope` caveats go through this — the other six kinds (`sinks`,
`taint_max`, `expires`, `max_depth`, `hosts`, `aud`) have nothing to check
against a relationship graph and pass through untouched.

## API

### `POST /mint`

```jsonc
// Request
{
  "subject": { "ns": "user", "id": "alice" },
  "caveats": [
    { "kind": "scope", "triples": [["repo", "*", "read"]] },
    { "kind": "expires", "at": 1780000000 }
  ]
}
```

```jsonc
// 201 — success
{ "token": "adc1. ...", "depth": 0 }

// 403 — one or more requested scope grants aren't held
{
  "error": {
    "code": "scope_not_granted",
    "message": "one or more requested scope grants are not held by subject at mint time",
    "details": [
      { "kind": "not_granted", "resourceKind": "repo", "resourceId": "*", "relation": "read" }
    ]
  }
}

// 502 — RBA unreachable (fails closed, not open)
{ "error": { "code": "rba_unavailable", "message": "..." } }

// 400 — malformed request (missing/extra fields, an invalid caveat, an
// unrecognized caveat kind — @adc/core's own closed-vocabulary rejection
// runs here, before any RBA call)
{ "error": { "code": "invalid_request", "message": "..." } }

// 429 — this service's own rate limit (MINT_RATE_LIMIT_PER_MINUTE),
// checked FIRST — before body parsing, before any RBA call
{ "error": { "code": "rate_limited", "message": "..." } }
```

A successful mint also records exactly one `'mint'` Principal-Graph event
— see "Principal-Graph events" below.

### `GET /health`

`200 { "status": "ok" }`, unauthenticated, no RBA call.

### `POST /revoke` — [`docs/PLAN.md`](../../docs/PLAN.md) Phase 7

Admin-authenticated (`Authorization: Bearer <MINT_ADMIN_API_KEY>`, checked
with a length-then-`timingSafeEqual` comparison). Marks a block-signature
hash — the same identity `@adc/core`'s `blockSignatureHash()` computes, sha256
hex of a block's raw Ed25519 signature — as revoked. Revoking block 0's
hash (the root signature every descendant token also carries) kills every
token minted from that root, for free; that's the whole mechanism.

```jsonc
// Request — "reason" is optional free text (max 500 chars), carried into
// the Principal-Graph event's taintLabels (see below); defaults to
// "revoked via POST /revoke" if omitted
{ "hash": "5b3f...<64 lowercase hex chars>", "reason": "compromised key, incident #42" }

// 200 — success (idempotent: revoking an already-revoked hash is a no-op, not an error)
{ "revoked": "5b3f..." }

// 401 — missing or wrong admin bearer token
{ "error": { "code": "unauthorized", "message": "..." } }

// 400 — malformed body, a hash that isn't 64 lowercase hex chars, a
// non-string "reason", or a "reason" over 500 characters
{ "error": { "code": "invalid_request", "message": "..." } }
```

A successful revoke also records exactly one `'revoke'` Principal-Graph
event — see "Principal-Graph events" below.

Revoked hashes live in an **in-memory store by default, optionally
file-backed** (`MINT_REVOCATION_STORE_PATH`) — see Configuration and
Known limitations below.

### `GET /revocations` — [`docs/PLAN.md`](../../docs/PLAN.md) Phase 7

Unauthenticated (the list contains only hashes, nothing sensitive —
matching ordinary public CRL/OCSP-list practice). Builds and signs a
*fresh* `@adc/revocation` `SignedRevocationList` from the current store
contents on every request, using the same root secret key that mints
tokens (no separate revocation-authority key or PKI — see
`packages/adc-revocation`'s README for the tradeoff this implies).

```jsonc
// 200
{
  "payload": { "v": "adc-crl1", "issuedAt": 1780000000, "ttlSeconds": 60, "revoked": ["5b3f..."] },
  "signature": "..."
}
```

A verifier doesn't call this route directly in normal operation — it
points `@adc/revocation`'s `createRevocationClient({ url: "<mint-base-url>/revocations", rootPublicKey })`
at it, which polls, verifies the signature, and exposes a fail-closed
`getRevokedHashes()` for `@adc/core`'s `verify()` to check against. See
that package's README for the full liveness-bound writeup (the "150s
worst case" number from Phase 7) and the client's caching/staleness
behavior.

## Principal-Graph events

[`docs/PLAN.md`](../../docs/PLAN.md) Phase 6: mint, attenuate, verify-allow,
verify-deny, seal, revoke. This service can only ever produce two of those
six — `'mint'` (on a successful `POST /mint`) and `'revoke'` (on a
successful `POST /revoke`) — using `@adc/graph`'s existing `buildMintEvent()`/
`buildRevokeEvent()` builders as-is, recorded into an injectable `GraphSink`
(`createMintServer({ graphSink, ... })`).

Two `GraphSink` implementations are actually usable here, both from
`@adc/graph`:

- **`createInMemoryGraphSink()`** — the default when `graphSink` isn't
  supplied and `MINT_GRAPH_EVENTS_PATH` isn't set. Private and
  process-local: events accumulate in memory and nothing outside the
  process can ever observe them. Fine for tests; not useful in a real
  deployment.
- **`createNdjsonGraphSink({ filePath })`** — wired in automatically when
  `MINT_GRAPH_EVENTS_PATH` is set (see Configuration): appends each event
  as one JSON line to that file, a standard audit-log shape an operator
  can tail, ship to a log pipeline, or eventually feed into a real
  Principal-Graph-side consumer. See `@adc/graph`'s README for the full
  writeup (including its `stream` mode, for logging to stdout instead of
  a file — not wired into this service's own config, but available to
  anyone constructing `createMintServer()` directly).

A real Principal-Graph-side sink (one that actually calls
`ensurePrincipal()`/`ensureResource()` against that project's own
database) is a bigger lift than either of the above — see `@adc/graph`'s
README for what one looks like — and isn't wired into this service by
default; inject it via the same `graphSink` option.

- **`'mint'`** — principal is derived automatically from the root public
  key (`rootKeyPrincipal()`); the event references the exact block-0
  identity of the token just minted. `onBehalfOf` is deliberately left
  `null`: the mint request's `subject` (`{ns, id}`) is an open, RBA-defined
  namespace with no fixed mapping onto `@adc/graph`'s closed
  `human | agent | service` principal-kind enum, and this package's own
  convention is "`null` when not attributable — never guessed" (see
  `@adc/graph`'s `GraphEvent.onBehalfOf` doc comment).
- **`'revoke'`** — principal is a single, fixed `{kind: 'service', source:
  'adc-mint-admin', externalId: 'admin'}` identity, since `POST /revoke`
  has no finer-grained caller identity than "held the shared admin bearer
  token" (see Known limitations). The request's optional `"reason"` field
  rides in the event's `taintLabels`.
- **Rejections are not represented.** `docs/PLAN.md`'s Phase 4 line — "the
  rejection is a Principal-Graph event once Phase 6 lands" — turns out not
  to be buildable with `@adc/graph`'s actual, shipped event vocabulary: a
  `scope_not_granted` mint rejection never produces a token, so there is no
  block, no signature, and nothing to derive a Principal-Graph `resource`
  identity from (`buildMintEvent()` requires a real minted `ParsedToken`).
  Representing a rejection would mean extending `@adc/graph`'s own,
  already-shipped API with a new resource kind — out of scope here; see
  Known limitations.
- **A sink failure never breaks the HTTP response.** `GraphSink.record()`
  is documented to be synchronous and never throw back into its caller,
  but this service doesn't rely on that being honored perfectly by every
  injected sink — a throwing sink is caught and reported via
  `onInternalError`, after the mint/revoke has already durably succeeded
  and its response already sent.

## Configuration

| env var | required | meaning |
| --- | --- | --- |
| `MINT_ROOT_SECRET_KEY_B64` | yes | The root Ed25519 secret key, base64, must decode to exactly 32 bytes. **The single most sensitive value this service touches** — never logged, never echoed in an error message (see `src/config.ts`'s doc comment). |
| `RBA_BASE_URL` | yes | e.g. `http://localhost:3000` for a local RBA instance. |
| `RBA_API_KEY` | yes | A bearer key RBA accepts for its read routes (`READONLY_API_KEY` is sufficient — this service never writes to RBA). |
| `MINT_ADMIN_API_KEY` | yes | Bearer token required on `POST /revoke`. A secret, but narrower blast radius than the root key: holding it lets someone revoke blocks, not mint or forge tokens. |
| `PORT` | no (default `3001`) | |
| `RBA_TIMEOUT_MS` | no (default `5000`) | Per-RBA-call timeout, covering the entire request including response body — not just until headers arrive. RBA is a synchronous dependency on the mint path; a hung call must not hang minting indefinitely. |
| `MINT_RATE_LIMIT_PER_MINUTE` | no (default `60`) | Service-wide `POST /mint` rate limit (a token bucket — see `src/rate-limiter.ts`), independent of and in addition to RBA's own per-API-key limits. Checked before body parsing or any RBA call. |
| `MINT_REVOCATION_STORE_PATH` | no (default unset — in-memory only) | Path to a JSON file the revocation store loads from at startup and writes through to on every successful revoke, so revocations survive a restart. See `src/revocation-store.ts` and Known limitations. |
| `MINT_GRAPH_EVENTS_PATH` | no (default unset — private in-memory sink) | Path to an NDJSON file every `'mint'`/`'revoke'` Principal-Graph event is appended to (`@adc/graph`'s `createNdjsonGraphSink`). See "Principal-Graph events" above. **Must not be the same path as `MINT_REVOCATION_STORE_PATH`** — `loadConfigFromEnv()` rejects that combination at startup (see Known limitations): the two files are written by incompatible strategies (replace vs. append) and would corrupt each other. |

## Running

```
npm run build   # also builds @adc/core first if needed — see prebuild
npm test        # node:test over dist/test/*.test.js, no network/Docker required
npm start        # requires the env vars above; talks to a real RBA instance
```

Against a local RBA for manual testing, from a checkout of that repo:
`cp .env.example .env && docker compose up -d` brings up Postgres +
RBA on `:3000` in one command (see that repo's own docker-compose.yml and
README).

## Testing strategy

No test in this package talks to a real RBA instance — no Docker, no
Postgres, no live network dependency for `npm test`:

- `test/bounding.test.ts` — the all-or-nothing bounding logic, against
  `src/rba/fake.ts`'s in-memory `FakeRbaClient`. Covers wildcard and point
  triples, cross-subject/cross-resource non-bleed-through, the per-target
  error/truncated-scan cases, RBA unreachability, deduplication, the
  request-size caps, and hardening regressions (a malformed short
  response, a non-boolean truthy `granted`/`allowed` value) that a
  correctly-typed fake alone wouldn't exercise.
- `test/rbaClient.test.ts` — `HttpRbaClient` against a local mock HTTP
  server built from RBA's actual `docs/openapi.json` shapes: request
  bodies, mixed success/error/truncated responses, RBA's `ApiError`
  envelope, non-JSON bodies, and — the one this suite specifically
  regression-tests — a response that stalls *after* headers arrive,
  which used to hang forever because the timeout was cleared as soon as
  `fetch()`'s own promise resolved (headers received), before the body
  had necessarily finished streaming.
- `test/mint.test.ts` — the full `mintWithBounding()` pipeline: request
  validation (including that a structurally invalid caveat or scope
  triple is rejected *before* it ever reaches bounding logic that isn't
  shaped to handle it, and before any RBA call), and that a rejected mint
  never produces a token.
- `test/server.test.ts` — the real HTTP server end-to-end, status codes
  and bodies for every outcome, oversized-body handling, unknown routes;
  also `POST /revoke`/`GET /revocations`: admin-auth success/failure
  (including the length-mismatch path through the constant-time
  comparison), idempotent revocation, malformed input, an injected
  `RevocationStore` for pre-seeding, and a full end-to-end test that
  mints a real token through this server, revokes its block-0 hash, and
  confirms `@adc/core`'s `verify()` denies it with `ADC_REVOKED` using the
  exact signed list this server served; a successful mint/revoke each
  recording exactly one correctly-shaped Principal-Graph event via an
  injected `GraphSink`, a rejected/invalid request recording none, an
  optional `"reason"` field on `POST /revoke` landing in the event's
  `taintLabels`, and a throwing `GraphSink` never affecting the HTTP
  response (only reported via `onInternalError`); `POST /mint`'s rate
  limit returning 429 once exhausted (independent of request validity,
  and not affecting `GET /health`/`POST /revoke`), and an injected
  `mintRateLimiter` overriding the config-derived default.
- `test/rate-limiter.test.ts` — the token-bucket limiter on its own:
  allows a burst up to `limit`, denies beyond it with no time passed,
  refills proportional to elapsed time via an injected clock (no real
  waiting), never refills past `limit` even after an enormous idle gap,
  independent buckets per instance, and input validation.
- `test/revocation-store.test.ts` — the store, both in-memory (idempotent
  `revoke()`, hash-shape validation, `list()` contents) and file-backed:
  a fresh file path starts empty and the first `revoke()` creates it,
  revocations surviving a simulated restart (a second `RevocationStore`
  instance against the same file), idempotent `revoke()` performing no
  disk write for an already-revoked hash, nested parent directories being
  created automatically, a corrupt (non-JSON) or wrong-shaped file being
  refused at load time rather than silently starting with an empty (==
  "nothing revoked") set, a hand-seeded pre-existing file loading
  correctly, and a disk-write failure leaving the in-memory state
  untouched rather than accepting the revoke only in memory.
- `test/config.test.ts` — env parsing and validation, including
  `MINT_ADMIN_API_KEY`, `MINT_RATE_LIMIT_PER_MINUTE`,
  `MINT_REVOCATION_STORE_PATH`, `MINT_GRAPH_EVENTS_PATH`, and the
  same-file collision check between the latter two (including that it
  resolves paths first — a relative path and its absolute equivalent
  still collide).
- `test/graph-sink.test.ts` — `buildGraphSinkFromConfig()`, the exact
  function `index.ts` calls to turn `MINT_GRAPH_EVENTS_PATH` into a real
  `GraphSink`: `undefined` in, `undefined` out; a real path in, a real,
  working sink out that durably writes to that exact path. Split out so
  this one piece of `index.ts`'s own wiring has direct test coverage —
  `index.ts` itself can't be imported in a test without triggering its
  real `loadConfigFromEnv()` side effect (found as a real coverage gap by
  adversarial review: a future typo here — building the sink but
  forgetting to pass it through, say — could leave
  `MINT_GRAPH_EVENTS_PATH` silently inert in production while every other
  test kept passing).

`test/server.test.ts` also has one integration test using `@adc/graph`'s
*real* `createNdjsonGraphSink` (not a stub) wired straight into a real
`createMintServer()` instance — a real mint and a real revoke through the
live HTTP server, then reading the actual NDJSON file back off disk to
confirm both events landed there correctly and in order. `@adc/graph`'s
own `test/ndjson-sink.test.ts` covers the sink's own behavior in
isolation (file vs. stream mode — including an `'error'` event on the
stream being safely routed to `onError` rather than crashing the process,
and missing parent directories being created automatically rather than
silently losing every event — both found by adversarial review,
append-not-truncate across a simulated restart, `Date`/`null`-field
serialization, input validation).

## Known limitations

- **`POST /mint`'s rate limit is service-wide, not per-caller.** There's
  no caller identity to key a per-caller limit on (see the next bullet) —
  `MINT_RATE_LIMIT_PER_MINUTE` is a single token bucket shared by every
  caller. RBA's own limits (`/scope`: 20 req/min, `/check`: 200 req/min,
  per API key) remain the limiting factor for how much *scope-bounding*
  traffic this service can actually sustain; this rate limit protects
  this service's own front door (and, transitively, RBA) from a runaway
  or malicious client, not RBA's per-key throughput. A legitimately busy,
  well-behaved deployment can still raise `MINT_RATE_LIMIT_PER_MINUTE` as
  needed.
- **No mint-time authentication of the caller.** Anyone who can reach this
  service can request a mint for any `subject` — RBA's bounding still
  confines what that subject can actually be granted, but *who is allowed
  to ask on Alice's behalf* is a separate concern this phase doesn't
  address (not called for in `docs/PLAN.md`'s Phase 4 either). A real
  deployment sits this behind its own network boundary/auth layer. Left
  as documented, by design — deliberately not reversed even though
  `POST /revoke` gained its own admin auth in the same round of work that
  added the rate limiter above, because `POST /revoke` is a rare,
  single-operator admin action while `POST /mint` is this service's
  entire normal traffic, with no established caller-identity model to
  authenticate against.
- **Rejected mints produce no Principal-Graph event.** See "Principal-Graph
  events" above for why: `@adc/graph`'s shipped event vocabulary has
  no way to represent an attempt that never produced a token. Successful
  mints and successful revokes DO now emit real events (also see
  "Principal-Graph events" above) — this is what remains unrepresented.
- **With no `graphSink` injected and `MINT_GRAPH_EVENTS_PATH` unset, the
  default is still a private, process-local, in-memory sink.**
  `createMintServer()` falls back to `@adc/graph`'s own
  `createInMemoryGraphSink()` — events accumulate in memory and are never
  actually consumed by anything. Setting `MINT_GRAPH_EVENTS_PATH` (see
  Configuration) closes most of this gap — events land in a real,
  durable, tail-able NDJSON file — but there's still no real
  HTTP-forwarding `GraphSink`, and can't sensibly be one this service
  defaults to on its own: Principal-Graph itself has no write API (see
  `@adc/graph`'s own README), so an actual Principal-Graph-side
  integration is always a deployment-specific sink someone builds and
  injects via `createMintServer({ graphSink, ... })`.
- **Revoked hashes are in-memory only unless `MINT_REVOCATION_STORE_PATH`
  is set.** With it unset (the default), `src/revocation-store.ts` is a
  plain `Set`; restarting this process un-revokes everything it held. With
  it set, revocations survive a restart via a synchronous, atomic
  (write-temp-then-rename) file write on every `revoke()` — see that
  file's own doc comment. **Single-writer only**: file-backed mode has no
  cross-process locking, so it's sized for this service's actual
  deployment shape (one process holding the one root key), not multiple
  instances sharing one file.
- **`MINT_REVOCATION_STORE_PATH` and `MINT_GRAPH_EVENTS_PATH` must be
  different files.** `loadConfigFromEnv()` throws at startup if they
  resolve to the same path — found by adversarial review: the revocation
  store does a full atomic *replace* of its file on every `revoke()`
  while the graph-events sink only ever *appends*, so the same path would
  have each silently corrupt the other (a revoke wiping out prior NDJSON
  history, then the next graph event appending NDJSON after the
  revocation store's own JSON object, which that store's own constructor
  then refuses to load on the next restart). This is the one
  misconfiguration checked for; nothing stops either path from colliding
  with some unrelated file the operator cares about.
- **Revocation reuses the root key — no separate revocation-authority
  key.** `POST /revoke`/`GET /revocations` sign with the same
  `MINT_ROOT_SECRET_KEY_B64` that mints tokens. Verifiers already trust
  that key, so no extra PKI is needed to bootstrap trust in the
  revocation list — but it also means a compromised root key can suppress
  its own revocations, same as it can mint anything. Documented, not
  fixed; see `packages/adc-revocation`'s README for the fuller writeup.
