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
```

### `GET /health`

`200 { "status": "ok" }`, unauthenticated, no RBA call.

## Configuration

| env var | required | meaning |
| --- | --- | --- |
| `MINT_ROOT_SECRET_KEY_B64` | yes | The root Ed25519 secret key, base64, must decode to exactly 32 bytes. **The single most sensitive value this service touches** — never logged, never echoed in an error message (see `src/config.ts`'s doc comment). |
| `RBA_BASE_URL` | yes | e.g. `http://localhost:3000` for a local RBA instance. |
| `RBA_API_KEY` | yes | A bearer key RBA accepts for its read routes (`READONLY_API_KEY` is sufficient — this service never writes to RBA). |
| `PORT` | no (default `3001`) | |
| `RBA_TIMEOUT_MS` | no (default `5000`) | Per-RBA-call timeout, covering the entire request including response body — not just until headers arrive. RBA is a synchronous dependency on the mint path; a hung call must not hang minting indefinitely. |

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
  and bodies for every outcome, oversized-body handling, unknown routes.
- `test/config.test.ts` — env parsing and validation.

## Known limitations

- **No client-side rate limiting.** RBA's own limits (`/scope`: 20
  req/min, `/check`: 200 req/min, per API key) are the only throttle. A
  burst of concurrent mint requests can exceed those and see some
  legitimately-grantable mints rejected as `rba_unavailable` (RBA
  returning 429) rather than queued or retried. Fail-closed under load is
  the intentional trade-off; a retry/backoff or a request queue is future
  work, not required by Phase 4's acceptance criteria.
- **No mint-time authentication of the caller.** Anyone who can reach this
  service can request a mint for any `subject` — RBA's bounding still
  confines what that subject can actually be granted, but *who is allowed
  to ask on Alice's behalf* is a separate concern this phase doesn't
  address (not called for in `docs/PLAN.md`'s Phase 4 either). A real
  deployment sits this behind its own network boundary/auth layer.
- **No Principal-Graph event on rejection.** `docs/PLAN.md`: "the
  rejection is a Principal-Graph event once Phase 6 lands" — Phase 6
  (`packages/adc-graph`) doesn't exist yet, so a `scope_not_granted`
  rejection is only visible in the HTTP response, not emitted anywhere.
