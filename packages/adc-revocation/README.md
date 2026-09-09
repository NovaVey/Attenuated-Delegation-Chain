# @adc/revocation

Signed revocation-list format, signing (for whoever holds the root key —
[`services/mint`](../../services/mint) in this repo), verification, and a
polling client (for a verifier) — [`docs/PLAN.md`](../../docs/PLAN.md)
Phase 7: "Signed revocation list of block-signature hashes, fetched by
verifiers on a poll interval. Revoking a root hash kills every descendant
for free, since every descendant token contains block 0's signature."

## What lives where

`@adc/core`'s own `verify()` performs the actual revocation **check** —
synchronous, offline, against a caller-supplied `Set<string>` (its
`revokedHashes` option; see that package's README's "Revocation" section).
That's deliberate: `docs/PLAN.md` section 0 requires "any verifier can
check that offline with a public key and no network call," so the check
itself has to stay inside `@adc/core`, and `@adc/core` explicitly has "No
integration deps" — it can never own a network-fetching concern.

**This package is what keeps that `Set<string>` current.** It has three
layers:

1. **Format + signing** (`list.ts`, `sign.ts`) — build a
   `RevocationListPayload` from a set of revoked hashes, sign it with the
   root secret key.
2. **Verification** (`verify.ts`) — check a fetched list's signature and
   freshness, never throwing on untrusted input.
3. **A polling client** (`client.ts`) — fetch, verify, and cache on an
   interval, exposing a fail-closed `getRevokedHashes()` for a verifier to
   pass straight into `@adc/core`'s `verify()`.

```
                    ┌─────────────┐   POST /revoke    ┌──────────────────┐
                    │ admin        │ ─────────────────▶│ services/mint     │
                    └─────────────┘                    │ (holds root key)  │
                                                         └────────┬─────────┘
                                                                  │ GET /revocations
                                                                  │ (signed list)
                                                                  ▼
┌──────────────┐  poll (30s)   ┌─────────────────────┐   getRevokedHashes()   ┌────────────────┐
│ verifier      │◀─────────────│ createRevocationClient│◀───────────────────── │ @adc/core verify│
│ process        │               │ (@adc/revocation)     │  passed as opts.revokedHashes         │
└──────────────┘               └─────────────────────┘                        └────────────────┘
```

## Same root key, no separate PKI — the tradeoff

The revocation list is signed by the **same** root secret key that mints
tokens, not a separate revocation-authority keypair. A verifier already
holds and trusts the root public key (it needs it to verify tokens at
all), so no extra key distribution is needed to bootstrap trust in the
list.

The residual, stated openly rather than buried (matching this codebase's
established convention — see `docs/PLAN.md`'s Claim 3 writeup): **a
compromised root key can suppress its own revocations**, the same way it
can already mint an unbounded token. This package doesn't defend against
that; it is a property of key reuse, not a bug in the signing/verification
logic itself. A deployment that wants revocation authority to survive a
minting-key compromise needs a genuinely separate revocation key and its
own distribution story — out of scope for Phase 7.

## Claim 4 — Revocation liveness, the number

> A revoked root kills every descendant within the stated freshness
> window, with the number from Phase 7.

```
liveness bound = list TTL + poll interval + clock skew
               = 60s + 30s + 60s = 150s worst case
```

- **List TTL — 60s** (`DEFAULT_TTL_SECONDS`): how long a signed list
  itself claims to be valid, from its own `issuedAt`.
- **Poll interval — 30s** (`DEFAULT_POLL_INTERVAL_MS`): how often
  `createRevocationClient`'s `start()` refetches.
- **Clock skew — 60s** (`DEFAULT_CLOCK_SKEW_SECONDS`): the allowance
  `verifySignedRevocationList()` grants on both ends of the TTL window,
  matching `@adc/core`'s own `DEFAULT_CLOCK_SKEW_SECONDS` convention.

Worst case: a revocation lands one instant *after* a verifier's client
just finished a poll (so the verifier won't see it for another full poll
interval), and the verifier's *previously cached* list is still treated as
valid for the full TTL-plus-skew window before `getRevokedHashes()`
finally returns `null` and forces a wait for the next successful poll.
Sum the three and a verifier can act on stale-but-not-yet-detected-as-stale
information for up to 150 seconds after a hash is revoked. All three
numbers are overridable per-deployment (`ttlSeconds` on `buildRevocationList()`,
`pollIntervalMs`/`clockSkewSeconds` on `createRevocationClient`) — tightening
any of them shrinks this bound at the cost of more frequent signing/polling.

## Usage

**Signing side** (a mint service holding the root key):

```ts
import { buildRevocationList, signRevocationList } from "@adc/revocation";

const list = buildRevocationList(revokedHashesFromYourStore); // dedupes, sorts, validates
const signed = signRevocationList(list, rootSecretKey);
// serve `signed` (JSON) from an unauthenticated GET route — it's just hashes
```

**Verifier side** (polling client, feeding `@adc/core`'s `verify()`):

```ts
import { createRevocationClient } from "@adc/revocation";
import { verify } from "@adc/core";

const client = createRevocationClient({
  url: "https://mint.example.com/revocations",
  rootPublicKey,
});
client.start(); // fetches immediately, then every pollIntervalMs

// ... later, per-request:
const revokedHashes = client.getRevokedHashes(); // Set<string> | null
const result = verify(tokenBytes, rootPublicKey, facts, { revokedHashes: revokedHashes ?? undefined });
```

`getRevokedHashes()` returns `null` when no list has ever been
successfully fetched, or the cached one has gone stale — **treat `null` as
"revocation status unknown," never as "nothing is revoked."** Passing
`revokedHashes: undefined` to `verify()` when the client returns `null`
means the revocation check is skipped entirely, not "passed" — a verifier
that wants to fail closed on an unknown revocation status should deny
outright rather than call `verify()` at all when `getRevokedHashes()` is
`null`. This package doesn't make that choice for you; it's a
deployment-level policy decision (docs/PLAN.md's own 5.1 already names the
cost: "a checked list costs a network dependency in the verifier, which
partly undoes the offline property" — how a verifier behaves when that
dependency is unavailable is exactly that tradeoff surfacing).

**One-shot verification**, without the polling client (e.g. a batch job
that fetches once):

```ts
import { verifySignedRevocationList } from "@adc/revocation";

const raw: unknown = await (await fetch(url)).json();
const result = verifySignedRevocationList(raw, rootPublicKey);
if (result.ok) {
  // result.revokedHashes: ReadonlySet<string>
} else {
  // result.code: "MALFORMED" | "BAD_SIGNATURE" | "EXPIRED", result.reason: string
}
```

## The signed payload

```jsonc
{
  "payload": {
    "v": "adc-crl1",
    "issuedAt": 1780000000,   // unix seconds
    "ttlSeconds": 60,
    "revoked": ["5b3f...<64 lowercase hex chars, sorted, deduped>"]
  },
  "signature": "base64url..."
}
```

Signed over a domain-separated input distinct from block signing's own:
`"adc-crl1\0" + canonicalEncode(payload)` — a different tag (`adc-crl1` vs.
block signing's `adc-v1`) so a signature over one can never be replayed as
valid for the other, even though both ultimately use the same root key.
Simpler than `@adc/core`'s own multi-field `buildSignInput()`: the
canonical JSON payload is self-delimiting and always the last (only)
variable-length field, so there's no field-boundary ambiguity to guard
against with length prefixes the way a multi-field layout needs.

## Freshness checking, precisely

`verifySignedRevocationList(raw, rootPublicKey, { now, clockSkewSeconds })`
rejects (`EXPIRED`) when either:

- `now < issuedAt - clockSkewSeconds` — the list claims to be issued in the
  future beyond ordinary clock drift. This guards the **signer's** own
  clock drifting forward, not an external forgery risk: only the
  legitimate root-key holder can produce *any* validly-signed list at all,
  so a future-dated `issuedAt` on a correctly-signed list means the
  signer's own clock is wrong, not that someone is attacking the system.
- `now > issuedAt + ttlSeconds + clockSkewSeconds` — the list has
  genuinely gone stale.

## `createRevocationClient`'s caching behavior

- A failed `poll()` (network error, non-2xx, malformed body, bad
  signature, an already-expired list) reports via `onError` and **leaves
  any still-cached, still-fresh value untouched** — a transient blip in
  reaching the mint service doesn't discard a legitimately-still-valid
  revocation set. Staleness is checked live against the wall clock on
  every `getRevokedHashes()` call, independent of whether the *most
  recent* poll attempt succeeded.
- `start()`/`stop()` are idempotent and the interval timer is `unref()`'d
  — holding a client open doesn't prevent a process from exiting.
- `now` is injectable (defaults to the real wall clock) for deterministic
  staleness tests, matching `@adc/core`'s own `Facts.now`/`VerifyOptions`
  testing convention.
- Every `poll()` runs under one `AbortController`/timer (`timeoutMs`,
  default 5000ms) covering the whole operation — connect through reading
  the full response body, not just until headers arrive — matching
  `services/mint/src/rba/client.ts`'s `HttpRbaClient`, the one other HTTP
  client in this codebase. A hung or slow-loris'd `GET /revocations`
  times out rather than hanging `poll()` (and, since `start()`'s interval
  fires new polls regardless of whether a previous one is still
  outstanding, potentially piling up unbounded concurrent hung requests)
  forever.
- Out-of-order responses can't regress the cache: two overlapping polls
  (ordinary network jitter, no attacker needed — a slow response racing
  the next interval tick, or an explicit `poll()` call racing `start()`'s
  own timer) can resolve in either order. `poll()` refuses to let a
  response whose `payload.issuedAt` is older than what's already cached
  overwrite it, regardless of which one actually *settles* last — found
  by adversarial review, reproduced with two concurrent polls where a
  slower, earlier-issued response landed after a faster, newer one and
  silently un-revoked an already-correctly-revoked hash.
- `verifySignedRevocationList()`'s own "never throws on untrusted input"
  contract is backstopped here too: `poll()`'s try/catch covers the fetch,
  the JSON parse, *and* the verify call, so a future regression in the
  verification path degrades to a reported `onError()`, never an
  unhandled rejection in this fire-and-forget call (both `start()`'s
  initial call and its interval invoke `poll()` as `void poll()` — nothing
  else is positioned to catch a throw here).

## Testing strategy

Every test uses real Ed25519 keys and real signing/verification — no stub
crypto:

- `test/list.test.ts` — `buildRevocationList()`: sorting/dedup, defaults,
  hash-shape rejection (non-hex, uppercase, wrong length, empty),
  `ttlSeconds`/`issuedAt` validation.
- `test/sign-verify.test.ts` — real sign→verify round trips (including an
  empty revoked set); a wrong root key, and every kind of post-signing
  tampering (adding/removing a hash, forging `issuedAt`, corrupting the
  signature string) caught as `BAD_SIGNATURE`; the full TTL/clock-skew
  boundary matrix (exactly at the boundary, one second past with zero
  skew, past-TTL-but-within-skew, past both); a suspiciously future-dated
  `issuedAt` beyond skew tolerance rejected as `EXPIRED` rather than
  treated as extra-fresh, alongside a mildly future one (ordinary drift)
  still accepted; an exhaustive list of malformed/null/wrong-typed input
  shapes all denying `MALFORMED` rather than throwing; unexpected extra
  fields ignored, not rejected (forward-compatible); an `issuedAt`/
  `ttlSeconds` beyond `Number.MAX_SAFE_INTEGER` (or `Infinity`/`NaN`)
  denying `MALFORMED` rather than reaching `canonicalEncode()` and
  throwing (a regression test for an adversarial-review finding — see
  below); `revocationSignInput()`/`signRevocationList()` rejecting a
  non-string entry in `payload.revoked` on a hand-built payload that
  bypasses `buildRevocationList()`'s own validation.
- `test/client.test.ts` — against a real local `node:http` mock server
  (matching `services/mint/test/rbaClient.test.ts`'s established pattern):
  fetch→verify→cache on a real signed list; network errors, non-2xx, a
  badly-signed response, and a malformed (non-JSON) body all reporting via
  `onError` and never throwing; a failed refresh leaving a still-fresh
  cached value untouched; `getRevokedHashes()` going to `null` once a
  cached list's own TTL+skew has passed, driven entirely by an injected
  clock (no real waiting); `start()`/`stop()` lifecycle (immediate poll on
  start, the interval firing again, no further polls after stop) and
  `start()`'s idempotency, using short real timers since this specific
  behavior is about real interval scheduling; a hung response (a server
  that accepts the connection and never replies) timing out via `onError`
  rather than hanging `poll()` forever; an out-of-safe-integer-range
  `issuedAt` in the response body reporting via `onError` rather than
  crashing the process (the end-to-end path a hostile/compromised
  `GET /revocations` response would actually take); two overlapping polls
  resolving out of order, confirming the slower, earlier-issued response
  does not regress a cache already holding the faster, newer one's data.

  The last three are regression tests for three real findings from an
  adversarial review of this package's first implementation: (1) an
  out-of-safe-integer-range `issuedAt`/`ttlSeconds` could crash any
  verifier polling a hostile or compromised `GET /revocations` endpoint,
  with no valid signature required (fixed in `verify.ts`'s `parseShape()`
  and backstopped by a catch-all in `verifySignedRevocationList()`
  itself); (2) two overlapping polls could resolve out of order and
  silently regress the cache to older, less-revoked data (fixed by the
  `payload.issuedAt` monotonicity guard in `client.ts`); (3) `poll()` had
  no timeout, so a hung or slow-loris'd endpoint could hang it
  indefinitely (fixed by the `timeoutMs` `AbortController`, matching
  `HttpRbaClient`'s established pattern).

See `packages/adc-core/test/revocation.test.ts` for the paired coverage of
the actual offline check inside `verify()` (revoking block 0 denies every
descendant across multiple attenuation hops and through `seal()`; revoking
an intermediate block denies that hop and its descendants but not a
sibling branch; revocation is checked and takes precedence before caveat
evaluation).

## Known limitations

- **No transport-level authentication on the list itself.** `GET
  /revocations` (`services/mint`'s reference implementation) is served
  unauthenticated — the list contains only hashes, nothing sensitive,
  matching ordinary public CRL/OCSP-list practice. Anyone can read it; the
  signature is what a verifier actually relies on, not who served it.
- **No delta/incremental lists.** Every fetch is the full current revoked
  set. Fine at the scale this project's own store (`services/mint`'s
  in-memory `Set`) implies; a deployment with a very large revoked set
  would want a different wire format.
- **The 150s liveness bound is the default, not a hard limit.** Every
  input to the formula is a per-deployment, overridable default — see
  "Claim 4" above.
