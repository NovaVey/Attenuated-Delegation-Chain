# Attenuated-Delegation-Chain
Delegation credentials for AI agents, biscuit-style: attenuable capability tokens that can only narrow at each hop, with a differential-fuzzing proof that no chain of caveats grants authority the root never held.

See [`docs/PLAN.md`](docs/PLAN.md) for the full design and phased build plan.

## Status

- **Phase 1 — done.** [`packages/adc-core`](packages/adc-core) implements the
  wire format, keypair generation, mint/attenuate/seal, and signature-chain
  verification.
- **Phase 2 — done.** The closed caveat vocabulary (`scope`, `sinks`,
  `taint_max`, `expires`, `max_depth`, `hosts`, `aud`) and `verify()`'s
  `facts`/`opts` evaluation against it.
- **Phase 3 — done.** [`packages/adc-testkit`](packages/adc-testkit): an
  independently-written reference evaluator, generators, and a
  differential fuzzer proving `verify()` and the reference evaluator agree
  (150 chains × 20 queries, 0 false grants — see that package's README for
  the full published line), plus property tests for Claims 2 (monotone
  decrease) and 3 (non-removability).
- **Phase 4 — done.** [`services/mint`](services/mint): the HTTP mint
  service. Holds the root key; consults [NovaVey/Relationship-Based-Authorization](https://github.com/NovaVey/Relationship-Based-Authorization)'s
  scope-bounding query (`POST /scope`/`POST /check`) before minting a root
  token, and rejects the whole mint — never silently trims — if a
  requested `scope` grant isn't actually held.
- **Phase 5 — done.** [`packages/adc-broker`](packages/adc-broker): the
  [Taint-Tracked-Tool-Broker](https://github.com/NovaVey/Taint-Tracked-Tool-Broker)
  adapter. `wrapWithAdcGate()` verifies an ADC token — against facts
  derived from live broker state (declared sink capabilities, detected
  destination host, the live taint watermark, the current time) — strictly
  before the call ever reaches the broker's own taint gate; a
  `createAdcAuditRedactor()` helper wires the token out of the audit trail.
- **Phase 6 — done.** [`packages/adc-graph`](packages/adc-graph):
  [Principal-Graph](https://github.com/NovaVey/Principal-Graph) event
  emitters for mint/attenuate/seal/verify-allow/verify-deny/revoke.
  Principal-Graph has no write API or importable library surface, so this
  package builds plain, correctly-shaped event data — event identity is
  the sha256 of each block's Ed25519 signature, the same value Phase 7's
  revocation list reuses — for a Principal-Graph-side adapter to
  consume; see that package's README for the worked reference adapter.
- **Phase 7 — done.** [`packages/adc-revocation`](packages/adc-revocation):
  a signed revocation-list format, signing/verification, and a polling
  client. `@adc/core`'s `verify()` gained an offline `revokedHashes` check
  (Step 4 of its pipeline, before caveat evaluation) against the same
  per-block signature hash Phase 6 defined — now the canonical
  `blockSignatureHash()` in `@adc/core` itself, with `@adc/graph`'s
  `blockIdentity()` delegating to it. [`services/mint`](services/mint)
  gained `POST /revoke` (admin-authenticated) and `GET /revocations`
  (unauthenticated, signed with the same root key that mints). Liveness
  bound: `list TTL (60s) + poll interval (30s) + clock skew (60s) = 150s`
  worst case — see that package's README for the full writeup.

## Packages

```
packages/adc-core      format, sign, attenuate, seal, verify, caveats (Phases 1-2)
packages/adc-testkit   reference evaluator, generators, differential fuzzer (Phase 3, dev-only)
services/mint           HTTP mint service: holds the root key, RBA scope bounding (Phase 4)
packages/adc-broker     Taint-Tracked-Tool-Broker adapter: verify-before-the-gate, facts, redaction (Phase 5)
packages/adc-graph      Principal-Graph event emitters: per-block-signature-hash identity (Phase 6)
packages/adc-revocation signed revocation-list format, signing/verification, polling client (Phase 7)
```

```
npm install
npm run build --workspaces
npm test --workspaces
```

## Consuming this repo

None of the `@adc/*` packages are published to npm (see "Versioning"
below). The only supported way to depend on them today is the way
[Control-Coverage-Range](https://github.com/NovaVey/Control-Coverage-Range)
does: this repo as a git submodule, with the consumer's own
`package.json` pointing `file:` dependencies straight at each package's
directory here (e.g. `"@adc/core": "file:./stack/attenuated-delegation-chain/packages/adc-core"`).

**That means build order is load-bearing, not folklore.** A `file:`
dependency resolves to whatever's on disk at that path *right now* — for
these packages that's `main`/`exports` pointing at `./dist/...`, which
doesn't exist until `npm run build` has actually run. So a consumer's own
`npm install` will fail (or silently resolve to a stale/missing `dist/`)
unless this repo has already been built, in this exact order:

1. Check out (or update) this repo — as a submodule, or otherwise.
2. **Build it**, from this repo's own root: `npm ci && npm run build --workspaces`
   (or `npm run build`, which fans out to every workspace already —
   `--if-present` skips `adc-testkit`, which has no build output any
   consumer needs).
3. *Then* run the consumer's own `npm install` — not before.

Control-Coverage-Range's own `scripts/build-stack.mjs` automates exactly
this (`npm ci && npm run build` in this repo, before its own root
`npm install`); if you're wiring up a new consumer, do the same rather
than discovering the ordering by a confusing install failure.

If this ever moves to option (a) — publishing `@adc/*` under a real npm
scope — this whole section goes away and a consumer just adds a normal
registry dependency. Until then, this is the real constraint, so it's
documented here rather than left for the next person to work out from a
stack trace.

## Versioning

None of the `@adc/*` packages here have been published to npm yet
(`npm run check-published-versions` confirms this on every push/PR — see
`.github/workflows/ci.yml`'s `version-guard` job).

The rule this project follows, adopted from sibling repos that have
already been bitten by the alternative (see
[taint-tracked-tool-broker](https://github.com/NovaVey/Taint-Tracked-Tool-Broker)'s
own CHANGELOG for the incident that established it): **no workspace
package's `version` may ever match an already-published npm version
containing different code.** A git checkout of `main` and a real,
already-published tarball silently claiming the identical version string
while containing different code is exactly the kind of type-drift trap
that's invisible until a downstream consumer — one building `dist/`
directly from a git submodule checkout of `main`, say, per "Consuming
this repo" above — hits it as a confusing bug with no clear cause.

So: once any `@adc/*` package here is ever actually published, `main`
must always sit on an unpublished version from that point forward —
ordinarily a `-dev.N` prerelease strictly above the last real release
(e.g. `0.2.0-dev.0` immediately after publishing `0.1.0`) — bumped to a
real release number only at the moment of publishing, and back up to the
next prerelease immediately after. `scripts/check-published-versions.mjs`
enforces this in CI for every non-`private` workspace package
(`@adc/core`, `@adc/graph`, `@adc/revocation`, `@adc/broker` as of this
writing — `@adc/testkit` and `@adc/mint-service` are `private: true` and
never published, so there's nothing for their version to collide with).
