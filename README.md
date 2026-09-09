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
  revocation list will reuse — for a Principal-Graph-side adapter to
  consume; see that package's README for the worked reference adapter.
- No revocation yet — see the packages'/service's READMEs for exact scope
  and security notes.
- Phase 7 (revocation) is not implemented.

## Packages

```
packages/adc-core      format, sign, attenuate, seal, verify, caveats (Phases 1-2)
packages/adc-testkit   reference evaluator, generators, differential fuzzer (Phase 3, dev-only)
services/mint           HTTP mint service: holds the root key, RBA scope bounding (Phase 4)
packages/adc-broker     Taint-Tracked-Tool-Broker adapter: verify-before-the-gate, facts, redaction (Phase 5)
packages/adc-graph      Principal-Graph event emitters: per-block-signature-hash identity (Phase 6)
```

```
npm install
npm run build --workspaces
npm test --workspaces
```
