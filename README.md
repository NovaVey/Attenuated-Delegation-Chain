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
- No revocation or RBA/broker/Principal-Graph integration yet — see the
  packages' READMEs for exact scope and security notes.
- Phases 4-7 (RBA mint bounding, the broker adapter, Principal-Graph
  events, revocation) are not implemented.

## Packages

```
packages/adc-core      format, sign, attenuate, seal, verify, caveats (Phases 1-2)
packages/adc-testkit   reference evaluator, generators, differential fuzzer (Phase 3, dev-only)
```

```
npm install
npm run build --workspaces
npm test --workspaces
```
