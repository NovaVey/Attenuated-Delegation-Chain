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
- No revocation or RBA/broker/Principal-Graph integration yet — see the
  package's README for exact scope and security notes.
- Phases 3-7 (the reference evaluator and differential fuzzer, RBA mint
  bounding, the broker adapter, Principal-Graph events, revocation) are not
  implemented.

## Packages

```
packages/adc-core   format, sign, attenuate, seal, verify, caveats (Phases 1-2)
```

```
npm install
npm run build --workspaces
npm test --workspaces
```
