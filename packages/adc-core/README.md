# @adc/core

Format, sign, attenuate, seal, verify for Attenuated Delegation Chain tokens.
No integration dependencies — see [`docs/PLAN.md`](../../docs/PLAN.md) for the
full design.

**Scope so far (Phases 1-2).** Signature-chain integrity (mint, attenuate,
seal, verify the chain and proof) plus the closed caveat vocabulary
(`scope`, `sinks`, `taint_max`, `expires`, `max_depth`, `hosts`, `aud`) and
its evaluation against caller-supplied facts. It does **not** check
revocation or consult Relationship-Based-Authorization — those land in
Phases 4 and 7. A `verify()` `Allow` means *the chain is a validly signed,
non-tampered, non-truncated attenuation of the given root key, and every
caveat in every block is satisfied by the supplied facts* — it says
nothing about revocation, and nothing beyond what the caveats you actually
minted encode (an unrestricted token, i.e. one with no caveats at all,
still verifies).

## Format

A token is a chain of blocks plus a proof, wire-encoded as:

```
adc1.<b64url(block0)>.<b64url(sig0)>. … .<b64url(blockN)>.<b64url(sigN)>.<proof>
```

- `adc1` — version tag.
- Each block is canonical JSON (`{"alg":"ed25519","nk":"…","c":[…]}`, keys
  sorted, no floats, no insignificant whitespace), base64url-encoded
  unpadded.
- `sig_i` is `Ed25519_Sign(secret_{i-1}, toSign_i)`, where `secret_{i-1}` is
  the root secret key for block 0, or the next-secret embedded in block
  `i-1` for every later block.
- `toSign_i = "adc-v1" || 0x00 || u32be(len(blockBytes_i)) || blockBytes_i
  || 0x01 || nextPubKey_i || prevSignature_{i-1}` — domain-separated,
  length-prefixed, and bound to the previous block's own signature so a
  block can never be transplanted onto a different chain that happens to
  share a key-derived prefix.
- The final segment is the **proof**: `k<b64url(secret)>` for an
  attenuable token (the holder can delegate further), or
  `s<b64url(sig)>` for a sealed token (no further attenuation possible —
  the sealing signature is `Ed25519_Sign(lastSecret, lastBlockSignature)`,
  after which the secret is discarded).

Depth is always `blocks.length - 1`, read from the wire structure — never
a self-reported field inside a block.

**The proof field on an attenuable token is a private key**, not an
opaque identifier. Treat it accordingly: never log it, never put it in an
audit sink, never mistake it for a token id.

## API

```ts
import {
  generateKeypair,
  mintRoot,
  attenuate,
  seal,
  verify,
  encodeToken,
  decodeToken,
} from "@adc/core";

// Minting (would normally happen in the mint service, with the root
// secret key, after an RBA scope-bounding check — Phase 4).
const root = generateKeypair();
let token = mintRoot(root.secretKey, {
  caveats: [
    { kind: "scope", triples: [["repo", "*", "read"]] },
    { kind: "expires", at: Math.floor(Date.now() / 1000) + 3600 },
  ],
});

// Attenuating narrows further (offline — no network call, no root key
// needed). A holder can only add caveats, never remove one an earlier
// hop added.
token = attenuate(token, { caveats: [{ kind: "sinks", classes: ["net:email"] }] });

// Sealing before handing to the least-trusted hop.
const sealed = seal(token);

// Verifying (offline — only the root public key is needed). `facts` are
// what the caller — typically the broker — actually observed about the
// action being authorized.
const wire = encodeToken(sealed);
const result = verify(wire, root.publicKey, {
  resourceKind: "repo",
  resourceId: "123",
  relation: "read",
  sink: "net:email",
});
if (result.ok) {
  console.log("depth", result.depth, "usedClockSkew", result.usedClockSkew);
} else {
  console.log("denied:", result.code, result.reason);
}
```

`verify()` never throws on token input — every malformed, tampered,
hostile, or caveat-violating wire string resolves to
`{ ok: false, code, reason }` with one of the reason codes in
`REASON_CODES` (`AdcError`/thrown errors are reserved for programmer
misuse of the minting API, e.g. calling `attenuate()` on a sealed token,
or passing a structurally invalid caveat to `mintRoot()`/`attenuate()`).

## Caveats

The seven kinds from docs/PLAN.md 1.5 — a **closed vocabulary**, not a
logic language. `mintRoot()`/`attenuate()` accept a typed `Caveat` union
(`{kind: "scope" | "sinks" | "taint_max" | "expires" | "max_depth" |
"hosts" | "aud", ...}`) and validate it (structure, closed-vocabulary
membership) before embedding it — a malformed caveat throws
`AdcError("ADC_MALFORMED", …)` at mint/attenuate time rather than failing
confusingly later at `verify()`.

`verify()`'s facts argument (2nd positional param) supplies what the
caller observed: `resourceKind`, `resourceId`, `relation` (for `scope`),
`sink` (`sinks`), `host` (`hosts`), `taintLevel` (`taint_max`), `audience`
(`aud`), and `now` (`expires` — defaults to the real wall clock if
omitted, pass it explicitly for deterministic tests). **A caveat whose
required fact wasn't supplied denies** rather than passing — there is no
silent "not applicable" case.

Every caveat in every block must independently be satisfied
(`verify()`'s step 5); there's no special cross-block merging logic
because a plain AND across every caveat instance already gives the right
answer:

- `expires`/`max_depth`: requiring `now <= at_i` (or `depth <= depth_i`)
  for *every* instance `i` is exactly requiring it hold against the
  **minimum** across all blocks — the "attenuation only narrows" property
  falls out of the composition rule for free, not from special-cased
  aggregation.
- `scope`/`sinks`/`hosts`/`taint_max`/`aud`: each additional caveat of
  that kind is one more constraint the fact must also satisfy, i.e. an
  intersection of permitted sets (or ceilings, or required values) across
  the chain.

**An unrecognized caveat `kind` denies with `ADC_MALFORMED`, it is never
silently skipped.** A verifier that ignored a caveat kind it didn't
recognize would *widen* effective authority instead of narrowing it — the
opposite of what a caveat is for. This is what makes the closed vocabulary
enforceable rather than aspirational.

`resourceKind`/`resourceId`/`relation` (scope) and sink classes (sinks)
are validated for *shape* only (non-empty strings; sink classes as
`namespace:action`), not against a hardcoded enum — those namespaces are
owned by RBA and the broker respectively, sibling packages this package
takes no dependency on (docs/PLAN.md section 2). `taint_max`'s three
levels are the one closed enum defined here, since the ordering
(`TRUSTED < DERIVED < RAW_UNTRUSTED`) is part of this spec, not an
external system's.

## Security notes specific to this package

- Ed25519 verification runs in strict RFC 8032/FIPS 186-5 mode
  (`{ zip215: false }`), not `@noble/curves`'s permissive default. Under
  the default cofactored (ZIP215) mode, certain low-order `(publicKey,
  signature)` pairs verify against *any* message; since a block's `nk` is
  attacker-influenced token content, feeding it into permissive
  verification would let a hand-crafted degenerate `nk` make forged
  continuations of a chain verify without the real secret. See
  `crypto.ts` and the corresponding regression test.
- Signature verification always runs over the exact raw bytes retained
  from decoding (or produced at mint/attenuate time) — never over a
  re-serialization of a parsed block. `decodeBlock()` is read-only; it is
  used to extract fields like `nk`, never to reconstruct the bytes that
  get signed or verified.
- `verify()` checks the structural depth cap (`maxDepth`) before decoding
  any individual block or signature payload — segment count (and
  therefore depth) is derivable from the cheap `.`-split alone
  (`wire.ts`'s `splitSegments`/`blockCountForSegments`), so an
  over-deep token is denied without paying for a base64 decode of
  every block/sig it carries.
- `mintRoot()`/`attenuate()` validate the `nextKeypair` testing hook when
  supplied: the secret must actually derive the given public key, and the
  returned token never shares a live buffer with the caller's `Keypair`
  object (the secret is copied). Without this, a caller who passed a
  mismatched keypair would get a token back with no error at all, only
  failing much later and confusingly, far from the actual mistake, at
  `verify()`.

## Adversarial review (Phase 1)

Before Phase 1 was committed, an independent multi-pass review (wire
format, `verify()` logic, the mint/attenuate/seal API surface, and test
coverage, each finding then adversarially re-verified) found 8 real
issues, all fixed here: the two hardening items above, `seal()` missing
the same blocks/sigs consistency check `attenuate()` has, and — the most
interesting one — that the original "swap a block between two tokens
sharing a prefix" tests passed for the *wrong* reason (an ordinary
next-key mismatch) rather than actually isolating the `prevSignature`
binding docs/PLAN.md 1.3 calls non-negotiable. `test/hardening.test.ts`
has the regression tests, including one that constructs two sibling
attenuations sharing the same `nk` (via the `nextKeypair` hook) so a
splice can only be caught by `prevSignature`, not by the key chain.

## Testing

```
npm run build   # tsc + copy test fixtures into dist/
npm test        # node:test over dist/test/*.test.js
```

- `test/roundtrip.test.ts` — the Phase 1 acceptance criteria: round-trip
  at depths 0-8, single-byte flips, block swaps between tokens sharing a
  prefix, prefix truncation, sealed-then-attenuate.
- `test/format.test.ts` — unit tests for canonical encoding, the byte
  helpers, the exact `toSign_i` layout, and block/wire encode-decode.
- `test/property.test.ts` — `fast-check` properties: canonical-encoding
  determinism, honest chains always verifying, single-byte mutations
  always denied, cross-root verification always failing, and (Phase 2)
  `expires`/`max_depth` agreeing with the minimum-across-blocks rule for
  randomized values.
- `test/golden-vectors.test.ts` + `test/fixtures/golden-vectors.json` —
  pins the wire format against tokens generated from fixed key material
  (`scripts/gen-golden-vectors.mjs`), so an accidental format change is
  caught here before anything else depends on it. Includes both positive
  vectors (must verify) and negative vectors (specific, committed
  corrupted byte strings that must be denied with a specific reason
  code) — the latter catch a regression that silently *widens*
  acceptance, which positive vectors alone cannot.
- `test/hardening.test.ts` — regression tests for the Phase 1
  adversarial-review findings below.
- `test/caveats.test.ts` — per-caveat unit tests including boundary cases
  (expiry exactly at expiry/skew boundary, `max_depth` exactly at the
  limit, `taint_max` exactly at the ceiling), the minimum-across-blocks
  behavior for `expires`, closed-vocabulary rejection, and mint-time
  validation. `test/property.test.ts` adds `fast-check` properties
  confirming `expires`/`max_depth` agree with the minimum-across-blocks
  rule for randomized values, not just the hand-picked cases.
