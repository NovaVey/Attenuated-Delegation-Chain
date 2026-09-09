# Attenuated-Delegation-Chain — Build Plan

Status: Phases 1-7 implemented (`packages/adc-core`, `packages/adc-testkit`, `services/mint`, `packages/adc-broker`, `packages/adc-graph`, `packages/adc-revocation`).

## 0. What this is

A bearer credential that says *this agent is acting for Alice, with this narrowed
subset of her authority, until this time, at this hop depth*. Every delegation hop
can only narrow, never widen, and any verifier can check that offline with a public
key and no network call.

It exists because the rest of the stack assumes it. Relationship-Based-Authorization
declares authentication out of scope and treats subjects as opaque ids. The
Taint-Tracked-Tool-Broker's `sessionId` is a label copied into audit records.
Principal-Graph can detect an on-behalf-of escalation after the fact but nothing in
the stack can prevent one. This is the missing noun.

Ships as an ESM library plus a small mint service. Minting is separate because it
needs the root private key and RBA access; verification needs neither.

---

## 1. Decisions locked before Phase 1

### 1.1 Format: biscuit shape, not macaroons

Macaroons are simpler, but HMAC chaining means every verifier needs the root secret.
That is wrong when the verifier is a broker running inside someone else's process.
Asymmetric signatures, offline attenuation, caveats evaluated at verification time.
The broker verifies with a public key and never holds minting authority.

### 1.2 Token = blocks + proof, and the proof is a key

Block 0 (the authority block) is signed by the root private key. Every block carries
a **next public key**. Block *i*'s signature is made with the *previous* block's
next-secret. The token's final field is the proof, which is one of:

- **attenuable** — the last next-secret. Whoever holds the token can delegate further.
- **sealed** — a signature over the last block signature, made with the last
  next-secret, which is then discarded. No further attenuation is possible.

Attenuating: generate a keypair, sign a new block using the secret currently in the
proof field, append block and signature, replace the proof with the new secret.

Seal before handing a token to the least-trusted hop.

**The proof field on an attenuable token is a private key.** It is a signing
capability, not just an identifier. It must never be logged, never land in an audit
sink, and never be treated as an opaque token id.

### 1.3 Signature input

```
toSign_i = "adc-v1"           // domain separation, ASCII, 6 bytes
         || 0x00
         || u32be(len(blockBytes_i))
         || blockBytes_i
         || algTag             // 0x01 = ed25519
         || nextPubKey_i       // 32 raw bytes
         || prevSignature_i-1  // 64 bytes, empty for block 0

sig_i = Ed25519_Sign(secret_i-1, toSign_i)
```

Two non-negotiable details:

- **Include the previous signature.** Without it, blocks can be transplanted between
  two tokens that share a prefix.
- **Length-prefix the block bytes.** Removes concatenation ambiguity between the
  block and the fields that follow it.

The domain-separation prefix costs nothing and closes off cross-protocol signature
reuse.

### 1.4 Wire encoding

```
adc1.<b64url(block0)>.<b64url(sig0)>.<b64url(block1)>.<b64url(sig1)>. … .k<b64url(secret)>
                                                                       ^ or s<b64url(sig)>
```

Segments joined by `.`. First segment is the version tag `adc1`. Then two segments
per block. Final segment is the proof, prefixed `k` (next-secret, attenuable) or `s`
(sealing signature, sealed).

Block payload is canonical JSON: keys sorted, UTF-8, integers only, no floats, no
insignificant whitespace. Fields: `alg`, `nk` (next public key, base64url raw), `c`
(caveat array).

**Verify over the bytes you received, never over a re-serialized parse of them.**
The decoder must retain the raw block slices, and the API must make it structurally
impossible to sign or verify anything other than those retained slices. This is the
single most likely place for a subtle break, so design it out in Phase 1 rather than
testing for it later.

### 1.5 Caveat language: closed vocabulary in v1

Not a logic language. Not Datalog. A fixed set of typed caveat structs, each with a
documented semantics as a set over the tuple space.

The reference evaluator in Phase 3 has to materialize the permitted set at each hop
and intersect. That is only possible over finite domains with decidable predicates.
A closed vocabulary is what makes the soundness line publishable. Say so in the
README so the door is visibly shut.

| kind        | payload                                             | permits                                                  |
| ----------- | --------------------------------------------------- | -------------------------------------------------------- |
| `scope`     | set of `(resourceKind, resourceId \| *, relation)`   | only listed triples                                       |
| `sinks`     | set of `exec:shell` / `write:fs` / `net:email`       | only listed sink capability classes                       |
| `taint_max` | ordered level, e.g. `TRUSTED < DERIVED < RAW_UNTRUSTED` | only when live taint level is at or below the ceiling  |
| `expires`   | unix seconds                                        | only when `now <= expires` within skew                    |
| `max_depth` | integer                                             | only when `blocks.length - 1 <= max_depth`                |
| `hosts`     | set of hostnames                                    | only listed destinations, mirroring `allowedOutboundHosts` |
| `aud`       | verifier identifier                                 | only at the named verifier (see 5.4)                      |

Resource kinds and relations import their string space from RBA namespaces. Sink
classes import from the broker. The vocabulary is the stack's vocabulary, not a
generic one.

Depth is counted from `blocks.length`. Never from a self-reported field in a block.
Expiry is the **minimum** across all blocks, not the value in the newest one.

### 1.6 Verification order

```
verify(tokenBytes, rootPubKey, facts, opts) -> Allow | Deny(code)
```

1. Parse and structural checks; reject above a configured hard depth cap.
2. Signature chain from the root public key forward.
3. Proof check: secret matches the last `nk`, or sealing signature verifies under it.
4. Revocation check (Phase 7).
5. Caveat evaluation: **every** caveat in **every** block must be satisfied.

Deny by default. Distinct reason codes so the broker can tell the cases apart:
`ADC_MALFORMED`, `ADC_SIG_INVALID`, `ADC_PROOF_INVALID`, `ADC_REVOKED`,
`ADC_EXPIRED`, `ADC_DEPTH_EXCEEDED`, `ADC_SCOPE`, `ADC_SINK`, `ADC_TAINT`,
`ADC_HOST`, `ADC_AUDIENCE`.

Facts supplied by the caller at verification: `resourceKind`, `resourceId`,
`relation`, `sink`, `host`, `taintLevel`, `now`, `audience`.

### 1.7 Runtime and crypto

- ESM only, TypeScript, `node:test`, `fast-check` for properties.
- Ed25519 via `@noble/curves`. Raw 32-byte keys without DER wrangling, zero native
  dependencies, no Windows build step. `node:crypto` is the fallback if a dependency
  has to go, but its raw-key ergonomics are worse.
- Clock skew allowance is explicit in `opts`, default 60s. Grants that only succeed
  inside the skew window get a distinct log field.

---

## 2. Repo layout

npm workspaces.

```
packages/adc-core        format, sign, attenuate, seal, verify. No integration deps.
packages/adc-testkit     reference evaluator, generators, fuzz runner. Dev only.
packages/adc-broker      broker adapter: verification plus facts injection.
packages/adc-graph       Principal-Graph event emitters.
services/mint            HTTP service. Holds the root key, calls RBA.
docs/                    this file, the soundness line, the gap list.
```

`adc-core` takes no dependency on the broker, RBA, or Principal-Graph. The adapters
depend on core, never the reverse.

---

## 3. Phases

One PR per phase. **The README section for a phase is written in that phase's PR**,
not in a docs sweep at the end.

### Phase 1 — Format and verify, no integration

Keypair generation, encode, decode, mint root, attenuate, seal, verify signature
chain only. No caveat evaluation yet.

Acceptance:

- Round-trip at depths 0 through 8.
- Flip any single byte anywhere in the token: verification fails.
- Swap a block between two tokens sharing a prefix: fails.
- Truncate to any prefix: fails.
- Present a sealed token and attempt to attenuate: fails.
- Golden vectors committed as JSON, pinning the format before anything depends on it.

### Phase 2 — Caveat vocabulary

The seven kinds from 1.5, each with a validator, canonical encoding, and written
set semantics. `verify()` grows the facts and options arguments. Reason codes land
here.

Acceptance: per-caveat unit tests including boundary cases at expiry, at exactly
`max_depth`, and at exactly the taint ceiling. Minimum-across-blocks expiry proven
by a test with a longer expiry in a later block.

### Phase 3 — Reference evaluator, fuzzer, soundness line

The reference evaluator takes a chain plus a finite test universe and materializes
the permitted tuple set per hop, then intersects. Suggested universe: 8 resources ×
6 relations × 3 sinks × 4 hosts × 3 taint levels × a discrete clock.

The fuzzer generates random root grants, random attenuation chains to depth 8, and
random queries, then compares the real verifier against the reference.

Verdicts are asymmetric:

- **False grant** (verifier allows, reference denies) — fails CI unconditionally.
- **False deny** (verifier denies, reference allows) — reported and tracked, allowed
  only against a committed exception list with a written reason per entry.

Every shrunk counterexample is committed as a permanent regression test.

Published line, same shape as the check engine's: *N chains × M queries, zero false
grants*, with the seed.

Claim 2 (monotone decrease) is asserted as an invariant on every fuzzed chain in
this phase. Claim 3 is a property test plus the written argument in section 4.

### Phase 4 — RBA mint bounding

Mint consults RBA's scope-bounding query. A root token can never contain a
(resource, relation) pair Alice does not actually hold at mint time. Reject the whole
mint rather than silently trimming.

Acceptance: minting a pair Alice lacks is rejected with a distinct error; the
rejection is a Principal-Graph event once Phase 6 lands.

### Phase 5 — Broker adapter

Verification runs **before** the taint gate. Both must pass. Denial reason codes stay
distinct so "no authority" is never confused with "tainted."

The adapter injects facts from broker state: the sink class about to be hit, the
destination host, the live taint level, the current time.

**Wire the token into `redactAuditArgs` in this PR, not later.** Redact the proof
field too, per 1.2.

### Phase 6 — Principal-Graph events

Mint, attenuate, verify-allow, verify-deny, seal, revoke.

Event identity is the per-block signature hash. This is also the revocation
identifier in Phase 7, so define it once here and reuse it.

### Phase 7 — Revocation

Signed revocation list of block-signature hashes, fetched by verifiers on a poll
interval.

Revoking a root hash kills every descendant for free, since every descendant token
contains block 0's signature.

Claim 4 needs a number attached. State the default in the README:

```
liveness bound = list TTL + poll interval + clock skew
               = 60s + 30s + 60s = 150s worst case
```

---

## 4. Proof claims

**Claim 1 — Attenuation soundness.** For any chain C rooted at R, the effective
authority of C is a subset of the authority of R. Established by differential fuzzing
against the reference evaluator (Phase 3), with asymmetric verdicts.

**Claim 2 — Monotone decrease.** Authority at hop N+1 is a subset of authority at
hop N. Asserted as an invariant on every fuzzed chain.

**Claim 3 — Non-removability.** *Argument plus property tests, not a proof. Labeled
as such in the README.*

The claim as stated precisely:

> No holder can strip a caveat added at or before their own hop, and no downstream
> holder can truncate the chain to any prefix, because either operation requires a
> secret key that appears in no token that holder ever received.

The residual, stated openly rather than buried: **an intermediate delegator can
replay its own earlier token.** Whoever held the token at hop *i* held secret *i*,
so they can re-present their older, broader copy at any time. That is not stripping,
it is replaying what they legitimately held, and no signature scheme removes it. It
is an expiry and revocation problem. Say this in the README rather than letting a
reader discover it.

**Claim 4 — Revocation liveness.** A revoked root kills every descendant within the
stated freshness window, with the number from Phase 7.

---

## 5. Limitations published on day one

### 5.1 Outstanding tokens cannot be enumerated

Offline attenuation means nobody has a list of live tokens. Revocation is therefore
short TTL or a checked list, and both cost something real. Short TTL costs re-mint
traffic and a mint service on the hot path. A checked list costs a network dependency
in the verifier, which partly undoes the offline property.

### 5.2 Authority is a snapshot of RBA at mint time

Offline verification means the token cannot re-consult RBA. If Alice loses a relation
an hour after minting, outstanding tokens still verify against it. This is a second,
independent argument for short root TTLs, and it belongs beside 5.1 rather than
inside it.

### 5.3 Confused deputy survives this

A correctly-scoped token used for an attacker-chosen but in-scope action still
verifies, and should. That is exactly why the taint gate stays and why verification
runs before it rather than instead of it.

### 5.4 Bearer, and unbound to a verifier

The same token presented to a different broker in a different deployment verifies
identically, as long as that broker trusts the same root key. Two options, and the
choice should be explicit:

- Add the `aud` caveat in Phase 2. Cheap, and it fits the closed vocabulary.
- Or publish the limitation and defer.

Proof-of-possession binding is the real fix and is a v2 item.

### 5.5 A token must never land in an audit sink unredacted

Bearer credential, and on an attenuable token the proof field is a live signing key.
Wired to `redactAuditArgs` in Phase 5.

### 5.6 Clock skew and expressiveness

Expiry is evaluated against a skew window, so a token is live slightly past its
nominal expiry at a verifier with a fast clock. Caveat expressiveness is deliberately
traded against decidability, per 1.5.

---

## 6. Deferred to v2

- Datalog or any open caveat language, with the decidability question answered first.
- Proof-of-possession binding.
- Threshold or rotating root keys.
- Cross-root delegation.
