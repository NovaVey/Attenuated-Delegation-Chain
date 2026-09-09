/**
 * @adc/core — Attenuated Delegation Chain: format, sign, attenuate, seal,
 * verify, the closed caveat vocabulary, and the revocation check. No
 * integration with RBA/broker/Principal-Graph — those are sibling
 * packages/services. See docs/PLAN.md.
 */

export {
  mintRoot,
  attenuate,
  seal,
  verify,
  encodeToken,
  decodeToken,
  encodeBlock,
  decodeBlock,
  generateKeypair,
  getPublicKey,
  DEFAULT_MAX_DEPTH,
  DEFAULT_CLOCK_SKEW_SECONDS,
} from "./token.js";

export type {
  ParsedToken,
  Proof,
  MintOptions,
  AttenuateOptions,
  VerifyOptions,
  VerifyResult,
} from "./token.js";

/**
 * `sign`/`verifySignature` are the raw Ed25519 primitives every other
 * signing operation in this codebase already goes through (block
 * signatures, the proof, the sealing signature) — including the ZIP215
 * hardening (`{ zip215: false }`, see crypto.ts's own doc comment) that
 * closes a real forgery class under @noble/curves's permissive default.
 * Exported so a sibling package that needs to sign/verify something else
 * with the SAME root key (e.g. `@adc/revocation`'s signed revocation
 * list) reuses this hardened implementation instead of a second,
 * independent call into @noble/curves that could silently miss that same
 * fix.
 */
export { sign, verifySignature } from "./crypto.js";
export type { Keypair } from "./crypto.js";
export type { RawCaveat, BlockFields } from "./block.js";
export { AdcError, REASON_CODES } from "./errors.js";
export type { ReasonCode } from "./errors.js";

export { parseCaveat, evaluateCaveat, resolveFacts, caveatToRaw, TAINT_LEVELS } from "./caveats.js";
export type { Caveat, CaveatKind, TaintLevel, Facts, ResolvedFacts, EvalContext, CaveatEvalResult } from "./caveats.js";

export { blockSignatureHash } from "./revocation.js";

export { canonicalEncode } from "./canonical.js";
export type { CanonicalValue } from "./canonical.js";

/** Unpadded base64url (RFC 4648 §5) — the same encoding every wire-format
 * segment already uses (`wire.ts`). Exported so a sibling package
 * encoding something else Ed25519-shaped (e.g. `@adc/revocation`'s list
 * signature) uses the identical, already-tested encoding rather than a
 * second implementation that could drift on an edge case (padding,
 * canonical-form rejection — see `b64urlDecode`'s own doc comment). */
export { b64urlEncode, b64urlDecode } from "./bytes.js";
