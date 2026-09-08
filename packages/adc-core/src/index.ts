/**
 * @adc/core — Attenuated Delegation Chain: format, sign, attenuate, seal,
 * verify, and the closed caveat vocabulary. No revocation, no integration
 * with RBA/broker/Principal-Graph yet. See docs/PLAN.md.
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

export type { Keypair } from "./crypto.js";
export type { RawCaveat, BlockFields } from "./block.js";
export { AdcError, REASON_CODES } from "./errors.js";
export type { ReasonCode } from "./errors.js";

export { parseCaveat, evaluateCaveat, resolveFacts, caveatToRaw, TAINT_LEVELS } from "./caveats.js";
export type { Caveat, CaveatKind, TaintLevel, Facts, ResolvedFacts, EvalContext, CaveatEvalResult } from "./caveats.js";
