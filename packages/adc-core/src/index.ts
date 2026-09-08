/**
 * @adc/core — Attenuated Delegation Chain: format, sign, attenuate, seal,
 * verify. Phase 1 scope: no caveat evaluation, no revocation, no
 * integration with RBA/broker/Principal-Graph. See docs/PLAN.md.
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
