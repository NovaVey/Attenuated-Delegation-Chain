/**
 * Distinct reason codes so a verifier (e.g. the broker) can tell denial
 * cases apart, per docs/PLAN.md section 1.6.
 *
 * Phase 1 only ever produces ADC_MALFORMED, ADC_SIG_INVALID,
 * ADC_PROOF_INVALID and ADC_DEPTH_EXCEEDED — the rest are reserved here so
 * the full contract is visible up front and later phases only need to
 * start *emitting* them, never invent new names.
 */
export const REASON_CODES = [
  "ADC_MALFORMED",
  "ADC_SIG_INVALID",
  "ADC_PROOF_INVALID",
  "ADC_REVOKED",
  "ADC_EXPIRED",
  "ADC_DEPTH_EXCEEDED",
  "ADC_SCOPE",
  "ADC_SINK",
  "ADC_TAINT",
  "ADC_HOST",
  "ADC_AUDIENCE",
] as const;

export type ReasonCode = (typeof REASON_CODES)[number];

/** Thrown by the minting/attenuation API (which is trusted-caller code, not
 * a verifier) on programmer error: wrong proof type, malformed input, etc.
 */
export class AdcError extends Error {
  readonly code: ReasonCode;

  constructor(code: ReasonCode, message: string) {
    super(message);
    this.name = "AdcError";
    this.code = code;
  }
}
