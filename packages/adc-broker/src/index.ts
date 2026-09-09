/**
 * @adc/broker — Taint-Tracked-Tool-Broker adapter: verifies an ADC token
 * against facts derived from live broker state, strictly before the
 * broker's own taint gate runs, plus an audit-redaction helper for the
 * token itself. See docs/PLAN.md Phase 5.
 */

export { wrapWithAdcGate, AdcGateError } from "./gate.js";
export type { AdcGateOptions } from "./gate.js";

export { deriveCallFacts } from "./facts.js";
export type { CallFactSets, FactsSourceTool } from "./facts.js";

export { verifyCall } from "./verify.js";

export { adcTaintLevel } from "./taint.js";

export { redactAdcTokens, createAdcAuditRedactor } from "./redact.js";
