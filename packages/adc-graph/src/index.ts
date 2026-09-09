/**
 * @adc/graph — Principal-Graph event emitters: mint, attenuate,
 * verify-allow, verify-deny, seal, revoke. See docs/PLAN.md Phase 6.
 *
 * This package emits plain, Principal-Graph-shaped event data — it has no
 * dependency on, and cannot write into, Principal-Graph itself (that repo
 * has no importable library surface and no write API; see this package's
 * README for the finding and the worked example of the adapter a real
 * deployment needs on the Principal-Graph side to actually consume what
 * this package builds).
 */

export type { GraphPrincipalKind, GraphPrincipalIdentity, GraphResourceIdentity } from "./identity.js";
export { ADC_RESOURCE_SOURCE, ADC_BLOCK_RESOURCE_KIND, rootKeyPrincipal, toBase64Url } from "./identity.js";

export { blockIdentity, blockResource, undecodableResource } from "./hash.js";

export type { GraphEvent, GraphSink } from "./event.js";

export { buildMintEvent, buildAttenuateEvent, buildSealEvent, buildVerifyEvent, buildRevokeEvent } from "./builders.js";

export { createInMemoryGraphSink } from "./sinks/memory.js";
