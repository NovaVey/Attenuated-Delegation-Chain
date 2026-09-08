/**
 * The in-memory token representation. `blocks` and `sigs` are the raw
 * bytes exactly as they were minted, attenuated, or decoded from the
 * wire — never a re-serialization. `sigs[i]` is the signature over
 * `blocks[i]` (i.e. `sig_i` in docs/PLAN.md section 1.3), made with the
 * secret key corresponding to `nk` in `blocks[i-1]` (or the root secret
 * key, for block 0).
 */
export interface ParsedToken {
  readonly version: "adc1";
  readonly blocks: readonly Uint8Array[];
  readonly sigs: readonly Uint8Array[];
  readonly proof: Proof;
}

export type Proof =
  | { readonly type: "attenuable"; readonly secretKey: Uint8Array }
  | { readonly type: "sealed"; readonly signature: Uint8Array };
