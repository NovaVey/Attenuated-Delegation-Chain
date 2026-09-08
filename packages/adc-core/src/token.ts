import { bytesEqual, utf8Decode } from "./bytes.js";
import { ALG_ED25519, decodeBlock, encodeBlock, type RawCaveat } from "./block.js";
import { buildSignInput } from "./signing.js";
import {
  generateKeypair,
  getPublicKey,
  sign,
  verifySignature,
  SECRET_KEY_LEN,
  type Keypair,
} from "./crypto.js";
import { AdcError, type ReasonCode } from "./errors.js";
import { blockCountForSegments, decodeSegments, splitSegments } from "./wire.js";
import type { ParsedToken } from "./types.js";

export type { ParsedToken, Proof } from "./types.js";
export { encodeToken, decodeToken } from "./wire.js";

/** Structural default; verify() rejects any token deeper than this before
 * doing any crypto. depth = blocks.length - 1, counted from the wire
 * structure, never from a self-reported field (docs/PLAN.md 1.5). */
export const DEFAULT_MAX_DEPTH = 32;

/** Default clock-skew allowance, seconds — reserved for Phase 2's
 * `expires` caveat; not used by Phase 1's chain-only verify(). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;

export interface MintOptions {
  readonly caveats?: readonly RawCaveat[];
  /** Testing/vector-generation hook only: inject the next keypair instead
   * of generating one randomly, so output is reproducible. Real callers
   * should omit this. */
  readonly nextKeypair?: Keypair;
}

export type AttenuateOptions = MintOptions;

/**
 * Resolves the keypair whose secret signs the *next* block and whose
 * public half becomes this block's `nk`. With no `nextKeypair` supplied,
 * generates one randomly (the normal path). With one supplied (the
 * testing/vector-generation hook), validates that the secret actually
 * derives the given public key — a caller who accidentally passes
 * mismatched keys would otherwise get a token back with no error at all,
 * whose proof can never be satisfied, failing only much later at
 * verify() with a confusing, far-away ADC_PROOF_INVALID or
 * ADC_SIG_INVALID — and returns a fresh copy of the secret rather than
 * the caller's own buffer, so the returned token never shares a live
 * buffer with a Keypair object the caller might later zero out as
 * ordinary key hygiene.
 */
function resolveNextKeypair(nextKeypair: Keypair | undefined): Keypair {
  if (nextKeypair === undefined) {
    return generateKeypair();
  }
  if (nextKeypair.secretKey.length !== SECRET_KEY_LEN) {
    throw new AdcError(
      "ADC_MALFORMED",
      `nextKeypair.secretKey must be ${SECRET_KEY_LEN} bytes, got ${nextKeypair.secretKey.length}`,
    );
  }
  const derivedPublicKey = getPublicKey(nextKeypair.secretKey);
  if (!bytesEqual(derivedPublicKey, nextKeypair.publicKey)) {
    throw new AdcError("ADC_MALFORMED", "nextKeypair.publicKey does not match nextKeypair.secretKey");
  }
  // derivedPublicKey is already a fresh array from getPublicKey(), not
  // aliased to the caller's buffer; only secretKey needs an explicit copy.
  return { secretKey: Uint8Array.from(nextKeypair.secretKey), publicKey: derivedPublicKey };
}

/** Mints a fresh root (block 0), signed by the root secret key. Returns
 * an attenuable token whose proof is the freshly generated next-secret. */
export function mintRoot(rootSecretKey: Uint8Array, opts: MintOptions = {}): ParsedToken {
  const { secretKey: nextSecretKey, publicKey: nextPublicKey } = resolveNextKeypair(opts.nextKeypair);

  const blockBytes = encodeBlock({
    alg: ALG_ED25519,
    nextPublicKey,
    caveats: opts.caveats ?? [],
  });

  const toSign = buildSignInput({ blockBytes, nextPubKey: nextPublicKey });
  const sig = sign(rootSecretKey, toSign);

  return {
    version: "adc1",
    blocks: [blockBytes],
    sigs: [sig],
    proof: { type: "attenuable", secretKey: nextSecretKey },
  };
}

/**
 * Attenuates a token: signs a new block with the secret currently held in
 * the proof field, appends it, and replaces the proof with the new
 * next-secret. Throws if the token is sealed — attenuation always
 * requires holding a signing capability, and sealing discards it.
 */
export function attenuate(token: ParsedToken, opts: AttenuateOptions = {}): ParsedToken {
  if (token.proof.type !== "attenuable") {
    throw new AdcError("ADC_PROOF_INVALID", "attenuate() requires an attenuable token; this token is sealed");
  }
  if (token.blocks.length === 0 || token.blocks.length !== token.sigs.length) {
    throw new AdcError("ADC_MALFORMED", "token has an inconsistent block/signature count");
  }

  const currentSecretKey = token.proof.secretKey;
  const { secretKey: nextSecretKey, publicKey: nextPublicKey } = resolveNextKeypair(opts.nextKeypair);

  const blockBytes = encodeBlock({
    alg: ALG_ED25519,
    nextPublicKey,
    caveats: opts.caveats ?? [],
  });

  const prevSignature = token.sigs[token.sigs.length - 1]!;
  const toSign = buildSignInput({ blockBytes, nextPubKey: nextPublicKey, prevSignature });
  const sig = sign(currentSecretKey, toSign);

  return {
    version: "adc1",
    blocks: [...token.blocks, blockBytes],
    sigs: [...token.sigs, sig],
    proof: { type: "attenuable", secretKey: nextSecretKey },
  };
}

/**
 * Seals a token: signs the last block's signature with the last
 * next-secret, then discards the secret. The returned token can never be
 * attenuated further. Callers should not retain the input token's proof
 * secret after sealing — see docs/PLAN.md 1.2.
 */
export function seal(token: ParsedToken): ParsedToken {
  if (token.proof.type !== "attenuable") {
    throw new AdcError("ADC_PROOF_INVALID", "seal() requires an attenuable token; this token is already sealed");
  }
  if (token.blocks.length === 0 || token.blocks.length !== token.sigs.length) {
    throw new AdcError("ADC_MALFORMED", "token has an inconsistent block/signature count");
  }

  const lastSignature = token.sigs[token.sigs.length - 1]!;
  const sealSignature = sign(token.proof.secretKey, lastSignature);

  return {
    version: "adc1",
    blocks: token.blocks,
    sigs: token.sigs,
    proof: { type: "sealed", signature: sealSignature },
  };
}

export type VerifyResult =
  | { readonly ok: true; readonly depth: number }
  | { readonly ok: false; readonly code: ReasonCode; readonly reason: string };

export interface VerifyOptions {
  /** Hard structural depth cap, checked before any crypto runs. */
  readonly maxDepth?: number;
}

function deny(code: ReasonCode, reason: string): VerifyResult {
  return { ok: false, code, reason };
}

/**
 * Verifies a token's signature chain and proof against `rootPublicKey`.
 *
 * Phase 1 scope only: parse + structural checks, signature chain, proof
 * check (docs/PLAN.md 1.6 steps 1-3). Revocation (step 4, Phase 7) and
 * caveat evaluation (step 5, Phase 2) are not implemented yet and are
 * silently skipped — a Phase 1 Allow says nothing about caveats,
 * revocation, or the facts a real deployment must eventually supply.
 *
 * Never throws on malformed or hostile token input: every failure mode
 * reachable from `tokenBytes` alone resolves to a Deny with a reason
 * code, never an exception. `rootPublicKey` is validated for length only
 * (32 bytes) and throws RangeError if wrong — it is not checked to be a
 * valid curve point, since a syntactically-valid-length but semantically
 * invalid root key just makes every signature check fail closed
 * (Deny(ADC_SIG_INVALID)), which is safe.
 */
export function verify(
  tokenBytes: string | Uint8Array,
  rootPublicKey: Uint8Array,
  opts: VerifyOptions = {},
): VerifyResult {
  if (rootPublicKey.length !== 32) {
    throw new RangeError(`rootPublicKey must be 32 bytes, got ${rootPublicKey.length}`);
  }
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;

  let wire: string;
  try {
    wire = typeof tokenBytes === "string" ? tokenBytes : utf8Decode(tokenBytes);
  } catch {
    return deny("ADC_MALFORMED", "token bytes are not valid UTF-8");
  }

  // Split first and check depth before decoding a single block or
  // signature: segment count (and therefore depth) is derivable from the
  // cheap split/structural check alone, so an over-deep token is denied
  // without paying for a base64 decode of every block/sig it carries.
  let segments: string[];
  try {
    segments = splitSegments(wire);
  } catch (err) {
    return deny("ADC_MALFORMED", `failed to parse token: ${(err as Error).message}`);
  }

  const depth = blockCountForSegments(segments.length) - 1;
  if (depth > maxDepth) {
    return deny("ADC_DEPTH_EXCEEDED", `depth ${depth} exceeds max depth ${maxDepth}`);
  }

  let token: ParsedToken;
  try {
    token = decodeSegments(segments);
  } catch (err) {
    return deny("ADC_MALFORMED", `failed to parse token: ${(err as Error).message}`);
  }

  let currentVerifyKey = rootPublicKey;
  for (let i = 0; i < token.blocks.length; i++) {
    const blockBytes = token.blocks[i]!;
    const sig = token.sigs[i]!;

    let nextPublicKey: Uint8Array;
    try {
      nextPublicKey = decodeBlock(blockBytes).nextPublicKey;
    } catch (err) {
      return deny("ADC_MALFORMED", `block ${i} is malformed: ${(err as Error).message}`);
    }

    const prevSignature = i === 0 ? undefined : token.sigs[i - 1];
    let toSign: Uint8Array;
    try {
      toSign = buildSignInput({ blockBytes, nextPubKey: nextPublicKey, prevSignature });
    } catch (err) {
      return deny("ADC_MALFORMED", `block ${i}: ${(err as Error).message}`);
    }

    if (!verifySignature(currentVerifyKey, toSign, sig)) {
      return deny("ADC_SIG_INVALID", `signature invalid at block ${i}`);
    }

    currentVerifyKey = nextPublicKey;
  }

  // currentVerifyKey now holds the last block's `nk` — the public half of
  // whatever the proof field must attest to.
  if (token.proof.type === "attenuable") {
    let derivedPublicKey: Uint8Array;
    try {
      derivedPublicKey = getPublicKey(token.proof.secretKey);
    } catch (err) {
      return deny("ADC_PROOF_INVALID", `proof secret is invalid: ${(err as Error).message}`);
    }
    if (!bytesEqual(derivedPublicKey, currentVerifyKey)) {
      return deny("ADC_PROOF_INVALID", "proof secret does not match the last block's next public key");
    }
  } else {
    const lastSignature = token.sigs[token.sigs.length - 1]!;
    if (!verifySignature(currentVerifyKey, lastSignature, token.proof.signature)) {
      return deny("ADC_PROOF_INVALID", "sealing signature does not verify under the last block's next public key");
    }
  }

  // Step 4 (revocation) and step 5 (caveat evaluation) land in later
  // phases; Phase 1's Allow covers signature-chain integrity only.
  return { ok: true, depth };
}

export { encodeBlock, decodeBlock } from "./block.js";
export { generateKeypair, getPublicKey } from "./crypto.js";
