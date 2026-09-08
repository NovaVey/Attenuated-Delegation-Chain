import { b64urlDecode, b64urlEncode } from "./bytes.js";
import { SECRET_KEY_LEN, SIGNATURE_LEN } from "./crypto.js";
import type { ParsedToken, Proof } from "./types.js";

export const VERSION_TAG = "adc1";

const PROOF_PREFIX_ATTENUABLE = "k";
const PROOF_PREFIX_SEALED = "s";

function encodeProof(proof: Proof): string {
  if (proof.type === "attenuable") {
    return PROOF_PREFIX_ATTENUABLE + b64urlEncode(proof.secretKey);
  }
  return PROOF_PREFIX_SEALED + b64urlEncode(proof.signature);
}

function decodeProof(segment: string): Proof {
  if (segment.length < 1) {
    throw new SyntaxError("proof segment is empty");
  }
  const prefix = segment[0];
  const payload = segment.slice(1);
  if (prefix === PROOF_PREFIX_ATTENUABLE) {
    const secretKey = b64urlDecode(payload);
    if (secretKey.length !== SECRET_KEY_LEN) {
      throw new SyntaxError(`attenuable proof must decode to ${SECRET_KEY_LEN} bytes`);
    }
    return { type: "attenuable", secretKey };
  }
  if (prefix === PROOF_PREFIX_SEALED) {
    const signature = b64urlDecode(payload);
    if (signature.length !== SIGNATURE_LEN) {
      throw new SyntaxError(`sealed proof must decode to ${SIGNATURE_LEN} bytes`);
    }
    return { type: "sealed", signature };
  }
  throw new SyntaxError(`unknown proof prefix '${prefix}'`);
}

/** Serializes a ParsedToken to the wire string. Always operates on the
 * token's stored raw block/sig bytes — never re-derives them. */
export function encodeToken(token: ParsedToken): string {
  if (token.version !== VERSION_TAG) {
    throw new SyntaxError(`unsupported version '${token.version}'`);
  }
  if (token.blocks.length === 0 || token.blocks.length !== token.sigs.length) {
    throw new SyntaxError("token must have at least one block, with one sig per block");
  }
  const segments: string[] = [token.version];
  for (let i = 0; i < token.blocks.length; i++) {
    segments.push(b64urlEncode(token.blocks[i]!));
    segments.push(b64urlEncode(token.sigs[i]!));
  }
  segments.push(encodeProof(token.proof));
  return segments.join(".");
}

/** Number of blocks a segment array of this length represents:
 * version + 2*N block/sig segments + proof. */
export function blockCountForSegments(segmentCount: number): number {
  return (segmentCount - 2) / 2;
}

/**
 * Splits and structurally validates the wire string into `.`-separated
 * segments, WITHOUT decoding any individual segment's base64url payload.
 * This is the cheap, allocation-light gate: segment count (and therefore
 * depth, via blockCountForSegments) is derivable from its result alone.
 * verify() calls this first so an over-deep or truncated token can be
 * denied — including on depth — before paying for a base64 decode of
 * every block and signature. decodeToken() (below) does that heavier work
 * as a second step.
 */
export function splitSegments(wire: string): string[] {
  if (wire.length === 0) {
    throw new SyntaxError("empty token");
  }
  const segments = wire.split(".");

  if (segments.length < 4 || segments.length % 2 !== 0) {
    // version + 2*N block/sig segments + proof, N >= 1, is always an even
    // segment count of at least 4. Anything else is a truncation or a
    // corrupted separator.
    throw new SyntaxError(`malformed token: unexpected segment count ${segments.length}`);
  }

  if (segments[0] !== VERSION_TAG) {
    throw new SyntaxError(`unsupported version '${segments[0]}'`);
  }

  return segments;
}

/**
 * Decodes already-split segments (from splitSegments) into a ParsedToken,
 * retaining the exact raw bytes for each block and signature (decoded
 * from base64url, but not otherwise reinterpreted). This is the expensive
 * per-segment pass — base64 decode plus a length check on every
 * signature — and does NOT check depth caps (splitSegments's caller
 * should do that first), signatures, proof correctness, or caveats;
 * those are verify()'s job.
 */
export function decodeSegments(segments: string[]): ParsedToken {
  const blockCount = blockCountForSegments(segments.length);
  const blocks: Uint8Array[] = [];
  const sigs: Uint8Array[] = [];
  for (let i = 0; i < blockCount; i++) {
    const blockSegment = segments[1 + 2 * i]!;
    const sigSegment = segments[2 + 2 * i]!;
    if (blockSegment.length === 0) {
      throw new SyntaxError(`malformed token: empty block segment at index ${i}`);
    }
    const sig = b64urlDecode(sigSegment);
    if (sig.length !== SIGNATURE_LEN) {
      throw new SyntaxError(`malformed token: sig ${i} must decode to ${SIGNATURE_LEN} bytes`);
    }
    blocks.push(b64urlDecode(blockSegment));
    sigs.push(sig);
  }

  const proof = decodeProof(segments[segments.length - 1]!);

  return { version: VERSION_TAG, blocks, sigs, proof };
}

/**
 * Parses the wire string into a ParsedToken. Structural validation only —
 * this does NOT check signatures, proof correctness, depth caps, or
 * caveats; that is verify()'s job. A malformed/truncated string always
 * throws SyntaxError here rather than silently producing a partial token.
 *
 * Equivalent to `decodeSegments(splitSegments(wire))`; verify() calls
 * those two steps separately so it can enforce a depth cap between them,
 * before paying for the full per-segment decode.
 */
export function decodeToken(wire: string): ParsedToken {
  return decodeSegments(splitSegments(wire));
}
