import { concatBytes, u32be, utf8Encode } from "./bytes.js";
import { PUBLIC_KEY_LEN, SIGNATURE_LEN } from "./crypto.js";

/** Domain-separation prefix, ASCII, 6 bytes. Closes off cross-protocol
 * signature reuse — docs/PLAN.md section 1.3. */
export const DOMAIN_TAG = utf8Encode("adc-v1");
if (DOMAIN_TAG.length !== 6) {
  throw new Error("invariant: DOMAIN_TAG must be exactly 6 bytes");
}

/** 0x01 = ed25519. The only algorithm v1 supports. */
export const ALG_TAG_ED25519 = 0x01;

const EMPTY = new Uint8Array(0);

/**
 * Builds `toSign_i` exactly as specified in docs/PLAN.md section 1.3:
 *
 *   toSign_i = "adc-v1" || 0x00 || u32be(len(blockBytes_i)) || blockBytes_i
 *            || algTag || nextPubKey_i || prevSignature_i-1
 *
 * `blockBytes` MUST be the exact bytes that were (or will be) signed —
 * never a re-serialization of a parsed object. `prevSignature` is the
 * 64-byte signature of the previous block, or `undefined`/empty for block 0.
 *
 * Including prevSignature binds each block to its exact position in its
 * own chain (not just to the key that signed it), so a block cannot be
 * transplanted onto a different token that happens to share a key-derived
 * prefix. Length-prefixing blockBytes removes any concatenation ambiguity
 * between the block and the fields that follow it.
 */
export function buildSignInput(params: {
  blockBytes: Uint8Array;
  nextPubKey: Uint8Array;
  prevSignature?: Uint8Array | undefined;
}): Uint8Array {
  const { blockBytes, nextPubKey } = params;
  const prevSignature = params.prevSignature ?? EMPTY;

  if (nextPubKey.length !== PUBLIC_KEY_LEN) {
    throw new RangeError(`nextPubKey must be ${PUBLIC_KEY_LEN} bytes, got ${nextPubKey.length}`);
  }
  if (prevSignature.length !== 0 && prevSignature.length !== SIGNATURE_LEN) {
    throw new RangeError(
      `prevSignature must be empty or ${SIGNATURE_LEN} bytes, got ${prevSignature.length}`,
    );
  }

  return concatBytes(
    DOMAIN_TAG,
    Uint8Array.of(0x00),
    u32be(blockBytes.length),
    blockBytes,
    Uint8Array.of(ALG_TAG_ED25519),
    nextPubKey,
    prevSignature,
  );
}
