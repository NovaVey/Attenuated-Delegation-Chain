import { ed25519 } from "@noble/curves/ed25519";

/** Raw 32-byte Ed25519 keys, no DER — per docs/PLAN.md section 1.7. */
export const SECRET_KEY_LEN = 32;
export const PUBLIC_KEY_LEN = 32;
export const SIGNATURE_LEN = 64;

export interface Keypair {
  secretKey: Uint8Array; // 32-byte seed
  publicKey: Uint8Array; // 32-byte raw point
}

export function generateKeypair(): Keypair {
  const secretKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

export function getPublicKey(secretKey: Uint8Array): Uint8Array {
  requireLen(secretKey, SECRET_KEY_LEN, "secretKey");
  return ed25519.getPublicKey(secretKey);
}

export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  requireLen(secretKey, SECRET_KEY_LEN, "secretKey");
  return ed25519.sign(message, secretKey);
}

export function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== PUBLIC_KEY_LEN || signature.length !== SIGNATURE_LEN) {
    return false;
  }
  try {
    // zip215: false selects strict RFC8032/FIPS 186-5 verification rather
    // than @noble/curves's default cofactored (ZIP215) mode. ZIP215's
    // cofactor multiplication is what makes some low-order (publicKey,
    // signature) pairs verify against *any* message — a real, documented
    // Ed25519 edge case, not a library bug. `nk` in a block is
    // attacker-influenced token content (any hop can put whatever bytes
    // it wants there), so a verifier that feeds attacker-controlled
    // values into signature checks must not use the permissive mode.
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    // @noble/curves throws on some malformed inputs (e.g. non-canonical
    // points) rather than returning false. A verifier must never let a
    // malformed signature turn into a thrown exception that skips the
    // caller's deny path — normalize to a boolean.
    return false;
  }
}

function requireLen(bytes: Uint8Array, len: number, name: string): void {
  if (bytes.length !== len) {
    throw new RangeError(`${name} must be ${len} bytes, got ${bytes.length}`);
  }
}
