import { b64urlDecode, b64urlEncode, utf8Decode } from "./bytes.js";
import { canonicalEncode, type CanonicalValue } from "./canonical.js";
import { PUBLIC_KEY_LEN } from "./crypto.js";

/** The algorithm tag stored *inside* the block payload's `alg` field.
 * Distinct from signing.ts's ALG_TAG_ED25519 (the 1-byte tag mixed into
 * the signature input) — this one is the human-readable wire value. */
export const ALG_ED25519 = "ed25519";

/**
 * A caveat is opaque at the block-encoding layer in Phase 1: the closed
 * vocabulary (docs/PLAN.md 1.5) and its validators land in Phase 2. All
 * this layer guarantees is that whatever is passed round-trips through
 * canonical JSON deterministically, so the wire format is already locked
 * in before any caveat semantics exist.
 */
export type RawCaveat = { readonly kind: string } & Record<string, CanonicalValue>;

export interface BlockFields {
  readonly alg: string;
  readonly nextPublicKey: Uint8Array;
  readonly caveats: readonly RawCaveat[];
}

/** Serializes block fields to the exact canonical-JSON bytes that get
 * signed and stored on the wire. */
export function encodeBlock(fields: BlockFields): Uint8Array {
  if (fields.nextPublicKey.length !== PUBLIC_KEY_LEN) {
    throw new RangeError(
      `nextPublicKey must be ${PUBLIC_KEY_LEN} bytes, got ${fields.nextPublicKey.length}`,
    );
  }
  const value: CanonicalValue = {
    alg: fields.alg,
    nk: b64urlEncode(fields.nextPublicKey),
    c: fields.caveats.map((c) => c as unknown as CanonicalValue),
  };
  return canonicalEncode(value);
}

/**
 * Parses raw block bytes for field access (e.g. to read `nk` and chain the
 * next verification key). This is a READ operation only — signature
 * verification must always run over the original `rawBytes`, never over
 * `canonicalEncode` applied to this parsed result, since a byte-identical
 * re-serialization is not guaranteed for input we did not produce
 * ourselves (see docs/PLAN.md 1.4: "verify over the bytes you received").
 */
export function decodeBlock(rawBytes: Uint8Array): BlockFields {
  let text: string;
  try {
    text = utf8Decode(rawBytes);
  } catch {
    throw new SyntaxError("block: invalid UTF-8");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new SyntaxError("block: invalid JSON");
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SyntaxError("block: expected a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const expectedKeys = ["alg", "c", "nk"];
  if (keys.length !== expectedKeys.length || keys.some((k, i) => k !== expectedKeys[i])) {
    throw new SyntaxError(`block: expected exactly fields ${expectedKeys.join(", ")}, got ${keys.join(", ")}`);
  }

  if (typeof obj.alg !== "string") {
    throw new SyntaxError("block: 'alg' must be a string");
  }
  if (obj.alg !== ALG_ED25519) {
    throw new SyntaxError(`block: unsupported alg '${obj.alg}'`);
  }

  if (typeof obj.nk !== "string") {
    throw new SyntaxError("block: 'nk' must be a string");
  }
  const nextPublicKey = b64urlDecode(obj.nk);
  if (nextPublicKey.length !== PUBLIC_KEY_LEN) {
    throw new SyntaxError(`block: 'nk' must decode to ${PUBLIC_KEY_LEN} bytes`);
  }

  if (!Array.isArray(obj.c)) {
    throw new SyntaxError("block: 'c' must be an array");
  }
  for (const entry of obj.c) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new SyntaxError("block: each caveat must be an object");
    }
    if (typeof (entry as Record<string, unknown>).kind !== "string") {
      throw new SyntaxError("block: each caveat must have a string 'kind'");
    }
  }

  return {
    alg: obj.alg,
    nextPublicKey,
    caveats: obj.c as RawCaveat[],
  };
}
