/** Low-level byte helpers: base64url, big-endian u32, concatenation. */

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Big-endian, unsigned 32-bit length prefix. */
export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new RangeError(`u32be: ${n} is not a valid unsigned 32-bit integer`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function readU32be(bytes: Uint8Array, offset: number): number {
  if (offset < 0 || offset + 4 > bytes.length) {
    throw new RangeError("readU32be: out of range");
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
}

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Unpadded base64url, per RFC 4648 §5. */
export function b64urlEncode(bytes: Uint8Array): string {
  // Node has a fast native path via Buffer; keep the wire format's own
  // notion of "unpadded base64url" explicit rather than relying on
  // Buffer's toString('base64url') padding behavior implicitly.
  const std = Buffer.from(bytes).toString("base64");
  return std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  if (!/^[A-Za-z0-9_-]+$/.test(s)) {
    throw new SyntaxError("b64urlDecode: invalid base64url alphabet");
  }
  let std = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = std.length % 4;
  if (pad === 1) {
    throw new SyntaxError("b64urlDecode: invalid length");
  }
  if (pad > 0) std += "=".repeat(4 - pad);
  const buf = Buffer.from(std, "base64");
  // Buffer.from silently drops invalid trailing bytes rather than
  // throwing; reject anything that didn't round-trip cleanly so a
  // corrupted segment is caught here rather than surfacing as a
  // downstream signature-verification failure with a confusing cause.
  if (b64urlEncode(buf) !== s) {
    throw new SyntaxError("b64urlDecode: not canonical base64url");
  }
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
