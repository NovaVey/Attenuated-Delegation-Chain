import { utf8Encode } from "./bytes.js";

/**
 * Canonical JSON encoding for block payloads (docs/PLAN.md section 1.4):
 * object keys sorted, UTF-8, integers only (no floats), no insignificant
 * whitespace. One byte sequence per logical value — this is what makes
 * the golden vectors reproducible and what the signature is computed over.
 *
 * `null` is deliberately unsupported: the closed caveat vocabulary (1.5)
 * never needs it, and disallowing it removes a source of encoding
 * ambiguity for free.
 */
export type CanonicalValue =
  | string
  | number
  | boolean
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

function stringify(value: CanonicalValue): string {
  if (typeof value === "boolean") return value ? "true" : "false";

  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new TypeError(`canonical JSON: only integers are allowed, got ${value}`);
    }
    if (!Number.isSafeInteger(value)) {
      throw new RangeError(`canonical JSON: integer out of safe range: ${value}`);
    }
    // Reject -0: it round-trips through JSON as "0", which would make two
    // distinct in-memory values encode identically — harmless here, but
    // cheap to forbid outright rather than reason about later.
    if (Object.is(value, -0)) {
      throw new RangeError("canonical JSON: -0 is not allowed");
    }
    return String(value);
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return "[" + value.map(stringify).join(",") + "]";
  }

  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + stringify(value[k]!)).join(",") +
      "}"
    );
  }

  throw new TypeError(`canonical JSON: unsupported value: ${JSON.stringify(value)}`);
}

export function canonicalEncode(value: CanonicalValue): Uint8Array {
  return utf8Encode(stringify(value));
}
