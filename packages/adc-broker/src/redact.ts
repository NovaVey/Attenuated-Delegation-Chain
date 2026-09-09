import type { TaintContext, ToolCall } from "taint-tracked-tool-broker";

/**
 * Matches an ADC token's wire encoding (docs/PLAN.md 1.4):
 * `adc1.<b64url>.<b64url>. ... .<b64url>` — the version tag `adc1` followed
 * by two or more `.`-separated base64url segments (at minimum: one block
 * segment and its signature; a real token has at least one more segment for
 * the proof). Deliberately liberal rather than a full grammar: this is a
 * redaction heuristic, not a parser, and erring toward redacting a string
 * that merely *looks* like a token is the safe direction — erring the other
 * way risks leaving real proof material in an audit sink.
 *
 * Boundaries are lookaround assertions against the base64url alphabet
 * itself (`[A-Za-z0-9_-]`), not `\b` — `\b` is defined in terms of `\w`
 * (`[A-Za-z0-9_]`), which does NOT include `-`, so a token whose last
 * segment happens to end in `-` immediately before a non-word delimiter
 * (e.g. `"Bearer adc1.xxx.yyy-  "`) would make `\b` fail to match at the
 * true end of the token, and the regex engine would backtrack the `{2,}`
 * repetition to a shorter match — leaving that trailing `-` sitting right
 * next to the redaction placeholder, unredacted. Matching the boundary
 * against the actual alphabet the token is made of has no such mismatch:
 * the greedy `+` always consumes every base64url character available, and
 * the lookahead only needs to confirm the character immediately after
 * isn't one too.
 */
const ADC_TOKEN_RE = /(?<![A-Za-z0-9_-])adc1(?:\.[A-Za-z0-9_-]+){2,}(?![A-Za-z0-9_-])/g;

/**
 * Recursively replaces any ADC-token-shaped substring in `value` with a
 * fixed placeholder — a value-*shape* redactor, not a key-name one: it
 * finds a token regardless of which object key (if any) holds it, since a
 * deployment that forwards an ADC token as part of a tool's own arguments
 * (docs/PLAN.md Phase 5: the same token used for verification may also be
 * the credential a sink tool presents downstream) can name that argument
 * anything (`token`, `auth`, `credential`, `delegation`, ...) — matching by
 * wire-format shape is the only way to reliably catch it regardless of
 * naming, complementing (not replacing) a key-name denylist like
 * taint-tracked-tool-broker's own docs/audit-redaction.md Pattern 3.
 *
 * Per docs/PLAN.md 1.2, this redacts the WHOLE token, not just its proof
 * segment: "[the proof field] must never be logged, never land in an audit
 * sink, and never be treated as an opaque token id" — a reader who can see
 * every other segment already has enough to reconstruct the proof
 * segment's role, so partial redaction wouldn't meaningfully protect it.
 *
 * `Map`/`Set` are walked and rebuilt (both keys and values, for `Map` —
 * mirroring taint-tracked-tool-broker's own `findOutboundHosts`/
 * `scanArgsForTaint`, which special-case both for the identical reason:
 * their entries live in an internal slot, not an own-enumerable property,
 * so the generic `Object.entries()` branch below sees nothing and would
 * otherwise silently erase them into `{}` — not a leak, but a real
 * audit-trail-integrity bug, since a tool call's args can legitimately
 * carry a `Map`/`Set` (the broker's default `cloneArgs` is
 * `structuredClone`, which preserves both). Anything else that is
 * `typeof === "object"` but isn't a plain object/array/Map/Set (a `Date`,
 * a typed array, ...) is returned as-is: none of those can hold a string
 * value a token could hide inside, so there's nothing to redact and every
 * reason not to silently flatten one into `{}` the same way.
 *
 * Guards against a circular `value` with a `seen` map from an original
 * object to its (possibly still-under-construction) redacted copy —
 * structuredClone (the broker's default `cloneArgs`) supports circular
 * references, so a real tool's args snapshot legitimately could be one;
 * an unguarded recursive walk would hang forever on it, which is a worse
 * failure mode for an audit-logging path than a little extra bookkeeping.
 * Registering each container's output object in `seen` BEFORE recursing
 * into its children — not just tracking that it was "seen" — matters: a
 * cyclic back-reference must resolve to the REDACTED copy already under
 * construction, never back to the original object, or the redacted
 * structure would carry a live reference to raw, unredacted content
 * (including the very token this function exists to strip) reachable
 * just one hop further through that back-reference.
 */
export function redactAdcTokens<T>(value: T, seen: WeakMap<object, unknown> = new WeakMap()): T {
  if (typeof value === "string") {
    return value.replace(ADC_TOKEN_RE, "[redacted:adc-token]") as unknown as T;
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  const cached = seen.get(value);
  if (cached !== undefined) {
    return cached as T;
  }

  if (Array.isArray(value)) {
    const out: unknown[] = [];
    seen.set(value, out);
    for (const item of value) out.push(redactAdcTokens(item, seen));
    return out as unknown as T;
  }
  if (value instanceof Map) {
    const out = new Map();
    seen.set(value, out);
    for (const [key, item] of value.entries()) {
      out.set(redactAdcTokens(key, seen), redactAdcTokens(item, seen));
    }
    return out as unknown as T;
  }
  if (value instanceof Set) {
    const out = new Set();
    seen.set(value, out);
    for (const item of value.values()) {
      out.add(redactAdcTokens(item, seen));
    }
    return out as unknown as T;
  }
  if (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null) {
    const out: Record<string, unknown> = {};
    seen.set(value, out);
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = redactAdcTokens(item, seen);
    }
    return out as T;
  }
  // A Date, a typed array, or any other non-plain object: none can hold a
  // string value a token could hide inside, so return it unchanged rather
  // than falling into the plain-object branch above and silently
  // flattening it into `{}` the same way Map/Set used to.
  return value;
}

/**
 * Builds a `redactAuditArgs`-compatible function for
 * `createBroker({ redactAuditArgs })` (taint-tracked-tool-broker's own
 * seam — see its docs/audit-redaction.md) that strips every ADC token out
 * of `call.args` before it reaches `auditSink.record()`.
 *
 * `andThen`, if supplied, runs AFTER this redaction, on the already-token-
 * redacted `call` — compose with an integrator's own pattern from
 * docs/audit-redaction.md (a sinkClass-based blanket redaction, a
 * privateDataSeen-based mask, a key denylist) to cover both concerns:
 *
 * ```ts
 * const broker = createBroker({
 *   redactAuditArgs: createAdcAuditRedactor((call) => redactDenylistedKeys(call.args)),
 * });
 * ```
 *
 * Called with no `andThen`, this alone is a complete, valid
 * `redactAuditArgs` — docs/PLAN.md Phase 5 requires the token be wired in,
 * not that every other pattern in taint-tracked-tool-broker's own docs
 * also be adopted.
 */
export function createAdcAuditRedactor(
  andThen?: (call: ToolCall, taint: TaintContext) => unknown,
): (call: ToolCall, taint: TaintContext) => unknown {
  return (call: ToolCall, taint: TaintContext): unknown => {
    const redactedArgs = redactAdcTokens(call.args);
    return andThen ? andThen({ ...call, args: redactedArgs }, taint) : redactedArgs;
  };
}
