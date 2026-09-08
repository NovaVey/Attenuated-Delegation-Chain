import type { RawCaveat } from "./block.js";
import type { ReasonCode } from "./errors.js";

/**
 * The closed caveat vocabulary — docs/PLAN.md section 1.5. Not a logic
 * language: a fixed set of typed structs, each with documented semantics
 * as a set over the tuple space, so the reference evaluator (Phase 3) can
 * materialize the permitted set at each hop and intersect.
 *
 * `resourceKind`/`resourceId`/`relation` (scope) and sink classes (sinks)
 * are deliberately typed as plain strings, not a closed enum: their
 * namespaces are owned by RBA and the broker respectively (sibling
 * packages this package takes no dependency on — see docs/PLAN.md
 * section 2). This layer validates their *shape*, not their membership in
 * an external registry; Phase 4/5 integration is where that happens.
 * `taint_max`'s levels are the exception — the ordering is part of this
 * spec (1.5), not an external namespace, so it is a closed enum here.
 */
export type Caveat =
  | { readonly kind: "scope"; readonly triples: readonly (readonly [resourceKind: string, resourceId: string, relation: string])[] }
  | { readonly kind: "sinks"; readonly classes: readonly string[] }
  | { readonly kind: "taint_max"; readonly level: TaintLevel }
  | { readonly kind: "expires"; readonly at: number }
  | { readonly kind: "max_depth"; readonly depth: number }
  | { readonly kind: "hosts"; readonly hostnames: readonly string[] }
  | { readonly kind: "aud"; readonly verifier: string };

export type CaveatKind = Caveat["kind"];

/** `TRUSTED < DERIVED < RAW_UNTRUSTED`, per docs/PLAN.md 1.5. Lower index
 * = more trusted. A `taint_max` caveat's `level` is the highest (most
 * permissive) taint level still permitted. */
export const TAINT_LEVELS = ["TRUSTED", "DERIVED", "RAW_UNTRUSTED"] as const;
export type TaintLevel = (typeof TAINT_LEVELS)[number];

/** Facts supplied by the caller at verification time — docs/PLAN.md 1.6.
 * Every field is optional: a caveat kind whose required fact is missing
 * denies (fails closed) rather than silently passing. `now` is the one
 * exception with a default — see `resolveFacts`. */
export interface Facts {
  readonly resourceKind?: string;
  readonly resourceId?: string;
  readonly relation?: string;
  readonly sink?: string;
  readonly host?: string;
  readonly taintLevel?: TaintLevel;
  /** Unix seconds. Defaults to the real wall clock if omitted — pass this
   * explicitly for deterministic tests. */
  readonly now?: number;
  readonly audience?: string;
}

export interface ResolvedFacts extends Facts {
  readonly now: number;
}

export function resolveFacts(facts: Facts): ResolvedFacts {
  return { ...facts, now: facts.now ?? Math.floor(Date.now() / 1000) };
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === "string" && x.length > 0;
}

function isNonNegativeSafeInteger(x: unknown): x is number {
  // -0 satisfies every other clause here (Number.isInteger(-0),
  // Number.isSafeInteger(-0), and -0 >= 0 are all true in JS) but
  // canonical.ts's stringify() explicitly rejects -0 in numeric fields —
  // reject it here too, at the point of validation, so mintRoot()/
  // attenuate() surface the documented AdcError("ADC_MALFORMED", ...)
  // instead of an untyped RangeError leaking out of encodeBlock() later.
  return (
    typeof x === "number" && Number.isInteger(x) && Number.isSafeInteger(x) && x >= 0 && !Object.is(x, -0)
  );
}

// RFC 1123 hostname shape: dot-separated labels, letters/digits/hyphens,
// no leading/trailing hyphen per label, max 63 chars per label. Doesn't
// validate the FQDN length cap (253) or attempt IDNA/unicode handling —
// good enough for a v1 closed-vocabulary shape check, not a full resolver.
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

// "namespace:action", e.g. exec:shell, write:fs, net:email (1.5's
// examples). The actual set of valid sink classes is broker-owned
// (Phase 5); this only pins the shape.
const SINK_CLASS_RE = /^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$/;

function requireExactKeys(obj: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Object.keys(obj).sort();
  const sortedExpected = [...expected].sort();
  if (keys.length !== sortedExpected.length || keys.some((k, i) => k !== sortedExpected[i])) {
    throw new SyntaxError(`caveat has unexpected fields: expected exactly [${sortedExpected.join(", ")}], got [${keys.join(", ")}]`);
  }
}

/**
 * Validates and narrows a raw (opaque, block.ts-decoded) caveat object
 * into the closed vocabulary. Throws SyntaxError on any structural
 * violation, INCLUDING an unrecognized `kind` — the closed vocabulary is
 * enforced by rejecting anything outside it, never by ignoring it. An
 * unrecognized or malformed caveat must never be silently skipped: a
 * caveat's whole purpose is to *narrow* authority, so silently dropping
 * one a verifier doesn't understand would widen effective authority
 * instead (docs/PLAN.md 1.5's "closed vocabulary" is precisely what makes
 * this the correct default).
 *
 * Used both by verify() (parsing untrusted wire content) and by
 * mintRoot()/attenuate() (validating caller-supplied caveats before
 * embedding them, so a malformed caveat fails fast at mint time rather
 * than confusingly at verify() much later).
 */
export function parseCaveat(raw: unknown): Caveat {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SyntaxError("caveat must be an object");
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.kind !== "string") {
    throw new SyntaxError("caveat must have a string 'kind'");
  }

  switch (obj.kind) {
    case "scope": {
      requireExactKeys(obj, ["kind", "triples"]);
      if (!Array.isArray(obj.triples)) {
        throw new SyntaxError("scope: 'triples' must be an array");
      }
      const triples = obj.triples.map((t, i) => {
        if (!Array.isArray(t) || t.length !== 3 || !t.every(isNonEmptyString)) {
          throw new SyntaxError(
            `scope: triples[${i}] must be a [resourceKind, resourceId-or-'*', relation] array of non-empty strings`,
          );
        }
        return t as unknown as readonly [string, string, string];
      });
      return { kind: "scope", triples };
    }

    case "sinks": {
      requireExactKeys(obj, ["kind", "classes"]);
      if (!Array.isArray(obj.classes)) {
        throw new SyntaxError("sinks: 'classes' must be an array");
      }
      const classes = obj.classes.map((c, i) => {
        if (!isNonEmptyString(c) || !SINK_CLASS_RE.test(c)) {
          throw new SyntaxError(`sinks: classes[${i}] must look like 'namespace:action' (e.g. 'exec:shell')`);
        }
        return c;
      });
      return { kind: "sinks", classes };
    }

    case "taint_max": {
      requireExactKeys(obj, ["kind", "level"]);
      if (typeof obj.level !== "string" || !(TAINT_LEVELS as readonly string[]).includes(obj.level)) {
        throw new SyntaxError(`taint_max: 'level' must be one of ${TAINT_LEVELS.join(", ")}`);
      }
      return { kind: "taint_max", level: obj.level as TaintLevel };
    }

    case "expires": {
      requireExactKeys(obj, ["kind", "at"]);
      if (!isNonNegativeSafeInteger(obj.at)) {
        throw new SyntaxError("expires: 'at' must be a non-negative integer (unix seconds)");
      }
      return { kind: "expires", at: obj.at };
    }

    case "max_depth": {
      requireExactKeys(obj, ["kind", "depth"]);
      if (!isNonNegativeSafeInteger(obj.depth)) {
        throw new SyntaxError("max_depth: 'depth' must be a non-negative integer");
      }
      return { kind: "max_depth", depth: obj.depth };
    }

    case "hosts": {
      requireExactKeys(obj, ["kind", "hostnames"]);
      if (!Array.isArray(obj.hostnames)) {
        throw new SyntaxError("hosts: 'hostnames' must be an array");
      }
      const hostnames = obj.hostnames.map((h, i) => {
        if (!isNonEmptyString(h) || !HOSTNAME_RE.test(h)) {
          throw new SyntaxError(`hosts: hostnames[${i}] is not a valid hostname`);
        }
        return h;
      });
      return { kind: "hosts", hostnames };
    }

    case "aud": {
      requireExactKeys(obj, ["kind", "verifier"]);
      if (!isNonEmptyString(obj.verifier)) {
        throw new SyntaxError("aud: 'verifier' must be a non-empty string");
      }
      return { kind: "aud", verifier: obj.verifier };
    }

    default:
      throw new SyntaxError(`unrecognized caveat kind '${obj.kind}'`);
  }
}

/** A validated Caveat is already RawCaveat-shaped (kind + CanonicalValue
 * fields) — this is a type-level view, not a transformation, so mint-time
 * callers can pass typed Caveats where encodeBlock expects RawCaveats. */
export function caveatToRaw(caveat: Caveat): RawCaveat {
  return caveat as unknown as RawCaveat;
}

export interface EvalContext {
  readonly facts: ResolvedFacts;
  /** blocks.length - 1, from the wire structure — never a self-reported
   * field (docs/PLAN.md 1.5). */
  readonly depth: number;
  readonly clockSkewSeconds: number;
}

export type CaveatEvalResult =
  | { readonly ok: true; readonly usedClockSkew?: boolean }
  | { readonly ok: false; readonly code: ReasonCode; readonly reason: string };

function evalDeny(code: ReasonCode, reason: string): CaveatEvalResult {
  return { ok: false, code, reason };
}

/**
 * Evaluates one caveat's set semantics against the supplied facts —
 * "permits" columns of the table in docs/PLAN.md 1.5. verify() calls this
 * for every caveat in every block and requires ALL to return ok:true
 * (1.6 step 5). That plain AND-across-every-instance composition is what
 * gives `expires` and `max_depth` their documented "minimum across
 * blocks" behavior for free: requiring `now <= at_i` for every `expires`
 * caveat i is exactly requiring `now <= min(at_i)`, and likewise for
 * `max_depth`'s ceiling — no special-cased aggregation needed. The same
 * composition gives `scope`/`sinks`/`hosts`/`taint_max`/`aud` their
 * narrowing behavior: each additional caveat of that kind is one more set
 * (or ceiling, or single required value) the fact must also satisfy.
 */
export function evaluateCaveat(caveat: Caveat, ctx: EvalContext): CaveatEvalResult {
  switch (caveat.kind) {
    case "scope": {
      const { resourceKind, resourceId, relation } = ctx.facts;
      if (resourceKind === undefined || resourceId === undefined || relation === undefined) {
        return evalDeny("ADC_SCOPE", "scope caveat present but resourceKind/resourceId/relation facts were not supplied");
      }
      const permitted = caveat.triples.some(
        ([rk, rid, rel]) => rk === resourceKind && (rid === "*" || rid === resourceId) && rel === relation,
      );
      return permitted
        ? { ok: true }
        : evalDeny("ADC_SCOPE", `(${resourceKind}, ${resourceId}, ${relation}) is not in the permitted scope`);
    }

    case "sinks": {
      const { sink } = ctx.facts;
      if (sink === undefined) {
        return evalDeny("ADC_SINK", "sinks caveat present but 'sink' fact was not supplied");
      }
      return caveat.classes.includes(sink) ? { ok: true } : evalDeny("ADC_SINK", `sink '${sink}' is not permitted`);
    }

    case "taint_max": {
      const { taintLevel } = ctx.facts;
      if (taintLevel === undefined) {
        return evalDeny("ADC_TAINT", "taint_max caveat present but 'taintLevel' fact was not supplied");
      }
      const liveIdx = (TAINT_LEVELS as readonly string[]).indexOf(taintLevel);
      const ceilingIdx = TAINT_LEVELS.indexOf(caveat.level);
      if (liveIdx === -1) {
        return evalDeny("ADC_TAINT", `unrecognized taintLevel '${taintLevel}'`);
      }
      return liveIdx <= ceilingIdx
        ? { ok: true }
        : evalDeny("ADC_TAINT", `taint level '${taintLevel}' exceeds ceiling '${caveat.level}'`);
    }

    case "expires": {
      const now = ctx.facts.now;
      if (now <= caveat.at) return { ok: true };
      if (now <= caveat.at + ctx.clockSkewSeconds) return { ok: true, usedClockSkew: true };
      return evalDeny("ADC_EXPIRED", `expired at ${caveat.at} (now ${now}, skew ${ctx.clockSkewSeconds}s)`);
    }

    case "max_depth":
      return ctx.depth <= caveat.depth
        ? { ok: true }
        : evalDeny("ADC_DEPTH_EXCEEDED", `depth ${ctx.depth} exceeds caveat max_depth ${caveat.depth}`);

    case "hosts": {
      const { host } = ctx.facts;
      if (host === undefined) {
        return evalDeny("ADC_HOST", "hosts caveat present but 'host' fact was not supplied");
      }
      const target = host.toLowerCase();
      return caveat.hostnames.some((h) => h.toLowerCase() === target)
        ? { ok: true }
        : evalDeny("ADC_HOST", `host '${host}' is not permitted`);
    }

    case "aud": {
      const { audience } = ctx.facts;
      if (audience === undefined) {
        return evalDeny("ADC_AUDIENCE", "aud caveat present but 'audience' fact was not supplied");
      }
      return caveat.verifier === audience
        ? { ok: true }
        : evalDeny("ADC_AUDIENCE", `audience '${audience}' does not match required verifier '${caveat.verifier}'`);
    }
  }
}
