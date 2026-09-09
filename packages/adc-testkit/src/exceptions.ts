import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import type { ChainSpec } from "./reference.js";
import type { Tuple } from "./universe.js";

/**
 * The committed false-deny exception list — docs/PLAN.md 3: "False deny
 * (verifier denies, reference allows) — reported and tracked, allowed
 * only against a committed exception list with a written reason per
 * entry." A false GRANT (verifier allows, reference denies) has no such
 * list: it always fails CI, unconditionally.
 *
 * Read directly from the source tree (../../exceptions.json relative to
 * the compiled dist/src/ location), not copied into dist — this file is
 * meant to be hand-edited with a written reason per entry, and reading it
 * from source avoids any stale-copy step.
 */
export interface FalseDenyException {
  readonly key: string;
  readonly reason: string;
}

export interface ExceptionsFile {
  readonly falseDenies: readonly FalseDenyException[];
}

const EXCEPTIONS_PATH = fileURLToPath(new URL("../../exceptions.json", import.meta.url));

/**
 * @param path Override for testing in isolation; defaults to the real
 * committed exceptions.json.
 */
export function loadExceptions(path: string = EXCEPTIONS_PATH): ExceptionsFile {
  // exceptions.json is a committed file that should always exist (as an
  // empty { "falseDenies": [] } when there are no exceptions yet — see
  // the repo's own copy). A missing file is far more likely a broken
  // EXCEPTIONS_PATH or a misplaced build than a legitimate "no
  // exceptions" state, and silently falling back to an empty result here
  // would make that indistinguishable from the real thing — exactly the
  // kind of gap that stays invisible for as long as there happen to be
  // zero false denies to actually match against it. Fail loudly instead.
  if (!existsSync(path)) {
    throw new Error(`exceptions.json not found at ${path} — expected it to exist (even if empty)`);
  }
  const raw = readFileSync(path, "utf8");
  const parsed = JSON.parse(raw) as ExceptionsFile;
  if (!Array.isArray(parsed.falseDenies)) {
    throw new SyntaxError(`exceptions.json: 'falseDenies' must be an array`);
  }
  return parsed;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
}

/**
 * A deterministic, stable key for one (chain, query, clockSkewSeconds)
 * case, for matching an observed false-deny against a committed
 * exceptions.json entry. This is a content hash of the logical case
 * itself — independent of fast-check's run bookkeeping (seed, run
 * index) — so it survives changes to numRuns, generator order, or the
 * seed, as long as the exact case recurs.
 */
export function falseDenyKey(spec: ChainSpec, query: Tuple, clockSkewSeconds: number): string {
  const canonical = stableStringify({ spec, query, clockSkewSeconds });
  return createHash("sha256").update(canonical).digest("hex").slice(0, 16);
}

export function isKnownFalseDeny(key: string, exceptions: ExceptionsFile): boolean {
  return exceptions.falseDenies.some((e) => e.key === key);
}
