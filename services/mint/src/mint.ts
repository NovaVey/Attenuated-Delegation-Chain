import { mintRoot, encodeToken, parseCaveat, AdcError, type Caveat } from "@adc/core";
import { boundScopeCaveats, type BoundingFailure } from "./bounding.js";
import type { RbaClient, Subject } from "./rba/client.js";

/**
 * Validates and mints in one place: structural validation of the request
 * body (never trusting the caller's shape claims), then RBA bounding
 * (docs/PLAN.md Phase 4), then the actual mint via @adc/core's
 * mintRoot(). Structural validation runs FIRST and before any RBA call —
 * boundScopeCaveats() assumes well-typed Caveat[] input (it destructures
 * scope triples directly) and mintRoot()'s own caveat validation only
 * runs after minting would already be attempted, so validating here
 * first is what keeps a malformed caveat from ever reaching bounding
 * logic that isn't shaped to handle it, and avoids spending an RBA
 * round-trip on a request that was never going to mint anyway.
 */

export type MintOutcome =
  | { readonly ok: true; readonly token: string; readonly depth: number }
  | { readonly ok: false; readonly code: "invalid_request"; readonly message: string }
  | { readonly ok: false; readonly code: "scope_not_granted"; readonly failures: readonly BoundingFailure[] }
  | { readonly ok: false; readonly code: "rba_unavailable"; readonly message: string };

function isNonEmptyString(x: unknown): x is string {
  return typeof x === "string" && x.length > 0;
}

function parseSubject(raw: unknown): Subject {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SyntaxError("'subject' must be an object");
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  if (keys.length !== 2 || keys[0] !== "id" || keys[1] !== "ns") {
    throw new SyntaxError("'subject' must have exactly fields 'ns', 'id'");
  }
  if (!isNonEmptyString(obj.ns) || !isNonEmptyString(obj.id)) {
    throw new SyntaxError("'subject.ns' and 'subject.id' must be non-empty strings");
  }
  return { ns: obj.ns, id: obj.id };
}

function parseCaveats(raw: unknown): Caveat[] {
  if (!Array.isArray(raw)) {
    throw new SyntaxError("'caveats' must be an array");
  }
  return raw.map((c, i) => {
    try {
      return parseCaveat(c);
    } catch (err) {
      throw new SyntaxError(`caveats[${i}] is invalid: ${(err as Error).message}`);
    }
  });
}

interface ParsedMintRequest {
  readonly subject: Subject;
  readonly caveats: readonly Caveat[];
}

function parseMintRequestBody(raw: unknown): ParsedMintRequest {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SyntaxError("request body must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  if (keys.length !== 2 || keys[0] !== "caveats" || keys[1] !== "subject") {
    throw new SyntaxError("request body must have exactly fields 'subject', 'caveats'");
  }
  return { subject: parseSubject(obj.subject), caveats: parseCaveats(obj.caveats) };
}

/**
 * The full mint pipeline, taking the raw (untrusted, `unknown`-typed)
 * request body. Never throws for a malformed request or an RBA failure —
 * always resolves to a MintOutcome. Can still throw for a genuinely
 * unexpected internal error (e.g. a bug in mintRoot() unrelated to caveat
 * validation, or the root secret key itself being invalid) — those are
 * the caller's (server.ts's) responsibility to turn into a 500, not
 * silently swallow.
 */
export async function mintWithBounding(rootSecretKey: Uint8Array, rba: RbaClient, rawBody: unknown): Promise<MintOutcome> {
  let request: ParsedMintRequest;
  try {
    request = parseMintRequestBody(rawBody);
  } catch (err) {
    return { ok: false, code: "invalid_request", message: (err as Error).message };
  }

  const boundingResult = await boundScopeCaveats(request.caveats, request.subject, rba);
  if (!boundingResult.ok) {
    if (boundingResult.failures.every((f) => f.kind === "rba_unavailable")) {
      const first = boundingResult.failures[0];
      return { ok: false, code: "rba_unavailable", message: first && "message" in first ? first.message : "RBA unavailable" };
    }
    return { ok: false, code: "scope_not_granted", failures: boundingResult.failures };
  }

  try {
    const token = mintRoot(rootSecretKey, { caveats: request.caveats });
    return { ok: true, token: encodeToken(token), depth: 0 };
  } catch (err) {
    // Caveats were already validated above via parseCaveat, so mintRoot's
    // own re-validation should never actually fire here — this is a
    // last-resort translation, not the primary validation path.
    if (err instanceof AdcError) {
      return { ok: false, code: "invalid_request", message: err.message };
    }
    throw err;
  }
}
