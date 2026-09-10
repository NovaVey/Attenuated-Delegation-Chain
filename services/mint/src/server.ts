import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { decodeToken, getPublicKey } from "@adc/core";
import { buildMintEvent, buildRevokeEvent, createInMemoryGraphSink, type GraphEvent, type GraphPrincipalIdentity, type GraphSink } from "@adc/graph";
import { buildRevocationList, signRevocationList } from "@adc/revocation";
import { mintWithBounding } from "./mint.js";
import { createTokenBucketRateLimiter, type RateLimiter } from "./rate-limiter.js";
import type { RbaClient } from "./rba/client.js";
import { RevocationStore } from "./revocation-store.js";

/**
 * Plain node:http server — no framework dependency, matching this repo's
 * minimal-dependency style (packages/adc-core, packages/adc-testkit).
 * Four routes: GET /health, POST /mint, POST /revoke, GET /revocations.
 */

const MAX_BODY_BYTES = 64 * 1024; // requests here are small; this is generous headroom, not a real limit

/** No caller identity of any kind exists for POST /revoke beyond "held
 * the shared admin bearer token" (see config.ts's adminApiKey and
 * README.md's Known limitations) — so every revoke event this service
 * emits names the same coarse, service-level actor rather than guessing
 * at a finer-grained identity that doesn't exist. */
const REVOKE_ADMIN_PRINCIPAL: GraphPrincipalIdentity = { kind: "service", source: "adc-mint-admin", externalId: "admin" };

export interface CreateMintServerOptions {
  readonly rootSecretKey: Uint8Array;
  readonly rba: RbaClient;
  /** Bearer token required on POST /revoke — see config.ts's own doc
   * comment on this same value. */
  readonly adminApiKey: string;
  /** Injectable for tests that want to assert on the store's contents
   * directly, or pre-seed revoked hashes without going through HTTP.
   * Defaults to a fresh, empty in-memory store. */
  readonly revocationStore?: RevocationStore;
  /** Max POST /mint requests per minute, service-wide — see
   * src/rate-limiter.ts. Default 60 (1/sec sustained): generous enough
   * not to trouble ordinary traffic, tight enough to meaningfully bound a
   * runaway or malicious client before a single RBA call is even made. */
  readonly mintRateLimitPerMinute?: number;
  /** Injectable for tests that want a deterministic rate limiter (a fixed
   * clock, or a pre-exhausted bucket) instead of one built from
   * `mintRateLimitPerMinute` against the real wall clock. */
  readonly mintRateLimiter?: RateLimiter;
  /** Where successful 'mint' and 'revoke' actions are recorded as
   * Principal-Graph events (docs/PLAN.md Phase 6) — see @adc/graph's own
   * README for why this package can only emit plain event data, not write
   * into Principal-Graph itself. Defaults to a fresh in-memory sink (see
   * @adc/graph's createInMemoryGraphSink); a real deployment injects a
   * sink that forwards to an actual Principal-Graph-side adapter.
   * Rejected mints (scope_not_granted) are NOT represented here —
   * @adc/graph's event vocabulary has no way to build an event for a mint
   * that never produced a token (no block, no signature, nothing to
   * derive a Principal-Graph resource identity from); see README.md's
   * Known limitations. */
  readonly graphSink?: GraphSink;
  /** Injectable for tests that want to assert on logged errors instead of
   * writing to the real console. Defaults to console.error. */
  readonly onInternalError?: (err: unknown) => void;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(payload);
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        reject(new Error(`request body exceeds ${maxBytes} bytes`));
        // Drain (not destroy) the rest: destroying the request also
        // tears down the underlying socket before handleMint's caller
        // gets a chance to write the 413 response on it — the client
        // would see a connection reset instead of an actual 413.
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

/** Fully-resolved server state — every `CreateMintServerOptions` optional
 * field defaulted exactly once, here, rather than each handler repeating
 * its own `opts.x ?? default` fallback. Built once per `createMintServer()`
 * call. */
interface ServerContext {
  readonly rootSecretKey: Uint8Array;
  readonly rootPublicKey: Uint8Array;
  readonly rba: RbaClient;
  readonly adminApiKey: string;
  readonly revocationStore: RevocationStore;
  readonly mintRateLimiter: RateLimiter;
  readonly graphSink: GraphSink;
  readonly onInternalError: (err: unknown) => void;
}

/** Records a 'mint' or 'revoke' Principal-Graph event, never letting a
 * sink failure affect the HTTP response — GraphSink's own contract says
 * record() is synchronous and never throws back into its caller (see
 * @adc/graph's event.ts doc comment), but a caller-injected sink might
 * not honor that; this is the backstop, matching the "an audit/
 * observability side channel never breaks the primary flow" discipline
 * already established elsewhere in this codebase (packages/adc-broker's
 * audit redaction). By the time this is called the mint or revoke has
 * already durably succeeded, so a sink failure here must never turn an
 * already-successful response into an error. */
function recordGraphEvent(ctx: ServerContext, build: () => GraphEvent): void {
  try {
    ctx.graphSink.record(build());
  } catch (err) {
    ctx.onInternalError(err);
  }
}

async function handleMint(req: IncomingMessage, res: ServerResponse, ctx: ServerContext): Promise<void> {
  if (!ctx.mintRateLimiter.tryAcquire()) {
    sendJson(res, 429, { error: { code: "rate_limited", message: "too many mint requests; try again shortly" } });
    return;
  }

  let raw: string;
  try {
    raw = await readBody(req, MAX_BODY_BYTES);
  } catch (err) {
    sendJson(res, 413, { error: { code: "payload_too_large", message: (err as Error).message } });
    return;
  }

  let parsed: unknown;
  try {
    parsed = raw.length > 0 ? JSON.parse(raw) : undefined;
  } catch {
    sendJson(res, 400, { error: { code: "invalid_request", message: "body must be valid JSON" } });
    return;
  }

  const outcome = await mintWithBounding(ctx.rootSecretKey, ctx.rba, parsed);

  if (outcome.ok) {
    sendJson(res, 201, { token: outcome.token, depth: outcome.depth });
    // Re-decode the just-minted wire token rather than threading the
    // ParsedToken out of mintWithBounding() — the same "re-decode
    // independently from the wire bytes" pattern @adc/graph's own
    // buildVerifyEvent() already uses, and it keeps mintWithBounding()'s
    // return contract unchanged for every other caller/test.
    recordGraphEvent(ctx, () => buildMintEvent(decodeToken(outcome.token), ctx.rootPublicKey));
    return;
  }

  if (outcome.code === "invalid_request") {
    sendJson(res, 400, { error: { code: "invalid_request", message: outcome.message } });
    return;
  }

  if (outcome.code === "scope_not_granted") {
    sendJson(res, 403, {
      error: {
        code: "scope_not_granted",
        message: "one or more requested scope grants are not held by subject at mint time",
        details: outcome.failures,
      },
    });
    return;
  }

  // outcome.code === "rba_unavailable"
  sendJson(res, 502, { error: { code: "rba_unavailable", message: outcome.message } });
}

/** Constant-time bearer-token check — an admin key is a secret worth the
 * same care as anything else in this service (see config.ts), and a
 * length-then-byte-compare via `===` leaks timing information a
 * length-checked timingSafeEqual() does not. Mirrors the `Authorization:
 * Bearer <key>` convention this codebase already uses client-side
 * against RBA (src/rba/client.ts). */
function isAuthorizedAdmin(req: IncomingMessage, adminApiKey: string): boolean {
  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const provided = Buffer.from(header.slice("Bearer ".length), "utf8");
  const expected = Buffer.from(adminApiKey, "utf8");
  // timingSafeEqual throws on a length mismatch rather than returning
  // false — guard that first, which itself leaks only the *length* of
  // the admin key (already implicitly public: it's a fixed operational
  // secret whose length isn't the thing being protected), not any byte
  // of it or of the guess.
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

async function handleRevoke(req: IncomingMessage, res: ServerResponse, ctx: ServerContext): Promise<void> {
  if (!isAuthorizedAdmin(req, ctx.adminApiKey)) {
    sendJson(res, 401, { error: { code: "unauthorized", message: "missing or invalid admin bearer token" } });
    return;
  }

  let raw: string;
  try {
    raw = await readBody(req, MAX_BODY_BYTES);
  } catch (err) {
    sendJson(res, 413, { error: { code: "payload_too_large", message: (err as Error).message } });
    return;
  }

  let parsed: unknown;
  try {
    parsed = raw.length > 0 ? JSON.parse(raw) : undefined;
  } catch {
    sendJson(res, 400, { error: { code: "invalid_request", message: "body must be valid JSON" } });
    return;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    sendJson(res, 400, { error: { code: "invalid_request", message: "request body must be a JSON object" } });
    return;
  }
  const body = parsed as Record<string, unknown>;
  const hash = body.hash;
  if (typeof hash !== "string") {
    sendJson(res, 400, { error: { code: "invalid_request", message: "'hash' must be a string" } });
    return;
  }
  // Optional — free text, carried into the Principal-Graph event's
  // taintLabels (see buildRevokeEvent's own doc comment: never
  // denyReason, since this event's decision is always 'allow', the
  // revocation itself succeeding). Not persisted anywhere else. Bounded
  // well below MAX_BODY_BYTES: this is meant to be a short human note
  // ("compromised key, incident #42"), not an arbitrary blob — a
  // downstream GraphSink that logs/stores/displays taint labels verbatim
  // shouldn't have to defend against one being stuffed with tens of KB of
  // text just because the admin-authenticated caller who supplies it
  // could.
  const MAX_REASON_LENGTH = 500;
  const reason = body.reason;
  if (reason !== undefined && typeof reason !== "string") {
    sendJson(res, 400, { error: { code: "invalid_request", message: "'reason', if present, must be a string" } });
    return;
  }
  if (typeof reason === "string" && reason.length > MAX_REASON_LENGTH) {
    sendJson(res, 400, { error: { code: "invalid_request", message: `'reason' must be at most ${MAX_REASON_LENGTH} characters` } });
    return;
  }

  try {
    ctx.revocationStore.revoke(hash);
  } catch (err) {
    sendJson(res, 400, { error: { code: "invalid_request", message: (err as Error).message } });
    return;
  }

  sendJson(res, 200, { revoked: hash });
  recordGraphEvent(ctx, () => buildRevokeEvent(hash, { actor: REVOKE_ADMIN_PRINCIPAL, reason: reason ?? "revoked via POST /revoke" }));
}

/** Builds and signs a FRESH list on every request — this store is small
 * (block-signature hashes only) and signing is cheap, so there's no
 * cached-list staleness of its own to manage here; the 60s TTL a
 * verifier's client (@adc/revocation's createRevocationClient) applies is
 * what actually bounds a *client's* view, not this endpoint's own
 * response. Unauthenticated: the list contains only hashes, nothing
 * sensitive — matching public CRL/OCSP-list practice. */
function handleRevocations(res: ServerResponse, ctx: ServerContext): void {
  const list = buildRevocationList(ctx.revocationStore.list());
  const signed = signRevocationList(list, ctx.rootSecretKey);
  sendJson(res, 200, signed);
}

export function createMintServer(opts: CreateMintServerOptions): Server {
  const ctx: ServerContext = {
    rootSecretKey: opts.rootSecretKey,
    // Deliberately eager: a wrong-length rootSecretKey now throws here,
    // at server construction, rather than lazily on the first mint/revoke
    // that actually needs the derived public key — the same "fail loudly
    // and immediately, not silently until first use" preference this
    // round of changes already applies to a corrupt revocation-store
    // file (see revocation-store.ts). index.ts's own config.ts already
    // validates the key's length before ever reaching this call, so this
    // never fires in production; it only changes WHEN a malformed key
    // passed directly to this function (bypassing config.ts) is caught.
    rootPublicKey: getPublicKey(opts.rootSecretKey),
    rba: opts.rba,
    adminApiKey: opts.adminApiKey,
    revocationStore: opts.revocationStore ?? new RevocationStore(),
    mintRateLimiter: opts.mintRateLimiter ?? createTokenBucketRateLimiter({ limit: opts.mintRateLimitPerMinute ?? 60, windowMs: 60_000 }),
    graphSink: opts.graphSink ?? createInMemoryGraphSink(),
    onInternalError: opts.onInternalError ?? ((err: unknown) => console.error("mint-service: unhandled error", err)),
  };

  return createServer((req, res) => {
    void (async () => {
      try {
        if (req.method === "GET" && req.url === "/health") {
          sendJson(res, 200, { status: "ok" });
          return;
        }
        if (req.method === "POST" && req.url === "/mint") {
          await handleMint(req, res, ctx);
          return;
        }
        if (req.method === "POST" && req.url === "/revoke") {
          await handleRevoke(req, res, ctx);
          return;
        }
        if (req.method === "GET" && req.url === "/revocations") {
          handleRevocations(res, ctx);
          return;
        }
        sendJson(res, 404, { error: { code: "not_found", message: "no such route" } });
      } catch (err) {
        ctx.onInternalError(err);
        if (!res.headersSent) {
          sendJson(res, 500, { error: { code: "internal_error", message: "unexpected server error" } });
        } else {
          res.destroy();
        }
      }
    })();
  });
}
