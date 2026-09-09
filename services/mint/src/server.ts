import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { buildRevocationList, signRevocationList } from "@adc/revocation";
import { mintWithBounding } from "./mint.js";
import type { RbaClient } from "./rba/client.js";
import { RevocationStore } from "./revocation-store.js";

/**
 * Plain node:http server — no framework dependency, matching this repo's
 * minimal-dependency style (packages/adc-core, packages/adc-testkit).
 * Four routes: GET /health, POST /mint, POST /revoke, GET /revocations.
 */

const MAX_BODY_BYTES = 64 * 1024; // requests here are small; this is generous headroom, not a real limit

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

async function handleMint(req: IncomingMessage, res: ServerResponse, opts: CreateMintServerOptions): Promise<void> {
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

  const outcome = await mintWithBounding(opts.rootSecretKey, opts.rba, parsed);

  if (outcome.ok) {
    sendJson(res, 201, { token: outcome.token, depth: outcome.depth });
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

async function handleRevoke(req: IncomingMessage, res: ServerResponse, opts: CreateMintServerOptions, store: RevocationStore): Promise<void> {
  if (!isAuthorizedAdmin(req, opts.adminApiKey)) {
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
  const hash = (parsed as Record<string, unknown>).hash;
  if (typeof hash !== "string") {
    sendJson(res, 400, { error: { code: "invalid_request", message: "'hash' must be a string" } });
    return;
  }

  try {
    store.revoke(hash);
  } catch (err) {
    sendJson(res, 400, { error: { code: "invalid_request", message: (err as Error).message } });
    return;
  }

  sendJson(res, 200, { revoked: hash });
}

/** Builds and signs a FRESH list on every request — this store is small
 * (block-signature hashes only) and signing is cheap, so there's no
 * cached-list staleness of its own to manage here; the 60s TTL a
 * verifier's client (@adc/revocation's createRevocationClient) applies is
 * what actually bounds a *client's* view, not this endpoint's own
 * response. Unauthenticated: the list contains only hashes, nothing
 * sensitive — matching public CRL/OCSP-list practice. */
function handleRevocations(res: ServerResponse, opts: CreateMintServerOptions, store: RevocationStore): void {
  const list = buildRevocationList(store.list());
  const signed = signRevocationList(list, opts.rootSecretKey);
  sendJson(res, 200, signed);
}

export function createMintServer(opts: CreateMintServerOptions): Server {
  const onInternalError = opts.onInternalError ?? ((err: unknown) => console.error("mint-service: unhandled error", err));
  const revocationStore = opts.revocationStore ?? new RevocationStore();

  return createServer((req, res) => {
    void (async () => {
      try {
        if (req.method === "GET" && req.url === "/health") {
          sendJson(res, 200, { status: "ok" });
          return;
        }
        if (req.method === "POST" && req.url === "/mint") {
          await handleMint(req, res, opts);
          return;
        }
        if (req.method === "POST" && req.url === "/revoke") {
          await handleRevoke(req, res, opts, revocationStore);
          return;
        }
        if (req.method === "GET" && req.url === "/revocations") {
          handleRevocations(res, opts, revocationStore);
          return;
        }
        sendJson(res, 404, { error: { code: "not_found", message: "no such route" } });
      } catch (err) {
        onInternalError(err);
        if (!res.headersSent) {
          sendJson(res, 500, { error: { code: "internal_error", message: "unexpected server error" } });
        } else {
          res.destroy();
        }
      }
    })();
  });
}
