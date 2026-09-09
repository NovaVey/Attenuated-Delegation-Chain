import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { mintWithBounding } from "./mint.js";
import type { RbaClient } from "./rba/client.js";

/**
 * Plain node:http server — no framework dependency, matching this repo's
 * minimal-dependency style (packages/adc-core, packages/adc-testkit).
 * Two routes: GET /health, POST /mint.
 */

const MAX_BODY_BYTES = 64 * 1024; // a mint request is small; this is generous headroom, not a real limit

export interface CreateMintServerOptions {
  readonly rootSecretKey: Uint8Array;
  readonly rba: RbaClient;
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

export function createMintServer(opts: CreateMintServerOptions): Server {
  const onInternalError = opts.onInternalError ?? ((err: unknown) => console.error("mint-service: unhandled error", err));

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
