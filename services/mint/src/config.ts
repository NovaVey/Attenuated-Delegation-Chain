import { resolve } from "node:path";

/**
 * Env-var configuration. The root secret key is the single most
 * sensitive value this service ever touches (docs/PLAN.md 1.2: "The
 * proof field on an attenuable token is a private key... must never be
 * logged") — the ROOT secret key handled here is the same class of
 * secret, one level up the chain, so the same rule applies: never log
 * it, never include it in an error message, never echo it back.
 */

export interface ServiceConfig {
  readonly port: number;
  readonly rootSecretKey: Uint8Array;
  readonly rba: {
    readonly baseUrl: string;
    readonly apiKey: string;
    readonly timeoutMs?: number;
  };
  /** Bearer token required on POST /revoke — see server.ts. A secret in
   * the same sense as everything else in this file (never logged, never
   * echoed back), though its blast radius is narrower than the root key:
   * holding it lets someone revoke blocks, not mint or forge tokens. */
  readonly adminApiKey: string;
  /** Max POST /mint requests per minute, service-wide (see
   * src/rate-limiter.ts's own doc comment on why this exists in addition
   * to RBA's own per-API-key limits). undefined when unset — server.ts
   * applies its own default, matching this file's established convention
   * for optional numeric settings (see rba.timeoutMs). */
  readonly mintRateLimitPerMinute?: number;
  /** Path to a JSON file backing the revocation store durably across
   * restarts — see src/revocation-store.ts. undefined (the default)
   * keeps the store purely in-memory, exactly as it's always been. */
  readonly revocationStoreFilePath?: string;
  /** Path to an NDJSON file every 'mint'/'revoke' Principal-Graph event is
   * appended to (see @adc/graph's createNdjsonGraphSink and this
   * service's own README). undefined (the default) keeps the private,
   * process-local in-memory sink server.ts already defaults to —
   * unobservable from outside the process, exactly as it's always been. */
  readonly graphEventsFilePath?: string;
}

function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value;
}

/** An empty string is treated the same as unset — matches how an
 * accidentally-set-but-blank env var behaves in most shells/orchestrators
 * (e.g. `FOO=` in a .env file, or a templated deployment variable that
 * resolved to empty). */
function optionalEnv(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name];
  return value === undefined || value.length === 0 ? undefined : value;
}

function decodeRootSecretKey(b64: string): Uint8Array {
  let bytes: Buffer;
  try {
    bytes = Buffer.from(b64, "base64");
  } catch (err) {
    throw new Error(`MINT_ROOT_SECRET_KEY_B64 is not valid base64: ${(err as Error).message}`);
  }
  if (bytes.length !== 32) {
    throw new Error(`MINT_ROOT_SECRET_KEY_B64 must decode to 32 bytes, got ${bytes.length}`);
  }
  return new Uint8Array(bytes);
}

export function loadConfigFromEnv(env: NodeJS.ProcessEnv = process.env): ServiceConfig {
  const portRaw = env.PORT ?? "3001";
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`PORT must be an integer in 1..65535, got '${portRaw}'`);
  }

  const rootSecretKey = decodeRootSecretKey(requireEnv(env, "MINT_ROOT_SECRET_KEY_B64"));
  const rbaBaseUrl = requireEnv(env, "RBA_BASE_URL");
  const rbaApiKey = requireEnv(env, "RBA_API_KEY");
  const adminApiKey = requireEnv(env, "MINT_ADMIN_API_KEY");

  let timeoutMs: number | undefined;
  if (env.RBA_TIMEOUT_MS !== undefined) {
    timeoutMs = Number(env.RBA_TIMEOUT_MS);
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new Error(`RBA_TIMEOUT_MS must be a positive integer, got '${env.RBA_TIMEOUT_MS}'`);
    }
  }

  let mintRateLimitPerMinute: number | undefined;
  if (env.MINT_RATE_LIMIT_PER_MINUTE !== undefined) {
    mintRateLimitPerMinute = Number(env.MINT_RATE_LIMIT_PER_MINUTE);
    // A positive INTEGER, matching PORT/RBA_TIMEOUT_MS's own convention
    // above — not just "> 0": a fractional value below 1 (e.g. "0.5")
    // would pass a bare "> 0" check yet produce a rate limiter whose own
    // bucket capacity can never reach the >= 1 threshold needed to grant
    // even a single request, silently denying every POST /mint forever
    // (see rate-limiter.ts's own hardening for the same issue).
    if (!Number.isInteger(mintRateLimitPerMinute) || mintRateLimitPerMinute < 1) {
      throw new Error(`MINT_RATE_LIMIT_PER_MINUTE must be a positive integer, got '${env.MINT_RATE_LIMIT_PER_MINUTE}'`);
    }
  }

  const revocationStoreFilePath = optionalEnv(env, "MINT_REVOCATION_STORE_PATH");
  const graphEventsFilePath = optionalEnv(env, "MINT_GRAPH_EVENTS_PATH");

  // Found by adversarial review: these two files are written by
  // completely different, incompatible strategies — the revocation store
  // does a full atomic REPLACE of the whole file on every revoke()
  // (revocation-store.ts), while the graph-events sink only ever APPENDS
  // lines (ndjson.ts). Pointed at the same path, each silently corrupts
  // the other: a revoke() replaces the file, destroying prior NDJSON
  // history, and the next graph event then appends NDJSON after the
  // revocation store's own JSON object, corrupting THAT — which
  // RevocationStore's constructor (run at module-top-level in index.ts)
  // then refuses to load on the next restart, crashing the service at
  // startup until an operator manually fixes the file. resolve() first,
  // not a raw string compare — two different-looking but equivalent
  // paths (a relative one and its absolute form, say) must collide here
  // too.
  if (revocationStoreFilePath !== undefined && graphEventsFilePath !== undefined && resolve(revocationStoreFilePath) === resolve(graphEventsFilePath)) {
    throw new Error(
      `MINT_REVOCATION_STORE_PATH and MINT_GRAPH_EVENTS_PATH must not point at the same file (both resolve to '${resolve(revocationStoreFilePath)}') — they are written by incompatible strategies (replace vs. append) and would corrupt each other`,
    );
  }

  return {
    port,
    rootSecretKey,
    rba: { baseUrl: rbaBaseUrl, apiKey: rbaApiKey, timeoutMs },
    adminApiKey,
    mintRateLimitPerMinute,
    revocationStoreFilePath,
    graphEventsFilePath,
  };
}
