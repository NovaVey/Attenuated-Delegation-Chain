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
}

function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value;
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

  return { port, rootSecretKey, rba: { baseUrl: rbaBaseUrl, apiKey: rbaApiKey, timeoutMs }, adminApiKey };
}
