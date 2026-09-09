import { test } from "node:test";
import assert from "node:assert/strict";
import { loadConfigFromEnv } from "../src/config.js";

const VALID_KEY_B64 = Buffer.from(new Uint8Array(32).fill(7)).toString("base64");

function baseEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    MINT_ROOT_SECRET_KEY_B64: VALID_KEY_B64,
    RBA_BASE_URL: "https://rba.example.com",
    RBA_API_KEY: "test-api-key",
    MINT_ADMIN_API_KEY: "test-admin-key",
    ...overrides,
  };
}

test("loads a valid config, defaulting PORT to 3001", () => {
  const config = loadConfigFromEnv(baseEnv());
  assert.equal(config.port, 3001);
  assert.equal(config.rootSecretKey.length, 32);
  assert.equal(config.rba.baseUrl, "https://rba.example.com");
  assert.equal(config.rba.apiKey, "test-api-key");
  assert.equal(config.rba.timeoutMs, undefined);
  assert.equal(config.adminApiKey, "test-admin-key");
});

test("respects an explicit PORT", () => {
  const config = loadConfigFromEnv(baseEnv({ PORT: "8080" }));
  assert.equal(config.port, 8080);
});

test("respects RBA_TIMEOUT_MS", () => {
  const config = loadConfigFromEnv(baseEnv({ RBA_TIMEOUT_MS: "2500" }));
  assert.equal(config.rba.timeoutMs, 2500);
});

test("throws on a missing MINT_ROOT_SECRET_KEY_B64", () => {
  const env = baseEnv();
  delete env.MINT_ROOT_SECRET_KEY_B64;
  assert.throws(() => loadConfigFromEnv(env), /MINT_ROOT_SECRET_KEY_B64/);
});

test("throws on a root secret key that doesn't decode to 32 bytes", () => {
  const shortKey = Buffer.from(new Uint8Array(16)).toString("base64");
  assert.throws(() => loadConfigFromEnv(baseEnv({ MINT_ROOT_SECRET_KEY_B64: shortKey })), /32 bytes/);
});

test("throws on a missing RBA_BASE_URL", () => {
  const env = baseEnv();
  delete env.RBA_BASE_URL;
  assert.throws(() => loadConfigFromEnv(env), /RBA_BASE_URL/);
});

test("throws on a missing RBA_API_KEY", () => {
  const env = baseEnv();
  delete env.RBA_API_KEY;
  assert.throws(() => loadConfigFromEnv(env), /RBA_API_KEY/);
});

test("throws on a missing MINT_ADMIN_API_KEY", () => {
  const env = baseEnv();
  delete env.MINT_ADMIN_API_KEY;
  assert.throws(() => loadConfigFromEnv(env), /MINT_ADMIN_API_KEY/);
});

test("throws on an invalid PORT", () => {
  assert.throws(() => loadConfigFromEnv(baseEnv({ PORT: "not-a-number" })), /PORT/);
  assert.throws(() => loadConfigFromEnv(baseEnv({ PORT: "0" })), /PORT/);
  assert.throws(() => loadConfigFromEnv(baseEnv({ PORT: "99999" })), /PORT/);
});

test("throws on an invalid RBA_TIMEOUT_MS", () => {
  assert.throws(() => loadConfigFromEnv(baseEnv({ RBA_TIMEOUT_MS: "-5" })), /RBA_TIMEOUT_MS/);
  assert.throws(() => loadConfigFromEnv(baseEnv({ RBA_TIMEOUT_MS: "not-a-number" })), /RBA_TIMEOUT_MS/);
});

test("the base64 root secret key decodes to the exact expected bytes, not a truncated or re-encoded value", () => {
  const config = loadConfigFromEnv(baseEnv());
  assert.deepEqual(config.rootSecretKey, new Uint8Array(32).fill(7));
});
