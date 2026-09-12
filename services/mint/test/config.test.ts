import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
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
  assert.equal(config.mintRateLimitPerMinute, undefined);
  assert.equal(config.revocationStoreFilePath, undefined);
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

test("respects MINT_RATE_LIMIT_PER_MINUTE", () => {
  const config = loadConfigFromEnv(baseEnv({ MINT_RATE_LIMIT_PER_MINUTE: "120" }));
  assert.equal(config.mintRateLimitPerMinute, 120);
});

test("throws on an invalid MINT_RATE_LIMIT_PER_MINUTE", () => {
  assert.throws(() => loadConfigFromEnv(baseEnv({ MINT_RATE_LIMIT_PER_MINUTE: "0" })), /MINT_RATE_LIMIT_PER_MINUTE/);
  assert.throws(() => loadConfigFromEnv(baseEnv({ MINT_RATE_LIMIT_PER_MINUTE: "-5" })), /MINT_RATE_LIMIT_PER_MINUTE/);
  assert.throws(() => loadConfigFromEnv(baseEnv({ MINT_RATE_LIMIT_PER_MINUTE: "not-a-number" })), /MINT_RATE_LIMIT_PER_MINUTE/);
  // A fractional value below 1 must be rejected too — see config.ts's own
  // doc comment: it would otherwise pass a bare "> 0" check yet build a
  // rate limiter that can never grant even a single request.
  assert.throws(() => loadConfigFromEnv(baseEnv({ MINT_RATE_LIMIT_PER_MINUTE: "0.5" })), /MINT_RATE_LIMIT_PER_MINUTE/);
  // Non-integer, otherwise positive — still rejected, matching PORT/RBA_TIMEOUT_MS's own integer-only convention.
  assert.throws(() => loadConfigFromEnv(baseEnv({ MINT_RATE_LIMIT_PER_MINUTE: "60.5" })), /MINT_RATE_LIMIT_PER_MINUTE/);
});

test("respects MINT_REVOCATION_STORE_PATH", () => {
  const config = loadConfigFromEnv(baseEnv({ MINT_REVOCATION_STORE_PATH: "/var/lib/adc-mint/revoked.json" }));
  assert.equal(config.revocationStoreFilePath, "/var/lib/adc-mint/revoked.json");
});

test("MINT_REVOCATION_STORE_PATH set to an empty string is treated the same as unset", () => {
  const config = loadConfigFromEnv(baseEnv({ MINT_REVOCATION_STORE_PATH: "" }));
  assert.equal(config.revocationStoreFilePath, undefined);
});

test("respects MINT_GRAPH_EVENTS_PATH", () => {
  const config = loadConfigFromEnv(baseEnv({ MINT_GRAPH_EVENTS_PATH: "/var/log/adc-mint/events.ndjson" }));
  assert.equal(config.graphEventsFilePath, "/var/log/adc-mint/events.ndjson");
});

test("MINT_GRAPH_EVENTS_PATH is undefined when unset, and an empty string is treated the same as unset", () => {
  assert.equal(loadConfigFromEnv(baseEnv()).graphEventsFilePath, undefined);
  assert.equal(loadConfigFromEnv(baseEnv({ MINT_GRAPH_EVENTS_PATH: "" })).graphEventsFilePath, undefined);
});

test("throws if MINT_REVOCATION_STORE_PATH and MINT_GRAPH_EVENTS_PATH point at the same file", () => {
  // Regression test for an adversarial-review finding: these two files
  // are written by incompatible strategies (replace vs. append) and
  // would silently corrupt each other if pointed at the same path.
  assert.throws(
    () => loadConfigFromEnv(baseEnv({ MINT_REVOCATION_STORE_PATH: "/var/lib/adc-mint/state.json", MINT_GRAPH_EVENTS_PATH: "/var/lib/adc-mint/state.json" })),
    /MINT_REVOCATION_STORE_PATH and MINT_GRAPH_EVENTS_PATH must not point at the same file/,
  );
});

test("the same-file check resolves paths first — a relative path and its equivalent absolute form still collide", () => {
  const cwdRelative = "state.json";
  const absolute = resolve(cwdRelative);
  assert.throws(
    () => loadConfigFromEnv(baseEnv({ MINT_REVOCATION_STORE_PATH: cwdRelative, MINT_GRAPH_EVENTS_PATH: absolute })),
    /MINT_REVOCATION_STORE_PATH and MINT_GRAPH_EVENTS_PATH must not point at the same file/,
  );
});

test("different paths for MINT_REVOCATION_STORE_PATH and MINT_GRAPH_EVENTS_PATH are fine", () => {
  const config = loadConfigFromEnv(baseEnv({ MINT_REVOCATION_STORE_PATH: "/var/lib/adc-mint/revoked.json", MINT_GRAPH_EVENTS_PATH: "/var/log/adc-mint/events.ndjson" }));
  assert.equal(config.revocationStoreFilePath, "/var/lib/adc-mint/revoked.json");
  assert.equal(config.graphEventsFilePath, "/var/log/adc-mint/events.ndjson");
});

test("the base64 root secret key decodes to the exact expected bytes, not a truncated or re-encoded value", () => {
  const config = loadConfigFromEnv(baseEnv());
  assert.deepEqual(config.rootSecretKey, new Uint8Array(32).fill(7));
});
