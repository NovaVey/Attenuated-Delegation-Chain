import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { verify, generateKeypair } from "@adc/core";
import { createMintServer } from "../src/server.js";
import { FakeRbaClient } from "../src/rba/fake.js";

const ALICE = { ns: "user", id: "alice" };

async function withServer<T>(
  rba: FakeRbaClient,
  rootSecretKey: Uint8Array,
  fn: (baseUrl: string) => Promise<T>,
): Promise<T> {
  const server = createMintServer({ rootSecretKey, rba, onInternalError: () => {} });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    return await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    server.close();
  }
}

test("GET /health returns 200", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: "ok" });
  });
});

test("POST /mint: 201 with a real, verifiable token when there are no scope caveats", async () => {
  const { secretKey, publicKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: ALICE, caveats: [] }),
    });
    assert.equal(res.status, 201);
    const body = (await res.json()) as { token: string; depth: number };
    assert.equal(body.depth, 0);
    assert.equal(verify(body.token, publicKey).ok, true);
  });
});

test("POST /mint: 201 when the requested scope IS granted", async () => {
  const { secretKey, publicKey } = generateKeypair();
  const rba = new FakeRbaClient([{ subject: ALICE, resourceKind: "repo", resourceId: "1", relation: "read" }]);
  await withServer(rba, secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: ALICE, caveats: [{ kind: "scope", triples: [["repo", "*", "read"]] }] }),
    });
    assert.equal(res.status, 201);
    const body = (await res.json()) as { token: string };
    assert.equal(verify(body.token, publicKey, { resourceKind: "repo", resourceId: "1", relation: "read" }).ok, true);
  });
});

test("POST /mint: 403 scope_not_granted when the requested scope is not held, and no token is returned", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: ALICE, caveats: [{ kind: "scope", triples: [["repo", "1", "admin"]] }] }),
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as { error: { code: string; details: unknown[] } };
    assert.equal(body.error.code, "scope_not_granted");
    assert.equal(body.error.details.length, 1);
    assert.equal("token" in body, false);
  });
});

test("POST /mint: 502 rba_unavailable when RBA is unreachable", async () => {
  const { secretKey } = generateKeypair();
  const rba = new FakeRbaClient();
  rba.setUnavailable(true);
  await withServer(rba, secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: ALICE, caveats: [{ kind: "scope", triples: [["repo", "1", "read"]] }] }),
    });
    assert.equal(res.status, 502);
    const body = (await res.json()) as { error: { code: string } };
    assert.equal(body.error.code, "rba_unavailable");
  });
});

test("POST /mint: 400 invalid_request on malformed JSON", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not valid json",
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as { error: { code: string } };
    assert.equal(body.error.code, "invalid_request");
  });
});

test("POST /mint: 400 invalid_request when the body is well-formed JSON but the wrong shape", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ foo: "bar" }),
    });
    assert.equal(res.status, 400);
  });
});

test("POST /mint: 413 when the request body is too large", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const hugeVerifier = "a".repeat(200_000);
    const res = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: ALICE, caveats: [{ kind: "aud", verifier: hugeVerifier }] }),
    });
    assert.equal(res.status, 413);
  });
});

test("unknown route returns 404", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/nope`);
    assert.equal(res.status, 404);
  });
});

test("GET /mint (wrong method) returns 404, not a crash", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/mint`, { method: "GET" });
    assert.equal(res.status, 404);
  });
});
