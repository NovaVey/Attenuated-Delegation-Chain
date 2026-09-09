import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { verify, generateKeypair, blockSignatureHash, decodeToken } from "@adc/core";
import { verifySignedRevocationList } from "@adc/revocation";
import { createMintServer, type CreateMintServerOptions } from "../src/server.js";
import { FakeRbaClient } from "../src/rba/fake.js";
import { RevocationStore } from "../src/revocation-store.js";

const ALICE = { ns: "user", id: "alice" };
const ADMIN_API_KEY = "test-admin-key";

async function withServer<T>(
  rba: FakeRbaClient,
  rootSecretKey: Uint8Array,
  fn: (baseUrl: string) => Promise<T>,
  extra: Partial<CreateMintServerOptions> = {},
): Promise<T> {
  const server = createMintServer({ rootSecretKey, rba, adminApiKey: ADMIN_API_KEY, onInternalError: () => {}, ...extra });
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

// --- POST /revoke -----------------------------------------------------

test("POST /revoke: 200 with the correct admin bearer token, and the hash shows up in GET /revocations", async () => {
  const { secretKey, publicKey } = generateKeypair();
  const hash = "a".repeat(64);
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const revokeRes = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
      body: JSON.stringify({ hash }),
    });
    assert.equal(revokeRes.status, 200);
    assert.deepEqual(await revokeRes.json(), { revoked: hash });

    const listRes = await fetch(`${baseUrl}/revocations`);
    assert.equal(listRes.status, 200);
    const result = verifySignedRevocationList(await listRes.json(), publicKey, { now: Math.floor(Date.now() / 1000) });
    assert.equal(result.ok, true);
    if (!result.ok) throw new Error("unreachable");
    assert.deepEqual([...result.revokedHashes], [hash]);
  });
});

test("POST /revoke: revoking the same hash twice is idempotent (200 both times, appears once)", async () => {
  const { secretKey, publicKey } = generateKeypair();
  const hash = "b".repeat(64);
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    for (let i = 0; i < 2; i++) {
      const res = await fetch(`${baseUrl}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
        body: JSON.stringify({ hash }),
      });
      assert.equal(res.status, 200);
    }
    const listRes = await fetch(`${baseUrl}/revocations`);
    const result = verifySignedRevocationList(await listRes.json(), publicKey, { now: Math.floor(Date.now() / 1000) });
    assert.equal(result.ok, true);
    if (!result.ok) throw new Error("unreachable");
    assert.deepEqual([...result.revokedHashes], [hash]);
  });
});

test("POST /revoke: 401 with no Authorization header", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hash: "a".repeat(64) }),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { error: { code: string } };
    assert.equal(body.error.code, "unauthorized");
  });
});

test("POST /revoke: 401 with the wrong bearer token", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer not-the-admin-key" },
      body: JSON.stringify({ hash: "a".repeat(64) }),
    });
    assert.equal(res.status, 401);
  });
});

test("POST /revoke: 401 for a bearer token that's a prefix/superstring of the real one (length-mismatch path)", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}x` },
      body: JSON.stringify({ hash: "a".repeat(64) }),
    });
    assert.equal(res.status, 401);
  });
});

test("POST /revoke: a malformed hash is rejected 400 invalid_request, auth still required first", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
      body: JSON.stringify({ hash: "not-a-valid-hash" }),
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as { error: { code: string } };
    assert.equal(body.error.code, "invalid_request");
  });
});

test("POST /revoke: a missing 'hash' field is 400 invalid_request", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
  });
});

test("POST /revoke: malformed JSON body is 400 invalid_request", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
      body: "{not valid json",
    });
    assert.equal(res.status, 400);
  });
});

// --- GET /revocations ---------------------------------------------------

test("GET /revocations: unauthenticated, and returns a validly-signed empty list when nothing's been revoked", async () => {
  const { secretKey, publicKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revocations`);
    assert.equal(res.status, 200);
    const result = verifySignedRevocationList(await res.json(), publicKey, { now: Math.floor(Date.now() / 1000) });
    assert.equal(result.ok, true);
    if (!result.ok) throw new Error("unreachable");
    assert.deepEqual([...result.revokedHashes], []);
  });
});

test("end-to-end: a token minted by this server, revoked via /revoke, denies under @adc/core's verify() using the fetched signed list", async () => {
  const { secretKey, publicKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const mintRes = await fetch(`${baseUrl}/mint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject: ALICE, caveats: [] }),
    });
    const { token } = (await mintRes.json()) as { token: string };
    assert.equal(verify(token, publicKey).ok, true, "sanity: mints a valid token before revocation");

    const parsed = decodeToken(token);
    const hash = blockSignatureHash(parsed.sigs[0]!);

    const revokeRes = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
      body: JSON.stringify({ hash }),
    });
    assert.equal(revokeRes.status, 200);

    const listRes = await fetch(`${baseUrl}/revocations`);
    const verifyResult = verifySignedRevocationList(await listRes.json(), publicKey, { now: Math.floor(Date.now() / 1000) });
    assert.equal(verifyResult.ok, true);
    if (!verifyResult.ok) throw new Error("unreachable");

    const denied = verify(token, publicKey, undefined, { revokedHashes: verifyResult.revokedHashes });
    assert.equal(denied.ok, false);
    if (denied.ok) throw new Error("unreachable");
    assert.equal(denied.code, "ADC_REVOKED");
  });
});

test("POST /revoke can pre-seed via an injected RevocationStore, observable through GET /revocations", async () => {
  const { secretKey, publicKey } = generateKeypair();
  const store = new RevocationStore();
  store.revoke("c".repeat(64));
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/revocations`);
      const result = verifySignedRevocationList(await res.json(), publicKey, { now: Math.floor(Date.now() / 1000) });
      assert.equal(result.ok, true);
      if (!result.ok) throw new Error("unreachable");
      assert.deepEqual([...result.revokedHashes], ["c".repeat(64)]);
    },
    { revocationStore: store },
  );
});
