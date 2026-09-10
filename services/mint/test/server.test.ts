import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { verify, generateKeypair, blockSignatureHash, decodeToken } from "@adc/core";
import { createInMemoryGraphSink } from "@adc/graph";
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

// --- Principal-Graph event emission -------------------------------------

test("POST /mint: a successful mint records exactly one 'mint' Principal-Graph event, referencing the real minted block", async () => {
  const { secretKey, publicKey } = generateKeypair();
  const graphSink = createInMemoryGraphSink();
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/mint`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ subject: ALICE, caveats: [] }),
      });
      assert.equal(res.status, 201);
      const { token } = (await res.json()) as { token: string };

      assert.equal(graphSink.events.length, 1);
      const event = graphSink.events[0]!;
      assert.equal(event.action, "mint");
      assert.equal(event.decision, "allow");
      assert.equal(event.principal.externalId, Buffer.from(publicKey).toString("base64url"), "principal is derived from the root public key");

      const parsed = decodeToken(token);
      const expectedHash = blockSignatureHash(parsed.sigs[0]!);
      assert.equal(event.resource.externalId, expectedHash, "the event references the exact block just minted");
    },
    { graphSink },
  );
});

test("POST /mint: a scope_not_granted rejection records NO Principal-Graph event (no token was ever minted)", async () => {
  const { secretKey } = generateKeypair();
  const graphSink = createInMemoryGraphSink();
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/mint`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ subject: ALICE, caveats: [{ kind: "scope", triples: [["repo", "1", "admin"]] }] }),
      });
      assert.equal(res.status, 403);
      assert.equal(graphSink.events.length, 0);
    },
    { graphSink },
  );
});

test("POST /mint: an invalid_request (malformed body) records NO Principal-Graph event", async () => {
  const { secretKey } = generateKeypair();
  const graphSink = createInMemoryGraphSink();
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/mint`, { method: "POST", headers: { "content-type": "application/json" }, body: "{not valid json" });
      assert.equal(res.status, 400);
      assert.equal(graphSink.events.length, 0);
    },
    { graphSink },
  );
});

test("POST /revoke: a successful revoke records exactly one 'revoke' Principal-Graph event with the fixed admin principal", async () => {
  const { secretKey } = generateKeypair();
  const graphSink = createInMemoryGraphSink();
  const hash = "a".repeat(64);
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
        body: JSON.stringify({ hash }),
      });
      assert.equal(res.status, 200);

      assert.equal(graphSink.events.length, 1);
      const event = graphSink.events[0]!;
      assert.equal(event.action, "revoke");
      assert.equal(event.decision, "allow");
      assert.equal(event.resource.externalId, hash);
      assert.equal(event.principal.kind, "service");
      assert.deepEqual([...event.taintLabels], ["reason:revoked via POST /revoke"]);
    },
    { graphSink },
  );
});

test("POST /revoke: an optional 'reason' field is carried into the event's taintLabels", async () => {
  const { secretKey } = generateKeypair();
  const graphSink = createInMemoryGraphSink();
  const hash = "b".repeat(64);
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
        body: JSON.stringify({ hash, reason: "compromised key, incident #42" }),
      });
      assert.equal(res.status, 200);
      assert.deepEqual([...graphSink.events[0]!.taintLabels], ["reason:compromised key, incident #42"]);
    },
    { graphSink },
  );
});

test("POST /revoke: a non-string 'reason' is 400 invalid_request", async () => {
  const { secretKey } = generateKeypair();
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
      body: JSON.stringify({ hash: "a".repeat(64), reason: 12345 }),
    });
    assert.equal(res.status, 400);
  });
});

test("POST /revoke: an overlong 'reason' (> 500 chars) is 400 invalid_request, and no revoke/event happens", async () => {
  const { secretKey } = generateKeypair();
  const graphSink = createInMemoryGraphSink();
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
        body: JSON.stringify({ hash: "a".repeat(64), reason: "x".repeat(501) }),
      });
      assert.equal(res.status, 400);

      const listRes = await fetch(`${baseUrl}/revocations`);
      const { payload } = (await listRes.json()) as { payload: { revoked: string[] } };
      assert.deepEqual(payload.revoked, [], "the hash must not have been revoked despite the bad reason arriving alongside it");
      assert.equal(graphSink.events.length, 0);
    },
    { graphSink },
  );
});

test("POST /revoke: a 'reason' at exactly the 500-char limit is accepted", async () => {
  const { secretKey } = generateKeypair();
  const hash = "a".repeat(64);
  await withServer(new FakeRbaClient(), secretKey, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
      body: JSON.stringify({ hash, reason: "x".repeat(500) }),
    });
    assert.equal(res.status, 200);
  });
});

test("POST /revoke: an unauthorized attempt records NO Principal-Graph event", async () => {
  const { secretKey } = generateKeypair();
  const graphSink = createInMemoryGraphSink();
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json" }, // no Authorization header
        body: JSON.stringify({ hash: "a".repeat(64) }),
      });
      assert.equal(res.status, 401);
      assert.equal(graphSink.events.length, 0);
    },
    { graphSink },
  );
});

test("a GraphSink that throws never breaks the HTTP response, and the failure is reported via onInternalError", async () => {
  const { secretKey } = generateKeypair();
  const internalErrors: unknown[] = [];
  const throwingSink = { record: () => { throw new Error("sink is down"); } };
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/mint`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ subject: ALICE, caveats: [] }),
      });
      assert.equal(res.status, 201, "the mint itself must still succeed despite the sink failure");
      const body = (await res.json()) as { token: string };
      assert.ok(body.token);
      assert.equal(internalErrors.length, 1);
      assert.match((internalErrors[0] as Error).message, /sink is down/);
    },
    { graphSink: throwingSink, onInternalError: (err) => internalErrors.push(err) },
  );
});

// --- POST /mint rate limiting --------------------------------------------

test("POST /mint: a request beyond the configured rate limit is rejected 429, without ever reaching RBA/minting", async () => {
  const { secretKey } = generateKeypair();
  const rba = new FakeRbaClient();
  await withServer(
    rba,
    secretKey,
    async (baseUrl) => {
      const mint = () =>
        fetch(`${baseUrl}/mint`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ subject: ALICE, caveats: [] }),
        });

      const first = await mint();
      const second = await mint();
      assert.equal(first.status, 201);
      assert.equal(second.status, 201);

      const third = await mint();
      assert.equal(third.status, 429);
      const body = (await third.json()) as { error: { code: string } };
      assert.equal(body.error.code, "rate_limited");
    },
    { mintRateLimitPerMinute: 2 },
  );
});

test("POST /mint: rate limiting is independent of the request's validity — a rate-limited call never reaches the invalid_request/scope checks", async () => {
  const { secretKey } = generateKeypair();
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const badBody = () => fetch(`${baseUrl}/mint`, { method: "POST", headers: { "content-type": "application/json" }, body: "{not valid json" });
      const first = await badBody();
      assert.equal(first.status, 400, "sanity: this body is normally a 400, not a 429");

      const second = await badBody();
      assert.equal(second.status, 429, "the SECOND call (limit is 1) is rate-limited even though the body is also invalid");
    },
    { mintRateLimitPerMinute: 1 },
  );
});

test("POST /mint: GET /health and POST /revoke are unaffected by the mint rate limit", async () => {
  const { secretKey } = generateKeypair();
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      // Exhaust the mint limit.
      await fetch(`${baseUrl}/mint`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ subject: ALICE, caveats: [] }) });
      const exhausted = await fetch(`${baseUrl}/mint`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ subject: ALICE, caveats: [] }) });
      assert.equal(exhausted.status, 429);

      const health = await fetch(`${baseUrl}/health`);
      assert.equal(health.status, 200);

      const revoke = await fetch(`${baseUrl}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_API_KEY}` },
        body: JSON.stringify({ hash: "a".repeat(64) }),
      });
      assert.equal(revoke.status, 200);
    },
    { mintRateLimitPerMinute: 1 },
  );
});

test("POST /mint: a custom injected RateLimiter (mintRateLimiter) is used verbatim instead of building one from mintRateLimitPerMinute", async () => {
  const { secretKey } = generateKeypair();
  let acquireCalls = 0;
  const customLimiter = { tryAcquire: () => { acquireCalls++; return acquireCalls <= 1; } };
  await withServer(
    new FakeRbaClient(),
    secretKey,
    async (baseUrl) => {
      const mint = () => fetch(`${baseUrl}/mint`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ subject: ALICE, caveats: [] }) });
      assert.equal((await mint()).status, 201);
      assert.equal((await mint()).status, 429);
      assert.equal(acquireCalls, 2);
    },
    { mintRateLimiter: customLimiter, mintRateLimitPerMinute: 999 }, // mintRateLimiter must win over this
  );
});

// --- fail-fast root key validation ---------------------------------------

test("createMintServer() throws immediately for a wrong-length rootSecretKey, rather than deferring the failure to the first request", () => {
  // Deliberate: see server.ts's own doc comment on the eager
  // getPublicKey() call in createMintServer(). index.ts's config.ts
  // already validates key length before ever reaching this function in
  // production, so this only matters for a caller invoking
  // createMintServer() directly with a bad key.
  assert.throws(() => createMintServer({
    rootSecretKey: new Uint8Array(16), // wrong length — must be 32
    rba: new FakeRbaClient(),
    adminApiKey: ADMIN_API_KEY,
  }));
});
