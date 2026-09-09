import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { generateKeypair } from "@adc/core";
import { buildRevocationList } from "../src/list.js";
import { signRevocationList } from "../src/sign.js";
import { createRevocationClient } from "../src/client.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

function freshRoot() {
  const { secretKey, publicKey } = generateKeypair();
  return { rootSecretKey: secretKey, rootPublicKey: publicKey };
}

/** Serves whatever `handler()` returns for every request — status 200
 * with a JSON body unless the handler says otherwise. Real HTTP, real
 * fetch, matching this codebase's established mock-server testing
 * convention (services/mint/test/rbaClient.test.ts). */
function startMockServer(handler: () => { status: number; body: unknown }): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = createServer((_req, res) => {
      const { status, body } = handler();
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("unexpected server address");
      resolve({ server, url: `http://127.0.0.1:${address.port}` });
    });
  });
}

test("poll(): fetches, verifies, and caches a real signed list from a real HTTP server", async () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A, HASH_B], { issuedAt: Math.floor(Date.now() / 1000), ttlSeconds: 60 }), rootSecretKey);
  const { server, url } = await startMockServer(() => ({ status: 200, body: signed }));

  try {
    const client = createRevocationClient({ url, rootPublicKey });
    assert.equal(client.getRevokedHashes(), null, "nothing cached before the first poll");

    await client.poll();

    const revoked = client.getRevokedHashes();
    assert.ok(revoked);
    assert.deepEqual([...revoked!].sort(), [HASH_A, HASH_B]);
  } finally {
    server.close();
  }
});

test("a network error on poll() reports via onError and leaves getRevokedHashes() at null, never throws", async () => {
  const { rootPublicKey } = freshRoot();
  const errors: Error[] = [];
  const client = createRevocationClient({
    url: "http://127.0.0.1:1", // nothing listens here
    rootPublicKey,
    onError: (err) => errors.push(err),
  });

  await assert.doesNotReject(() => client.poll());
  assert.equal(client.getRevokedHashes(), null);
  assert.equal(errors.length, 1);
});

test("a non-2xx response reports via onError, never throws", async () => {
  const { rootPublicKey } = freshRoot();
  const { server, url } = await startMockServer(() => ({ status: 503, body: { error: "unavailable" } }));
  const errors: Error[] = [];

  try {
    const client = createRevocationClient({ url, rootPublicKey, onError: (err) => errors.push(err) });
    await client.poll();
    assert.equal(client.getRevokedHashes(), null);
    assert.equal(errors.length, 1);
    assert.match(errors[0]!.message, /503/);
  } finally {
    server.close();
  }
});

test("a badly-signed response (wrong root key on the server side) reports via onError, never throws", async () => {
  const { rootSecretKey: wrongKey } = freshRoot();
  const { rootPublicKey } = freshRoot(); // client trusts a DIFFERENT key than what signs the list
  const signed = signRevocationList(buildRevocationList([HASH_A], { issuedAt: Math.floor(Date.now() / 1000) }), wrongKey);
  const { server, url } = await startMockServer(() => ({ status: 200, body: signed }));
  const errors: Error[] = [];

  try {
    const client = createRevocationClient({ url, rootPublicKey, onError: (err) => errors.push(err) });
    await client.poll();
    assert.equal(client.getRevokedHashes(), null);
    assert.equal(errors.length, 1);
    assert.match(errors[0]!.message, /BAD_SIGNATURE/);
  } finally {
    server.close();
  }
});

test("a failed refresh leaves a still-fresh cached value untouched (transient blip doesn't discard legitimately-live revocation data)", async () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const goodList = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_000, ttlSeconds: 300 }), rootSecretKey);

  let mode: "good" | "down" = "good";
  const { server, url } = await startMockServer(() =>
    mode === "good" ? { status: 200, body: goodList } : { status: 500, body: { error: "internal" } },
  );

  try {
    const client = createRevocationClient({ url, rootPublicKey, now: () => 1_010 });
    await client.poll();
    assert.deepEqual([...client.getRevokedHashes()!], [HASH_A]);

    mode = "down";
    await client.poll(); // fails — server now returns 500

    // Still within the first list's own TTL (issuedAt 1000 + ttl 300 = 1300,
    // injected "now" is still 1010) — the old, still-legitimately-fresh
    // value must survive an unrelated failed refresh attempt.
    assert.deepEqual([...client.getRevokedHashes()!], [HASH_A]);
  } finally {
    server.close();
  }
});

test("getRevokedHashes() returns null once the cached list's own TTL (plus skew) has passed, via the injected clock — no real waiting", async () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const signed = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_000, ttlSeconds: 60 }), rootSecretKey);
  const { server, url } = await startMockServer(() => ({ status: 200, body: signed }));

  let clock = 1_010; // within TTL at poll time
  try {
    const client = createRevocationClient({ url, rootPublicKey, clockSkewSeconds: 0, now: () => clock });
    await client.poll();
    assert.ok(client.getRevokedHashes());

    clock = 1_500; // long past issuedAt(1000) + ttl(60)
    assert.equal(client.getRevokedHashes(), null, "must fail closed once the cached list itself goes stale");
  } finally {
    server.close();
  }
});

test("start()/stop(): start() polls immediately and again on an interval; stop() halts further polling", async () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let callCount = 0;
  const signed = signRevocationList(buildRevocationList([], { issuedAt: Math.floor(Date.now() / 1000), ttlSeconds: 300 }), rootSecretKey);
  const { server, url } = await startMockServer(() => {
    callCount++;
    return { status: 200, body: signed };
  });

  try {
    const client = createRevocationClient({ url, rootPublicKey, pollIntervalMs: 20 });
    client.start();

    // Immediate poll happens synchronously-ish inside start(); give it a
    // tick to actually land.
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(callCount, 1, "start() must poll immediately, not only after the first interval");

    await new Promise((resolve) => setTimeout(resolve, 60));
    const afterRunning = callCount;
    assert.ok(afterRunning > 1, "the interval must fire at least once more while running");

    client.stop();
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(callCount, afterRunning, "no further polls after stop()");
  } finally {
    server.close();
  }
});

test("start() is idempotent: calling it twice doesn't start a second interval", async () => {
  const { rootSecretKey, rootPublicKey } = freshRoot();
  let callCount = 0;
  const signed = signRevocationList(buildRevocationList([], { issuedAt: Math.floor(Date.now() / 1000), ttlSeconds: 300 }), rootSecretKey);
  const { server, url } = await startMockServer(() => {
    callCount++;
    return { status: 200, body: signed };
  });

  try {
    const client = createRevocationClient({ url, rootPublicKey, pollIntervalMs: 1000 });
    client.start();
    client.start(); // second call must be a no-op, not a second timer
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(callCount, 1);
    client.stop();
  } finally {
    server.close();
  }
});

test("an out-of-safe-integer-range issuedAt in the response body reports via onError, never throws or crashes the process", async () => {
  // Regression test for an adversarial-review finding: an issuedAt/
  // ttlSeconds beyond Number.MAX_SAFE_INTEGER used to reach
  // canonicalEncode() (via revocationSignInput, called BEFORE the
  // signature check) and throw, uncaught, from this fire-and-forget
  // poll() — an unauthenticated remote DoS, since no valid signature was
  // needed to trigger it. Both the immediate cause (canonicalEncode's own
  // input) and the source (parseShape's Number.isSafeInteger check) are
  // covered elsewhere; this is the end-to-end path a hostile/compromised
  // GET /revocations response would actually take.
  const { rootPublicKey } = freshRoot();
  const hostileBody = {
    payload: { v: "adc-crl1", issuedAt: Number.MAX_SAFE_INTEGER + 2, ttlSeconds: 60, revoked: [] },
    signature: "not-checked-before-the-crash-used-to-happen",
  };
  const { server, url } = await startMockServer(() => ({ status: 200, body: hostileBody }));
  const errors: Error[] = [];

  try {
    const client = createRevocationClient({ url, rootPublicKey, onError: (err) => errors.push(err) });
    await assert.doesNotReject(() => client.poll());
    assert.equal(client.getRevokedHashes(), null);
    assert.equal(errors.length, 1);
  } finally {
    server.close();
  }
});

test("out-of-order polls: a slower, earlier-issued response that resolves AFTER a faster, later-issued one does not regress the cache", async () => {
  // Regression test for an adversarial-review finding: two overlapping
  // poll() calls (a slow response racing the next interval tick, or an
  // explicit poll() racing start()'s own timer) can resolve out of order.
  // Reproduced directly: an older list (not yet reflecting a revocation)
  // that's slow to resolve used to silently overwrite a newer, already-
  // cached list that DID reflect the revocation, once it finally landed.
  const { rootSecretKey, rootPublicKey } = freshRoot();
  const listA = signRevocationList(buildRevocationList([], { issuedAt: 1_000, ttlSeconds: 300 }), rootSecretKey); // older, nothing revoked
  const listB = signRevocationList(buildRevocationList([HASH_A], { issuedAt: 1_010, ttlSeconds: 300 }), rootSecretKey); // newer, HASH_A revoked

  let callCount = 0;
  const fetchImpl: typeof fetch = async () => {
    callCount++;
    if (callCount === 1) {
      // The first call (fetching the OLDER list) is slow.
      await new Promise((resolve) => setTimeout(resolve, 60));
      return new Response(JSON.stringify(listA), { status: 200 });
    }
    // The second call (fetching the NEWER list) is fast.
    return new Response(JSON.stringify(listB), { status: 200 });
  };

  const client = createRevocationClient({ url: "http://unused.example/revocations", rootPublicKey, fetchImpl, now: () => 1_020 });

  const p1 = client.poll(); // older list — starts first, resolves last
  await new Promise((resolve) => setTimeout(resolve, 10)); // let p1's fetch actually start
  const p2 = client.poll(); // newer list — starts second, resolves first

  await p2;
  assert.deepEqual([...client.getRevokedHashes()!], [HASH_A], "the newer, faster response is cached correctly");

  await p1; // the slow, OLDER response lands last
  assert.deepEqual(
    [...client.getRevokedHashes()!],
    [HASH_A],
    "the stale, later-arriving-but-actually-older response must not regress the cache",
  );
});

test("a hung response (server accepts the connection but never replies) times out via onError instead of hanging poll() forever", async () => {
  const { rootPublicKey } = freshRoot();
  // Deliberately never call res.end() / res.write() — simulates a
  // slow-loris'd or simply unresponsive GET /revocations.
  const server = createServer(() => {});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("unexpected address");
  const url = `http://127.0.0.1:${address.port}`;
  const errors: Error[] = [];

  try {
    const client = createRevocationClient({ url, rootPublicKey, timeoutMs: 50, onError: (err) => errors.push(err) });
    const start = Date.now();
    await assert.doesNotReject(() => client.poll());
    assert.ok(Date.now() - start < 2000, "poll() must not hang indefinitely on a stalled response");
    assert.equal(client.getRevokedHashes(), null);
    assert.equal(errors.length, 1);
    assert.match(errors[0]!.message, /timed out/);
  } finally {
    server.close();
  }
});

test("a malformed (non-JSON) response body reports via onError, never throws", async () => {
  const { rootPublicKey } = freshRoot();
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("not json");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("unexpected address");
  const url = `http://127.0.0.1:${address.port}`;
  const errors: Error[] = [];

  try {
    const client = createRevocationClient({ url, rootPublicKey, onError: (err) => errors.push(err) });
    await client.poll();
    assert.equal(client.getRevokedHashes(), null);
    assert.equal(errors.length, 1);
  } finally {
    server.close();
  }
});

