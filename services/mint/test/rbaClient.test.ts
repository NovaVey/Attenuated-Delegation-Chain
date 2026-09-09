import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { HttpRbaClient, RbaHttpError } from "../src/rba/client.js";

/**
 * Validates HttpRbaClient's request/response handling against RBA's
 * actual wire shapes (docs/openapi.json in NovaVey/Relationship-Based-
 * Authorization, cross-checked directly, not just via the exploration
 * that informed this client), using a local mock server rather than a
 * live RBA instance — no Docker/Postgres dependency for this suite, and
 * it exercises the real HTTP code path (headers, JSON (de)serialization,
 * timeouts, error mapping), unlike the FakeRbaClient used by
 * bounding.test.ts.
 */

interface MockHandler {
  (body: unknown, headers: Record<string, string | string[] | undefined>): { status: number; body: unknown };
}

function startMockServer(handler: MockHandler): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        const body = raw.length > 0 ? JSON.parse(raw) : undefined;
        const { status, body: responseBody } = handler(body, req.headers);
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(responseBody));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("unexpected server address");
      resolve({ server, url: `http://127.0.0.1:${address.port}` });
    });
  });
}

test("scopeQuery: sends the exact RBA request shape and parses a real-shaped mixed response", async () => {
  let capturedBody: unknown;
  let capturedAuth: string | string[] | undefined;

  const { server, url } = await startMockServer((body, headers) => {
    capturedBody = body;
    capturedAuth = headers.authorization;
    return {
      status: 200,
      body: {
        subject: { ns: "user", id: "alice" },
        grants: [
          { namespace: "repo", relationOrPermission: "read", granted: true, truncated: false },
          { namespace: "repo", relationOrPermission: "write", granted: false, truncated: false },
          { namespace: "repo", relationOrPermission: "admin", granted: false, truncated: true },
          { namespace: "issue", relationOrPermission: "comment", error: { code: "infrastructure_unavailable", message: "db down" } },
        ],
      },
    };
  });

  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "test-key" });
    const response = await client.scopeQuery(
      { ns: "user", id: "alice" },
      [
        { namespace: "repo", relationOrPermission: "read" },
        { namespace: "repo", relationOrPermission: "write" },
        { namespace: "repo", relationOrPermission: "admin" },
        { namespace: "issue", relationOrPermission: "comment" },
      ],
    );

    assert.deepEqual(capturedBody, {
      subject: { ns: "user", id: "alice" },
      targets: [
        { namespace: "repo", relationOrPermission: "read" },
        { namespace: "repo", relationOrPermission: "write" },
        { namespace: "repo", relationOrPermission: "admin" },
        { namespace: "issue", relationOrPermission: "comment" },
      ],
    });
    assert.equal(capturedAuth, "Bearer test-key");
    assert.equal(response.grants.length, 4);
    assert.equal((response.grants[0] as { granted: boolean }).granted, true);
    assert.equal((response.grants[2] as { truncated: boolean }).truncated, true);
    assert.ok("error" in response.grants[3]!);
  } finally {
    server.close();
  }
});

test("check: sends the exact RBA request shape and parses the response", async () => {
  const { server, url } = await startMockServer(() => ({
    status: 200,
    body: {
      allowed: true,
      subject: { ns: "user", id: "alice" },
      relation: "read",
      object: { ns: "repo", id: "123" },
      depth: 1,
      path: { kind: "direct" },
    },
  }));
  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "test-key" });
    const response = await client.check({ ns: "user", id: "alice" }, "read", { ns: "repo", id: "123" });
    assert.equal(response.allowed, true);
    assert.equal(response.depth, 1);
  } finally {
    server.close();
  }
});

test("a 403 forbidden response (scoped API key) surfaces as RbaHttpError with the code and message intact", async () => {
  const { server, url } = await startMockServer(() => ({
    status: 403,
    body: { error: { code: "forbidden", message: "API key scope does not cover namespace 'repo'" } },
  }));
  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "scoped-key" });
    await assert.rejects(
      () => client.check({ ns: "user", id: "alice" }, "read", { ns: "repo", id: "123" }),
      (err: unknown) => {
        assert.ok(err instanceof RbaHttpError);
        assert.equal(err.status, 403);
        assert.equal(err.code, "forbidden");
        assert.match(err.message, /does not cover namespace/);
        return true;
      },
    );
  } finally {
    server.close();
  }
});

test("a 503 infrastructure_unavailable response surfaces as RbaHttpError", async () => {
  const { server, url } = await startMockServer(() => ({
    status: 503,
    body: { error: { code: "infrastructure_unavailable", message: "database unreachable" } },
  }));
  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "test-key" });
    await assert.rejects(
      () => client.check({ ns: "user", id: "alice" }, "read", { ns: "repo", id: "123" }),
      (err: unknown) => err instanceof RbaHttpError && err.status === 503,
    );
  } finally {
    server.close();
  }
});

test("an unparsable (non-JSON) response body surfaces as RbaHttpError instead of throwing a raw SyntaxError", async () => {
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("not json");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("unexpected address");
  const url = `http://127.0.0.1:${address.port}`;
  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "test-key" });
    await assert.rejects(
      () => client.check({ ns: "user", id: "alice" }, "read", { ns: "repo", id: "123" }),
      RbaHttpError,
    );
  } finally {
    server.close();
  }
});

test("a request that times out surfaces as RbaHttpError, not an unhandled rejection", async () => {
  const server = createServer((req) => {
    req.resume();
    // Never responds — simulates a hung RBA instance.
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("unexpected address");
  const url = `http://127.0.0.1:${address.port}`;
  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "test-key", timeoutMs: 100 });
    await assert.rejects(
      () => client.check({ ns: "user", id: "alice" }, "read", { ns: "repo", id: "123" }),
      (err: unknown) => {
        assert.ok(err instanceof RbaHttpError);
        assert.match(err.message, /timed out/);
        return true;
      },
    );
  } finally {
    server.close();
  }
});

test("a response that stalls AFTER headers arrive (body never finishes) still times out, not hangs forever", async () => {
  // Regression test: the timeout used to be cleared as soon as fetch()'s
  // own promise resolved — which happens once headers arrive, not once
  // the body finishes streaming. A server that sends headers promptly but
  // then never finishes the body would have hung res.text() forever.
  const server = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.write('{"allo'); // partial, and deliberately never res.end()'d
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("unexpected address");
  const url = `http://127.0.0.1:${address.port}`;
  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "test-key", timeoutMs: 100 });
    await assert.rejects(
      () => client.check({ ns: "user", id: "alice" }, "read", { ns: "repo", id: "123" }),
      (err: unknown) => {
        assert.ok(err instanceof RbaHttpError);
        assert.match(err.message, /timed out/);
        return true;
      },
    );
  } finally {
    server.close();
  }
});

test("a trailing slash on baseUrl doesn't produce a double slash in the request path", async () => {
  let capturedUrl: string | undefined;
  const server = createServer((req, res) => {
    capturedUrl = req.url;
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ allowed: false, subject: { ns: "user", id: "alice" }, relation: "read", object: { ns: "repo", id: "1" }, depth: 0 }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("unexpected address");
  try {
    const client = new HttpRbaClient({ baseUrl: `http://127.0.0.1:${address.port}/`, apiKey: "k" });
    await client.check({ ns: "user", id: "alice" }, "read", { ns: "repo", id: "1" });
    assert.equal(capturedUrl, "/check");
  } finally {
    server.close();
  }
});

test("scopeQuery rejects more than SCOPE_QUERY_MAX_TARGETS without making a request", async () => {
  const { server, url } = await startMockServer(() => {
    assert.fail("should not have called the mock server");
  });
  try {
    const client = new HttpRbaClient({ baseUrl: url, apiKey: "k" });
    const targets = Array.from({ length: 51 }, (_, i) => ({ namespace: `ns${i}`, relationOrPermission: "read" }));
    await assert.rejects(() => client.scopeQuery({ ns: "user", id: "alice" }, targets), RangeError);
  } finally {
    server.close();
  }
});
