import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { generateKeypair, mintRoot } from "@adc/core";
import { buildMintEvent, buildRevokeEvent } from "../src/builders.js";
import { createNdjsonGraphSink } from "../src/sinks/ndjson.js";

/** A fresh scratch directory per test, cleaned up afterward — real
 * filesystem I/O, no mocking. */
function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "adc-graph-ndjson-test-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A minimal in-memory Writable collecting every chunk written to it —
 * for testing the `stream` mode without any real I/O. */
function createCollectingStream(): { stream: Writable; chunks: () => string[] } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, callback) {
      chunks.push(chunk.toString("utf8"));
      callback();
    },
  });
  return { stream, chunks: () => chunks };
}

function readLines(filePath: string): unknown[] {
  const content = readFileSync(filePath, "utf8");
  return content
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));
}

test("filePath mode: each record() appends one JSON line, in order", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "events.ndjson");
    const sink = createNdjsonGraphSink({ filePath });
    const { secretKey, publicKey } = generateKeypair();

    sink.record(buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date(1000) }));
    sink.record(buildRevokeEvent("a".repeat(64), { actor: { kind: "service", source: "test", externalId: "x" }, reason: "test", now: new Date(2000) }));

    const events = readLines(filePath);
    assert.equal(events.length, 2);
    assert.equal((events[0] as { action: string }).action, "mint");
    assert.equal((events[1] as { action: string }).action, "revoke");
  });
});

test("filePath mode: creates the file if it doesn't exist", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "fresh.ndjson");
    const sink = createNdjsonGraphSink({ filePath });
    const { secretKey, publicKey } = generateKeypair();
    sink.record(buildMintEvent(mintRoot(secretKey), publicKey));
    assert.equal(readLines(filePath).length, 1);
  });
});

test("filePath mode: missing parent directories are created automatically, rather than every record() silently and permanently losing the event", () => {
  // Regression test for an adversarial-review finding: without creating
  // the parent directory first, a not-yet-existing directory (the exact
  // shape services/mint's own .env.example suggests, e.g.
  // /var/log/adc-mint/events.ndjson before /var/log/adc-mint exists) made
  // every single record() call throw ENOENT — silently, since the only
  // caller in this codebase (services/mint's recordGraphEvent()) catches
  // and merely logs it, never surfacing to an HTTP response.
  withTempDir((dir) => {
    const filePath = join(dir, "nested", "deeper", "events.ndjson");
    const sink = createNdjsonGraphSink({ filePath });
    const { secretKey, publicKey } = generateKeypair();
    sink.record(buildMintEvent(mintRoot(secretKey), publicKey));
    assert.equal(readLines(filePath).length, 1);
  });
});

test("filePath mode: appends to (never truncates) a pre-existing file — a fresh sink pointed at the same file preserves prior history", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "events.ndjson");
    const { secretKey, publicKey } = generateKeypair();

    const first = createNdjsonGraphSink({ filePath });
    first.record(buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date(1000) }));

    // Simulates a process restart: a brand-new sink instance against the
    // same file must not clobber what's already there.
    const second = createNdjsonGraphSink({ filePath });
    second.record(buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date(2000) }));

    assert.equal(readLines(filePath).length, 2);
  });
});

test("filePath mode: a pre-existing file with unrelated content is appended to, not overwritten", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "events.ndjson");
    writeFileSync(filePath, JSON.stringify({ action: "pre-existing" }) + "\n", "utf8");

    const sink = createNdjsonGraphSink({ filePath });
    const { secretKey, publicKey } = generateKeypair();
    sink.record(buildMintEvent(mintRoot(secretKey), publicKey));

    const events = readLines(filePath) as Array<{ action: string }>;
    assert.equal(events.length, 2);
    assert.equal(events[0]!.action, "pre-existing");
    assert.equal(events[1]!.action, "mint");
  });
});

test("occurredAt (a Date) serializes as an ISO-8601 string", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "events.ndjson");
    const sink = createNdjsonGraphSink({ filePath });
    const { secretKey, publicKey } = generateKeypair();
    sink.record(buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date("2026-01-01T00:00:00.000Z") }));

    const [event] = readLines(filePath) as Array<{ occurredAt: string }>;
    assert.equal(event!.occurredAt, "2026-01-01T00:00:00.000Z");
  });
});

test("null-valued fields (denyReason, reversible, requestDigest, onBehalfOf) serialize as literal null, never dropped", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "events.ndjson");
    const sink = createNdjsonGraphSink({ filePath });
    const { secretKey, publicKey } = generateKeypair();
    sink.record(buildMintEvent(mintRoot(secretKey), publicKey));

    const [event] = readLines(filePath) as Array<Record<string, unknown>>;
    for (const key of ["denyReason", "reversible", "onBehalfOf"]) {
      assert.ok(key in event!, `expected key '${key}' to be present`);
      assert.equal(event![key], null);
    }
  });
});

test("stream mode: each record() writes one JSON line to the given stream", () => {
  const { stream, chunks } = createCollectingStream();
  const sink = createNdjsonGraphSink({ stream });
  const { secretKey, publicKey } = generateKeypair();

  sink.record(buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date(1000) }));
  sink.record(buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date(2000) }));

  const written = chunks().join("");
  const lines = written.split("\n").filter((l) => l.length > 0);
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]!).action, "mint");
});

test("throws if neither filePath nor stream is provided", () => {
  assert.throws(() => createNdjsonGraphSink(), RangeError);
  assert.throws(() => createNdjsonGraphSink({}), RangeError);
});

test("throws if both filePath and stream are provided", () => {
  const { stream } = createCollectingStream();
  assert.throws(() => createNdjsonGraphSink({ filePath: "/tmp/whatever.ndjson", stream }), RangeError);
});

test("stream mode: an 'error' event on the stream is routed to onError, never crashes the process", () => {
  // Regression test for an adversarial-review finding: Writable.write()
  // doesn't throw synchronously on an I/O failure — it reports one later
  // via an async 'error' event, and Node's default behavior for an
  // EventEmitter's 'error' event with NO listener attached is to throw
  // it as an uncaught exception. createNdjsonGraphSink() must always
  // attach its own listener so a broken pipe / destroyed stream can
  // never crash whatever process this sink is wired into (e.g.
  // services/mint, which holds the root secret key) — confirmed here by
  // checking that emitting 'error' does NOT throw (a stream with no
  // listener would throw synchronously right out of emit()).
  const { stream } = createCollectingStream();
  const errors: Error[] = [];
  createNdjsonGraphSink({ stream, onError: (err) => errors.push(err) });

  const simulated = new Error("simulated broken pipe");
  assert.doesNotThrow(() => stream.emit("error", simulated));
  assert.equal(errors.length, 1);
  assert.equal(errors[0], simulated);
});

test("stream mode: without a custom onError, a stream error is still safely handled (the default doesn't crash the process either)", () => {
  // Stub console.error for the duration of this test only, matching this
  // codebase's convention elsewhere (services/mint's own onInternalError
  // default) of never actually exercising a real console call from a
  // test — restored in `finally` regardless of outcome.
  const original = console.error;
  console.error = () => {};
  try {
    const { stream } = createCollectingStream();
    createNdjsonGraphSink({ stream }); // no onError provided — must fall back to a safe default, not "no listener at all"
    assert.doesNotThrow(() => stream.emit("error", new Error("simulated failure")));
  } finally {
    console.error = original;
  }
});

test("two independent file-backed sinks against different files don't interfere", () => {
  withTempDir((dir) => {
    const pathA = join(dir, "a.ndjson");
    const pathB = join(dir, "b.ndjson");
    const sinkA = createNdjsonGraphSink({ filePath: pathA });
    const sinkB = createNdjsonGraphSink({ filePath: pathB });
    const { secretKey, publicKey } = generateKeypair();

    sinkA.record(buildMintEvent(mintRoot(secretKey), publicKey));
    assert.equal(readLines(pathA).length, 1);
    assert.throws(() => readFileSync(pathB)); // sinkB's file was never created — no cross-talk
  });
});
