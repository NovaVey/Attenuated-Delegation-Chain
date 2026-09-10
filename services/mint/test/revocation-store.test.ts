import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RevocationStore } from "../src/revocation-store.js";

const VALID_HASH = "a".repeat(64);

/** A fresh scratch directory per test, cleaned up afterward — real
 * filesystem I/O, no mocking, matching this codebase's general
 * preference for exercising the real thing over a stubbed one. */
function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "adc-revocation-store-test-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("revoke()/list(): a revoked hash shows up in list()", () => {
  const store = new RevocationStore();
  store.revoke(VALID_HASH);
  assert.deepEqual(store.list(), [VALID_HASH]);
});

test("revoke(): idempotent — revoking the same hash twice doesn't duplicate it", () => {
  const store = new RevocationStore();
  store.revoke(VALID_HASH);
  store.revoke(VALID_HASH);
  assert.deepEqual(store.list(), [VALID_HASH]);
});

test("list(): empty for a fresh store", () => {
  assert.deepEqual(new RevocationStore().list(), []);
});

test("revoke(): rejects anything that isn't a 64-char lowercase hex hash", () => {
  const store = new RevocationStore();
  for (const bad of ["not-a-hash", "A".repeat(64), "a".repeat(63), "a".repeat(65), ""]) {
    assert.throws(() => store.revoke(bad), RangeError, `expected RangeError for ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(store.list(), [], "no partial/invalid entries leaked into the store");
});

test("list(): reflects multiple distinct revoked hashes", () => {
  const store = new RevocationStore();
  const hashB = "b".repeat(64);
  store.revoke(VALID_HASH);
  store.revoke(hashB);
  assert.deepEqual([...store.list()].sort(), [VALID_HASH, hashB].sort());
});

// --- file-backed persistence -------------------------------------------

test("file-backed: with no filePath, behaves exactly like the pure in-memory store (no file created)", () => {
  withTempDir((dir) => {
    const untouched = join(dir, "should-never-exist.json");
    const store = new RevocationStore();
    store.revoke(VALID_HASH);
    assert.deepEqual(store.list(), [VALID_HASH]);
    assert.throws(() => readFileSync(untouched)); // never written — filePath was never given
  });
});

test("file-backed: a fresh (non-existent) file path starts empty, and the first revoke() creates the file", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "revoked.json");
    const store = new RevocationStore({ filePath });
    assert.deepEqual(store.list(), []);

    store.revoke(VALID_HASH);
    const onDisk = JSON.parse(readFileSync(filePath, "utf8"));
    assert.deepEqual(onDisk, { revoked: [VALID_HASH] });
  });
});

test("file-backed: revocations survive a restart (a fresh RevocationStore instance against the same file loads them)", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "revoked.json");
    const hashB = "b".repeat(64);

    const first = new RevocationStore({ filePath });
    first.revoke(VALID_HASH);
    first.revoke(hashB);

    const second = new RevocationStore({ filePath }); // simulates a process restart
    assert.deepEqual([...second.list()].sort(), [VALID_HASH, hashB].sort());
  });
});

test("file-backed: revoke() is idempotent and performs no disk write for an already-revoked hash", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "revoked.json");
    const store = new RevocationStore({ filePath });
    store.revoke(VALID_HASH);
    const mtimeAfterFirst = readFileSync(filePath, "utf8");

    store.revoke(VALID_HASH); // already revoked — must be a pure no-op
    assert.equal(readFileSync(filePath, "utf8"), mtimeAfterFirst, "file content unchanged — no redundant write");
    assert.deepEqual(store.list(), [VALID_HASH]);
  });
});

test("file-backed: a malformed hash still throws RangeError before any disk write, and doesn't touch the file", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "revoked.json");
    const store = new RevocationStore({ filePath });
    assert.throws(() => store.revoke("not-a-hash"), RangeError);
    assert.throws(() => readFileSync(filePath)); // never created — the bad hash never reached the persistence path
  });
});

test("file-backed: nested, non-existent parent directories are created automatically", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "nested", "deeper", "revoked.json");
    const store = new RevocationStore({ filePath });
    store.revoke(VALID_HASH);
    assert.deepEqual(JSON.parse(readFileSync(filePath, "utf8")), { revoked: [VALID_HASH] });
  });
});

test("file-backed: loading refuses a corrupt (non-JSON) file rather than silently starting with an empty (== nothing revoked) set", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "revoked.json");
    writeFileSync(filePath, "{not valid json", "utf8");
    assert.throws(() => new RevocationStore({ filePath }), /not valid JSON/);
  });
});

test("file-backed: loading refuses a well-formed-JSON file with the wrong shape", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "revoked.json");
    for (const bad of [
      "[]", // an array, not {revoked: [...]}
      '{"wrongField": []}',
      '{"revoked": "not-an-array"}',
      '{"revoked": ["not-a-valid-hash"]}',
      '{"revoked": [123]}',
      "null",
      '"just a string"',
    ]) {
      writeFileSync(filePath, bad, "utf8");
      assert.throws(() => new RevocationStore({ filePath }), `expected a throw for content: ${bad}`);
    }
  });
});

test("file-backed: a well-formed pre-existing file (e.g. hand-seeded before first startup) loads correctly", () => {
  withTempDir((dir) => {
    const filePath = join(dir, "revoked.json");
    const hashB = "b".repeat(64);
    writeFileSync(filePath, JSON.stringify({ revoked: [VALID_HASH, hashB] }), "utf8");
    const store = new RevocationStore({ filePath });
    assert.deepEqual([...store.list()].sort(), [VALID_HASH, hashB].sort());
  });
});

test("file-backed: a disk write failure (filePath's parent is actually a file, not a directory) leaves the in-memory state untouched and propagates the error", () => {
  withTempDir((dir) => {
    const blockingFile = join(dir, "not-a-directory");
    writeFileSync(blockingFile, "occupied", "utf8");
    const filePath = join(blockingFile, "revoked.json"); // parent "directory" is actually a plain file

    const store = new RevocationStore({ filePath });
    assert.throws(() => store.revoke(VALID_HASH));
    assert.deepEqual(store.list(), [], "the failed write must not have been committed to memory either");
  });
});
