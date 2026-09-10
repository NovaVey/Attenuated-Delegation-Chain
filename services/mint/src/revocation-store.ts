import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Store of revoked block-signature hashes — the thing `POST /revoke`
 * writes to and `GET /revocations` reads from (via @adc/revocation's
 * buildRevocationList()/signRevocationList()).
 *
 * **In-memory by default, optionally file-backed.** With no `filePath`,
 * this is exactly the plain `Set`-backed, lost-on-restart store from
 * Phase 7 — docs/PLAN.md's Phase 7 acceptance criteria (the signed-list
 * format, the offline check, the liveness bound) never required
 * persistence, and that mode still exists unchanged for anything that
 * doesn't need it (every existing test, for one). With `filePath` set,
 * revocations survive a restart: loaded once at construction, and
 * written through synchronously on every successful `revoke()` — see
 * `writeFileAtomic()`'s own doc comment for why that write happens
 * BEFORE the in-memory `Set` is updated, not after.
 *
 * **Single-writer only.** File-backed mode has no cross-process locking
 * or coordination — it's sized for this service's actual deployment
 * shape (one mint-service process holding the one root secret key), not
 * multiple instances sharing one file. Running more than one instance
 * against the same `filePath` concurrently is unsupported and would race.
 */

const BLOCK_HASH_PATTERN = /^[0-9a-f]{64}$/;

export interface RevocationStoreOptions {
  /** Path to a JSON file this store loads from at construction and
   * writes through to on every revoke(). Omit to keep the pure
   * in-memory, lost-on-restart behavior. */
  readonly filePath?: string;
}

interface StoreFileShape {
  readonly revoked: readonly string[];
}

export class RevocationStore {
  private readonly revoked: Set<string>;
  private readonly filePath: string | undefined;

  constructor(opts: RevocationStoreOptions = {}) {
    this.filePath = opts.filePath;
    this.revoked = this.filePath ? loadFromFile(this.filePath) : new Set<string>();
  }

  /** Idempotent — revoking an already-revoked hash is a no-op, not an
   * error (matches this codebase's general preference for idempotent
   * write operations over surfacing "already done" as a failure), and in
   * file-backed mode performs no I/O at all in that case (the file
   * already reflects it). Throws RangeError for anything that isn't a
   * well-formed block-signature hash (64 lowercase hex chars, the
   * sha256-hex shape @adc/core's blockSignatureHash() produces) — the
   * caller (server.ts) turns that into a 400, never a 500. In file-backed
   * mode, a disk write failure (full disk, permission error, ...)
   * propagates as a thrown error too, and — critically — leaves the
   * in-memory Set untouched: see writeFileAtomic()'s doc comment for why
   * a revoke() that can't be durably persisted must not silently take
   * effect only in memory. */
  revoke(hash: string): void {
    if (!BLOCK_HASH_PATTERN.test(hash)) {
      throw new RangeError("'hash' must be 64 lowercase hex characters (a block-signature hash — see @adc/core's blockSignatureHash())");
    }
    if (this.revoked.has(hash)) return;
    if (this.filePath) {
      writeFileAtomic(this.filePath, { revoked: [...this.revoked, hash].sort() });
    }
    this.revoked.add(hash);
  }

  /** Unsorted; buildRevocationList() (from @adc/revocation) sorts and
   * dedupes on its own, so this doesn't need to. Always the in-memory
   * view — kept consistent with disk by revoke()'s write-before-commit
   * ordering, so no extra file read is needed here. */
  list(): readonly string[] {
    return [...this.revoked];
  }
}

function loadFromFile(filePath: string): Set<string> {
  if (!existsSync(filePath)) {
    return new Set<string>(); // first run — nothing to load yet, not an error
  }

  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    throw new Error(`RevocationStore: could not read ${filePath}: ${(err as Error).message}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    // Never silently start with an empty ("nothing is revoked") set on a
    // corrupt file — that would be a silent SECURITY REGRESSION (every
    // previously-revoked token becomes valid again), not a graceful
    // degradation. An operator must notice and fix this explicitly.
    throw new Error(
      `RevocationStore: ${filePath} exists but is not valid JSON — refusing to silently start with an empty revoked set: ${(err as Error).message}`,
    );
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`RevocationStore: ${filePath} does not have the expected {"revoked": [...]} shape`);
  }
  const obj = parsed as Record<string, unknown>;
  if (!Array.isArray(obj.revoked)) {
    throw new Error(`RevocationStore: ${filePath}'s "revoked" field must be an array`);
  }
  for (const hash of obj.revoked) {
    if (typeof hash !== "string" || !BLOCK_HASH_PATTERN.test(hash)) {
      throw new Error(`RevocationStore: ${filePath} contains an entry that isn't a valid block-signature hash: ${JSON.stringify(hash)}`);
    }
  }
  return new Set(obj.revoked as string[]);
}

/**
 * Writes the FULL revoked set to `filePath`, atomically: first to a
 * sibling temp file, then `renameSync()` into place. `rename(2)` replaces
 * the destination in one atomic filesystem operation on the same
 * volume — a crash or power loss mid-write can only ever leave the OLD
 * `filePath` intact or the NEW one fully written, never a half-written,
 * corrupt file at the real path (which `loadFromFile()` would otherwise
 * have to somehow recover from on the next start).
 *
 * Called from `revoke()` BEFORE the in-memory `Set` is updated,
 * deliberately: if this throws (disk full, permission denied, ...), the
 * caller must see the revoke as having failed outright, not as having
 * "succeeded in memory but not on disk" — the latter is a real security
 * gap (this process enforces the revocation until its next restart, at
 * which point it silently reverts, with nothing telling anyone that
 * happened). Failing the whole operation keeps in-memory and on-disk
 * state always consistent with each other.
 */
function writeFileAtomic(filePath: string, data: StoreFileShape): void {
  mkdirSync(dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmpPath, JSON.stringify(data, null, 2) + "\n", "utf8");
  renameSync(tmpPath, filePath);
}
