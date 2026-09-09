/**
 * In-memory store of revoked block-signature hashes — the thing
 * `POST /revoke` writes to and `GET /revocations` reads from (via
 * @adc/revocation's buildRevocationList()/signRevocationList()).
 *
 * **Lost on restart.** This is the simplest thing that could serve a real
 * signed list, not a durability claim — see README.md's Known
 * limitations. docs/PLAN.md's Phase 7 acceptance criteria are about the
 * signed-list format, the offline check, and the liveness bound; nothing
 * in it requires persistent storage, so this in-memory Set is enough to
 * exercise the whole pipeline end to end. A real deployment would back
 * this with a database and treat this class's shape as the interface to
 * preserve.
 */

const BLOCK_HASH_PATTERN = /^[0-9a-f]{64}$/;

export class RevocationStore {
  private readonly revoked = new Set<string>();

  /** Idempotent — revoking an already-revoked hash is a no-op, not an
   * error (matches this codebase's general preference for idempotent
   * write operations over surfacing "already done" as a failure). Throws
   * RangeError for anything that isn't a well-formed block-signature hash
   * (64 lowercase hex chars, the sha256-hex shape @adc/core's
   * blockSignatureHash() produces) — the caller (server.ts) turns that
   * into a 400, never a 500. */
  revoke(hash: string): void {
    if (!BLOCK_HASH_PATTERN.test(hash)) {
      throw new RangeError("'hash' must be 64 lowercase hex characters (a block-signature hash — see @adc/core's blockSignatureHash())");
    }
    this.revoked.add(hash);
  }

  /** Unsorted; buildRevocationList() (from @adc/revocation) sorts and
   * dedupes on its own, so this doesn't need to. */
  list(): readonly string[] {
    return [...this.revoked];
  }
}
