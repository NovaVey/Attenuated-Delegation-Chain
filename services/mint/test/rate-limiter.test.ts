import { test } from "node:test";
import assert from "node:assert/strict";
import { createTokenBucketRateLimiter } from "../src/rate-limiter.js";

test("allows up to `limit` requests immediately (bucket starts full)", () => {
  const limiter = createTokenBucketRateLimiter({ limit: 3, windowMs: 60_000 });
  assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), true);
});

test("denies the (limit + 1)th request with no time having passed", () => {
  const limiter = createTokenBucketRateLimiter({ limit: 2, windowMs: 60_000 });
  assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), false);
  assert.equal(limiter.tryAcquire(), false, "still denied — denial doesn't itself consume capacity");
});

test("refills over time, driven entirely by the injected clock — no real waiting", () => {
  let clock = 0;
  const limiter = createTokenBucketRateLimiter({ limit: 10, windowMs: 10_000, now: () => clock }); // 1 token/second
  for (let i = 0; i < 10; i++) assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), false, "bucket exhausted");

  clock += 500; // half a second: 0.5 tokens refilled, still under 1
  assert.equal(limiter.tryAcquire(), false);

  clock += 500; // one full second elapsed since exhaustion: 1 token refilled
  assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), false, "consumed the one refilled token");
});

test("never refills past `limit` — a very long idle period doesn't let a caller bank unlimited burst capacity", () => {
  let clock = 0;
  const limiter = createTokenBucketRateLimiter({ limit: 5, windowMs: 1_000, now: () => clock });
  for (let i = 0; i < 5; i++) assert.equal(limiter.tryAcquire(), true);

  clock += 1_000_000_000; // an enormous idle gap
  let allowed = 0;
  for (let i = 0; i < 20; i++) {
    if (limiter.tryAcquire()) allowed++;
  }
  assert.equal(allowed, 5, "capped at `limit`, not proportional to the elapsed idle time");
});

test("each createTokenBucketRateLimiter() call is an independent bucket", () => {
  const a = createTokenBucketRateLimiter({ limit: 1, windowMs: 60_000 });
  const b = createTokenBucketRateLimiter({ limit: 1, windowMs: 60_000 });
  assert.equal(a.tryAcquire(), true);
  assert.equal(a.tryAcquire(), false);
  assert.equal(b.tryAcquire(), true, "a fresh limiter's own bucket is unaffected by another instance's state");
});

test("rejects a non-positive limit or windowMs", () => {
  assert.throws(() => createTokenBucketRateLimiter({ limit: 0, windowMs: 1000 }), RangeError);
  assert.throws(() => createTokenBucketRateLimiter({ limit: -1, windowMs: 1000 }), RangeError);
  assert.throws(() => createTokenBucketRateLimiter({ limit: 10, windowMs: 0 }), RangeError);
  assert.throws(() => createTokenBucketRateLimiter({ limit: 10, windowMs: -5 }), RangeError);
  assert.throws(() => createTokenBucketRateLimiter({ limit: NaN, windowMs: 1000 }), RangeError);
});

test("rejects a limit below 1 (not just <= 0) — a sub-1 bucket capacity could never reach tryAcquire()'s own >= 1 threshold", () => {
  // Regression test for an adversarial-review finding: a limit in (0, 1)
  // (e.g. a misconfigured MINT_RATE_LIMIT_PER_MINUTE=0.5) used to pass
  // the old `limit <= 0` check, then silently deny every single request
  // forever — the bucket's own cap was below the 1-token minimum
  // tryAcquire() needs to ever grant one.
  assert.throws(() => createTokenBucketRateLimiter({ limit: 0.5, windowMs: 60_000 }), RangeError);
  assert.throws(() => createTokenBucketRateLimiter({ limit: 0.999, windowMs: 60_000 }), RangeError);
});

test("a limit of exactly 1 is valid and works correctly", () => {
  const limiter = createTokenBucketRateLimiter({ limit: 1, windowMs: 60_000 });
  assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), false);
});
