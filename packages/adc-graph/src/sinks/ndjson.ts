import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { GraphEvent, GraphSink } from "../event.js";

export interface NdjsonGraphSinkOptions {
  /** Append each event as one JSON line to this file — created (along
   * with any missing parent directories) if missing, appended to (never
   * truncated) if it already exists, matching an audit trail's own
   * "never silently lose history" expectation. Each `record()` call
   * opens, writes, and closes the file synchronously (`fs.appendFileSync`)
   * — this sink is sized for low/moderate event volume (a mint or revoke
   * call, not a request-per-millisecond hot path), not a high-throughput
   * logging pipeline. Provide exactly one of `filePath` or `stream`. */
  readonly filePath?: string;
  /** Write each event as one JSON line to this stream instead of a file —
   * e.g. `process.stdout`, for a 12-factor-style "log to stdout, let the
   * platform capture it" deployment. Provide exactly one of `filePath` or
   * `stream`.
   *
   * A stream's write failures surface asynchronously, via its own
   * `'error'` event — never as a synchronous throw out of `record()` the
   * way file mode's do. This sink always attaches its own `'error'`
   * listener (routing to `onError`) so a failing stream can never crash
   * the process with an unhandled `'error'` event — Node's default
   * behavior for an EventEmitter's `'error'` event with no listener at
   * all is to throw it as an uncaught exception. */
  readonly stream?: NodeJS.WritableStream;
  /** Called when `stream` mode's underlying stream emits an `'error'`
   * event (e.g. a broken pipe, a destroyed stream, a log shipper closing
   * its end) — the only way to observe a stream-mode write failure, since
   * it happens asynchronously, on a later tick than the `record()` call
   * that triggered it, and so can never be caught by a try/catch around
   * that call (see @adc/core's own `onError` convention on
   * `RevocationClientOptions`/`HttpRbaClientOptions` for the same
   * "report it, don't throw it into an unrelated later caller" shape).
   * Only relevant in `stream` mode — ignored in `filePath` mode, where a
   * write failure throws synchronously out of `record()` instead.
   * Defaults to logging via `console.error`. */
  readonly onError?: (err: Error) => void;
}

/**
 * A `GraphSink` that appends each event as one newline-delimited JSON
 * line — the standard "audit log" shape: tail it, ship it to a log
 * pipeline, or eventually feed it into a real Principal-Graph-side
 * consumer. Exists because this package's only other reference
 * implementation, `createInMemoryGraphSink()` (sinks/memory.ts), is
 * exactly that — a reference for tests — and produces nothing an
 * operator can actually observe in a real deployment; this is the
 * smallest sink that does.
 *
 * No default destination: a caller must supply exactly one of `filePath`
 * or `stream` — this package doesn't pick a default deployment policy
 * (e.g. "silently write to stdout") on a consumer's behalf; that's a
 * decision for whoever wires this in (see services/mint's own
 * MINT_GRAPH_EVENTS_PATH for a worked example).
 *
 * `record()` never does anything to make an event's own claims more
 * trustworthy — no signing, no hash-chaining, no tamper-evidence. It is
 * exactly as durable and exactly as trusted as the file or stream it
 * writes to, the same way `createInMemoryGraphSink()` is exactly as
 * durable as the process it runs in.
 */
export function createNdjsonGraphSink(opts: NdjsonGraphSinkOptions = {}): GraphSink {
  if (opts.filePath !== undefined && opts.stream !== undefined) {
    throw new RangeError("createNdjsonGraphSink: provide exactly one of filePath or stream, not both");
  }
  if (opts.filePath === undefined && opts.stream === undefined) {
    throw new RangeError("createNdjsonGraphSink: provide exactly one of filePath or stream");
  }
  const filePath = opts.filePath;
  const stream = opts.stream;
  const onError = opts.onError ?? ((err: Error): void => console.error("adc-graph: ndjson sink stream error", err));

  // Attached once, at construction — not because of any particular event,
  // but because an EventEmitter with zero 'error' listeners throws
  // whatever it emits as an uncaught exception by default. A found-by-
  // adversarial-review bug: without this, a broken pipe or a destroyed
  // stream on a later tick could crash the entire process this sink is
  // wired into (e.g. services/mint, which holds the root secret key) —
  // reachable only through `stream` mode, since file mode's failures
  // surface synchronously out of record() instead (see below).
  stream?.on("error", onError);

  return {
    record(event: GraphEvent): void {
      // JSON.stringify calls Date.prototype.toJSON() automatically
      // (== toISOString()), and every other GraphEvent field is already
      // a plain string/boolean/null/nested-identity-object — no custom
      // replacer needed. A null-*valued* field (denyReason, reversible,
      // requestDigest, onBehalfOf) serializes as a literal `null`, never
      // dropped — JSON.stringify only omits keys whose value is
      // `undefined`, and GraphEvent's own doc comment already requires
      // every field to be a present key (see event.ts).
      const line = JSON.stringify(event) + "\n";
      if (filePath !== undefined) {
        // mkdirSync is cheap and idempotent when the directory already
        // exists (the common case, on every call after the first) —
        // matches revocation-store.ts's own writeFileAtomic(), which
        // does the same thing for the same reason: without it, a
        // missing parent directory makes every single record() call
        // throw ENOENT, silently and permanently losing every audit
        // event (recordGraphEvent()'s own try/catch in services/mint
        // reports it via onInternalError, but nothing else notices) —
        // also found by adversarial review.
        mkdirSync(dirname(filePath), { recursive: true });
        appendFileSync(filePath, line, "utf8");
      } else {
        stream!.write(line);
      }
    },
  };
}
