import type { GraphEvent, GraphSink } from "../event.js";

/**
 * A trivial, in-memory `GraphSink` — for tests, and as the minimal
 * reference implementation of the `GraphSink` contract. Not a substitute
 * for a real Principal-Graph-side adapter (see this package's README for
 * the worked example of what one looks like): this never resolves
 * `event.principal`/`event.resource`/`event.onBehalfOf` into
 * Principal-Graph row ids, never writes anywhere durable, and never
 * hash-chains anything — it just remembers what it was given.
 */
export function createInMemoryGraphSink(): GraphSink & { readonly events: readonly GraphEvent[] } {
  const events: GraphEvent[] = [];
  return {
    events,
    record(event: GraphEvent): void {
      events.push(event);
    },
  };
}
