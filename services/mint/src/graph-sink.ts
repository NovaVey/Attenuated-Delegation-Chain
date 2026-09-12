import { createNdjsonGraphSink, type GraphSink } from "@adc/graph";

/**
 * Builds the `GraphSink` index.ts wires into `createMintServer()`, from
 * config's own `graphEventsFilePath`. Pulled out as its own small, pure,
 * side-effect-free function specifically so this exact piece of wiring
 * has direct test coverage — index.ts itself can't be imported in a test
 * without triggering its top-level `loadConfigFromEnv()` call (which
 * throws without a full set of real env vars), matching this codebase's
 * established convention that entry-point scripts aren't unit-tested
 * directly (see this package's README's Testing strategy). Without this
 * split, a future typo in index.ts's wiring (e.g. building the sink but
 * forgetting to pass it through, or reading the wrong config field) could
 * leave `MINT_GRAPH_EVENTS_PATH` silently inert in production while every
 * existing test still passed — found during adversarial review as a real
 * coverage gap, not yet an actual bug.
 */
export function buildGraphSinkFromConfig(graphEventsFilePath: string | undefined): GraphSink | undefined {
  // undefined when MINT_GRAPH_EVENTS_PATH is unset — createMintServer()'s
  // own default (a private, in-memory GraphSink) applies unchanged,
  // exactly as before this option existed.
  return graphEventsFilePath ? createNdjsonGraphSink({ filePath: graphEventsFilePath }) : undefined;
}
