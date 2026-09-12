import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, mintRoot } from "@adc/core";
import { buildMintEvent } from "@adc/graph";
import { buildGraphSinkFromConfig } from "../src/graph-sink.js";

/**
 * Direct coverage for the exact piece of wiring index.ts does — see
 * graph-sink.ts's own doc comment on why this is split out: index.ts
 * can't be imported in a test without triggering its real
 * loadConfigFromEnv() side effect.
 */

test("buildGraphSinkFromConfig(undefined): returns undefined (MINT_GRAPH_EVENTS_PATH unset — createMintServer()'s own default applies)", () => {
  assert.equal(buildGraphSinkFromConfig(undefined), undefined);
});

test("buildGraphSinkFromConfig(path): returns a real, working GraphSink that durably writes to that exact path", () => {
  const dir = mkdtempSync(join(tmpdir(), "adc-mint-graph-sink-test-"));
  try {
    const filePath = join(dir, "events.ndjson");
    const sink = buildGraphSinkFromConfig(filePath);
    assert.ok(sink, "expected a real GraphSink, not undefined, for a defined path");

    const { secretKey, publicKey } = generateKeypair();
    sink!.record(buildMintEvent(mintRoot(secretKey), publicKey));

    const lines = readFileSync(filePath, "utf8").split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 1);
    assert.equal(JSON.parse(lines[0]!).action, "mint");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
