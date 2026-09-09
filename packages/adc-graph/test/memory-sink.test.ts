import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair, mintRoot } from "@adc/core";
import { buildMintEvent } from "../src/builders.js";
import { createInMemoryGraphSink } from "../src/sinks/memory.js";

test("createInMemoryGraphSink: record() appends, events are readable back in order", () => {
  const sink = createInMemoryGraphSink();
  const { secretKey, publicKey } = generateKeypair();
  const eventA = buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date(1000) });
  const eventB = buildMintEvent(mintRoot(secretKey), publicKey, { now: new Date(2000) });

  sink.record(eventA);
  sink.record(eventB);

  assert.equal(sink.events.length, 2);
  assert.equal(sink.events[0], eventA);
  assert.equal(sink.events[1], eventB);
});

test("createInMemoryGraphSink: a fresh sink starts empty", () => {
  const sink = createInMemoryGraphSink();
  assert.deepEqual(sink.events, []);
});

test("createInMemoryGraphSink: two independent sinks don't share state", () => {
  const sinkA = createInMemoryGraphSink();
  const sinkB = createInMemoryGraphSink();
  const { secretKey, publicKey } = generateKeypair();
  sinkA.record(buildMintEvent(mintRoot(secretKey), publicKey));
  assert.equal(sinkA.events.length, 1);
  assert.equal(sinkB.events.length, 0);
});
