import { test } from "node:test";
import assert from "node:assert/strict";
import { LEVEL_ORDER, type TaintLevel as BrokerTaintLevel } from "taint-tracked-tool-broker";
import { TAINT_LEVELS } from "@adc/core";
import { adcTaintLevel } from "../src/taint.js";

test("maps every broker taint level to the expected ADC level", () => {
  assert.equal(adcTaintLevel("CLEAN"), "TRUSTED");
  assert.equal(adcTaintLevel("DERIVED_UNTRUSTED"), "DERIVED");
  assert.equal(adcTaintLevel("RAW_UNTRUSTED"), "RAW_UNTRUSTED");
});

test("the mapping preserves ordering: broker LEVEL_ORDER and ADC TAINT_LEVELS agree on every pair", () => {
  // Regression guard: if either library ever reorders or adds a level,
  // this fails loudly instead of silently producing an incorrect
  // taint_max evaluation. Checks every pair, not just adjacent ones, so a
  // non-monotonic remap would also be caught.
  const brokerLevels = Object.keys(LEVEL_ORDER) as BrokerTaintLevel[];
  assert.equal(brokerLevels.length, TAINT_LEVELS.length, "both libraries must define the same number of levels");

  for (const a of brokerLevels) {
    for (const b of brokerLevels) {
      const brokerCmp = Math.sign(LEVEL_ORDER[a] - LEVEL_ORDER[b]);
      const adcCmp = Math.sign(TAINT_LEVELS.indexOf(adcTaintLevel(a)) - TAINT_LEVELS.indexOf(adcTaintLevel(b)));
      assert.equal(adcCmp, brokerCmp, `ordering mismatch: broker(${a} vs ${b}) = ${brokerCmp}, adc(${a} vs ${b}) = ${adcCmp}`);
    }
  }
});

test("throws RangeError on an unrecognized level (defensive — unreachable via the type system)", () => {
  assert.throws(() => adcTaintLevel("SOMETHING_NEW" as BrokerTaintLevel), RangeError);
});
