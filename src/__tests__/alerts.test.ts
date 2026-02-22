import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { shouldAlert, meetsThreshold, createAlertState } from "../alerts.js";
import type { SecurityEvent } from "../config.js";

function makeEvent(title: string, severity: SecurityEvent["severity"] = "high"): SecurityEvent {
  return {
    id: "test",
    timestamp: Date.now(),
    severity,
    category: "process",
    title,
    description: "test",
    details: {},
    hostname: "test",
  };
}

describe("shouldAlert", () => {
  it("allows first alert", () => {
    const state = createAlertState();
    assert.equal(shouldAlert(makeEvent("Test"), state), true);
  });

  it("deduplicates same title within 1 minute", () => {
    const state = createAlertState();
    const now = Date.now();
    assert.equal(shouldAlert(makeEvent("Same Event"), state, now), true);
    assert.equal(shouldAlert(makeEvent("Same Event"), state, now + 1000), false);
    assert.equal(shouldAlert(makeEvent("Same Event"), state, now + 30_000), false);
    assert.equal(shouldAlert(makeEvent("Same Event"), state, now + 59_000), false);
  });

  it("allows same title after 1 minute window", () => {
    const state = createAlertState();
    const now = Date.now();
    shouldAlert(makeEvent("Recurring"), state, now);
    assert.equal(shouldAlert(makeEvent("Recurring"), state, now + 61_000), true);
  });

  it("allows different titles", () => {
    const state = createAlertState();
    const now = Date.now();
    assert.equal(shouldAlert(makeEvent("Event A"), state, now), true);
    assert.equal(shouldAlert(makeEvent("Event B"), state, now), true);
    assert.equal(shouldAlert(makeEvent("Event C"), state, now), true);
  });

  it("rate limits at 10 per minute", () => {
    const state = createAlertState();
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      assert.equal(shouldAlert(makeEvent(`Event ${i}`), state, now), true);
    }
    // 11th should be blocked
    assert.equal(shouldAlert(makeEvent("Event 10"), state, now), false);
  });

  it("allows alerts again after rate limit window expires", () => {
    const state = createAlertState();
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      shouldAlert(makeEvent(`Event ${i}`), state, now);
    }
    // After 1 minute, rate limit resets
    assert.equal(shouldAlert(makeEvent("New Event"), state, now + 61_000), true);
  });
});

describe("meetsThreshold", () => {
  it("critical meets all thresholds", () => {
    assert.equal(meetsThreshold("critical", "info"), true);
    assert.equal(meetsThreshold("critical", "low"), true);
    assert.equal(meetsThreshold("critical", "medium"), true);
    assert.equal(meetsThreshold("critical", "high"), true);
    assert.equal(meetsThreshold("critical", "critical"), true);
  });

  it("info only meets info threshold", () => {
    assert.equal(meetsThreshold("info", "info"), true);
    assert.equal(meetsThreshold("info", "low"), false);
    assert.equal(meetsThreshold("info", "medium"), false);
    assert.equal(meetsThreshold("info", "high"), false);
  });

  it("high meets high and below", () => {
    assert.equal(meetsThreshold("high", "high"), true);
    assert.equal(meetsThreshold("high", "medium"), true);
    assert.equal(meetsThreshold("high", "critical"), false);
  });

  it("defaults to high when invalid severity given", () => {
    assert.equal(meetsThreshold("critical", "invalid"), true);
    assert.equal(meetsThreshold("high", "invalid"), true);
    assert.equal(meetsThreshold("medium", "invalid"), false);
  });
});
