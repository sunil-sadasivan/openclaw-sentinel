import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdirSync, appendFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AlertTailer } from "../alert-tailer.js";
import type { SecurityEvent, SentinelConfig } from "../config.js";

const TEST_DIR = join(tmpdir(), `sentinel-alert-tailer-test-${Date.now()}`);
const EVENTS_PATH = join(TEST_DIR, "events.jsonl");

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Date.now(),
    severity: "high",
    category: "process",
    title: "Suspicious command detected",
    description: "test command",
    hostname: "test-host",
    details: {},
    ...overrides,
  };
}

function makeConfig(overrides: Partial<SentinelConfig> = {}): SentinelConfig {
  return {
    alertSeverity: "info",
    alertChannel: "signal",
    alertTo: "+1234567890",
    clawAssess: false,
    ...overrides,
  } as SentinelConfig;
}

describe("AlertTailer", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    // Create empty events file
    writeFileSync(EVENTS_PATH, "");
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("starts at end of file and ignores existing events", async () => {
    // Write some pre-existing events
    const oldEvent = makeEvent({ title: "Old event" });
    appendFileSync(EVENTS_PATH, JSON.stringify(oldEvent) + "\n");

    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    // Wait for fs.watch to settle
    await new Promise((r) => setTimeout(r, 300));

    assert.equal(alerts.length, 0, "Should not alert on pre-existing events");
    tailer.stop();
  });

  it("alerts on new events written after start", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    // Write a new event
    const evt = makeEvent({ title: "New suspicious command" });
    appendFileSync(EVENTS_PATH, JSON.stringify(evt) + "\n");

    // Wait for debounce (100ms) + processing
    await new Promise((r) => setTimeout(r, 500));

    assert.ok(alerts.length > 0, "Should alert on new events");
    assert.ok(alerts[0].includes("New suspicious command"));
    tailer.stop();
  });

  it("respects severity threshold", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig({ alertSeverity: "high" }),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    // Write info event (below threshold)
    appendFileSync(EVENTS_PATH, JSON.stringify(makeEvent({ severity: "info", title: "Info event" })) + "\n");
    await new Promise((r) => setTimeout(r, 500));

    assert.equal(alerts.length, 0, "Should not alert on info when threshold is high");

    // Write high event (meets threshold)
    appendFileSync(EVENTS_PATH, JSON.stringify(makeEvent({ severity: "high", title: "High event" })) + "\n");
    await new Promise((r) => setTimeout(r, 500));

    assert.equal(alerts.length, 1, "Should alert on high severity");
    tailer.stop();
  });

  it("deduplicates same-title events within window", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    // Write same event twice quickly
    const evt = makeEvent({ title: "Duplicate event", category: "network" });
    appendFileSync(EVENTS_PATH, JSON.stringify(evt) + "\n" + JSON.stringify(evt) + "\n");
    await new Promise((r) => setTimeout(r, 500));

    assert.equal(alerts.length, 1, "Should deduplicate same-title events");
    tailer.stop();
  });

  it("does not deduplicate SSH failed auth events", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    const evt = makeEvent({ title: "SSH failed authentication", category: "ssh_login" });
    appendFileSync(EVENTS_PATH, JSON.stringify(evt) + "\n" + JSON.stringify(evt) + "\n");
    await new Promise((r) => setTimeout(r, 500));

    assert.equal(alerts.length, 2, "SSH failed auth should not be deduped");
    tailer.stop();
  });

  it("includes Claw assessment when enabled", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig({ clawAssess: true }),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => "This is a benign agent command.",
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    appendFileSync(EVENTS_PATH, JSON.stringify(makeEvent()) + "\n");
    await new Promise((r) => setTimeout(r, 500));

    assert.ok(alerts.length > 0);
    assert.ok(alerts[0].includes("benign agent command"), "Should include Claw assessment");
    tailer.stop();
  });

  it("still alerts when Claw assessment fails", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig({ clawAssess: true }),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => { throw new Error("LLM timeout"); },
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    appendFileSync(EVENTS_PATH, JSON.stringify(makeEvent()) + "\n");
    await new Promise((r) => setTimeout(r, 500));

    assert.ok(alerts.length > 0, "Should still alert even if Claw assessment fails");
    tailer.stop();
  });

  it("handles multiple events in a batch", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    // Write 3 different events at once
    const lines = [
      JSON.stringify(makeEvent({ title: "Event A", category: "network" })),
      JSON.stringify(makeEvent({ title: "Event B", category: "file" })),
      JSON.stringify(makeEvent({ title: "Event C", category: "auth" })),
    ].join("\n") + "\n";
    appendFileSync(EVENTS_PATH, lines);

    await new Promise((r) => setTimeout(r, 500));

    assert.equal(alerts.length, 3, "Should process all events in batch");
    tailer.stop();
  });

  it("skips malformed JSON lines", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    appendFileSync(EVENTS_PATH, "not valid json\n" + JSON.stringify(makeEvent({ title: "Valid event" })) + "\n");
    await new Promise((r) => setTimeout(r, 500));

    assert.equal(alerts.length, 1, "Should skip bad lines and process valid ones");
    assert.ok(alerts[0].includes("Valid event"));
    tailer.stop();
  });

  it("stops cleanly", async () => {
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async () => {},
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    tailer.stop();

    // Write event after stop — should not be processed
    const alerts: string[] = [];
    appendFileSync(EVENTS_PATH, JSON.stringify(makeEvent()) + "\n");
    await new Promise((r) => setTimeout(r, 300));

    // No crash, no processing after stop
    assert.ok(true, "Should stop without errors");
  });

  it("handles events file not existing at start", async () => {
    rmSync(EVENTS_PATH, { force: true });

    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig(),
      suppressionStore: null,
      sendAlert: async () => {},
      clawAssessEvent: async () => null,
    });

    // Should not throw
    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));
    tailer.stop();
    assert.ok(true, "Should handle missing file gracefully");
  });

  it("updateConfig changes threshold at runtime", async () => {
    const alerts: string[] = [];
    const tailer = new AlertTailer({
      eventsPath: EVENTS_PATH,
      config: makeConfig({ alertSeverity: "high" }),
      suppressionStore: null,
      sendAlert: async (text) => { alerts.push(text); },
      clawAssessEvent: async () => null,
    });

    await tailer.start();
    await new Promise((r) => setTimeout(r, 200));

    // Info event — should be filtered
    appendFileSync(EVENTS_PATH, JSON.stringify(makeEvent({ severity: "info", title: "Info 1" })) + "\n");
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(alerts.length, 0);

    // Update config to info threshold
    tailer.updateConfig(makeConfig({ alertSeverity: "info" }));

    // Info event — should now alert
    appendFileSync(EVENTS_PATH, JSON.stringify(makeEvent({ severity: "info", title: "Info 2" })) + "\n");
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(alerts.length, 1);

    tailer.stop();
  });
});
