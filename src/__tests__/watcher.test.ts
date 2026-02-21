import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { ResultLogWatcher } from "../watcher.js";

function makeTempDir(): string {
  return join(tmpdir(), `sentinel-test-${randomUUID()}`);
}

describe("ResultLogWatcher", () => {
  const cleanupDirs: string[] = [];

  after(async () => {
    for (const dir of cleanupDirs) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("emits 'started' event", async () => {
    const dir = makeTempDir();
    cleanupDirs.push(dir);
    await mkdir(dir, { recursive: true });

    const watcher = new ResultLogWatcher(dir);
    const started = new Promise<void>((resolve) => {
      watcher.on("started", resolve);
    });
    await watcher.start();
    await started;
    watcher.stop();
  });

  it("parses new JSON lines appended to log", async () => {
    const dir = makeTempDir();
    cleanupDirs.push(dir);
    await mkdir(dir, { recursive: true });

    const logFile = join(dir, "osqueryd.results.log");
    // Create empty file first
    await writeFile(logFile, "");

    const watcher = new ResultLogWatcher(dir);
    const results: any[] = [];

    watcher.on("result", (r: any) => results.push(r));
    await watcher.start();

    // Wait for watcher to initialize
    await new Promise((r) => setTimeout(r, 100));

    // Append a result line
    const testResult = {
      name: "process_events",
      hostIdentifier: "test-host",
      calendarTime: "Sat Feb 21 17:00:00 2026 UTC",
      unixTime: 1771695600,
      epoch: 0,
      counter: 0,
      numerics: false,
      decorations: {},
      columns: { path: "/tmp/test", cmdline: "test", uid: "0" },
      action: "added",
    };

    await writeFile(logFile, JSON.stringify(testResult) + "\n");

    // Wait for poll cycle (2s fallback + buffer)
    await new Promise((r) => setTimeout(r, 3000));

    watcher.stop();

    assert.equal(results.length, 1);
    assert.equal(results[0].name, "process_events");
    assert.equal(results[0].columns.path, "/tmp/test");
  });

  it("handles multiple lines at once", async () => {
    const dir = makeTempDir();
    cleanupDirs.push(dir);
    await mkdir(dir, { recursive: true });

    const logFile = join(dir, "osqueryd.results.log");
    await writeFile(logFile, "");

    const watcher = new ResultLogWatcher(dir);
    const results: any[] = [];
    watcher.on("result", (r: any) => results.push(r));
    await watcher.start();
    await new Promise((r) => setTimeout(r, 100));

    const lines = [
      JSON.stringify({ name: "query_1", columns: { a: "1" } }),
      JSON.stringify({ name: "query_2", columns: { b: "2" } }),
      JSON.stringify({ name: "query_3", columns: { c: "3" } }),
    ].join("\n") + "\n";

    await writeFile(logFile, lines);
    await new Promise((r) => setTimeout(r, 3000));
    watcher.stop();

    assert.equal(results.length, 3);
    assert.equal(results[0].name, "query_1");
    assert.equal(results[2].name, "query_3");
  });

  it("skips malformed JSON lines", async () => {
    const dir = makeTempDir();
    cleanupDirs.push(dir);
    await mkdir(dir, { recursive: true });

    const logFile = join(dir, "osqueryd.results.log");
    await writeFile(logFile, "");

    const watcher = new ResultLogWatcher(dir);
    const results: any[] = [];
    watcher.on("result", (r: any) => results.push(r));
    await watcher.start();
    await new Promise((r) => setTimeout(r, 100));

    const lines = [
      "not valid json",
      JSON.stringify({ name: "valid", columns: {} }),
      "{broken",
    ].join("\n") + "\n";

    await writeFile(logFile, lines);
    await new Promise((r) => setTimeout(r, 3000));
    watcher.stop();

    assert.equal(results.length, 1);
    assert.equal(results[0].name, "valid");
  });

  it("handles file rotation (truncation)", async () => {
    const dir = makeTempDir();
    cleanupDirs.push(dir);
    await mkdir(dir, { recursive: true });

    const logFile = join(dir, "osqueryd.results.log");
    // Start with some content
    await writeFile(logFile, JSON.stringify({ name: "old" }) + "\n");

    const watcher = new ResultLogWatcher(dir);
    const results: any[] = [];
    watcher.on("result", (r: any) => results.push(r));
    await watcher.start();
    await new Promise((r) => setTimeout(r, 100));

    // Truncate and write new content (simulating log rotation)
    await writeFile(logFile, JSON.stringify({ name: "after_rotate" }) + "\n");
    await new Promise((r) => setTimeout(r, 3000));
    watcher.stop();

    assert.ok(results.some((r) => r.name === "after_rotate"));
  });
});
