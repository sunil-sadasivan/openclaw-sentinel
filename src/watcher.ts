/**
 * Event-driven log watcher — tails osqueryd result logs for real-time alerting.
 *
 * osqueryd writes scheduled query results as JSON lines to its results log.
 * We watch the file and parse new lines as they arrive.
 */

import { open, stat } from "node:fs/promises";
import { watch, existsSync } from "node:fs";
import { join } from "node:path";
import { EventEmitter } from "node:events";

export interface OsqueryResult {
  name: string; // query name (e.g., "process_events")
  hostIdentifier: string;
  calendarTime: string;
  unixTime: number;
  epoch: number;
  counter: number;
  numerics: boolean;
  columns: Record<string, string>;
  action: "added" | "removed" | "snapshot";
}

export interface OsqueryResultBatch {
  name: string;
  hostIdentifier: string;
  calendarTime: string;
  unixTime: number;
  epoch: number;
  counter: number;
  numerics: boolean;
  decorations: Record<string, string>;
  // Differential results
  columns?: Record<string, string>;
  action?: string;
  // Snapshot results
  snapshot?: Record<string, string>[];
}

export class ResultLogWatcher extends EventEmitter {
  private logPath: string;
  private offset: number = 0;
  private watcher: ReturnType<typeof watch> | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private reading = false;

  constructor(logDir: string) {
    super();
    this.logPath = join(logDir, "osqueryd.results.log");
  }

  async start(): Promise<void> {
    // Initialize offset to end of file (skip existing results)
    if (existsSync(this.logPath)) {
      const stats = await stat(this.logPath);
      this.offset = stats.size;
    }

    // Primary: fs.watch for immediate notification
    try {
      this.watcher = watch(this.logPath, { persistent: false }, (eventType) => {
        if (eventType === "change") {
          this.readNewLines();
        }
      });
      this.watcher.on("error", () => {
        // File may not exist yet — that's fine, poll will catch it
      });
    } catch {
      // fs.watch may fail if file doesn't exist yet
    }

    // Fallback: poll every 2 seconds in case fs.watch misses events
    this.pollTimer = setInterval(() => this.readNewLines(), 2000);

    this.emit("started");
  }

  stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.emit("stopped");
  }

  private async readNewLines(): Promise<void> {
    if (this.reading) return;
    if (!existsSync(this.logPath)) return;

    this.reading = true;

    try {
      const stats = await stat(this.logPath);

      // File was truncated/rotated — reset offset
      if (stats.size < this.offset) {
        this.offset = 0;
      }

      // No new data
      if (stats.size <= this.offset) {
        this.reading = false;
        return;
      }

      // Read new bytes
      const fh = await open(this.logPath, "r");
      try {
        const bufSize = stats.size - this.offset;
        const buf = Buffer.alloc(bufSize);
        await fh.read(buf, 0, bufSize, this.offset);
        this.offset = stats.size;

        const text = buf.toString("utf-8");
        const lines = text.split("\n").filter((l) => l.trim());

        for (const line of lines) {
          try {
            const result = JSON.parse(line) as OsqueryResultBatch;
            this.emit("result", result);
          } catch {
            // Skip malformed lines
          }
        }
      } finally {
        await fh.close();
      }
    } catch (err) {
      // Non-fatal — file may be temporarily unavailable
      this.emit("error", err);
    } finally {
      this.reading = false;
    }
  }
}
