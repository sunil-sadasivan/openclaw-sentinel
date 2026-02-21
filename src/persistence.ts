/**
 * Event persistence — JSONL file store with auto-rotation.
 */

import { appendFile, readFile, writeFile, stat, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import type { SecurityEvent } from "./config.js";

const DEFAULT_MAX_SIZE_MB = 10;
const ROTATION_KEEP_RATIO = 0.5; // Keep last 50% on rotation

export class EventStore {
  private filePath: string;
  private maxSizeBytes: number;

  constructor(sentinelDir: string, maxSizeMB: number = DEFAULT_MAX_SIZE_MB) {
    this.filePath = join(sentinelDir, "events.jsonl");
    this.maxSizeBytes = maxSizeMB * 1024 * 1024;
  }

  /**
   * Append a security event to the JSONL file.
   * Auto-rotates if file exceeds max size.
   */
  async append(event: SecurityEvent): Promise<void> {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true });
    }

    const line = JSON.stringify(event) + "\n";
    await appendFile(this.filePath, line);

    // Check if rotation needed
    try {
      const stats = await stat(this.filePath);
      if (stats.size > this.maxSizeBytes) {
        await this.rotate();
      }
    } catch {
      // stat failed — file may have been removed
    }
  }

  /**
   * Load the most recent N events from the file.
   * Reads from the end efficiently for large files.
   */
  async loadRecent(limit: number = 100): Promise<SecurityEvent[]> {
    if (!existsSync(this.filePath)) return [];

    try {
      const content = await readFile(this.filePath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);

      // Take last N lines
      const recentLines = lines.slice(-limit);
      const events: SecurityEvent[] = [];

      for (const line of recentLines) {
        try {
          events.push(JSON.parse(line));
        } catch {
          // Skip malformed lines
        }
      }

      return events;
    } catch {
      return [];
    }
  }

  /**
   * Rotate the file — keep the last 50% of lines.
   */
  async rotate(): Promise<void> {
    if (!existsSync(this.filePath)) return;

    try {
      const content = await readFile(this.filePath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);

      const keepCount = Math.floor(lines.length * ROTATION_KEEP_RATIO);
      const kept = lines.slice(-keepCount);

      await writeFile(this.filePath, kept.join("\n") + "\n");
      console.log(
        `[sentinel] Rotated events.jsonl: ${lines.length} → ${kept.length} entries`,
      );
    } catch (err) {
      console.error("[sentinel] Event log rotation failed:", err);
    }
  }

  /**
   * Get the file path (for status reporting).
   */
  get path(): string {
    return this.filePath;
  }
}
