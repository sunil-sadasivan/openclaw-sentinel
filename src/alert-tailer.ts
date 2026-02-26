/**
 * AlertTailer — Tails events.jsonl and handles all alerting logic.
 *
 * Decouples detection (log stream watchers, osquery) from alerting
 * (rate limiting, dedup, suppression, Claw assessment, delivery).
 *
 * Architecture:
 *   Watchers → logEvent() → events.jsonl → AlertTailer → assess → deliver
 */

import { watch, type FSWatcher } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import type { SecurityEvent, SentinelConfig } from "./config.js";
import { shouldAlert, meetsThreshold, createAlertState, type AlertState } from "./alerts.js";
import { SuppressionStore } from "./suppressions.js";
import { formatAlert } from "./analyzer.js";

export interface AlertTailerOptions {
  eventsPath: string;
  config: SentinelConfig;
  suppressionStore: SuppressionStore | null;
  sendAlert: (text: string) => Promise<void>;
  clawAssessEvent: (evt: SecurityEvent) => Promise<string | null>;
}

export class AlertTailer {
  private eventsPath: string;
  private config: SentinelConfig;
  private suppressionStore: SuppressionStore | null;
  private sendAlert: (text: string) => Promise<void>;
  private clawAssessEvent: (evt: SecurityEvent) => Promise<string | null>;
  private alertState: AlertState;
  private fileOffset: number = 0;
  private watcher: FSWatcher | null = null;
  private running: boolean = false;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private pollInterval: ReturnType<typeof setInterval> | null = null;

  constructor(opts: AlertTailerOptions) {
    this.eventsPath = opts.eventsPath;
    this.config = opts.config;
    this.suppressionStore = opts.suppressionStore;
    this.sendAlert = opts.sendAlert;
    this.clawAssessEvent = opts.clawAssessEvent;
    this.alertState = createAlertState();
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Start at end of file (only process new events)
    try {
      const st = await stat(this.eventsPath);
      this.fileOffset = st.size;
      console.log(`[sentinel] AlertTailer started, offset=${this.fileOffset}`);
    } catch {
      this.fileOffset = 0;
      console.log("[sentinel] AlertTailer started, events file not yet created");
    }

    // Watch for changes
    try {
      this.watcher = watch(this.eventsPath, { persistent: false }, (eventType) => {
        if (eventType === "change") {
          this.debouncedProcessNew();
        }
      });
      this.watcher.on("error", (err) => {
        console.warn(`[sentinel] AlertTailer watcher error: ${err.message}`);
      });
    } catch {
      // File might not exist yet — poll for it
      this.pollInterval = setInterval(async () => {
        try {
          await stat(this.eventsPath);
          if (this.pollInterval) clearInterval(this.pollInterval);
          this.pollInterval = null;
          if (this.running) this.start();
        } catch { /* keep waiting */ }
      }, 5000);
    }
  }

  stop(): void {
    this.running = false;
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    console.log("[sentinel] AlertTailer stopped");
  }

  private debouncedProcessNew(): void {
    // Debounce: multiple writes within 100ms get batched
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => {
      this.processNewLines().catch((err) => {
        console.error(`[sentinel] AlertTailer processing error: ${err.message}`);
      });
    }, 100);
  }

  private async processNewLines(): Promise<void> {
    if (!this.running) return;

    try {
      const st = await stat(this.eventsPath);
      if (st.size <= this.fileOffset) return; // No new data

      // Read only new bytes
      const stream = createReadStream(this.eventsPath, {
        start: this.fileOffset,
        encoding: "utf8",
      });
      const rl = createInterface({ input: stream, crlfDelay: Infinity });

      const newEvents: SecurityEvent[] = [];
      for await (const line of rl) {
        if (!line.trim()) continue;
        try {
          const evt = JSON.parse(line) as SecurityEvent;
          newEvents.push(evt);
        } catch {
          // Skip malformed lines
        }
      }

      this.fileOffset = st.size;

      // Process each event through the alert pipeline
      for (const evt of newEvents) {
        await this.processEvent(evt);
      }
    } catch (err: any) {
      console.error(`[sentinel] AlertTailer read error: ${err.message}`);
    }
  }

  private async processEvent(evt: SecurityEvent): Promise<void> {
    const meets = meetsThreshold(evt.severity, this.config.alertSeverity);
    if (!meets) return;

    const should = shouldAlert(evt, this.alertState);
    if (!should) return;

    // Check suppression
    const suppressed = this.suppressionStore?.isSuppressed(evt);
    if (suppressed) {
      console.log(`[sentinel] Alert suppressed by rule "${suppressed.reason}" (${SuppressionStore.describe(suppressed)})`);
      return;
    }

    // Claw assessment
    if (this.config.clawAssess) {
      console.log(`[sentinel] Claw assessment enabled, calling for: ${evt.title}`);
      try {
        const assessment = await this.clawAssessEvent(evt);
        console.log(`[sentinel] Claw assessment result: ${assessment?.slice(0, 80) ?? "(null)"}`);
        await this.sendAlert(formatAlert(evt, assessment));
      } catch (err: any) {
        console.warn(`[sentinel] Claw assessment failed: ${err.message ?? err}`);
        await this.sendAlert(formatAlert(evt)).catch(() => {});
      }
    } else {
      await this.sendAlert(formatAlert(evt)).catch((err: any) => {
        console.error(`[sentinel] Alert delivery failed: ${err.message ?? err}`);
      });
    }
  }

  /** Update config at runtime (e.g., after reload) */
  updateConfig(config: SentinelConfig): void {
    this.config = config;
  }
}
