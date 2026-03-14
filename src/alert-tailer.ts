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
  clawAssessBatch?: (evts: SecurityEvent[]) => Promise<Map<string, string | null>>;
}

/** How long to wait for more events before flushing a batch assessment */
const BATCH_WINDOW_MS = 10_000; // 10 seconds
/** Max events to accumulate before forcing a flush */
const BATCH_MAX_SIZE = 20;

export class AlertTailer {
  private eventsPath: string;
  private config: SentinelConfig;
  private suppressionStore: SuppressionStore | null;
  private sendAlert: (text: string) => Promise<void>;
  private clawAssessEvent: (evt: SecurityEvent) => Promise<string | null>;
  private clawAssessBatch?: (evts: SecurityEvent[]) => Promise<Map<string, string | null>>;
  private alertState: AlertState;
  private fileOffset: number = 0;
  private watcher: FSWatcher | null = null;
  private running: boolean = false;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private pollInterval: ReturnType<typeof setInterval> | null = null;

  // Batch assessment queue
  private pendingAssessments: SecurityEvent[] = [];
  private batchFlushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(opts: AlertTailerOptions) {
    this.eventsPath = opts.eventsPath;
    this.config = opts.config;
    this.suppressionStore = opts.suppressionStore;
    this.sendAlert = opts.sendAlert;
    this.clawAssessEvent = opts.clawAssessEvent;
    this.clawAssessBatch = opts.clawAssessBatch;
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
    if (this.batchFlushTimer) {
      clearTimeout(this.batchFlushTimer);
      this.batchFlushTimer = null;
    }
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    // Flush any remaining pending assessments without Claw assessment
    if (this.pendingAssessments.length > 0) {
      const remaining = this.pendingAssessments.splice(0);
      for (const evt of remaining) {
        this.sendAlert(formatAlert(evt)).catch(() => {});
      }
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

    // If clawAssess is enabled, queue into batch instead of calling per-event
    if (this.config.clawAssess) {
      this.queueForBatchAssessment(evt);
    } else {
      await this.sendAlert(formatAlert(evt)).catch((err: any) => {
        console.error(`[sentinel] Alert delivery failed: ${err.message ?? err}`);
      });
    }
  }

  /**
   * Queue an event for batched Claw assessment.
   * Waits up to BATCH_WINDOW_MS for more events, then sends
   * a single assessment request for the entire batch.
   */
  private queueForBatchAssessment(evt: SecurityEvent): void {
    this.pendingAssessments.push(evt);
    console.log(`[sentinel] Queued for batch assessment: ${evt.title} (${this.pendingAssessments.length} pending)`);

    // Force flush if batch is full
    if (this.pendingAssessments.length >= BATCH_MAX_SIZE) {
      if (this.batchFlushTimer) {
        clearTimeout(this.batchFlushTimer);
        this.batchFlushTimer = null;
      }
      this.flushBatchAssessment().catch((err) => {
        console.error(`[sentinel] Batch assessment flush error: ${err.message}`);
      });
      return;
    }

    // Otherwise reset the debounce timer
    if (this.batchFlushTimer) clearTimeout(this.batchFlushTimer);
    this.batchFlushTimer = setTimeout(() => {
      this.batchFlushTimer = null;
      this.flushBatchAssessment().catch((err) => {
        console.error(`[sentinel] Batch assessment flush error: ${err.message}`);
      });
    }, BATCH_WINDOW_MS);
  }

  /**
   * Flush all pending events as a single batched Claw assessment.
   * One agent call for N events instead of N agent calls.
   */
  private async flushBatchAssessment(): Promise<void> {
    if (this.pendingAssessments.length === 0) return;

    const batch = this.pendingAssessments.splice(0);
    console.log(`[sentinel] Flushing batch assessment for ${batch.length} event(s)`);

    // If we have a batch assessor, use it (single LLM call for all events)
    if (this.clawAssessBatch) {
      try {
        const assessments = await this.clawAssessBatch(batch);
        for (const evt of batch) {
          const assessment = assessments.get(evt.id) ?? null;
          await this.sendAlert(formatAlert(evt, assessment));
        }
        return;
      } catch (err: any) {
        console.warn(`[sentinel] Batch assessment failed, falling back to single: ${err.message ?? err}`);
      }
    }

    // Fallback: single assessment call for all events combined
    try {
      const assessment = await this.clawAssessEvent(
        batch.length === 1 ? batch[0] : this.mergeBatchForAssessment(batch),
      );
      // Apply the same assessment to all events in the batch
      for (const evt of batch) {
        await this.sendAlert(formatAlert(evt, assessment));
      }
    } catch (err: any) {
      console.warn(`[sentinel] Claw assessment failed: ${err.message ?? err}`);
      // Send without assessment
      for (const evt of batch) {
        await this.sendAlert(formatAlert(evt)).catch(() => {});
      }
    }
  }

  /**
   * Merge multiple events into a single synthetic event for assessment.
   * This lets us send one prompt to the LLM covering all events.
   */
  private mergeBatchForAssessment(evts: SecurityEvent[]): SecurityEvent {
    const summaries = evts.map((e, i) => {
      const details = typeof e.details === "string" ? e.details : JSON.stringify(e.details);
      return `[${i + 1}] ${e.severity}/${e.category}: ${e.title} — ${e.description} (${details})`;
    });
    return {
      id: evts[0].id,
      timestamp: evts[0].timestamp,
      severity: evts.reduce((max, e) => {
        const order = ["info", "low", "medium", "high", "critical"];
        return order.indexOf(e.severity) > order.indexOf(max) ? e.severity : max;
      }, evts[0].severity),
      category: evts[0].category,
      title: `${evts.length} security events detected`,
      description: summaries.join("\n"),
      details: { eventCount: evts.length, events: evts.map(e => ({ title: e.title, severity: e.severity, category: e.category })) },
      hostname: evts[0].hostname,
    };
  }

  /** Update config at runtime (e.g., after reload) */
  updateConfig(config: SentinelConfig): void {
    this.config = config;
  }
}
