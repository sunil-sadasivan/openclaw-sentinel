/**
 * OpenClaw Sentinel Plugin
 *
 * Real-time endpoint security monitoring using osquery in daemon mode.
 * Uses event-driven log tailing for sub-second alerting.
 *
 * Architecture:
 *   osqueryd (daemon, managed externally via launchd) → writes results to JSON log
 *   Sentinel watcher  → tails log file via fs.watch + poll fallback
 *   Analyzer          → evaluates results against detection rules
 *   OpenClaw messaging → alerts on configured channel
 *
 * Note: osqueryd requires root/sudo — it must be started separately
 * (e.g., via launchd). This plugin only watches the result logs.
 */

import { existsSync, readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { Type } from "@sinclair/typebox";
import type { SentinelConfig, SecurityEvent } from "./config.js";
import { findOsquery, query } from "./osquery.js";
import { shouldAlert, meetsThreshold, createAlertState } from "./alerts.js";
import { EventStore } from "./persistence.js";
import { ResultLogWatcher } from "./watcher.js";
import type { OsqueryResultBatch } from "./watcher.js";
import { LogStreamWatcher } from "./log-stream.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
import {
  analyzeProcessEvents,
  analyzeLoginEvents,
  analyzeFailedAuth,
  analyzeListeningPorts,
  analyzeFileEvents,
  formatAlert,
} from "./analyzer.js";

// ── State ──
const state = {
  knownHosts: new Set<string>(),
  knownPorts: new Set<number>(),
  eventLog: [] as SecurityEvent[],
  initialized: false,
  daemonRunning: false,
  watching: false,
};

const MAX_EVENT_LOG = 1000;
const SENTINEL_DIR_DEFAULT = join(homedir(), ".openclaw", "sentinel");
const alertRateState = createAlertState();
let eventStore: EventStore | null = null;

function logEvent(evt: SecurityEvent): void {
  state.eventLog.push(evt);
  if (state.eventLog.length > MAX_EVENT_LOG) {
    state.eventLog = state.eventLog.slice(-MAX_EVENT_LOG);
  }
  // Persist to disk
  eventStore?.append(evt).catch((err) => {
    console.error("[sentinel] Failed to persist event:", err);
  });
}

/**
 * Initialize baseline state — learn what's "normal" on first run.
 */
async function initializeBaseline(
  osqueryiPath: string,
): Promise<void> {
  if (state.initialized) return;

  try {
    const logins = await query(
      osqueryiPath,
      "SELECT DISTINCT host FROM logged_in_users WHERE host != '' AND host != 'localhost';",
    );
    for (const row of logins) {
      if (row.host) state.knownHosts.add(row.host);
    }

    const ports = await query(
      osqueryiPath,
      "SELECT DISTINCT port FROM listening_ports WHERE port > 0;",
    );
    for (const row of ports) {
      const port = parseInt(row.port ?? "0", 10);
      if (port > 0) state.knownPorts.add(port);
    }

    state.initialized = true;
    console.log(
      `[sentinel] Baseline: ${state.knownHosts.size} hosts, ${state.knownPorts.size} ports`,
    );
  } catch (err) {
    console.error("[sentinel] baseline init failed:", err);
  }
}

/**
 * Check if osqueryd is running (look for pid file or process).
 */
async function checkDaemon(sentinelDir: string): Promise<boolean> {
  const pidFile = join(sentinelDir, "osqueryd.pid");
  if (!existsSync(pidFile)) return false;

  try {
    const pid = parseInt(await readFile(pidFile, "utf-8"), 10);
    process.kill(pid, 0); // Check if process exists (doesn't actually kill)
    return true;
  } catch {
    return false;
  }
}

/**
 * Handle an osquery result batch — route to appropriate analyzer.
 */
function handleResult(
  result: OsqueryResultBatch,
  config: SentinelConfig,
  sendAlert: (text: string) => Promise<void>,
): void {
  let events: SecurityEvent[] = [];

  const rows = result.snapshot ?? (result.columns ? [result.columns] : []);

  switch (result.name) {
    case "process_events":
      events = analyzeProcessEvents(rows, config);
      break;
    case "logged_in_users":
      events = analyzeLoginEvents(rows, state.knownHosts);
      break;
    case "failed_auth":
      events = analyzeFailedAuth(rows);
      break;
    case "listening_ports":
      events = analyzeListeningPorts(rows, state.knownPorts);
      break;
    default:
      if (
        result.name?.includes("file") ||
        result.name?.includes("integrity")
      ) {
        events = analyzeFileEvents(rows);
      }
      break;
  }

  for (const evt of events) {
    logEvent(evt);

    if (meetsThreshold(evt.severity, config.alertSeverity) && shouldAlert(evt, alertRateState)) {
      sendAlert(formatAlert(evt)).catch((err) => {
        console.error("[sentinel] alert failed:", err);
      });
    }
  }

  if (events.length > 0) {
    console.log(
      `[sentinel] ${events.length} events from ${result.name}`,
    );
  }
}

/**
 * OpenClaw plugin entry point.
 */
export default function sentinel(api: any): void {
    // api.getConfig() may not return all fields — merge with config file as fallback
  const apiConfig = api.getConfig?.() ?? {};
  let fileConfig: Record<string, unknown> = {};
  try {
    const cfgPath = join(homedir(), ".openclaw", "openclaw.json");
    const raw = JSON.parse(readFileSync(cfgPath, "utf8"));
    fileConfig = raw?.plugins?.entries?.sentinel?.config ?? {};
  } catch { /* ignore */ }
  const pluginConfig: SentinelConfig = { ...fileConfig, ...apiConfig } as SentinelConfig;
  console.log(`[sentinel] Config: alertSeverity=${pluginConfig.alertSeverity}, alertChannel=${pluginConfig.alertChannel}`);
  let watcher: ResultLogWatcher | null = null;
  let logStreamWatcher: LogStreamWatcher | null = null;
  const sentinelDir = pluginConfig.logPath ?? SENTINEL_DIR_DEFAULT;

  const sendAlert = async (text: string): Promise<void> => {
    const channel = pluginConfig.alertChannel;
    const to = pluginConfig.alertTo;
    if (!channel || !to) {
      console.error("[sentinel] Alert skipped: no alertChannel/alertTo configured");
      return;
    }
    try {
      // Use openclaw CLI for reliable message delivery
      const args = ["message", "send", "--channel", channel, "--target", to, "--message", text];
      await execFileAsync("openclaw", args, { timeout: 15_000 });
      console.log(`[sentinel] Alert sent via ${channel} to ${to}`);
    } catch (err: any) {
      console.error("[sentinel] Alert delivery failed:", err?.message ?? err, text.slice(0, 200));
    }
  };

  // ── Agent tool: sentinel_status ──
  api.registerTool({
    name: "sentinel_status",
    description:
      "Get current security monitoring status — daemon state, active alerts, event counts, and system health.",
    parameters: Type.Object({}),
    async execute() {
      // Refresh daemon status
      state.daemonRunning = await checkDaemon(sentinelDir);

      const recentEvents = state.eventLog.slice(-20);
      const criticalCount = state.eventLog.filter(
        (e) => e.severity === "critical",
      ).length;
      const highCount = state.eventLog.filter(
        (e) => e.severity === "high",
      ).length;

      const status = {
        mode: "event-driven",
        daemonRunning: state.daemonRunning,
        watching: state.watching,
        initialized: state.initialized,
        knownHosts: Array.from(state.knownHosts),
        knownPorts: Array.from(state.knownPorts).sort((a, b) => a - b),
        totalEvents: state.eventLog.length,
        criticalEvents: criticalCount,
        highEvents: highCount,
        sentinelDir,
        recentEvents: recentEvents.map((e) => ({
          time: new Date(e.timestamp).toISOString(),
          severity: e.severity,
          category: e.category,
          title: e.title,
        })),
      };

      return {
        content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
      };
    },
  });

  // ── Agent tool: sentinel_query ──
  // Tables that can make outbound requests or exfiltrate data
  const BLOCKED_TABLES = [
    "carves",        // file carving (exfiltration)
    "curl",          // HTTP requests
    "curl_certificate", // TLS connections
  ];

  api.registerTool({
    name: "sentinel_query",
    description:
      "Run a custom osquery SQL query for ad-hoc security investigation. " +
      "Blocked tables: carves, curl, curl_certificate (security risk).",
    parameters: Type.Object({
      sql: Type.String({ description: "osquery SQL query" }),
    }),
    async execute(_id: string, params: { sql: string }) {
      // Safety: block dangerous tables
      const sqlLower = params.sql.toLowerCase();
      const blocked = BLOCKED_TABLES.find((t) => sqlLower.includes(t));
      if (blocked) {
        return {
          content: [
            {
              type: "text",
              text: `Blocked: table "${blocked}" is not allowed for security reasons.`,
            },
          ],
        };
      }

      // Audit log
      console.log(`[sentinel] Query: ${params.sql}`);

      const osqueryiPath = findOsquery(pluginConfig.osqueryPath);
      if (!osqueryiPath) {
        return {
          content: [
            {
              type: "text",
              text: "osquery not installed. Run: brew install osquery",
            },
          ],
        };
      }
      try {
        const results = await query(osqueryiPath, params.sql);
        return {
          content: [
            { type: "text", text: JSON.stringify(results, null, 2) },
          ],
        };
      } catch (err) {
        return {
          content: [{ type: "text", text: `Query error: ${String(err)}` }],
        };
      }
    },
  });

  // ── Agent tool: sentinel_events ──
  api.registerTool({
    name: "sentinel_events",
    description:
      "Get recent security events. Filter by severity or category.",
    parameters: Type.Object({
      severity: Type.Optional(Type.String()),
      category: Type.Optional(Type.String()),
      limit: Type.Optional(Type.Number()),
    }),
    async execute(
      _id: string,
      params: { severity?: string; category?: string; limit?: number },
    ) {
      let events = [...state.eventLog];
      if (params.severity)
        events = events.filter((e) => e.severity === params.severity);
      if (params.category)
        events = events.filter((e) => e.category === params.category);
      events = events.slice(-(params.limit ?? 20));

      return {
        content: [
          {
            type: "text",
            text:
              events.length === 0
                ? "No security events found."
                : events.map((e) => formatAlert(e)).join("\n\n---\n\n"),
          },
        ],
      };
    },
  });

  // ── Cleanup on process exit ──
  const cleanup = () => {
    if (watcher) {
      watcher.stop();
      watcher = null;
      state.watching = false;
    }
    if (logStreamWatcher) {
      logStreamWatcher.stop();
      logStreamWatcher = null;
    }
  };
  process.on("exit", cleanup);
  process.on("SIGTERM", cleanup);
  process.on("SIGINT", cleanup);

  // ── Start monitoring immediately (fire-and-forget) ──
  if (state.watching) {
    console.log("[sentinel] Already initialized, skipping double-init");
    return;
  }

  (async () => {
    try {
      const osqueryiPath = findOsquery(pluginConfig.osqueryPath);

      if (!osqueryiPath) {
        console.warn(
          "[sentinel] osquery not found. Install via: brew install osquery",
        );
        console.warn(
          "[sentinel] Tools registered but monitoring inactive.",
        );
        return;
      }

      console.log(`[sentinel] Starting in event-driven mode...`);

      // 0. Initialize event store and load persisted events
      eventStore = new EventStore(sentinelDir);
      const persisted = await eventStore.loadRecent(MAX_EVENT_LOG);
      if (persisted.length > 0) {
        state.eventLog = persisted;
        console.log(`[sentinel] Restored ${persisted.length} events from disk`);
      }

      // 1. Initialize baseline
      await initializeBaseline(osqueryiPath);

      // 2. Check if osqueryd is running
      state.daemonRunning = await checkDaemon(sentinelDir);
      if (!state.daemonRunning) {
        console.warn(
          "[sentinel] osqueryd not running. Start it with: sudo osqueryd --config_path=" +
            join(sentinelDir, "config", "osquery.conf") +
            " --database_path=" +
            join(sentinelDir, "db") +
            " --logger_path=" +
            join(sentinelDir, "logs", "osquery") +
            " --pidfile=" +
            join(sentinelDir, "osqueryd.pid") +
            " --logger_plugin=filesystem --disable_events=false --events_expiry=3600 --daemonize --force",
        );
      } else {
        console.log("[sentinel] osqueryd is running ✓");
      }

      // 3. Start watching the results log (even if daemon not running — it may start later)
      const logDir = join(sentinelDir, "logs", "osquery");
      watcher = new ResultLogWatcher(logDir);

      watcher.on("result", (result: OsqueryResultBatch) => {
        handleResult(result, pluginConfig, sendAlert);
      });

      watcher.on("error", (err: Error) => {
        console.error("[sentinel] watcher error:", err.message);
      });

      watcher.on("started", () => {
        state.watching = true;
        console.log("[sentinel] Event-driven monitoring active ⚡");
      });

      await watcher.start();

      // Start real-time log stream watcher for SSH events
      logStreamWatcher = new LogStreamWatcher(
        (evt) => {
          logEvent(evt);
          if (
            meetsThreshold(evt.severity, pluginConfig.alertSeverity) &&
            shouldAlert(evt, alertRateState)
          ) {
            sendAlert(formatAlert(evt)).catch((err) => {
              console.error("[sentinel] alert failed:", err);
            });
          }
          console.log(
            `[sentinel] [real-time] ${evt.severity}/${evt.category}: ${evt.title}`,
          );
        },
        state.knownHosts,
      );
      logStreamWatcher.start();
    } catch (err) {
      console.error("[sentinel] Failed to start:", err);
    }
  })();
}
