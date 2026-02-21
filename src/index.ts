/**
 * OpenClaw Sentinel Plugin
 *
 * Real-time endpoint security monitoring using osquery in daemon mode.
 * Uses event-driven log tailing for sub-second alerting.
 *
 * Architecture:
 *   osqueryd (daemon) → writes results to JSON log
 *   Sentinel watcher  → tails log file via fs.watch + poll fallback
 *   Analyzer          → evaluates results against detection rules
 *   OpenClaw messaging → alerts on configured channel
 */

import { execFile, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { Type } from "@sinclair/typebox";
import type { SentinelConfig, SecurityEvent } from "./config.js";
import { DEFAULT_CONFIG } from "./config.js";
import { findOsquery, query, generateOsqueryConfig } from "./osquery.js";
import { ResultLogWatcher } from "./watcher.js";
import type { OsqueryResultBatch } from "./watcher.js";
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
  daemonPid: null as number | null,
  watching: false,
};

const MAX_EVENT_LOG = 1000;
const SENTINEL_DIR_DEFAULT = join(homedir(), ".openclaw", "sentinel");

function logEvent(evt: SecurityEvent): void {
  state.eventLog.push(evt);
  if (state.eventLog.length > MAX_EVENT_LOG) {
    state.eventLog = state.eventLog.slice(-MAX_EVENT_LOG);
  }
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
  } catch (err) {
    console.error("[sentinel] baseline init failed:", err);
  }
}

/**
 * Start osqueryd in daemon mode with our config.
 */
async function startDaemon(
  config: SentinelConfig,
  sentinelDir: string,
): Promise<number | null> {
  const configDir = join(sentinelDir, "config");
  const logDir = join(sentinelDir, "logs", "osquery");
  const dbDir = join(sentinelDir, "db");
  const pidFile = join(sentinelDir, "osqueryd.pid");

  await mkdir(configDir, { recursive: true });
  await mkdir(logDir, { recursive: true });
  await mkdir(dbDir, { recursive: true });

  // Write osquery config
  const osqueryConfig = generateOsqueryConfig(config);
  // Override log path to our sentinel dir
  (osqueryConfig as any).options.logger_path = logDir;
  const configFile = join(configDir, "osquery.conf");
  await writeFile(configFile, JSON.stringify(osqueryConfig, null, 2));

  // Find osqueryd (daemon binary)
  const osquerydPaths = [
    config.osqueryPath?.replace("osqueryi", "osqueryd"),
    "/opt/homebrew/bin/osqueryd",
    "/usr/local/bin/osqueryd",
    "/usr/bin/osqueryd",
  ].filter(Boolean) as string[];

  let osquerydPath: string | null = null;
  for (const p of osquerydPaths) {
    if (existsSync(p)) {
      osquerydPath = p;
      break;
    }
  }

  if (!osquerydPath) {
    console.error("[sentinel] osqueryd not found");
    return null;
  }

  // Check if already running
  if (existsSync(pidFile)) {
    try {
      const pid = parseInt(await readFile(pidFile, "utf-8"), 10);
      process.kill(pid, 0); // Check if process exists
      console.log(`[sentinel] osqueryd already running (pid ${pid})`);
      return pid;
    } catch {
      // Process not running, clean up pid file
    }
  }

  // Start osqueryd
  const child = spawn(
    osquerydPath,
    [
      `--config_path=${configFile}`,
      `--database_path=${dbDir}`,
      `--logger_path=${logDir}`,
      `--pidfile=${pidFile}`,
      "--logger_plugin=filesystem",
      "--disable_events=false",
      "--disable_endpointsecurity=false",
      "--events_expiry=3600",
      "--events_max=100000",
      "--force",
      "--daemonize=false", // Stay in foreground so we manage lifecycle
    ],
    {
      stdio: "ignore",
      detached: true,
    },
  );

  child.unref();

  if (child.pid) {
    console.log(`[sentinel] osqueryd started (pid ${child.pid})`);
    // Write pid file ourselves since daemonize=false
    await writeFile(pidFile, String(child.pid));
    return child.pid;
  }

  return null;
}

/**
 * Stop the osqueryd daemon.
 */
async function stopDaemon(sentinelDir: string): Promise<void> {
  const pidFile = join(sentinelDir, "osqueryd.pid");
  if (!existsSync(pidFile)) return;

  try {
    const pid = parseInt(await readFile(pidFile, "utf-8"), 10);
    process.kill(pid, "SIGTERM");
    console.log(`[sentinel] osqueryd stopped (pid ${pid})`);
  } catch {
    // Process already gone
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
    // File events from es_process_file_events
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

    if (evt.severity === "critical" || evt.severity === "high") {
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
  const pluginConfig: SentinelConfig = api.getConfig?.() ?? {};
  let watcher: ResultLogWatcher | null = null;
  const sentinelDir =
    pluginConfig.logPath ?? SENTINEL_DIR_DEFAULT;

  // ── Agent tool: sentinel_status ──
  api.registerTool({
    name: "sentinel_status",
    description:
      "Get current security monitoring status — daemon state, active alerts, event counts, and system health.",
    parameters: Type.Object({}),
    async execute() {
      const recentEvents = state.eventLog.slice(-20);
      const criticalCount = state.eventLog.filter(
        (e) => e.severity === "critical",
      ).length;
      const highCount = state.eventLog.filter(
        (e) => e.severity === "high",
      ).length;

      const status = {
        mode: "event-driven",
        daemonPid: state.daemonPid,
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
  api.registerTool({
    name: "sentinel_query",
    description:
      "Run a custom osquery SQL query for ad-hoc security investigation.",
    parameters: Type.Object({
      sql: Type.String({ description: "osquery SQL query" }),
    }),
    async execute(_id: string, params: { sql: string }) {
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

  // ── Lifecycle: start ──
  api.onReady?.(async () => {
    const osqueryiPath = findOsquery(pluginConfig.osqueryPath);

    if (!osqueryiPath) {
      console.warn(
        "[sentinel] osquery not found. Install via: brew install osquery",
      );
      return;
    }

    console.log(`[sentinel] Starting in event-driven mode...`);

    const sendAlert = async (text: string): Promise<void> => {
      try {
        await api.sendMessage?.({
          channel: pluginConfig.alertChannel,
          to: pluginConfig.alertTo,
          message: text,
        });
      } catch {
        console.error("[sentinel] Alert delivery failed:", text);
      }
    };

    // 1. Initialize baseline
    await initializeBaseline(osqueryiPath);
    console.log(
      `[sentinel] Baseline: ${state.knownHosts.size} hosts, ${state.knownPorts.size} ports`,
    );

    // 2. Start osqueryd daemon
    const pid = await startDaemon(pluginConfig, sentinelDir);
    state.daemonPid = pid;

    // 3. Start watching the results log
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
  });

  // ── Lifecycle: shutdown ──
  api.onShutdown?.(async () => {
    if (watcher) {
      watcher.stop();
      watcher = null;
      state.watching = false;
    }
    await stopDaemon(sentinelDir);
    console.log("[sentinel] Shutdown complete");
  });
}
