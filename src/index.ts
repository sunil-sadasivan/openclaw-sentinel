/**
 * OpenClaw Sentinel Plugin
 *
 * Real-time endpoint security monitoring using osquery in daemon mode.
 * Uses event-driven log tailing for sub-second alerting.
 *
 * Architecture:
 *   Watchers (log stream + osquery) → events.jsonl → AlertTailer → assess → deliver
 *
 *   Detection is decoupled from alerting — watchers only parse and persist,
 *   while AlertTailer handles rate limiting, dedup, suppression, Claw assessment,
 *   and delivery by tailing events.jsonl.
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
import { AlertTailer } from "./alert-tailer.js";
import { EventStore } from "./persistence.js";
import { ResultLogWatcher } from "./watcher.js";
import type { OsqueryResultBatch } from "./watcher.js";
import { LogStreamWatcher } from "./log-stream.js";
import { SuppressionStore } from "./suppressions.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// Use globalThis so state survives module re-evaluation on SIGUSR1 restarts.
const G = globalThis as any;
const SENTINEL_NS = "__sentinel__";
if (!G[SENTINEL_NS]) G[SENTINEL_NS] = { cleanup: null, initialized: false };
const _g = G[SENTINEL_NS] as { cleanup: (() => void) | null; initialized: boolean };


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
let suppressionStore: SuppressionStore | null = null;

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
 * Use the LLM (via openclaw CLI) to generate a one-line human-readable
 * assessment of a security event. Returns the assessment string, or null
 * on failure.
 */
async function clawAssessEvent(evt: SecurityEvent): Promise<string | null> {
  const details = typeof evt.details === "string" ? evt.details : JSON.stringify(evt.details);
  const prompt = `You are a security-savvy AI agent named Claw monitoring your human's machine. A security event was detected:

Title: ${evt.title}
Severity: ${evt.severity}
Category: ${evt.category}
Description: ${evt.description}
Details: ${details}

Context: This machine runs OpenClaw (an AI assistant platform) which frequently spawns commands via heartbeats, cron jobs, and agent tasks — python one-liners, curl/wget API calls, bq queries, git, npm/node, etc. The user is the machine owner.

Reply with ONLY a single short sentence (under 30 words) giving your honest take on whether this is a real problem or likely benign. Be direct, opinionated, and useful — like a senior engineer glancing at an alert. No preamble.`;

  try {
    const { stdout } = await execFileAsync("openclaw", ["agent", "--agent", "main", "--message", prompt, "--json"], {
      timeout: 30_000,
    });
    // Parse JSON response — openclaw agent --json returns { result: { payloads: [{ text: "..." }] } }
    try {
      // Skip any non-JSON prefix lines (e.g. "Config warnings:...")
      const jsonStart = stdout.indexOf("{");
      const jsonStr = jsonStart >= 0 ? stdout.slice(jsonStart) : stdout;
      const parsed = JSON.parse(jsonStr.trim());
      const text = parsed?.result?.payloads?.[0]?.text
        ?? parsed?.message
        ?? parsed?.text
        ?? null;
      return typeof text === "string" ? text.trim().slice(0, 200) : null;
    } catch {
      // Fallback: treat raw stdout as the response
      const clean = stdout.replace(/^Config warnings:.*\n?/gm, "").trim();
      return clean.slice(0, 200) || null;
    }
  } catch (err: any) {
    console.warn(`[sentinel] Claw assessment failed: ${err?.message ?? err}`);
    return null;
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
    // AlertTailer handles alerting by tailing events.jsonl
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
  console.log(`[sentinel] Config v2026.2.26-1: alertSeverity=${pluginConfig.alertSeverity}, alertChannel=${pluginConfig.alertChannel}, clawAssess=${pluginConfig.clawAssess}, trustedPatterns=${(pluginConfig.trustedCommandPatterns ?? []).length}`);
  let watcher: ResultLogWatcher | null = null;
  let logStreamWatcher: LogStreamWatcher | null = null;
  let alertTailer: AlertTailer | null = null;
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

  // osqueryi meta-commands that could execute shell commands or exfiltrate data
  const BLOCKED_PATTERNS = [
    /^\s*\./,                    // Any dot-command (.shell, .output, .read, .mode, etc.)
    /;\s*\./,                    // Dot-command after semicolon
    /ATTACH\s/i,                 // ATTACH database
    /LOAD\s/i,                   // Load extension
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
      // Safety: block meta-commands that could execute shell commands or exfiltrate data
      const blockedPattern = BLOCKED_PATTERNS.find((p) => p.test(params.sql));
      if (blockedPattern) {
        return {
          content: [
            {
              type: "text",
              text: `Blocked: osquery meta-commands and dangerous statements are not allowed for security reasons.`,
            },
          ],
        };
      }

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

  // ── Agent tool: sentinel_suppress ──
  api.registerTool({
    name: "sentinel_suppress",
    description:
      "Manage alert suppression rules. Actions: 'add' (create a suppression), 'list' (show all), 'remove' (delete by id), 'cleanup' (remove expired). " +
      "Scopes: 'title' (suppress all alerts with this title), 'category' (suppress entire category like ssh_login/privilege/auth), " +
      "'field' (suppress when a specific detail field matches, e.g. field=user fieldValue=alice), 'exact' (suppress only this exact title+description). " +
      "Always explain to the user what will be suppressed before adding a rule.",
    parameters: Type.Object({
      action: Type.Union([
        Type.Literal("add"),
        Type.Literal("list"),
        Type.Literal("remove"),
        Type.Literal("cleanup"),
      ]),
      scope: Type.Optional(Type.Union([
        Type.Literal("exact"),
        Type.Literal("title"),
        Type.Literal("category"),
        Type.Literal("field"),
      ])),
      title: Type.Optional(Type.String({ description: "Event title to match (for scope=title or scope=exact)" })),
      category: Type.Optional(Type.String({ description: "Event category to match (for scope=category): process, network, file, auth, privilege, ssh_login" })),
      description: Type.Optional(Type.String({ description: "Event description to match (for scope=exact)" })),
      field: Type.Optional(Type.String({ description: "Detail field name to match (for scope=field)" })),
      fieldValue: Type.Optional(Type.String({ description: "Detail field value to match (for scope=field)" })),
      reason: Type.Optional(Type.String({ description: "Human-readable reason for this suppression" })),
      expiresIn: Type.Optional(Type.String({ description: "Expiry duration: '1h', '1d', '7d', '30d', or 'never'" })),
      id: Type.Optional(Type.String({ description: "Suppression rule ID (for remove action)" })),
    }),
    async execute(
      _id: string,
      params: {
        action: "add" | "list" | "remove" | "cleanup";
        scope?: "exact" | "title" | "category" | "field";
        title?: string;
        category?: string;
        description?: string;
        field?: string;
        fieldValue?: string;
        reason?: string;
        expiresIn?: string;
        id?: string;
      },
    ) {
      if (!suppressionStore) {
        return { content: [{ type: "text", text: "Suppression store not initialized." }] };
      }

      switch (params.action) {
        case "list": {
          const rules = await suppressionStore.list();
          if (rules.length === 0) {
            return { content: [{ type: "text", text: "No suppression rules configured." }] };
          }
          const lines = rules.map((r) => {
            const expired = (r as any)._expired ? " [EXPIRED]" : "";
            const count = r.suppressCount > 0 ? ` (suppressed ${r.suppressCount}x, last: ${new Date(r.lastSuppressedAt!).toLocaleString()})` : " (never triggered)";
            return `- **${r.id}**${expired}: ${SuppressionStore.describe(r)}${count}\n  Reason: ${r.reason}\n  Created: ${new Date(r.createdAt).toLocaleString()}${r.expiresAt ? `\n  Expires: ${new Date(r.expiresAt).toLocaleString()}` : ""}`;
          });
          return { content: [{ type: "text", text: `**Suppression Rules (${rules.length}):**\n\n${lines.join("\n\n")}` }] };
        }

        case "add": {
          if (!params.scope) {
            return { content: [{ type: "text", text: "Missing required parameter: scope (exact, title, category, or field)" }] };
          }
          if (!params.reason) {
            return { content: [{ type: "text", text: "Missing required parameter: reason (explain why this is being suppressed)" }] };
          }

          // Validate scope-specific params
          if (params.scope === "title" && !params.title) {
            return { content: [{ type: "text", text: "scope=title requires the 'title' parameter" }] };
          }
          if (params.scope === "category" && !params.category) {
            return { content: [{ type: "text", text: "scope=category requires the 'category' parameter" }] };
          }
          if (params.scope === "field" && (!params.field || !params.fieldValue)) {
            return { content: [{ type: "text", text: "scope=field requires both 'field' and 'fieldValue' parameters" }] };
          }
          if (params.scope === "exact" && !params.title) {
            return { content: [{ type: "text", text: "scope=exact requires the 'title' parameter" }] };
          }

          // Parse expiry
          let expiresAt: number | null = null;
          if (params.expiresIn && params.expiresIn !== "never") {
            const match = params.expiresIn.match(/^(\d+)(h|d)$/);
            if (match) {
              const amount = parseInt(match[1], 10);
              const unit = match[2] === "h" ? 3600_000 : 86400_000;
              expiresAt = Date.now() + amount * unit;
            }
          }

          const rule = await suppressionStore.add({
            scope: params.scope,
            title: params.title,
            category: params.category,
            description: params.description,
            field: params.field,
            fieldValue: params.fieldValue,
            reason: params.reason,
            expiresAt,
          });

          console.log(`[sentinel] Suppression added: ${rule.id} — ${SuppressionStore.describe(rule)}`);

          return {
            content: [{
              type: "text",
              text: `✅ Suppression rule added:\n\n- **ID:** ${rule.id}\n- **Matches:** ${SuppressionStore.describe(rule)}\n- **Reason:** ${rule.reason}\n- **Expires:** ${rule.expiresAt ? new Date(rule.expiresAt).toLocaleString() : "Never"}`,
            }],
          };
        }

        case "remove": {
          if (!params.id) {
            return { content: [{ type: "text", text: "Missing required parameter: id (use 'list' to see rule IDs)" }] };
          }
          const removed = await suppressionStore.remove(params.id);
          if (removed) {
            console.log(`[sentinel] Suppression removed: ${params.id}`);
            return { content: [{ type: "text", text: `✅ Suppression rule ${params.id} removed.` }] };
          }
          return { content: [{ type: "text", text: `❌ No rule found with ID: ${params.id}` }] };
        }

        case "cleanup": {
          const count = await suppressionStore.cleanup();
          return { content: [{ type: "text", text: count > 0 ? `Cleaned up ${count} expired rules.` : "No expired rules to clean up." }] };
        }

        default:
          return { content: [{ type: "text", text: `Unknown action: ${params.action}` }] };
      }
    },
  });

  // ── Clean up previous instance if re-initializing (SIGUSR1 restart) ──
  if (typeof _g.cleanup === "function") {
    console.log("[sentinel] Cleaning up previous instance before re-init");
    _g.cleanup();
    _g.cleanup = null;
    _g.initialized = false;
  }

  // ── Cleanup on process exit ──
  const cleanup = () => {
    if (alertTailer) {
      alertTailer.stop();
      alertTailer = null;
    }
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
  _g.cleanup = cleanup;
  process.on("exit", cleanup);
  process.on("SIGTERM", cleanup);
  process.on("SIGINT", cleanup);

  // ── Start monitoring immediately (fire-and-forget) ──
  if (_g.initialized) {
    console.log("[sentinel] Already initialized, skipping double-init");
    return;
  }
  _g.initialized = true;

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
      suppressionStore = new SuppressionStore(sentinelDir);
      await suppressionStore.load();
      const suppressions = await suppressionStore.list();
      if (suppressions.length > 0) {
        console.log(`[sentinel] Loaded ${suppressions.length} suppression rules`);
      }
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
          // AlertTailer handles alerting by tailing events.jsonl
          console.log(
            `[sentinel] [real-time] ${evt.severity}/${evt.category}: ${evt.title}`,
          );
        },
        state.knownHosts,
      );
      logStreamWatcher.start();

      // Start AlertTailer — single pipeline for all alerting
      const eventsPath = join(sentinelDir, "events.jsonl");
      alertTailer = new AlertTailer({
        eventsPath,
        config: pluginConfig,
        suppressionStore,
        sendAlert,
        clawAssessEvent,
      });
      await alertTailer.start();
    } catch (err) {
      console.error("[sentinel] Failed to start:", err);
    }
  })();
}
