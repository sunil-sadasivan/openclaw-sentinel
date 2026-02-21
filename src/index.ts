/**
 * OpenClaw Sentinel Plugin
 *
 * Real-time endpoint security monitoring using osquery.
 * Monitors process execution, SSH connections, privilege escalation,
 * file integrity, and network activity. Alerts via OpenClaw messaging.
 */

import { Type } from "@sinclair/typebox";
import type { SentinelConfig, SecurityEvent } from "./config.js";
import { DEFAULT_CONFIG } from "./config.js";
import { findOsquery, query } from "./osquery.js";
import {
  analyzeProcessEvents,
  analyzeLoginEvents,
  analyzeFailedAuth,
  analyzeListeningPorts,
  analyzeFileEvents,
  formatAlert,
} from "./analyzer.js";

// State tracking across polls
const state = {
  knownHosts: new Set<string>(),
  knownPorts: new Set<number>(),
  lastPollTime: 0,
  eventLog: [] as SecurityEvent[],
  initialized: false,
};

const MAX_EVENT_LOG = 1000;

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
  osqueryPath: string,
  config: SentinelConfig,
): Promise<void> {
  if (state.initialized) return;

  try {
    // Learn current logged-in hosts
    const logins = await query(
      osqueryPath,
      "SELECT DISTINCT host FROM logged_in_users WHERE host != '' AND host != 'localhost';",
    );
    for (const row of logins) {
      if (row.host) state.knownHosts.add(row.host);
    }
    // Also trust Tailscale IPs by default
    // (100.x.x.x range is always Tailscale)

    // Learn current listening ports
    const ports = await query(
      osqueryPath,
      "SELECT DISTINCT port FROM listening_ports WHERE port > 0;",
    );
    for (const row of ports) {
      const port = parseInt(row.port ?? "0", 10);
      if (port > 0) state.knownPorts.add(port);
    }

    state.initialized = true;
  } catch (err) {
    // Non-fatal — we'll try again next poll
    console.error("[sentinel] baseline init failed:", err);
  }
}

/**
 * Run a single monitoring cycle.
 */
async function poll(
  osqueryPath: string,
  config: SentinelConfig,
  sendAlert: (text: string) => Promise<void>,
): Promise<SecurityEvent[]> {
  const allEvents: SecurityEvent[] = [];

  try {
    // Process execution monitoring
    if (config.enableProcessMonitor ?? DEFAULT_CONFIG.enableProcessMonitor) {
      const since = state.lastPollTime || Math.floor(Date.now() / 1000) - 60;
      const rows = await query(
        osqueryPath,
        `SELECT pid, path, cmdline, uid, euid, username, signing_id, platform_binary, event_type, time FROM es_process_events WHERE time > ${since} AND event_type = 'exec';`,
      );
      allEvents.push(...analyzeProcessEvents(rows, config));
    }
  } catch {
    // es_process_events requires Endpoint Security — may not be available
  }

  try {
    // Login monitoring
    const logins = await query(
      osqueryPath,
      "SELECT type, user, host, time, pid FROM logged_in_users;",
    );
    allEvents.push(...analyzeLoginEvents(logins, state.knownHosts));
  } catch {
    /* ignore */
  }

  try {
    // Failed auth / SSH brute force detection
    const failedAuth = await query(
      osqueryPath,
      "SELECT time, message FROM asl WHERE facility = 'auth' AND level <= 3 AND (message LIKE '%authentication error%' OR message LIKE '%Failed password%' OR message LIKE '%Invalid user%') ORDER BY time DESC LIMIT 50;",
    );
    allEvents.push(...analyzeFailedAuth(failedAuth));
  } catch {
    /* ignore */
  }

  try {
    // Network monitoring
    if (config.enableNetworkMonitor ?? DEFAULT_CONFIG.enableNetworkMonitor) {
      const ports = await query(
        osqueryPath,
        "SELECT lp.port, lp.address, lp.protocol, p.name, p.path FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port > 0;",
      );
      allEvents.push(...analyzeListeningPorts(ports, state.knownPorts));
    }
  } catch {
    /* ignore */
  }

  try {
    // File integrity monitoring
    if (config.enableFileIntegrity ?? DEFAULT_CONFIG.enableFileIntegrity) {
      const since = state.lastPollTime || Math.floor(Date.now() / 1000) - 60;
      const files = await query(
        osqueryPath,
        `SELECT pid, path, filename, dest_filename, event_type, time FROM es_process_file_events WHERE time > ${since};`,
      );
      allEvents.push(...analyzeFileEvents(files));
    }
  } catch {
    /* ignore */
  }

  state.lastPollTime = Math.floor(Date.now() / 1000);

  // Log and alert
  for (const evt of allEvents) {
    logEvent(evt);

    // Alert for high+ severity
    if (evt.severity === "critical" || evt.severity === "high") {
      try {
        await sendAlert(formatAlert(evt));
      } catch (alertErr) {
        console.error("[sentinel] alert send failed:", alertErr);
      }
    }
  }

  return allEvents;
}

/**
 * OpenClaw plugin entry point.
 */
export default function sentinel(api: any): void {
  const pluginConfig: SentinelConfig = api.getConfig?.() ?? {};
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let osqueryPath: string | null = null;

  // ── Agent tool: sentinel_status ──
  api.registerTool({
    name: "sentinel_status",
    description:
      "Get the current security monitoring status — active alerts, event counts, and system health.",
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
        monitoring: !!pollTimer,
        osqueryAvailable: !!osqueryPath,
        osqueryPath,
        initialized: state.initialized,
        knownHosts: Array.from(state.knownHosts),
        knownPorts: Array.from(state.knownPorts).sort((a, b) => a - b),
        totalEvents: state.eventLog.length,
        criticalEvents: criticalCount,
        highEvents: highCount,
        recentEvents: recentEvents.map((e) => ({
          time: new Date(e.timestamp).toISOString(),
          severity: e.severity,
          category: e.category,
          title: e.title,
        })),
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(status, null, 2),
          },
        ],
      };
    },
  });

  // ── Agent tool: sentinel_query ──
  api.registerTool({
    name: "sentinel_query",
    description:
      "Run a custom osquery SQL query against the endpoint. Use for ad-hoc security investigation.",
    parameters: Type.Object({
      sql: Type.String({
        description: "osquery SQL query to execute",
      }),
    }),
    async execute(_id: string, params: { sql: string }) {
      if (!osqueryPath) {
        return {
          content: [
            {
              type: "text",
              text: "osquery is not installed. Install via: brew install osquery",
            },
          ],
        };
      }

      try {
        const results = await query(osqueryPath, params.sql);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(results, null, 2),
            },
          ],
        };
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `Query error: ${String(err)}`,
            },
          ],
        };
      }
    },
  });

  // ── Agent tool: sentinel_events ──
  api.registerTool({
    name: "sentinel_events",
    description:
      "Get recent security events detected by Sentinel. Filter by severity or category.",
    parameters: Type.Object({
      severity: Type.Optional(
        Type.String({
          description:
            "Filter by severity: critical, high, medium, low, info",
        }),
      ),
      category: Type.Optional(
        Type.String({
          description:
            "Filter by category: process, network, file, auth, privilege",
        }),
      ),
      limit: Type.Optional(
        Type.Number({ description: "Max events to return (default 20)" }),
      ),
    }),
    async execute(
      _id: string,
      params: { severity?: string; category?: string; limit?: number },
    ) {
      let events = [...state.eventLog];

      if (params.severity) {
        events = events.filter((e) => e.severity === params.severity);
      }
      if (params.category) {
        events = events.filter((e) => e.category === params.category);
      }

      const limit = params.limit ?? 20;
      events = events.slice(-limit);

      return {
        content: [
          {
            type: "text",
            text:
              events.length === 0
                ? "No security events found matching filters."
                : events.map((e) => formatAlert(e)).join("\n\n---\n\n"),
          },
        ],
      };
    },
  });

  // ── Lifecycle: start monitoring ──
  api.onReady?.(() => {
    osqueryPath = findOsquery(pluginConfig.osqueryPath);

    if (!osqueryPath) {
      console.warn(
        "[sentinel] osquery not found. Install via: brew install osquery",
      );
      return;
    }

    console.log(`[sentinel] osquery found at ${osqueryPath}`);

    const sendAlert = async (text: string): Promise<void> => {
      // Use OpenClaw's messaging to alert on the configured channel
      try {
        await api.sendMessage?.({
          channel: pluginConfig.alertChannel,
          to: pluginConfig.alertTo,
          message: text,
        });
      } catch {
        console.error("[sentinel] Failed to send alert:", text);
      }
    };

    // Initialize baseline
    initializeBaseline(osqueryPath, pluginConfig).then(() => {
      console.log(
        `[sentinel] Baseline initialized: ${state.knownHosts.size} hosts, ${state.knownPorts.size} ports`,
      );
    });

    // Start polling
    const intervalMs =
      pluginConfig.pollIntervalMs ?? DEFAULT_CONFIG.pollIntervalMs;

    pollTimer = setInterval(async () => {
      if (!osqueryPath) return;
      try {
        const events = await poll(osqueryPath, pluginConfig, sendAlert);
        if (events.length > 0) {
          console.log(
            `[sentinel] ${events.length} security events detected`,
          );
        }
      } catch (err) {
        console.error("[sentinel] poll error:", err);
      }
    }, intervalMs);

    console.log(
      `[sentinel] Monitoring started (poll every ${intervalMs / 1000}s)`,
    );
  });

  // ── Lifecycle: cleanup ──
  api.onShutdown?.(() => {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    console.log("[sentinel] Monitoring stopped");
  });
}
