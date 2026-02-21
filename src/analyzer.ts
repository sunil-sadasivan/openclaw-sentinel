/**
 * Security event analyzer — evaluates osquery results and generates security events.
 */

import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import type { SecurityEvent, Severity, SentinelConfig } from "./config.js";
import { DEFAULT_CONFIG } from "./config.js";

const HOST = hostname();

function event(
  severity: Severity,
  category: SecurityEvent["category"],
  title: string,
  description: string,
  details: Record<string, unknown> = {},
): SecurityEvent {
  return {
    id: randomUUID(),
    timestamp: Date.now(),
    severity,
    category,
    title,
    description,
    details,
    hostname: HOST,
  };
}

/**
 * Analyze process execution events from es_process_events.
 */
export function analyzeProcessEvents(
  rows: Record<string, string>[],
  config: SentinelConfig,
): SecurityEvent[] {
  const events: SecurityEvent[] = [];
  const trustedPaths = config.trustedPaths ?? DEFAULT_CONFIG.trustedPaths;
  const trustedSigningIds =
    config.trustedSigningIds ?? DEFAULT_CONFIG.trustedSigningIds;

  for (const row of rows) {
    const path = row.path ?? "";
    const cmdline = row.cmdline ?? "";
    const uid = row.uid ?? "";
    const euid = row.euid ?? "";
    const signingId = row.signing_id ?? "";
    const platformBinary = row.platform_binary ?? "0";
    const username = row.username ?? "";

    // Skip trusted paths
    if (trustedPaths.some((tp) => path.startsWith(tp))) continue;

    // Skip trusted signing IDs
    if (trustedSigningIds.some((ts) => signingId.startsWith(ts))) continue;

    // CRITICAL: Unsigned binary execution
    if (platformBinary === "0" && !signingId) {
      events.push(
        event(
          "high",
          "process",
          "Unsigned binary executed",
          `Unsigned process executed: ${path}\nUser: ${username} (uid=${uid})\nCommand: ${cmdline}`,
          { path, cmdline, uid, euid, username },
        ),
      );
      continue;
    }

    // HIGH: Process running as root that shouldn't be
    if (euid === "0" && uid !== "0") {
      events.push(
        event(
          "high",
          "privilege",
          "Privilege escalation detected",
          `Process escalated to root: ${path}\nUser: ${username} (uid=${uid}, euid=0)\nCommand: ${cmdline}`,
          { path, cmdline, uid, euid, username, signingId },
        ),
      );
      continue;
    }

    // MEDIUM: Suspicious command patterns
    const suspiciousPatterns = [
      /curl.*\|.*sh/i,
      /wget.*\|.*sh/i,
      /python.*-c.*import/i,
      /base64.*decode/i,
      /nc\s+-l/i,
      /ncat.*-l/i,
      /reverse.*shell/i,
      /\/dev\/tcp\//i,
      /mkfifo/i,
    ];

    if (suspiciousPatterns.some((p) => p.test(cmdline))) {
      events.push(
        event(
          "high",
          "process",
          "Suspicious command detected",
          `Potentially malicious command: ${cmdline}\nProcess: ${path}\nUser: ${username}`,
          { path, cmdline, uid, username },
        ),
      );
    }
  }

  return events;
}

/**
 * Analyze logged-in users for SSH connections.
 */
export function analyzeLoginEvents(
  rows: Record<string, string>[],
  knownHosts: Set<string>,
): SecurityEvent[] {
  const events: SecurityEvent[] = [];

  for (const row of rows) {
    const user = row.user ?? "";
    const host = row.host ?? "";
    const type = row.type ?? "";

    // Skip local logins
    if (!host || host === "localhost" || host === "::1" || host === "127.0.0.1")
      continue;

    // Skip known Tailscale IPs (100.x.x.x)
    if (host.startsWith("100.")) continue;

    // New remote login from unknown host
    if (!knownHosts.has(host)) {
      events.push(
        event(
          "high",
          "auth",
          "SSH login from unknown host",
          `User "${user}" logged in from unknown host: ${host}\nLogin type: ${type}`,
          { user, host, type },
        ),
      );
    }
  }

  return events;
}

/**
 * Analyze listening ports for new services.
 */
export function analyzeListeningPorts(
  rows: Record<string, string>[],
  knownPorts: Set<number>,
): SecurityEvent[] {
  const events: SecurityEvent[] = [];

  for (const row of rows) {
    const port = parseInt(row.port ?? "0", 10);
    const name = row.name ?? "";
    const path = row.path ?? "";
    const address = row.address ?? "";

    if (port === 0) continue;

    // Skip known ports
    if (knownPorts.has(port)) continue;

    // Skip localhost-only
    if (address === "127.0.0.1" || address === "::1") continue;

    events.push(
      event(
        "medium",
        "network",
        "New listening port detected",
        `Port ${port} opened by "${name}" (${path})\nBinding: ${address}`,
        { port, name, path, address },
      ),
    );
  }

  return events;
}

/**
 * Analyze file integrity changes.
 */
export function analyzeFileEvents(
  rows: Record<string, string>[],
): SecurityEvent[] {
  const events: SecurityEvent[] = [];

  for (const row of rows) {
    const filename = row.filename ?? "";
    const eventType = row.event_type ?? "";
    const path = row.path ?? "";
    const pid = row.pid ?? "";

    // Critical system files
    const criticalFiles = [
      "/etc/sudoers",
      "/etc/hosts",
      "/etc/ssh/sshd_config",
      "/etc/passwd",
    ];

    const isCritical = criticalFiles.some((f) => filename.startsWith(f));

    // Launch daemon/agent changes (persistence)
    const isPersistence =
      filename.includes("/LaunchDaemons/") ||
      filename.includes("/LaunchAgents/");

    if (isCritical) {
      events.push(
        event(
          "critical",
          "file",
          "Critical system file modified",
          `File "${filename}" was ${eventType}\nBy process: ${path} (pid=${pid})`,
          { filename, eventType, processPath: path, pid },
        ),
      );
    } else if (isPersistence) {
      events.push(
        event(
          "high",
          "file",
          "Launch daemon/agent modified",
          `Persistence mechanism changed: ${filename}\nAction: ${eventType}\nBy process: ${path}`,
          { filename, eventType, processPath: path, pid },
        ),
      );
    }
  }

  return events;
}

/**
 * Format a security event for human-readable alerting.
 */
export function formatAlert(evt: SecurityEvent): string {
  const severityEmoji: Record<Severity, string> = {
    critical: "🚨",
    high: "🔴",
    medium: "🟡",
    low: "🔵",
    info: "ℹ️",
  };

  const emoji = severityEmoji[evt.severity];
  const time = new Date(evt.timestamp).toLocaleTimeString();

  return [
    `${emoji} **SENTINEL: ${evt.title}**`,
    `Severity: ${evt.severity.toUpperCase()} | ${evt.category}`,
    `Host: ${evt.hostname} | ${time}`,
    "",
    evt.description,
  ].join("\n");
}
