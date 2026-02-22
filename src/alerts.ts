/**
 * Alert rate limiting, dedup, and severity threshold logic.
 */

import type { SecurityEvent, Severity } from "./config.js";
import { SEVERITY_ORDER } from "./config.js";

const MAX_ALERTS_PER_MINUTE = 10;
const ALERT_DEDUP_WINDOW_MS = 60 * 1000; // 1 minute

export interface AlertRecord {
  time: number;
  title: string;
}

export interface AlertState {
  recentAlerts: AlertRecord[];
}

export function createAlertState(): AlertState {
  return { recentAlerts: [] };
}

/**
 * Check if an alert should be sent (rate limit + dedup).
 */
export function shouldAlert(
  evt: SecurityEvent,
  alertState: AlertState,
  now: number = Date.now(),
): boolean {
  // Clean entries older than the dedup window (5 min)
  alertState.recentAlerts = alertState.recentAlerts.filter(
    (a) => now - a.time < ALERT_DEDUP_WINDOW_MS,
  );

  // Rate limit: max alerts per minute (count only last 60s)
  const recentCount = alertState.recentAlerts.filter(
    (a) => now - a.time < 60_000,
  ).length;
  if (recentCount >= MAX_ALERTS_PER_MINUTE) {
    return false;
  }

  // Skip dedup for failed auth — every attempt matters
  const skipDedup =
    evt.category === "ssh_login" &&
    (evt.title.includes("failed") || evt.title.includes("Failed") || evt.title.includes("invalid") || evt.title.includes("Invalid"));

  if (!skipDedup) {
    // Dedup: same title within window
    const isDupe = alertState.recentAlerts.some(
      (a) => a.title === evt.title && now - a.time < ALERT_DEDUP_WINDOW_MS,
    );
    if (isDupe) return false;
  }

  alertState.recentAlerts.push({ time: now, title: evt.title });
  return true;
}

/**
 * Check if event meets minimum severity threshold.
 */
export function meetsThreshold(
  severity: Severity,
  minSeverity: string = "high",
): boolean {
  const evtLevel = SEVERITY_ORDER.indexOf(severity);
  const minLevel = SEVERITY_ORDER.indexOf(minSeverity as Severity);
  return evtLevel >= (minLevel >= 0 ? minLevel : 3); // default to "high"
}
