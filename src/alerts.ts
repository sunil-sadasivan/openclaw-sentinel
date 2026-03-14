/**
 * Alert rate limiting, dedup, and severity threshold logic.
 */

import type { SecurityEvent, Severity } from "./config.js";
import { SEVERITY_ORDER } from "./config.js";

const MAX_ALERTS_PER_MINUTE = 10;
const ALERT_DEDUP_WINDOW_MS = 15 * 60 * 1000; // 15 minutes (was 1 minute — way too short for noisy events)

export interface AlertRecord {
  time: number;
  key: string; // dedup key: title + distinguishing detail (path, port, etc.)
}

export interface AlertState {
  recentAlerts: AlertRecord[];
}

export function createAlertState(): AlertState {
  return { recentAlerts: [] };
}

/**
 * Build a dedup key from a security event.
 * Includes title + distinguishing details (path, port, user) so that
 * different instances of the same alert type are deduped separately,
 * but the same instance isn't repeated every minute.
 */
export function dedupKey(evt: SecurityEvent): string {
  const details =
    typeof evt.details === "object" && evt.details !== null
      ? evt.details
      : {};
  // Pick the most distinguishing field for each category
  const distinguisher =
    (details as any).path ??
    (details as any).port ??
    (details as any).address ??
    (details as any).host ??
    (details as any).username ??
    "";
  return `${evt.title}::${distinguisher}`;
}

/**
 * Check if an alert should be sent (rate limit + dedup).
 */
export function shouldAlert(
  evt: SecurityEvent,
  alertState: AlertState,
  now: number = Date.now(),
): boolean {
  // Clean entries older than the dedup window
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

  const key = dedupKey(evt);

  // Skip dedup for failed auth — every attempt matters
  const skipDedup =
    evt.category === "ssh_login" &&
    (evt.title.includes("failed") || evt.title.includes("Failed") || evt.title.includes("invalid") || evt.title.includes("Invalid"));

  if (!skipDedup) {
    // Dedup: same key (title + distinguishing detail) within 15-minute window
    const isDupe = alertState.recentAlerts.some(
      (a) => a.key === key && now - a.time < ALERT_DEDUP_WINDOW_MS,
    );
    if (isDupe) return false;
  }

  alertState.recentAlerts.push({ time: now, key });
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
