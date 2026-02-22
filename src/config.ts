/**
 * Sentinel configuration types and defaults.
 */

/** Severity levels for security events */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export interface SentinelConfig {
  osqueryPath?: string;
  configPath?: string;
  alertChannel?: string;
  alertTo?: string;
  alertSeverity?: Severity;
  logPath?: string;
  pollIntervalMs?: number;
  enableProcessMonitor?: boolean;
  enableFileIntegrity?: boolean;
  enableNetworkMonitor?: boolean;
  trustedSigningIds?: string[];
  trustedPaths?: string[];
  watchPaths?: string[];
}

export const DEFAULT_CONFIG: Required<
  Pick<
    SentinelConfig,
    | "pollIntervalMs"
    | "enableProcessMonitor"
    | "enableFileIntegrity"
    | "enableNetworkMonitor"
    | "trustedSigningIds"
    | "trustedPaths"
    | "watchPaths"
  >
> = {
  pollIntervalMs: 30_000, // 30 seconds
  enableProcessMonitor: true,
  enableFileIntegrity: true,
  enableNetworkMonitor: true,
  trustedSigningIds: [
    "com.apple.",
    "com.google.Chrome",
    "com.microsoft.",
    "com.docker.",
    "org.mozilla.",
    "com.electron.",
  ],
  trustedPaths: [
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/System/",
    "/Library/Apple/",
  ],
  watchPaths: [
    "/etc/hosts",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
  ],
};

/** A security event detected by Sentinel */
export interface SecurityEvent {
  id: string;
  timestamp: number;
  severity: Severity;
  category: "process" | "network" | "file" | "auth" | "privilege" | "ssh_login";
  title: string;
  description: string;
  details: Record<string, unknown>;
  hostname: string;
}
