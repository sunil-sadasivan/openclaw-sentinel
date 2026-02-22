/**
 * LogStreamWatcher — Real-time event monitoring via macOS `log stream` or Linux `journalctl`.
 *
 * Spawns a long-running subprocess that tails system logs for specific events
 * (SSH login, failed password, sudo) and emits SecurityEvents in real-time.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import type { SecurityEvent } from "./config.js";

type EventCallback = (event: SecurityEvent) => void;

function event(
  severity: SecurityEvent["severity"],
  category: SecurityEvent["category"],
  title: string,
  description: string,
  details?: Record<string, unknown>,
): SecurityEvent {
  return {
    id: `ls-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Date.now(),
    severity,
    category,
    title,
    description,
    details: details ?? {},
    hostname: "",
  };
}

/**
 * Parse a macOS `log stream` line for SSH events.
 * Lines look like:
 *   2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Accepted publickey for sunil from 100.79.207.74 port 52341 ssh2
 *   2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Failed password for sunil from 203.0.113.42 port 22 ssh2
 *   2026-02-22 16:30:00.123456-0500  0x1234  Default  0x0  0  sshd: Invalid user admin from 203.0.113.42 port 22
 */
function parseMacOSLogLine(
  line: string,
  knownHosts: Set<string>,
): SecurityEvent | null {
  // Match "Accepted" logins
  const acceptedMatch = line.match(
    /sshd.*?:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
  );
  if (acceptedMatch) {
    const [, method, user, host, port] = acceptedMatch;
    const isTailscale = isTailscaleIP(host);
    const isKnown = knownHosts.has(host) || isTailscale;

    return event(
      isKnown ? "info" : "high",
      "ssh_login",
      isKnown ? "SSH login detected" : "SSH login from unknown host",
      `User "${user}" logged in via ${method} from ${isTailscale ? "Tailscale" : isKnown ? "known" : "UNKNOWN"} host: ${host}:${port}`,
      { user, host, port, method, tailscale: isTailscale, known: isKnown },
    );
  }

  // Match "Failed password"
  const failedMatch = line.match(
    /sshd.*?:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
  );
  if (failedMatch) {
    const [, user, host, port] = failedMatch;
    return event(
      "high",
      "ssh_login",
      "SSH failed password attempt",
      `Failed password for "${user}" from ${host}:${port}`,
      { user, host, port, type: "failed_password" },
    );
  }

  // Match "Invalid user"
  const invalidMatch = line.match(
    /sshd.*?:\s+Invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
  );
  if (invalidMatch) {
    const [, user, host, port] = invalidMatch;
    return event(
      "high",
      "ssh_login",
      "SSH invalid user attempt",
      `Invalid user "${user}" from ${host}:${port}`,
      { user, host, port, type: "invalid_user" },
    );
  }

  return null;
}

/**
 * Parse a Linux journalctl line for SSH events.
 * Lines look like:
 *   Feb 22 16:30:00 hostname sshd[1234]: Accepted publickey for sunil from 100.79.207.74 port 52341 ssh2
 */
function parseLinuxLogLine(
  line: string,
  knownHosts: Set<string>,
): SecurityEvent | null {
  // Same patterns work for both — sshd output is consistent
  return parseMacOSLogLine(line, knownHosts);
}

function isTailscaleIP(host: string): boolean {
  const octets = host.split(".").map(Number);
  return octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127;
}

export class LogStreamWatcher {
  private process: ChildProcess | null = null;
  private callback: EventCallback;
  private knownHosts: Set<string>;
  private platform: string;
  private running = false;

  constructor(
    callback: EventCallback,
    knownHosts: Set<string>,
    platform?: string,
  ) {
    this.callback = callback;
    this.knownHosts = knownHosts;
    this.platform = platform ?? process.platform;
  }

  start(): void {
    if (this.running) return;
    this.running = true;

    if (this.platform === "darwin") {
      this.startMacOS();
    } else {
      this.startLinux();
    }
  }

  private startMacOS(): void {
    const predicate =
      'process == "sshd" AND (eventMessage CONTAINS "Accepted" OR eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "Invalid user")';

    this.process = spawn("log", ["stream", "--predicate", predicate, "--style", "default"], {
      stdio: ["ignore", "pipe", "ignore"],
    });

    console.log("[sentinel] LogStreamWatcher started (macOS log stream, SSH events)");
    this.wireUp((line) => parseMacOSLogLine(line, this.knownHosts));
  }

  private startLinux(): void {
    this.process = spawn("journalctl", ["-f", "-u", "sshd", "-u", "ssh", "--no-pager", "-o", "short"], {
      stdio: ["ignore", "pipe", "ignore"],
    });

    console.log("[sentinel] LogStreamWatcher started (Linux journalctl, SSH events)");
    this.wireUp((line) => parseLinuxLogLine(line, this.knownHosts));
  }

  private wireUp(parser: (line: string) => SecurityEvent | null): void {
    if (!this.process?.stdout) return;

    const rl = createInterface({ input: this.process.stdout });

    rl.on("line", (line) => {
      const evt = parser(line);
      if (evt) {
        this.callback(evt);
      }
    });

    this.process.on("exit", (code) => {
      console.log(`[sentinel] LogStreamWatcher exited (code ${code})`);
      if (this.running) {
        // Auto-restart after 5 seconds
        setTimeout(() => {
          console.log("[sentinel] LogStreamWatcher restarting...");
          if (this.platform === "darwin") this.startMacOS();
          else this.startLinux();
        }, 5000);
      }
    });

    this.process.on("error", (err) => {
      console.error("[sentinel] LogStreamWatcher error:", err.message);
    });
  }

  stop(): void {
    this.running = false;
    if (this.process) {
      this.process.kill("SIGTERM");
      this.process = null;
    }
  }

  /** Update known hosts (e.g. after baseline refresh) */
  updateKnownHosts(hosts: Set<string>): void {
    this.knownHosts = hosts;
  }
}
