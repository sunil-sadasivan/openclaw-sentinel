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

/**
 * Parse macOS /var/log/system.log lines for SSH events.
 * Lines look like:
 *   Feb 22 16:39:32 sunils-mac-mini sshd-session: sunil [priv][58912]: USER_PROCESS: 58916 ttys001
 *   Feb 22 16:38:12 sunils-mac-mini sshd-session: sunil [priv][53930]: DEAD_PROCESS: 53934 ttys012
 *   Feb 22 16:51:16 sunils-mac-mini sshd[60738]: Failed password for sunil from 100.79.207.74 port 52341 ssh2
 *   Feb 22 16:51:16 sunils-mac-mini sshd[60738]: Invalid user admin from 100.79.207.74 port 52341
 */
function parseMacOSSyslog(
  line: string,
  knownHosts: Set<string>,
): SecurityEvent | null {
  // Match sshd-session USER_PROCESS (successful login)
  const sessionMatch = line.match(
    /sshd-session:\s+(\S+)\s+\[priv\]\[(\d+)\]:\s+USER_PROCESS:\s+(\d+)\s+(\S+)/,
  );
  if (sessionMatch) {
    const [, user, parentPid, pid, tty] = sessionMatch;
    // We don't have the source IP from syslog — query utmpx for it
    return event(
      "info",
      "ssh_login",
      "SSH session started",
      `User "${user}" started SSH session (PID ${pid}, TTY ${tty})`,
      { user, pid, parentPid, tty, source: "syslog" },
    );
  }

  // Match Failed password (if sshd logs this to system.log)
  const failedMatch = line.match(
    /sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
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

  // Match Invalid user
  const invalidMatch = line.match(
    /sshd\[\d+\]:\s+Invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
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

  // Match sudo from system.log
  const sudoMatch = line.match(
    /sudo\[(\d+)\]:\s+(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/,
  );
  if (sudoMatch) {
    const [, pid, user, tty, pwd, targetUser, command] = sudoMatch;
    return event(
      "medium",
      "privilege",
      "sudo command executed",
      `${user} → ${targetUser}: ${command.trim()} (TTY ${tty}, PID ${pid})`,
      { user, targetUser, command: command.trim(), tty, pwd, pid },
    );
  }

  // Match sudo USER_PROCESS from system.log (macOS Sequoia format)
  const sudoSessionMatch = line.match(
    /sudo\[(\d+)\]:\s+USER_PROCESS/,
  );
  if (sudoSessionMatch) {
    return event(
      "info",
      "privilege",
      "sudo session started",
      `sudo session started (PID ${sudoSessionMatch[1]})`,
      { pid: sudoSessionMatch[1], source: "syslog" },
    );
  }

  return null;
}

/**
 * Parse macOS unified log lines for PAM authentication errors.
 * Line format:
 *   2026-02-22 16:56:51.705020-0500  0x14e5ecb  Default  0x0  62761  0  sshd-session: error: PAM: authentication error for sunil from 100.79.207.74
 */
function parseMacOSAuthError(
  line: string,
  _knownHosts: Set<string>,
): SecurityEvent | null {
  // PAM authentication error (valid user, wrong password)
  const authMatch = line.match(
    /sshd-session.*?PAM:\s+authentication\s+error\s+for\s+(\S+)\s+from\s+(\S+)/,
  );
  if (authMatch) {
    const [, user, host] = authMatch;
    return event(
      "high",
      "ssh_login",
      "SSH failed authentication",
      `Failed authentication (PAM) for "${user}" from ${host}`,
      { user, host, type: "pam_auth_error" },
    );
  }

  // PAM unknown user (invalid username)
  const unknownMatch = line.match(
    /sshd-session.*?PAM:\s+unknown\s+user\s+for\s+illegal\s+user\s+(\S+)\s+from\s+(\S+)/,
  );
  if (unknownMatch) {
    const [, user, host] = unknownMatch;
    return event(
      "high",
      "ssh_login",
      "SSH invalid user attempt",
      `Unknown user "${user}" attempted login from ${host}`,
      { user, host, type: "unknown_user" },
    );
  }

  // Invalid user line
  const invalidMatch = line.match(
    /sshd-session.*?Invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
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

  // Failed keyboard-interactive/pam
  const failedMatch = line.match(
    /sshd-session.*?Failed\s+\S+\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
  );
  if (failedMatch) {
    const [, user, host, port] = failedMatch;
    return event(
      "high",
      "ssh_login",
      "SSH failed authentication",
      `Failed login for "${user}" from ${host}:${port}`,
      { user, host, port, type: "failed_auth" },
    );
  }

  return null;
}

/**
 * Parse screen sharing / VNC connection events.
 */
function parseScreenSharing(line: string): SecurityEvent | null {
  // Authentication attempt
  const authMatch = line.match(
    /screensharingd.*?Authentication:\s+(.*)/,
  );
  if (authMatch) {
    return event(
      "high",
      "auth",
      "Screen sharing authentication",
      `Screen sharing auth attempt: ${authMatch[1]}`,
      { type: "screen_sharing", detail: authMatch[1] },
    );
  }

  // VNC connection
  const vncMatch = line.match(
    /screensharingd.*?VNC.*?(\d+\.\d+\.\d+\.\d+)/,
  );
  if (vncMatch) {
    return event(
      "high",
      "auth",
      "VNC connection detected",
      `VNC connection from ${vncMatch[1]}`,
      { type: "vnc", host: vncMatch[1] },
    );
  }

  // Client connection
  const clientMatch = line.match(
    /screensharingd.*?client\s+(\S+)\s+connected/i,
  );
  if (clientMatch) {
    return event(
      "high",
      "auth",
      "Screen sharing client connected",
      `Screen sharing client connected: ${clientMatch[1]}`,
      { type: "screen_sharing_client", client: clientMatch[1] },
    );
  }

  return null;
}

/**
 * Parse user account change events from opendirectoryd.
 */
function parseUserAccountChange(line: string): SecurityEvent | null {
  const createdMatch = line.match(
    /opendirectoryd.*?(?:user|record)\s+(\S+).*?created/i,
  );
  if (createdMatch) {
    return event(
      "critical",
      "auth",
      "User account created",
      `New user account created: ${createdMatch[1]}`,
      { user: createdMatch[1], type: "user_created" },
    );
  }

  const deletedMatch = line.match(
    /opendirectoryd.*?(?:user|record)\s+(\S+).*?deleted/i,
  );
  if (deletedMatch) {
    return event(
      "high",
      "auth",
      "User account deleted",
      `User account deleted: ${deletedMatch[1]}`,
      { user: deletedMatch[1], type: "user_deleted" },
    );
  }

  const passwordMatch = line.match(
    /opendirectoryd.*?(?:user|record)\s+(\S+).*?password\s+changed/i,
  );
  if (passwordMatch) {
    return event(
      "high",
      "auth",
      "User password changed",
      `Password changed for user: ${passwordMatch[1]}`,
      { user: passwordMatch[1], type: "password_changed" },
    );
  }

  return null;
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

  private syslogProcess: ChildProcess | null = null;

  private startMacOS(): void {
    // Two sources on modern macOS:
    // 1. /var/log/system.log — successful SSH sessions (sshd-session USER_PROCESS)
    // 2. unified log stream — failed auth (PAM errors from sshd-session)

    // Source 1: tail system.log for successful logins
    this.process = spawn("tail", ["-F", "-n", "0", "/var/log/system.log"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    console.log("[sentinel] LogStreamWatcher started (macOS system.log tail, SSH sessions)");
    this.wireUp((line) => parseMacOSSyslog(line, this.knownHosts));

    // Source 2: log stream for failed SSH auth + sudo + screen sharing + user account changes
    const predicate = [
      // SSH failed auth
      '(process == "sshd-session" AND (eventMessage CONTAINS "authentication error" OR eventMessage CONTAINS "unknown user" OR eventMessage CONTAINS "Invalid user" OR eventMessage CONTAINS "Failed"))',
      // Screen sharing connections
      '(process == "screensharingd" AND (eventMessage CONTAINS "Authentication" OR eventMessage CONTAINS "client" OR eventMessage CONTAINS "VNC"))',
      // User account changes (creation, deletion, modification)
      '(process == "opendirectoryd" AND (eventMessage CONTAINS "created" OR eventMessage CONTAINS "deleted" OR eventMessage CONTAINS "password changed"))',
    ].join(" OR ");
    this.syslogProcess = spawn("log", ["stream", "--predicate", predicate, "--style", "default", "--info"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    console.log("[sentinel] LogStreamWatcher started (macOS log stream, failed auth)");

    if (this.syslogProcess.stdout) {
      const rl = createInterface({ input: this.syslogProcess.stdout });
      rl.on("line", (line) => {
        const evt = parseMacOSAuthError(line, this.knownHosts)
          ?? parseScreenSharing(line)
          ?? parseUserAccountChange(line);
        if (evt) this.callback(evt);
      });
    }

    console.log("[sentinel] LogStreamWatcher started (macOS log stream, auth + screen sharing + user accounts)");

    this.syslogProcess.on("exit", (code) => {
      console.log(`[sentinel] LogStream (unified log) exited (code ${code})`);
      if (this.running) {
        setTimeout(() => this.startMacOSUnifiedLog(), 5000);
      }
    });
  }

  private startMacOSUnifiedLog(): void {
    const predicate = [
      '(process == "sshd-session" AND (eventMessage CONTAINS "authentication error" OR eventMessage CONTAINS "unknown user" OR eventMessage CONTAINS "Invalid user" OR eventMessage CONTAINS "Failed"))',
      '(process == "screensharingd" AND (eventMessage CONTAINS "Authentication" OR eventMessage CONTAINS "client" OR eventMessage CONTAINS "VNC"))',
      '(process == "opendirectoryd" AND (eventMessage CONTAINS "created" OR eventMessage CONTAINS "deleted" OR eventMessage CONTAINS "password changed"))',
    ].join(" OR ");
    this.syslogProcess = spawn("log", ["stream", "--predicate", predicate, "--style", "default", "--info"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (this.syslogProcess.stdout) {
      const rl = createInterface({ input: this.syslogProcess.stdout });
      rl.on("line", (line) => {
        const evt = parseMacOSAuthError(line, this.knownHosts)
          ?? parseScreenSharing(line)
          ?? parseUserAccountChange(line);
        if (evt) this.callback(evt);
      });
    }
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
    if (this.syslogProcess) {
      this.syslogProcess.kill("SIGTERM");
      this.syslogProcess = null;
    }
  }

  /** Update known hosts (e.g. after baseline refresh) */
  updateKnownHosts(hosts: Set<string>): void {
    this.knownHosts = hosts;
  }
}
