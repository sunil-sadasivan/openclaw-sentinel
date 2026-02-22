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
 * Parse Linux sudo events from journalctl / auth.log.
 * Lines look like:
 *   Feb 22 16:30:00 hostname sudo[1234]:   sunil : TTY=pts/0 ; PWD=/home/sunil ; USER=root ; COMMAND=/usr/bin/apt update
 *   Feb 22 16:30:00 hostname sudo[1234]: pam_unix(sudo:session): session opened for user root(uid=0) by sunil(uid=1000)
 *   Feb 22 16:30:00 hostname sudo[1234]:   sunil : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/sunil ; USER=root ; COMMAND=/usr/bin/rm -rf /
 */
function parseLinuxSudo(line: string): SecurityEvent | null {
  // Standard sudo command log
  const cmdMatch = line.match(
    /sudo\[\d+\]:\s+(\S+)\s*:\s*(?:.*?;\s*)?TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/,
  );
  if (cmdMatch) {
    const [, user, tty, pwd, targetUser, command] = cmdMatch;
    const hasFailure = line.includes("incorrect password");
    return event(
      hasFailure ? "high" : "medium",
      "privilege",
      hasFailure ? "sudo authentication failure" : "sudo command executed",
      `${user} → ${targetUser}: ${command.trim()} (TTY ${tty})`,
      { user, targetUser, command: command.trim(), tty, pwd, failed: hasFailure },
    );
  }

  // PAM session opened for sudo
  const sessionMatch = line.match(
    /sudo\[\d+\]:\s+pam_unix\(sudo:session\):\s+session\s+opened\s+for\s+user\s+(\S+).*?by\s+(\S+)/,
  );
  if (sessionMatch) {
    const [, targetUser, user] = sessionMatch;
    return event(
      "info",
      "privilege",
      "sudo session started",
      `sudo session opened: ${user} → ${targetUser}`,
      { user: user.replace(/\(.*\)/, ""), targetUser: targetUser.replace(/\(.*\)/, ""), source: "pam" },
    );
  }

  return null;
}

/**
 * Parse Linux user account change events.
 * Lines from useradd/userdel/usermod/passwd via journalctl or auth.log:
 *   Feb 22 16:30:00 hostname useradd[1234]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash
 *   Feb 22 16:30:00 hostname userdel[1234]: delete user 'olduser'
 *   Feb 22 16:30:00 hostname usermod[1234]: change user 'sunil' password
 *   Feb 22 16:30:00 hostname passwd[1234]: pam_unix(passwd:chauthtok): password changed for sunil
 *   Feb 22 16:30:00 hostname groupadd[1234]: new group: name=newgroup, GID=1002
 */
function parseLinuxUserAccount(line: string): SecurityEvent | null {
  // New user created
  const useraddMatch = line.match(
    /useradd\[\d+\]:\s+new\s+user:\s+name=(\S+)/,
  );
  if (useraddMatch) {
    return event(
      "critical",
      "auth",
      "User account created",
      `New user account created: ${useraddMatch[1]}`,
      { user: useraddMatch[1], type: "user_created" },
    );
  }

  // User deleted
  const userdelMatch = line.match(
    /userdel\[\d+\]:\s+delete\s+user\s+'(\S+)'/,
  );
  if (userdelMatch) {
    return event(
      "high",
      "auth",
      "User account deleted",
      `User account deleted: ${userdelMatch[1]}`,
      { user: userdelMatch[1], type: "user_deleted" },
    );
  }

  // Password changed via passwd command
  const passwdMatch = line.match(
    /passwd\[\d+\]:\s+pam_unix\(passwd:chauthtok\):\s+password\s+changed\s+for\s+(\S+)/,
  );
  if (passwdMatch) {
    return event(
      "high",
      "auth",
      "User password changed",
      `Password changed for user: ${passwdMatch[1]}`,
      { user: passwdMatch[1], type: "password_changed" },
    );
  }

  // User modified (usermod)
  const usermodMatch = line.match(
    /usermod\[\d+\]:\s+change\s+user\s+'(\S+)'/,
  );
  if (usermodMatch) {
    return event(
      "high",
      "auth",
      "User account modified",
      `User account modified: ${usermodMatch[1]}`,
      { user: usermodMatch[1], type: "user_modified" },
    );
  }

  // New group (often accompanies user creation)
  const groupaddMatch = line.match(
    /groupadd\[\d+\]:\s+new\s+group:\s+name=(\S+)/,
  );
  if (groupaddMatch) {
    return event(
      "medium",
      "auth",
      "Group created",
      `New group created: ${groupaddMatch[1]}`,
      { group: groupaddMatch[1], type: "group_created" },
    );
  }

  return null;
}

/**
 * Parse Linux remote desktop / VNC events.
 * Lines from xrdp, vncserver, x11vnc:
 *   Feb 22 16:30:00 hostname xrdp[1234]: connected client: 203.0.113.42
 *   Feb 22 16:30:00 hostname xrdp-sesman[1234]: session started for user sunil
 *   Feb 22 16:30:00 hostname x11vnc[1234]: Got connection from client 203.0.113.42
 */
function parseLinuxRemoteDesktop(line: string): SecurityEvent | null {
  // xrdp client connection
  const xrdpMatch = line.match(
    /xrdp\[\d+\]:\s+.*?(?:connected|connection).*?(\d+\.\d+\.\d+\.\d+)/i,
  );
  if (xrdpMatch) {
    return event(
      "high",
      "auth",
      "RDP connection detected",
      `RDP connection from ${xrdpMatch[1]}`,
      { type: "rdp", host: xrdpMatch[1] },
    );
  }

  // xrdp session started
  const xrdpSessionMatch = line.match(
    /xrdp-sesman\[\d+\]:\s+.*?session\s+started.*?user\s+(\S+)/i,
  );
  if (xrdpSessionMatch) {
    return event(
      "high",
      "auth",
      "RDP session started",
      `RDP session started for user: ${xrdpSessionMatch[1]}`,
      { type: "rdp_session", user: xrdpSessionMatch[1] },
    );
  }

  // VNC connection (x11vnc, tigervnc, etc.)
  const vncMatch = line.match(
    /(?:x11vnc|vnc|Xvnc)\[\d+\]:\s+.*?(?:connection|connect).*?(\d+\.\d+\.\d+\.\d+)/i,
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

  return null;
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
    // Watch multiple systemd units for comprehensive monitoring:
    // - sshd/ssh: SSH login/failure events
    // - sudo: privilege escalation
    // - systemd-logind: session events
    // - xrdp/vnc: remote desktop access
    // Also use SYSLOG_IDENTIFIER for useradd/userdel/usermod/passwd/groupadd
    this.process = spawn("journalctl", [
      "-f", "--no-pager", "-o", "short",
      "-u", "sshd", "-u", "ssh",
      "-u", "sudo",
      "-u", "systemd-logind",
      "-u", "xrdp", "-u", "xrdp-sesman",
      // Catch useradd/userdel/passwd via syslog identifiers
      "-t", "useradd", "-t", "userdel", "-t", "usermod", "-t", "passwd", "-t", "groupadd",
      // VNC servers
      "-t", "x11vnc", "-t", "Xvnc",
    ], {
      stdio: ["ignore", "pipe", "ignore"],
    });

    console.log("[sentinel] LogStreamWatcher started (Linux journalctl, SSH + sudo + user accounts + remote desktop)");
    this.wireUp((line) => {
      return parseLinuxLogLine(line, this.knownHosts)
        ?? parseLinuxSudo(line)
        ?? parseLinuxUserAccount(line)
        ?? parseLinuxRemoteDesktop(line);
    });
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
