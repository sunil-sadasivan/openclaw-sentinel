/**
 * osquery integration — manages the osqueryd daemon and queries results.
 */

import { spawn, execFile } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import type { SentinelConfig } from "./config.js";

const DEFAULT_OSQUERY_PATHS = [
  "/opt/homebrew/bin/osqueryi",
  "/usr/local/bin/osqueryi",
  "/usr/bin/osqueryi",
];

export function findOsquery(configPath?: string): string | null {
  if (configPath && existsSync(configPath)) return configPath;
  for (const p of DEFAULT_OSQUERY_PATHS) {
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Run an osquery SQL query and return parsed JSON results.
 */
export async function query(
  osqueryPath: string,
  sql: string,
): Promise<Record<string, string>[]> {
  return new Promise((resolve, reject) => {
    execFile(
      osqueryPath,
      ["--json", sql],
      { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`osquery error: ${stderr || err.message}`));
          return;
        }
        try {
          const results = JSON.parse(stdout || "[]");
          resolve(results);
        } catch (parseErr) {
          reject(new Error(`osquery parse error: ${String(parseErr)}`));
        }
      },
    );
  });
}

/** Generate the osquery config file for daemon mode */
export function generateOsqueryConfig(config: SentinelConfig): object {
  const watchPaths = config.watchPaths ?? [
    "/etc/hosts",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
  ];

  return {
    options: {
      logger_plugin: "filesystem",
      logger_path: join(
        config.logPath ?? join(homedir(), ".openclaw", "sentinel", "logs"),
        "osquery",
      ),
      disable_events: false,
      enable_file_events: config.enableFileIntegrity ?? true,
      // macOS Endpoint Security framework
      disable_endpointsecurity: false,
      // Keep event expiry reasonable
      events_expiry: 3600,
      events_max: 100000,
    },
    schedule: {
      // Process monitoring — catch suspicious process execution
      process_events: {
        query:
          "SELECT pid, path, cmdline, uid, euid, username, signing_id, team_id, platform_binary, event_type, time FROM es_process_events WHERE event_type = 'exec';",
        interval: 30,
        removed: false,
        description: "Process execution events from Endpoint Security",
      },
      // SSH and login monitoring
      logged_in_users: {
        query: "SELECT type, user, host, time, pid FROM logged_in_users;",
        interval: 60,
        removed: false,
        description: "Currently logged-in users",
      },
      // Listening ports — detect new services
      listening_ports: {
        query:
          "SELECT lp.port, lp.address, lp.protocol, p.name, p.path, p.cmdline FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port > 0;",
        interval: 120,
        removed: false,
        description: "Listening network ports with process info",
      },
      // Sudo and privilege escalation
      shell_history: {
        query:
          "SELECT uid, command, time FROM shell_history WHERE command LIKE '%sudo%' OR command LIKE '%chmod%' OR command LIKE '%chown%' ORDER BY time DESC LIMIT 20;",
        interval: 60,
        removed: false,
        description: "Shell commands involving privilege changes",
      },
      // Launch daemon/agent persistence
      launch_daemons: {
        query:
          "SELECT name, path, program, program_arguments, run_at_load FROM launchd WHERE path LIKE '/Library/LaunchDaemons/%' OR path LIKE '/Library/LaunchAgents/%';",
        interval: 300,
        removed: false,
        description: "Launch daemons and agents (persistence detection)",
      },
      // SSH keys — detect additions
      ssh_keys: {
        query: "SELECT uid, path, encrypted FROM user_ssh_keys;",
        interval: 300,
        removed: false,
        description: "SSH keys on the system",
      },
      // Open network connections to external IPs
      open_sockets: {
        query:
          "SELECT p.name, p.path, pos.remote_address, pos.remote_port, pos.local_port, pos.protocol FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' AND pos.remote_address != '127.0.0.1' AND pos.remote_address != '::1' AND pos.remote_address != '0.0.0.0' LIMIT 50;",
        interval: 120,
        removed: false,
        description: "Outbound network connections",
      },
    },
    file_paths: {
      critical_files: watchPaths,
    },
    decorators: {
      load: ["SELECT hostname FROM system_info;"],
    },
  };
}

/** Write osquery config to disk */
export async function writeOsqueryConfig(
  configDir: string,
  config: SentinelConfig,
): Promise<string> {
  await mkdir(configDir, { recursive: true });
  const configFile = join(configDir, "osquery.conf");
  const osqueryConfig = generateOsqueryConfig(config);
  await writeFile(configFile, JSON.stringify(osqueryConfig, null, 2));
  return configFile;
}
