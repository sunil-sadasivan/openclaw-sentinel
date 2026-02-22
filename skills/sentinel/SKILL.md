# Sentinel — Endpoint Security Monitoring

You have access to real-time endpoint security monitoring via three tools powered by [osquery](https://osquery.io).

## Tools

### `sentinel_status`
Check if monitoring is active, how many events have been detected, and the current baseline (known hosts/ports). Call this first when investigating security concerns.

### `sentinel_events`
Get recent security events. Filter by severity (`critical`, `high`, `medium`, `low`, `info`) or category (`process`, `network`, `file`, `auth`, `privilege`). Use this to review what Sentinel has flagged.

### `sentinel_query`
Run ad-hoc osquery SQL for deeper investigation. osquery exposes 200+ virtual tables backed by live OS APIs — every query returns real-time system state, not cached data.

**Blocked tables** (security risk): `carves`, `curl`, `curl_certificate`

## When to use these tools

- User asks about security, open ports, running processes, SSH connections, or system health
- During heartbeat security checks
- Investigating suspicious activity or alerts
- Auditing system configuration (firewall, SSH keys, launch daemons)

## Common investigation queries

### System overview
```sql
-- Who's logged in right now?
SELECT type, user, host, time, pid FROM logged_in_users;

-- What's listening on the network?
SELECT lp.port, lp.protocol, lp.address, p.name, p.path
FROM listening_ports lp JOIN processes p ON lp.pid = p.pid
WHERE lp.port > 0 ORDER BY lp.port;

-- What processes are running as root?
SELECT pid, name, path, cmdline FROM processes WHERE uid = 0 ORDER BY start_time DESC LIMIT 30;
```

### SSH & authentication
```sql
-- SSH keys on this machine
SELECT uid, path, encrypted FROM user_ssh_keys;

-- Authorized keys (who can SSH in?)
SELECT * FROM authorized_keys;

-- SSH config
SELECT * FROM ssh_configs;
```

### Persistence mechanisms
```sql
-- Launch daemons and agents (macOS)
SELECT name, path, program, program_arguments, run_at_load
FROM launchd
WHERE path LIKE '/Library/LaunchDaemons/%' OR path LIKE '/Library/LaunchAgents/%'
   OR path LIKE '%/Library/LaunchAgents/%';

-- Cron jobs
SELECT * FROM crontab;

-- Startup items (Linux)
SELECT name, path, source FROM startup_items;
```

### Process investigation
```sql
-- Processes with open network connections
SELECT p.name, p.path, pos.remote_address, pos.remote_port, pos.local_port
FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid
WHERE pos.remote_address != '' AND pos.remote_address != '127.0.0.1'
  AND pos.remote_address != '::1' AND pos.remote_address != '0.0.0.0'
ORDER BY p.name;

-- Find a specific process
SELECT pid, name, path, cmdline, uid, parent FROM processes WHERE name LIKE '%suspicious%';

-- Process tree (who spawned what)
SELECT p.pid, p.name, p.path, p.cmdline, pp.name AS parent_name
FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid
WHERE p.uid = 0 ORDER BY p.start_time DESC LIMIT 20;
```

### File integrity & system config
```sql
-- Check a specific file's hash
SELECT path, sha256 FROM hash WHERE path = '/etc/hosts';

-- Firewall status (macOS)
SELECT * FROM alf;
SELECT * FROM alf_exceptions;

-- Disk encryption
SELECT * FROM disk_encryption;

-- System info
SELECT hostname, cpu_type, hardware_model, physical_memory FROM system_info;
```

### Network investigation
```sql
-- DNS resolvers
SELECT * FROM dns_resolvers;

-- ARP table (who's on the local network)
SELECT address, mac, interface FROM arp_cache;

-- Interfaces
SELECT interface, address, mask, type FROM interface_addresses WHERE address != '';

-- Routes
SELECT destination, gateway, interface FROM routes WHERE destination != '::1';
```

## Interpreting results

- **Unsigned binaries** from `/tmp`, `/var/tmp`, or user home dirs are suspicious
- **Root processes** you don't recognize warrant investigation
- **Listening ports** on `0.0.0.0` (all interfaces) are externally accessible — only expected for intentional services
- **SSH logins** from IPs outside your Tailscale range (`100.64.0.0/10`) or known hosts are flagged
- **New LaunchDaemons/LaunchAgents** could be persistence mechanisms
- **Failed auth attempts** — 3+ in a minute suggests targeted access attempts, 10+ suggests brute force

## Alert severity levels

| Severity | Meaning | Examples |
|----------|---------|---------|
| 🚨 critical | Immediate threat | Brute force attack, critical file modified (/etc/sudoers) |
| 🔴 high | Likely malicious | Unsigned binary, privilege escalation, unknown SSH login, persistence change |
| 🟡 medium | Unusual activity | New listening port, single failed login, suspicious command |
| 🔵 low | Informational | Minor config changes |
| ℹ️ info | Baseline data | Normal system activity |

## Tips

- Always check `sentinel_status` first to confirm monitoring is active
- Use `sentinel_events` before running ad-hoc queries — Sentinel may have already flagged the issue
- For recurring checks, suggest the user add items to their HEARTBEAT.md
- When reporting findings, distinguish between **confirmed threats** and **unusual but potentially benign** activity
- If osqueryd is not running, suggest: `sudo ./scripts/setup-daemon.sh` from the plugin directory
