# 🛡️ OpenClaw Sentinel

Real-time endpoint security monitoring plugin for [OpenClaw](https://github.com/openclaw/openclaw).

Sentinel uses [osquery](https://osquery.io) to monitor your macOS endpoints for security events and alerts you in real-time via your configured OpenClaw channel (Signal, Slack, Telegram, etc.).

## What it monitors

| Category | What | Severity |
|----------|------|----------|
| **Process** | Unsigned binary execution | 🔴 High |
| **Process** | Suspicious command patterns (reverse shells, curl\|sh, etc.) | 🔴 High |
| **Privilege** | Privilege escalation (uid≠0 running as euid=0) | 🔴 High |
| **Auth** | SSH login from unknown host | 🔴 High |
| **File** | Critical system file modification (/etc/sudoers, /etc/hosts) | 🚨 Critical |
| **File** | Launch daemon/agent changes (persistence mechanisms) | 🔴 High |
| **Network** | New listening port opened | 🟡 Medium |

## Prerequisites

```bash
brew install osquery
```

osquery must have **Full Disk Access** for Endpoint Security framework monitoring:
System Settings → Privacy & Security → Full Disk Access → add `/opt/homebrew/bin/osqueryd`

## Installation

```bash
openclaw plugins install @openclaw/sentinel
```

Or for local development:
```bash
cd openclaw-sentinel
npm install && npm run build
# Add to openclaw.json plugins.entries
```

## Configuration

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "sentinel": {
        "enabled": true,
        "config": {
          "alertChannel": "signal",
          "alertTo": "+14085551234",
          "pollIntervalMs": 30000,
          "enableProcessMonitor": true,
          "enableFileIntegrity": true,
          "enableNetworkMonitor": true,
          "trustedSigningIds": [
            "com.apple.",
            "com.google.Chrome",
            "com.microsoft."
          ],
          "trustedPaths": [
            "/usr/bin/",
            "/usr/sbin/",
            "/bin/",
            "/sbin/",
            "/System/"
          ]
        }
      }
    }
  }
}
```

## Agent Tools

Sentinel registers three tools available to your OpenClaw agent:

### `sentinel_status`
Get current monitoring status — active state, known hosts/ports, event counts.

### `sentinel_query`
Run ad-hoc osquery SQL queries for security investigation.
```
"Show me all processes listening on external ports"
→ sentinel_query: SELECT lp.port, p.name, p.path FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.address != '127.0.0.1';
```

### `sentinel_events`
Retrieve recent security events with optional severity/category filters.

## How it works

Sentinel runs in **event-driven mode** for near real-time alerting:

1. **Baseline learning** — On first start, learns your normal state (known SSH hosts, listening ports)
2. **osqueryd daemon** — Starts osqueryd with scheduled queries that write results to a JSON log
3. **Log tailing** — Watches the results log via `fs.watch()` + 2-second poll fallback
4. **Analysis** — Evaluates each result batch against detection rules as it arrives
5. **Instant alerting** — High/critical events trigger immediate alerts via OpenClaw (typically < 1 second from detection)
6. **In-memory event log** — All events stored for agent query access

```
osqueryd (daemon)
    ↓ writes JSON results to log file
    ↓
Sentinel watcher (fs.watch + poll)
    ↓ parses new lines instantly
    ↓
Analyzer (detection rules)
    ↓ severity >= high?
    ↓
OpenClaw messaging → Signal/Slack/Telegram/etc.
```

### Detection rules

- **Unsigned binaries**: Any process without Apple platform signing or a known signing ID
- **Privilege escalation**: Processes where effective UID (0/root) differs from real UID
- **Suspicious commands**: Pattern matching for reverse shells, encoded payloads, pipe-to-shell
- **SSH anomalies**: Logins from IPs not in the known hosts baseline (Tailscale 100.x.x.x auto-trusted)
- **Persistence**: New or modified LaunchDaemons/LaunchAgents
- **Critical files**: Changes to /etc/sudoers, /etc/hosts, /etc/ssh/sshd_config, /etc/passwd
- **Network**: New externally-bound listening ports not in the baseline

## Development

```bash
git clone https://github.com/sunil-sadasivan/openclaw-sentinel.git
cd openclaw-sentinel
npm install
npm run build
npm run dev  # watch mode
```

## License

MIT

## Author

[Sunil Sadasivan](https://github.com/sunil-sadasivan) / [Libra Labs LLC](https://libralabs.dev)
