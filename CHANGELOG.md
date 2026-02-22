# Changelog

## [0.2.0] - 2026-02-23

### Added
- **Real-time sudo monitoring** — detects `sudo` commands and sessions via `/var/log/system.log` tail. Catches privilege escalation in sub-second, replacing 60s `shell_history` polling.
- **Screen sharing / VNC detection** — monitors `screensharingd` via unified log stream for authentication attempts, VNC connections, and client connections (high severity).
- **User account change detection** — monitors `opendirectoryd` for user creation (critical), deletion (high), and password changes (high).
- **Dual-source macOS SSH monitoring** — `/var/log/system.log` tail for successful logins + unified `log stream` for failed auth (PAM errors). Fixes broken unified-log-only approach (sshd doesn't emit auth events to unified logging on macOS).
- **Expanded SSH failure patterns** — catches PAM auth errors, unknown users, invalid users, and failed keyboard-interactive attempts.
- **Platform-aware osquery config** — macOS-specific tables (es_process_events, launchd, asl) vs Linux-specific (process_events, syslog, systemd_units, crontab).
- **Linux parity for real-time monitoring**:
  - sudo commands + PAM sessions via `journalctl -u sudo`
  - User account changes via `useradd`/`userdel`/`usermod`/`passwd`/`groupadd` syslog identifiers
  - RDP/VNC detection via `xrdp`/`xrdp-sesman`/`x11vnc`/`Xvnc` journal units
  - All flow through the same analyzer → alert pipeline as macOS equivalents

### Fixed
- **Alert delivery** — replaced non-existent `api.sendMessage()` with `openclaw message send` CLI.
- **Config loading** — fallback to reading `~/.openclaw/openclaw.json` when `api.getConfig()` returns incomplete data.
- **CLI flag** — `--target` not `--to` for `openclaw message send`.

### Changed
- SSH failed auth events skip dedup — every attempt generates an alert.
- Alert dedup window reduced from 5 min to 1 min.
- `logged_in_users` osquery poll interval: 60s → 10s (backup detection).
- Tailscale/known host SSH logins generate info-level events (previously skipped).

## [0.1.0] - 2026-02-21

### Added
- Initial release
- osquery-based security monitoring (poll-based)
- Agent tools: `sentinel_status`, `sentinel_query`, `sentinel_events`
- Signal alert delivery
- macOS + Linux support
