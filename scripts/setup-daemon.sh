#!/bin/bash
#
# setup-daemon.sh — Install osqueryd as a system daemon for OpenClaw Sentinel
#
# Usage: sudo ./scripts/setup-daemon.sh [--uninstall]
#
# Supports macOS (launchd) and Linux (systemd).
# Starts osqueryd on boot with Sentinel's config.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }

# ── Detect OS ──
OS="$(uname -s)"
case "$OS" in
  Darwin) INIT_SYSTEM="launchd" ;;
  Linux)
    if command -v systemctl &>/dev/null; then
      INIT_SYSTEM="systemd"
    else
      error "Linux detected but systemd not found. Only systemd is supported."
      exit 1
    fi
    ;;
  *)
    error "Unsupported OS: $OS"
    exit 1
    ;;
esac

# ── Common: find osqueryd ──
find_osqueryd() {
  local candidates=(
    /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd  # macOS .pkg
    /usr/local/bin/osqueryd
    /opt/homebrew/bin/osqueryd
    /usr/bin/osqueryd
    /usr/sbin/osqueryd
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  done
}

# ── Common: find user and sentinel dir ──
find_sentinel_dir() {
  local real_user="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
  if [[ -z "$real_user" ]]; then
    error "Cannot determine the real user. Run with: sudo $0"
    exit 1
  fi

  local real_home
  if [[ "$OS" == "Darwin" ]]; then
    real_home=$(dscl . -read "/Users/$real_user" NFSHomeDirectory | awk '{print $2}')
  else
    real_home=$(getent passwd "$real_user" | cut -d: -f6)
  fi

  echo "$real_user" "$real_home" "${real_home}/.openclaw/sentinel"
}

# ── Common: create dirs and config ──
setup_sentinel_dir() {
  local sentinel_dir="$1"

  mkdir -p "$sentinel_dir/config"
  mkdir -p "$sentinel_dir/db"
  mkdir -p "$sentinel_dir/logs/osquery"

  local config_file="$sentinel_dir/config/osquery.conf"
  if [[ ! -f "$config_file" ]]; then
    warn "No osquery config found — generating default"

    # Try to use the Node.js config generator (single source of truth)
    if command -v node &>/dev/null && [[ -f "$REPO_DIR/dist/osquery.js" ]]; then
      node -e "
        import('file://$REPO_DIR/dist/osquery.js').then(m => {
          const config = m.generateOsqueryConfig({});
          process.stdout.write(JSON.stringify(config, null, 2));
        });
      " > "$config_file" 2>/dev/null && {
        info "Generated $config_file (from plugin source)"
        return
      }
    fi

    # Fallback: inline config
    cat > "$config_file" << 'OSQUERY_CONF'
{
  "options": {
    "logger_plugin": "filesystem",
    "disable_events": "false",
    "events_expiry": "3600",
    "events_max": "100000"
  },
  "schedule": {
    "process_events": {
      "query": "SELECT pid, path, cmdline, uid, euid, username, signing_id, team_id, platform_binary, event_type, time FROM es_process_events WHERE event_type = 'exec';",
      "interval": 30,
      "description": "Process execution events from Endpoint Security"
    },
    "logged_in_users": {
      "query": "SELECT type, user, host, time, pid FROM logged_in_users;",
      "interval": 60,
      "description": "Currently logged-in users"
    },
    "listening_ports": {
      "query": "SELECT lp.port, lp.address, lp.protocol, p.name, p.path, p.cmdline FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port > 0;",
      "interval": 120,
      "description": "Listening network ports with process info"
    },
    "failed_auth": {
      "query": "SELECT time, message FROM asl WHERE facility = 'auth' AND level <= 3 AND (message LIKE '%authentication error%' OR message LIKE '%Failed password%' OR message LIKE '%Invalid user%') ORDER BY time DESC LIMIT 50;",
      "interval": 60,
      "description": "Failed authentication attempts"
    },
    "launch_daemons": {
      "query": "SELECT name, path, program, program_arguments, run_at_load FROM launchd WHERE path LIKE '/Library/LaunchDaemons/%' OR path LIKE '/Library/LaunchAgents/%';",
      "interval": 300,
      "description": "LaunchDaemons and LaunchAgents"
    },
    "shell_history": {
      "query": "SELECT uid, command, time FROM shell_history WHERE command LIKE '%sudo%' OR command LIKE '%chmod%' OR command LIKE '%chown%' ORDER BY time DESC LIMIT 20;",
      "interval": 60,
      "description": "Shell commands involving privilege changes"
    },
    "ssh_keys": {
      "query": "SELECT uid, path, encrypted FROM user_ssh_keys;",
      "interval": 300,
      "description": "SSH keys on the system"
    },
    "open_sockets": {
      "query": "SELECT p.name, p.path, pos.remote_address, pos.remote_port, pos.local_port, pos.protocol FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid WHERE pos.remote_address != '' AND pos.remote_address != '127.0.0.1' AND pos.remote_address != '::1' AND pos.remote_address != '0.0.0.0' LIMIT 50;",
      "interval": 120,
      "description": "Outbound network connections"
    }
  },
  "decorators": {
    "load": ["SELECT hostname FROM system_info;"]
  }
}
OSQUERY_CONF
    info "Generated $config_file (inline fallback)"
  fi
}

# ── Common: kill existing manual osqueryd ──
kill_existing() {
  local sentinel_dir="$1"
  if [[ -f "$sentinel_dir/osqueryd.pid" ]]; then
    local old_pid
    old_pid=$(cat "$sentinel_dir/osqueryd.pid" 2>/dev/null || echo "")
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      warn "Killing existing osqueryd (pid $old_pid)..."
      kill "$old_pid" 2>/dev/null || true
      sleep 1
    fi
  fi
}

# ════════════════════════════════════════════
# macOS (launchd)
# ════════════════════════════════════════════

PLIST_NAME="com.openclaw.osqueryd"
PLIST_DEST="/Library/LaunchDaemons/${PLIST_NAME}.plist"
PLIST_TEMPLATE="${REPO_DIR}/launchd/${PLIST_NAME}.plist"

launchd_uninstall() {
  echo "Uninstalling osqueryd daemon (launchd)..."
  if launchctl list "$PLIST_NAME" &>/dev/null; then
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
    info "Daemon stopped"
  fi
  if [[ -f "$PLIST_DEST" ]]; then
    rm "$PLIST_DEST"
    info "Removed $PLIST_DEST"
  fi
  echo "Done."
}

launchd_install() {
  local osqueryd="$1" sentinel_dir="$2"

  if [[ ! -f "$PLIST_TEMPLATE" ]]; then
    error "Plist template not found: $PLIST_TEMPLATE"
    exit 1
  fi

  # Stop existing
  if launchctl list "$PLIST_NAME" &>/dev/null; then
    warn "Stopping existing daemon..."
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
  fi

  # Install plist
  sed \
    -e "s|__OSQUERYD_PATH__|${osqueryd}|g" \
    -e "s|__SENTINEL_DIR__|${sentinel_dir}|g" \
    "$PLIST_TEMPLATE" > "$PLIST_DEST"

  chmod 644 "$PLIST_DEST"
  chown root:wheel "$PLIST_DEST"
  info "Installed $PLIST_DEST"

  # Load
  launchctl load "$PLIST_DEST"
  sleep 2

  if launchctl list "$PLIST_NAME" &>/dev/null; then
    info "osqueryd daemon is running (launchd)"
  else
    error "Daemon failed to start. Check: $sentinel_dir/logs/osqueryd-stderr.log"
    exit 1
  fi

  echo ""
  echo -e "${GREEN}Done!${NC} osqueryd is running as a launchd daemon."
  echo ""
  echo "Important: Grant Full Disk Access to osqueryd for Endpoint Security:"
  echo "  System Settings → Privacy & Security → Full Disk Access"
  echo "  Add: $osqueryd"
  echo ""
  echo "Commands:"
  echo "  Status:    sudo launchctl list $PLIST_NAME"
  echo "  Stop:      sudo launchctl unload $PLIST_DEST"
  echo "  Start:     sudo launchctl load $PLIST_DEST"
  echo "  Uninstall: sudo $0 --uninstall"
  echo "  Logs:      tail -f $sentinel_dir/logs/osquery/osqueryd.results.log"
}

# ════════════════════════════════════════════
# Linux (systemd)
# ════════════════════════════════════════════

SYSTEMD_UNIT="openclaw-osqueryd"
SYSTEMD_DEST="/etc/systemd/system/${SYSTEMD_UNIT}.service"
SYSTEMD_TEMPLATE="${REPO_DIR}/systemd/${SYSTEMD_UNIT}.service"

systemd_uninstall() {
  echo "Uninstalling osqueryd daemon (systemd)..."
  if systemctl is-active "$SYSTEMD_UNIT" &>/dev/null; then
    systemctl stop "$SYSTEMD_UNIT"
    info "Daemon stopped"
  fi
  if systemctl is-enabled "$SYSTEMD_UNIT" &>/dev/null; then
    systemctl disable "$SYSTEMD_UNIT"
    info "Daemon disabled"
  fi
  if [[ -f "$SYSTEMD_DEST" ]]; then
    rm "$SYSTEMD_DEST"
    systemctl daemon-reload
    info "Removed $SYSTEMD_DEST"
  fi
  echo "Done."
}

systemd_install() {
  local osqueryd="$1" sentinel_dir="$2"

  if [[ ! -f "$SYSTEMD_TEMPLATE" ]]; then
    error "Systemd template not found: $SYSTEMD_TEMPLATE"
    exit 1
  fi

  # Stop existing
  if systemctl is-active "$SYSTEMD_UNIT" &>/dev/null; then
    warn "Stopping existing daemon..."
    systemctl stop "$SYSTEMD_UNIT"
  fi

  # Install unit
  sed \
    -e "s|__OSQUERYD_PATH__|${osqueryd}|g" \
    -e "s|__SENTINEL_DIR__|${sentinel_dir}|g" \
    "$SYSTEMD_TEMPLATE" > "$SYSTEMD_DEST"

  chmod 644 "$SYSTEMD_DEST"
  info "Installed $SYSTEMD_DEST"

  systemctl daemon-reload
  systemctl enable "$SYSTEMD_UNIT"
  systemctl start "$SYSTEMD_UNIT"

  sleep 2

  if systemctl is-active "$SYSTEMD_UNIT" &>/dev/null; then
    info "osqueryd daemon is running (systemd)"
  else
    error "Daemon failed to start. Check: journalctl -u $SYSTEMD_UNIT"
    exit 1
  fi

  echo ""
  echo -e "${GREEN}Done!${NC} osqueryd is running as a systemd service."
  echo ""
  echo "Commands:"
  echo "  Status:    sudo systemctl status $SYSTEMD_UNIT"
  echo "  Stop:      sudo systemctl stop $SYSTEMD_UNIT"
  echo "  Start:     sudo systemctl start $SYSTEMD_UNIT"
  echo "  Logs:      journalctl -u $SYSTEMD_UNIT -f"
  echo "  Uninstall: sudo $0 --uninstall"
}

# ════════════════════════════════════════════
# Main
# ════════════════════════════════════════════

# Handle --uninstall
if [[ "${1:-}" == "--uninstall" ]]; then
  if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)"
    exit 1
  fi
  case "$INIT_SYSTEM" in
    launchd) launchd_uninstall ;;
    systemd) systemd_uninstall ;;
  esac
  exit 0
fi

# Preflight
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root (sudo)"
  echo "  Usage: sudo $0"
  exit 1
fi

# Find osqueryd
OSQUERYD=$(find_osqueryd)
if [[ -z "$OSQUERYD" ]]; then
  error "osqueryd not found."
  echo "  Install from: https://osquery.io/downloads"
  echo "  macOS: download the .pkg installer"
  echo "  Linux: see https://osquery.io/downloads/official"
  exit 1
fi
info "Found osqueryd: $OSQUERYD"

# Find sentinel dir
read -r REAL_USER REAL_HOME SENTINEL_DIR <<< "$(find_sentinel_dir)"
info "User: $REAL_USER"
info "Sentinel dir: $SENTINEL_DIR"
info "Init system: $INIT_SYSTEM"

# Setup
setup_sentinel_dir "$SENTINEL_DIR"
kill_existing "$SENTINEL_DIR"

# Install
case "$INIT_SYSTEM" in
  launchd) launchd_install "$OSQUERYD" "$SENTINEL_DIR" ;;
  systemd) systemd_install "$OSQUERYD" "$SENTINEL_DIR" ;;
esac
