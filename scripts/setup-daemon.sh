#!/bin/bash
#
# setup-daemon.sh — Install osqueryd as a launchd daemon for OpenClaw Sentinel
#
# Usage: sudo ./scripts/setup-daemon.sh [--uninstall]
#
# This creates a system LaunchDaemon that starts osqueryd on boot
# and keeps it running. Sentinel watches the osqueryd result logs.
#

set -euo pipefail

PLIST_NAME="com.openclaw.osqueryd"
PLIST_DEST="/Library/LaunchDaemons/${PLIST_NAME}.plist"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
TEMPLATE="${REPO_DIR}/launchd/${PLIST_NAME}.plist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }

# ── Uninstall ──
if [[ "${1:-}" == "--uninstall" ]]; then
    echo "Uninstalling osqueryd daemon..."
    if launchctl list "$PLIST_NAME" &>/dev/null; then
        launchctl unload "$PLIST_DEST" 2>/dev/null || true
        info "Daemon stopped"
    fi
    if [[ -f "$PLIST_DEST" ]]; then
        rm "$PLIST_DEST"
        info "Removed $PLIST_DEST"
    fi
    echo "Done. osqueryd daemon removed."
    exit 0
fi

# ── Preflight checks ──
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)"
    echo "  Usage: sudo $0"
    exit 1
fi

if [[ ! -f "$TEMPLATE" ]]; then
    error "Plist template not found: $TEMPLATE"
    exit 1
fi

# Find osqueryd
OSQUERYD=""
for candidate in \
    /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd \
    /opt/homebrew/bin/osqueryd \
    /usr/local/bin/osqueryd \
    /usr/bin/osqueryd; do
    if [[ -x "$candidate" ]]; then
        OSQUERYD="$candidate"
        break
    fi
done

if [[ -z "$OSQUERYD" ]]; then
    error "osqueryd not found. Install from https://osquery.io/downloads"
    exit 1
fi

info "Found osqueryd: $OSQUERYD"

# Find the user's sentinel directory
# Look for the user who ran sudo
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
if [[ -z "$REAL_USER" ]]; then
    error "Cannot determine the real user. Run with: sudo $0"
    exit 1
fi

REAL_HOME=$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory | awk '{print $2}')
SENTINEL_DIR="${REAL_HOME}/.openclaw/sentinel"

info "User: $REAL_USER"
info "Sentinel dir: $SENTINEL_DIR"

# Create sentinel directories
mkdir -p "$SENTINEL_DIR/config"
mkdir -p "$SENTINEL_DIR/db"
mkdir -p "$SENTINEL_DIR/logs/osquery"

# Generate osquery config if it doesn't exist
CONFIG_FILE="$SENTINEL_DIR/config/osquery.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    warn "No osquery config found — generating default"
    cat > "$CONFIG_FILE" << 'OSQUERY_CONF'
{
  "options": {
    "logger_plugin": "filesystem",
    "disable_events": "false",
    "disable_endpointsecurity": "false",
    "events_expiry": "3600",
    "events_max": "100000"
  },
  "schedule": {
    "process_events": {
      "query": "SELECT pid, path, cmdline, uid, time, signing_id FROM es_process_events WHERE time > (strftime('%s','now') - 60);",
      "interval": 30,
      "description": "Process execution events from Endpoint Security"
    },
    "logged_in_users": {
      "query": "SELECT * FROM logged_in_users;",
      "interval": 60,
      "description": "Currently logged in users"
    },
    "listening_ports": {
      "query": "SELECT lp.port, lp.protocol, lp.address, p.name, p.path FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port > 0;",
      "interval": 120,
      "description": "Listening network ports"
    },
    "failed_auth": {
      "query": "SELECT time, message FROM asl WHERE facility = 'auth' AND level <= 3 AND time > (strftime('%s','now') - 120);",
      "interval": 60,
      "description": "Failed authentication attempts"
    },
    "launch_daemons": {
      "query": "SELECT name, path, program, program_arguments, run_at_load FROM launchd WHERE path LIKE '/Library/LaunchDaemons/%' OR path LIKE '/Library/LaunchAgents/%';",
      "interval": 300,
      "description": "LaunchDaemons and LaunchAgents"
    },
    "ssh_keys": {
      "query": "SELECT * FROM user_ssh_keys;",
      "interval": 300,
      "description": "SSH keys on the system"
    }
  }
}
OSQUERY_CONF
    info "Generated $CONFIG_FILE"
fi

# ── Stop existing daemon if running ──
if launchctl list "$PLIST_NAME" &>/dev/null; then
    warn "Stopping existing daemon..."
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
fi

# Also kill any manually-started osqueryd using our sentinel dir
if [[ -f "$SENTINEL_DIR/osqueryd.pid" ]]; then
    OLD_PID=$(cat "$SENTINEL_DIR/osqueryd.pid" 2>/dev/null || echo "")
    if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
        warn "Killing existing osqueryd (pid $OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
fi

# ── Install plist ──
sed \
    -e "s|__OSQUERYD_PATH__|${OSQUERYD}|g" \
    -e "s|__SENTINEL_DIR__|${SENTINEL_DIR}|g" \
    "$TEMPLATE" > "$PLIST_DEST"

chmod 644 "$PLIST_DEST"
chown root:wheel "$PLIST_DEST"

info "Installed $PLIST_DEST"

# ── Load daemon ──
launchctl load "$PLIST_DEST"

# Verify it started
sleep 2
if launchctl list "$PLIST_NAME" &>/dev/null; then
    info "osqueryd daemon is running"
else
    error "Daemon failed to start. Check: $SENTINEL_DIR/logs/osqueryd-stderr.log"
    exit 1
fi

echo ""
echo -e "${GREEN}Done!${NC} osqueryd is running as a system daemon."
echo ""
echo "Important: Grant Full Disk Access to osqueryd for Endpoint Security:"
echo "  System Settings → Privacy & Security → Full Disk Access"
echo "  Add: $OSQUERYD"
echo ""
echo "Commands:"
echo "  Status:    sudo launchctl list $PLIST_NAME"
echo "  Stop:      sudo launchctl unload $PLIST_DEST"
echo "  Start:     sudo launchctl load $PLIST_DEST"
echo "  Uninstall: sudo $0 --uninstall"
echo "  Logs:      tail -f $SENTINEL_DIR/logs/osquery/osqueryd.results.log"
