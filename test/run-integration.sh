#!/bin/bash
#
# Integration test: full end-to-end validation of sentinel plugin
# Runs natively (no Docker required). Needs: node, osqueryi
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
pass() { echo -e "${GREEN}✅ $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; exit 1; }

cd "$REPO_DIR"

echo "=== 1. Build ==="
npm run build && pass "TypeScript compiled" || fail "Build failed"

echo ""
echo "=== 2. Unit tests ==="
node --test dist/__tests__/alerts.test.js dist/__tests__/analyzer.test.js && pass "Unit tests passed" || fail "Unit tests failed"

echo ""
echo "=== 3. Watcher test ==="
node --test dist/__tests__/watcher.test.js && pass "Watcher tests passed" || fail "Watcher tests failed"

echo ""
echo "=== 4. osquery available ==="
OSQUERYI=$(which osqueryi 2>/dev/null || echo "")
if [[ -z "$OSQUERYI" ]]; then
  # Try common paths
  for p in /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryi /opt/homebrew/bin/osqueryi /usr/local/bin/osqueryi; do
    [[ -x "$p" ]] && OSQUERYI="$p" && break
  done
fi
if [[ -n "$OSQUERYI" ]]; then
  VERSION=$("$OSQUERYI" --version 2>&1 | head -1)
  pass "osqueryi found: $VERSION"
else
  fail "osqueryi not found"
fi

echo ""
echo "=== 5. osqueryi queries work ==="
RESULT=$("$OSQUERYI" --json "SELECT version FROM osquery_info;" 2>/dev/null)
if echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); process.exit(d[0]?.version ? 0 : 1)"; then
  pass "osqueryi query execution works"
else
  fail "osqueryi query failed"
fi

echo ""
echo "=== 6. Config generation (single source of truth) ==="
CONFIG_FILE="$TEST_DIR/osquery.conf"
node -e "
  import { generateOsqueryConfig } from './dist/osquery.js';
  const config = generateOsqueryConfig({});
  const json = JSON.stringify(config, null, 2);
  process.stdout.write(json);
" > "$CONFIG_FILE" 2>/dev/null
QUERY_COUNT=$(node -e "const c=JSON.parse(require('fs').readFileSync('$CONFIG_FILE','utf8')); console.log(Object.keys(c.schedule).length)")
if [[ "$QUERY_COUNT" -ge 7 ]]; then
  pass "Config generated with $QUERY_COUNT scheduled queries"
else
  fail "Config only has $QUERY_COUNT queries (expected 7+)"
fi

echo ""
echo "=== 7. Plugin manifest valid ==="
node -e "
  import { readFileSync } from 'fs';
  const m = JSON.parse(readFileSync('openclaw.plugin.json', 'utf-8'));
  if (!m.id) throw new Error('missing id');
  if (!m.configSchema) throw new Error('missing configSchema');
  if (!m.skills?.length) throw new Error('missing skills');
  const props = Object.keys(m.configSchema.properties).length;
  console.log('  id:', m.id, '| version:', m.version, '| schema props:', props, '| skills:', m.skills.join(', '));
" && pass "Manifest valid" || fail "Manifest invalid"

echo ""
echo "=== 8. Skill file exists ==="
if [[ -f skills/sentinel/SKILL.md ]]; then
  LINES=$(wc -l < skills/sentinel/SKILL.md)
  pass "SKILL.md present ($LINES lines)"
else
  fail "SKILL.md missing"
fi

echo ""
echo "=== 9. Persistence end-to-end ==="
node -e "
  import { EventStore } from './dist/persistence.js';
  const store = new EventStore('$TEST_DIR/persist');
  const evt = {
    id: 'test-1', timestamp: Date.now(), severity: 'high',
    category: 'auth', title: 'Test', description: 'test',
    details: {}, hostname: 'test'
  };
  await store.append(evt);
  await store.append({ ...evt, id: 'test-2' });
  await store.append({ ...evt, id: 'test-3' });
  const loaded = await store.loadRecent(10);
  if (loaded.length !== 3) throw new Error('Expected 3, got ' + loaded.length);
  console.log('  Wrote 3 events, loaded 3 back');
" && pass "Persistence works" || fail "Persistence failed"

echo ""
echo "=== 10. Watcher end-to-end (fake log) ==="
WATCHER_DIR="$TEST_DIR/watcher"
mkdir -p "$WATCHER_DIR"
touch "$WATCHER_DIR/osqueryd.results.log"
node -e "
  import { ResultLogWatcher } from './dist/watcher.js';
  import { appendFileSync } from 'fs';

  const watcher = new ResultLogWatcher('$WATCHER_DIR');
  const results = [];
  watcher.on('result', r => results.push(r));
  
  await watcher.start();
  await new Promise(r => setTimeout(r, 200));

  // Simulate osqueryd writing results
  const events = [
    { name: 'logged_in_users', columns: { host: '203.0.113.42', user: 'root' }, action: 'added' },
    { name: 'listening_ports', columns: { port: '4444', name: 'nc' }, action: 'added' },
  ];
  for (const e of events) {
    appendFileSync('$WATCHER_DIR/osqueryd.results.log', JSON.stringify(e) + '\n');
  }

  await new Promise(r => setTimeout(r, 3000));
  watcher.stop();

  if (results.length === 2) {
    console.log('  Picked up 2 events from fake log');
  } else {
    throw new Error('Expected 2 results, got ' + results.length);
  }
" && pass "Watcher live-tailing works" || fail "Watcher live-tailing failed"

echo ""
echo "=== 11. Analyzer integration (fake events → alerts) ==="
node -e "
  import { analyzeProcessEvents, analyzeLoginEvents, analyzeFailedAuth, analyzeListeningPorts, analyzeFileEvents, formatAlert } from './dist/analyzer.js';

  // Unsigned binary
  let events = analyzeProcessEvents([
    { path: '/tmp/evil', cmdline: '/tmp/evil', uid: '501', euid: '501', signing_id: '', platform_binary: '0', username: 'test' }
  ], { trustedPaths: ['/usr/bin/'], trustedSigningIds: ['com.apple.'] });
  if (events.length !== 1) throw new Error('Process: expected 1, got ' + events.length);
  
  // Unknown SSH
  events = analyzeLoginEvents([
    { user: 'root', host: '185.220.101.1', type: 'user' }
  ], new Set(['192.168.1.1']));
  if (events.length !== 1) throw new Error('Login: expected 1, got ' + events.length);
  
  // Brute force
  events = analyzeFailedAuth(Array.from({length: 15}, () => ({ time: '0', message: 'Failed password' })));
  if (events[0].severity !== 'critical') throw new Error('Brute force should be critical');
  
  // New port
  events = analyzeListeningPorts([
    { port: '4444', name: 'nc', path: '/usr/bin/nc', address: '0.0.0.0' }
  ], new Set([22, 80]));
  if (events.length !== 1) throw new Error('Port: expected 1, got ' + events.length);
  
  // Persistence
  events = analyzeFileEvents([
    { filename: '/Library/LaunchDaemons/com.evil.plist', event_type: 'created', path: '/usr/bin/cp', pid: '1' }
  ]);
  if (events.length !== 1) throw new Error('File: expected 1, got ' + events.length);
  
  // Format
  const alert = formatAlert(events[0]);
  if (!alert.includes('SENTINEL')) throw new Error('Format missing SENTINEL header');
  
  console.log('  All 5 analyzer modules produced correct results');
" && pass "Analyzer integration works" || fail "Analyzer failed"

echo ""
echo "=== 12. Alert rate limiting ==="
node -e "
  import { shouldAlert, meetsThreshold, createAlertState } from './dist/alerts.js';
  
  const state = createAlertState();
  const now = Date.now();
  const evt = (title) => ({
    id: 'x', timestamp: now, severity: 'high', category: 'auth',
    title, description: '', details: {}, hostname: 'test'
  });
  
  // Dedup
  if (!shouldAlert(evt('Same'), state, now)) throw new Error('First should pass');
  if (shouldAlert(evt('Same'), state, now + 1000)) throw new Error('Dedup should block');
  
  // Rate limit
  const state2 = createAlertState();
  for (let i = 0; i < 10; i++) shouldAlert(evt('E' + i), state2, now);
  if (shouldAlert(evt('E11'), state2, now)) throw new Error('Rate limit should block');
  if (!shouldAlert(evt('E12'), state2, now + 61000)) throw new Error('Should pass after 1min');
  
  // Severity threshold
  if (!meetsThreshold('critical', 'high')) throw new Error('critical >= high');
  if (meetsThreshold('medium', 'high')) throw new Error('medium < high');
  if (!meetsThreshold('info', 'info')) throw new Error('info >= info');
  
  console.log('  Dedup, rate limiting, and severity thresholds all correct');
" && pass "Rate limiting works" || fail "Rate limiting failed"

echo ""
echo "=== 13. Setup script syntax check ==="
bash -n scripts/setup-daemon.sh && pass "setup-daemon.sh syntax valid" || fail "setup-daemon.sh has syntax errors"

echo ""
echo "=== 14. npm pack (publishable) ==="
TARBALL=$(npm pack --dry-run 2>&1 | grep "\.tgz" | head -1 | awk '{print $NF}')
if [[ -n "$TARBALL" ]]; then
  FILE_COUNT=$(npm pack --dry-run 2>&1 | grep -c "^npm" || echo "0")
  pass "npm pack would produce: $TARBALL"
else
  fail "npm pack failed"
fi

echo ""
echo "======================================="
echo -e "${GREEN}✅ All 14 integration tests passed!${NC}"
echo "======================================="
