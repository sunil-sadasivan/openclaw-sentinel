# AGENTS.md — openclaw-sentinel

## Version Consistency Rule

When bumping the version, **ALL THREE files must match**:

1. `package.json` → `"version": "X.Y.Z"`
2. `openclaw.plugin.json` → `"version": "X.Y.Z"`
3. `src/index.ts` → `Config v{X.Y.Z}:` log line

Never publish or push with mismatched versions.

## Config Key Naming

- Config keys use **camelCase** (e.g. `clawAssess`, `alertChannel`)
- The `clawAssess` key enables the 🦞 one-line assessment on alerts
- Config schema lives in `openclaw.plugin.json` under `configSchema`
- Runtime config is read from `api.getConfig()` merged with `~/.openclaw/openclaw.json`

## Build & Deploy

```bash
npm run build          # TypeScript → dist/
npm test               # Run test suite
npm publish --otp=XXX  # Publish to npm (requires TOTP)
```

After local changes, copy to the running extension:
```bash
cp -r dist/* ~/.openclaw/extensions/sentinel/dist/
cp package.json ~/.openclaw/extensions/sentinel/package.json
cp openclaw.plugin.json ~/.openclaw/extensions/sentinel/openclaw.plugin.json
```

Then restart the gateway to reload.

## Git Workflow

- **Never push directly to `main`.** Branch off main, push, open PR.
- Branch naming: `claw/<descriptive-name>`
- Sunil reviews and merges.

## Architecture

- `src/index.ts` — Plugin entry point, event routing, alert dispatch, `clawAssessEvent()`
- `src/analyzer.ts` — Event analysis, `formatAlert()`, `safeAgentPatterns`
- `src/alerts.ts` — Alert dedup, rate limiting, suppression store
- `src/log-stream.ts` — Real-time log stream watchers (SSH, sudo, screen sharing, user accounts, suspicious commands)
- `src/watcher.ts` — osquery result log watcher (fs.watch)
- `src/osquery.ts` — osqueryi query runner
- `src/config.ts` — Config types and defaults
- `src/persistence.ts` — Event persistence (JSON file)

## Alert Delivery

Alerts are sent via `openclaw message send` CLI. The `clawAssess` feature calls `openclaw agent --agent main --message <prompt> --json` to get a one-line 🦞 assessment appended to each alert.

## Testing

```bash
npm test  # Jest test suite
```

Tests are in `src/__tests__/`. Currently 92+ tests covering analyzers, query safety, log stream parsers, and alert logic.
