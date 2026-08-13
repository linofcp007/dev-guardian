# dev-guardian MCP server

Stdio MCP server that exposes the dev-guardian plugin's security, quality,
bugfix, deps, compliance, observability, and performance capabilities as
**52 MCP tools** and **18 MCP resources**.

The server is registered in the plugin manifest at
`.claude-plugin/plugin.json` under `mcpServers.dev-guardian` — Claude Code
and Claude Desktop will discover and launch it automatically once the
plugin is installed.

## Layout

```
mcp/
├── src/
│   ├── server.ts                # entry point (stdio transport)
│   ├── tools/                   # 52 MCP tool handlers + scan-tool factory
│   ├── resources/               # 18 MCP resources (guardian://…)
│   ├── runners/                 # process + shell + scanner-parser registry
│   ├── storage/                 # better-sqlite3 + migrations
│   ├── platform/                # OS / shell / pkg-mgr / path detection
│   ├── fingerprint/             # stable finding fingerprint (cross-platform)
│   ├── treeHash/                # working-tree hash (git + fallback walk)
│   ├── severity/                # severity filter helpers
│   └── progress/                # MCP notifications/progress emitter
├── test/
│   ├── unit/                    # ~150 tests against modules in isolation
│   ├── integration/             # ~40 tests against the registry + storage
│   └── e2e/                     # real-scanner test (skipped without scanners)
└── scripts/
    ├── copy-assets.mjs          # post-build: copies .sql to dist/
    └── smoke.mjs                # stdio handshake check (initialize + tools/list)
```

## Build, run, test

```bash
# Install deps (Node 20+ required)
cd mcp && npm install

# Type-check
npm run typecheck

# Build (tsc + copy SQL migrations into dist/)
npm run build

# Run unit + integration tests
npm test

# Smoke-test the built server over stdio
npm run build && node scripts/smoke.mjs

# Dev loop without rebuilding
npm run dev    # tsx src/server.ts
```

## How the plugin host launches it

`.claude-plugin/plugin.json` carries this block:

```jsonc
{
  "mcpServers": {
    "dev-guardian": {
      "command": "node",
      "args": ["${CLAUDE_PLUGIN_ROOT}/mcp/dist/server.js"]
    }
  }
}
```

When the host loads the plugin, it spawns `node mcp/dist/server.js` and
communicates with it over stdio JSON-RPC.

On startup the server:

1. Opens `<project_root>/.guardian/guardian.db` (or falls back to a temp
   location with a warning if that directory is not writable).
2. Runs forward-only SQL migrations.
3. Probes a usable bash (Git Bash → WSL → PATH bash on Windows;
   `/bin/bash` → PATH bash on POSIX) and caches the choice in
   `runtime_meta`.
4. Reaps any scans left `running` from a previous lifetime.
5. Adds `.guardian/` to the target project's `.gitignore` if missing.
6. Connects the stdio transport and registers all tools + resources.

## Storage model

Single SQLite file at `<project_root>/.guardian/guardian.db`:

| Table              | Purpose                                                       |
|--------------------|---------------------------------------------------------------|
| `scans`            | One row per scan invocation (any tool).                       |
| `findings`         | One row per finding instance, keyed by stable fingerprint.    |
| `cves`             | CVE rows deduped across scans (Trivy fs output).              |
| `suppressions`     | False-positive marks (with optional TTL).                     |
| `baselines`        | Regression baselines (history-preserving; latest = active).   |
| `tree_cache`       | tree_hash → scan_id helper for the 5-minute cache window.     |
| `stack_snapshots`  | Persisted `detect_stack` outputs.                             |
| `runtime_meta`     | Server-level KV (chosen shell, etc.).                         |
| `schema_meta`      | Migration version.                                            |

## Tools (52)

This grouping covers a subset, kept for illustration; it is not exhaustive. The root
[`README.md`](../README.md) carries the complete, current tool table.

Grouped by category:

- **Security (6)**: `security_scan_full`, `scan_sast`, `scan_secrets`,
  `scan_deps`, `scan_containers`, `scan_iac`
- **Quality / Bugs (3)**: `bug_hunt`, `quality_check`, `review_pr`
- **Deps (2)**: `deps_audit`, `deps_update_plan`
- **Compliance (2)**: `compliance_check`, `generate_sbom`
- **Ops (4)**: `detect_stack`, `init_project`, `observability_setup`,
  `perf_check`
- **Meta (4)**: `audit_executive`, `diff_scans`, `suppress_finding`,
  `set_baseline`
- **Toolchain (2)**: `check_toolchain`, `install_toolchain`

## Resources (18)

This list covers a subset, kept for illustration; it is not exhaustive. The root
[`README.md`](../README.md) carries the complete, current resource list.

```
guardian://scans/latest
guardian://scans/history
guardian://scans/{scan_id}
guardian://findings/open
guardian://findings/critical
guardian://findings/by-severity/{level}
guardian://cves/active
guardian://sbom
guardian://stack
guardian://compliance/status
guardian://baseline
```

All return JSON. Resources with missing data return an explicit empty
shape (`{ last_run: null }`, `{ active: false }`, etc.) rather than an
error — see the spec at `.specs/dev-guardian-mcp/requirements.md`
(US-7 AC-2).

## Cross-platform notes

- **Windows**: the server probes `wsl bash` → `Git Bash` → `bash.exe` and
  caches the working choice. WSL paths are translated automatically
  (`C:\Users\foo` → `/mnt/c/Users/foo`). Without any of those, the server
  still boots but every script-invoking tool returns a `no_bash_shell`
  domain error so resources stay queryable.
- **macOS / Linux**: prefers `/bin/bash`, falls back to `PATH bash`.
- **Output cap**: every spawned process is bounded to 5 MB of stdout; over
  that, the tool returns `output_too_large` with the report paths so the
  scan data is still recoverable from disk.

## Files outside `mcp/` that this server touches

By design (see US-12 AC-1 in the spec), the MCP server **only** writes to:

- `mcp/**` (its own source / dist / node_modules)
- `<project_root>/.guardian/**` (DB + reports)
- `<project_root>/.gitignore` (one-shot, to add `.guardian/` if missing)

`scripts/`, `configs/`, `skills/`, `commands/` are read-only from the
server's perspective.

## Adding a new scan tool

1. Add a parser under `src/runners/scannerParsers/<scanner>.ts` if the
   scanner emits a new format.
2. Create `src/tools/<myTool>.ts`, call `makeScanTool({...})` with the
   factory.
3. Side-effect import the new file in `src/server.ts`.
4. Drop fixture JSON and an integration test alongside the existing ones
   under `test/integration/`.

That's it — caching, persistence, progress notifications, severity
filtering, fingerprinting, and the MCP wrapper all come for free.
