#!/usr/bin/env node
/**
 * dev-guardian MCP server — entry point.
 *
 * Boot sequence:
 *   0. Refuse to start, with one line on stderr and exit 1, on a Node without
 *      `node:sqlite` (< 22.13) — not a stack trace from deep in module loading.
 *   1. Resolve project_path (defaults to process.cwd()).
 *   2. Open SQLite at `<project_root>/.guardian/guardian.db` (or temp
 *      fallback), apply migrations.
 *   3. Probe a usable bash. Failure is fatal-for-scripts but the server
 *      still starts so resources and pure-SQL tools can serve data.
 *   4. Reap scans whose owning process died (storage/maintenance.ts).
 *      Best-effort: a failure is logged and never stops the server.
 *   5. Keep `.guardian/` out of git in the target project's `.gitignore`
 *      (every `.guardian` directory's contents, at any depth, with its
 *      `baseline.json` re-included — gitignoreGuard.ts).
 *   6. Build the McpServer, attach the registered TOOLS and RESOURCES.
 *   7. Connect the stdio transport. Block until the host closes it. A client
 *      that closes our stdout (EPIPE on the next write) is a disconnect, not
 *      a crash: exit 0.
 *   8. AFTER connecting, schedule scan retention in the background: short
 *      batches under a per-start work budget, so a large backlog never delays
 *      startup (storage/maintenance.ts#scheduleRetention).
 *
 * The bootstrap never logs to stdout — that channel belongs to the MCP
 * JSON-RPC stream. Everything diagnostic goes to stderr (visible to the
 * host's plugin manager, hidden from the client conversation).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { resolve } from 'node:path';
import type { PluginContext } from './context.js';
import { ensureGuardianIgnored } from './gitignoreGuard.js';
import { resolveScriptsDir } from './platform/scriptsDir.js';
import { probeShell } from './platform/shellProbe.js';
import { resolveVersion } from './platform/version.js';
import type { ProgressNotifier, ProgressPayload } from './progress/progressEmitter.js';
import { NODE_SQLITE_REQUIRED, nodeSqliteAvailable } from './storage/db.js';
import { GuardianDbError, openDatabase, Storage } from './storage/index.js';
import { reapOrphanedScans, scheduleRetention } from './storage/maintenance.js';
import { attachAllResources } from './resources/index.js';
import { attachAllTools, TOOLS } from './tools/index.js';
import { RESOURCES } from './resources/index.js';

// Registers every tool + resource (the public MCP surface). See registerAll.ts.
import './registerAll.js';

const SERVER_NAME = 'dev-guardian';

// Single source of truth for the version we report to the host, shared with
// every SARIF `tool.driver.version` this project emits — see
// `platform/version.ts`'s own doc comment for why resolving it needs to try
// two candidate depths, not one.
const SERVER_VERSION = resolveVersion();

async function main(): Promise<void> {
  // storage/db.ts loads node:sqlite lazily precisely so this check can run.
  if (!nodeSqliteAvailable()) {
    process.stderr.write(`${NODE_SQLITE_REQUIRED}
`);
    process.exit(1);
  }

  const projectPath = resolve(process.cwd());

  const { db, path: dbPath, warning: storageWarning } = openDatabase({ projectPath });
  const storage = new Storage(db);
  logErr(`db opened: ${dbPath}`);
  if (storageWarning) logErr(`db warning: ${storageWarning}`);

  // Reap dead processes' scans. Never fatal. (Retention runs after connect.)
  reapOrphanedScans(storage, logErr);

  // Probe a usable shell once; tools read the choice from the cache later.
  const shell = await probeShell(storage.runtimeMeta);
  if (shell === null) {
    logErr(
      'no usable bash found — script-invoking tools will return no_bash_shell. ' +
        'Install Git Bash or WSL, then restart.',
    );
  } else {
    logErr(`shell: ${shell.label}`);
  }

  // Ensure .guardian/ is git-ignored in the target project (baseline.json excepted).
  const guard = ensureGuardianIgnored(projectPath);
  if (guard.updated) logErr(`.gitignore ${guard.reason} for .guardian/`);

  // Build the MCP server.
  const mcp = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  const progressNotifier: ProgressNotifier = {
    send: (payload: ProgressPayload) => {
      // McpServer exposes the underlying low-level Server as `.server`.
      // notifications/progress is what we want; the SDK accepts a plain
      // method+params shape.
      void mcp.server.notification({
        method: 'notifications/progress',
        params: { ...payload },
      });
    },
  };

  const ctx: PluginContext = {
    storage,
    shell,
    scriptsDir: resolveScriptsDir(),
    progressNotifier,
    ...(storageWarning ? { storageWarning } : {}),
  };

  attachAllTools(mcp, ctx);
  attachAllResources(mcp, ctx);
  logErr(`registered ${TOOLS.length} tool(s), ${RESOURCES.length} resource(s)`);

  const background = { cancel: (): void => {} };
  installShutdownHooks(mcp, storage, background);

  await mcp.connect(new StdioServerTransport());
  logErr('listening on stdio');

  background.cancel = scheduleRetention(storage, logErr);
}

function installShutdownHooks(
  mcp: McpServer,
  storage: Storage,
  background: { cancel: () => void },
): void {
  let closing = false;
  const shutdown = (reason: string, closeTransport: boolean): void => {
    if (closing) return;
    closing = true;
    logErr(`${reason}; shutting down`);
    background.cancel();
    try {
      storage.close();
    } catch {
      /* ignore */
    }
    if (!closeTransport) process.exit(0);
    void mcp.close().finally(() => {
      process.exit(0);
    });
  };
  process.on('SIGINT', () => shutdown('received SIGINT', true));
  process.on('SIGTERM', () => shutdown('received SIGTERM', true));

  // The SDK's stdio transport listens for errors on stdin only. When the
  // client closes its end of our stdout, the next write fails with EPIPE, and
  // an 'error' event nobody listens for crashes the process (exit 1, with a
  // stack trace). That is the client disconnecting: shut down cleanly.
  // Nothing more can reach the client, so the transport is not closed first.
  process.stdout.on('error', (error: NodeJS.ErrnoException) => {
    if (error.code === 'EPIPE') {
      shutdown('stdout closed by the client (EPIPE)', false);
      return;
    }
    logErr(`fatal: stdout: ${error.stack ?? error.message}`);
    process.exit(1);
  });
  // stderr is diagnostics only; if it is gone too there is nobody left to tell.
  process.stderr.on('error', () => {});
}

function logErr(line: string): void {
  process.stderr.write(`[dev-guardian] ${line}\n`);
}

main().catch((err) => {
  // A database the server cannot use (corrupt, incomplete, untrusted) is said
  // in its own one line, which names the file and what to do — a stack trace
  // from inside SQLite says neither.
  if (err instanceof GuardianDbError) {
    logErr(`fatal: ${err.message}`);
    process.exit(1);
  }
  logErr(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
