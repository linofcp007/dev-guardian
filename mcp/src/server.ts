#!/usr/bin/env node
/**
 * dev-guardian MCP server — entry point.
 *
 * Boot sequence:
 *   1. Resolve project_path (defaults to process.cwd()).
 *   2. Open SQLite at `<project_root>/.guardian/guardian.db` (or temp
 *      fallback), apply migrations.
 *   3. Probe a usable bash. Failure is fatal-for-scripts but the server
 *      still starts so resources and pure-SQL tools can serve data.
 *   4. Reap any scans left in `running` by a previous lifetime.
 *   5. Add `.guardian/` to the target project's `.gitignore` if missing.
 *   6. Build the McpServer, attach the registered TOOLS and RESOURCES.
 *   7. Connect the stdio transport. Block until the host closes it.
 *
 * The bootstrap never logs to stdout — that channel belongs to the MCP
 * JSON-RPC stream. Everything diagnostic goes to stderr (visible to the
 * host's plugin manager, hidden from the client conversation).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PluginContext } from './context.js';
import { ensureGuardianIgnored } from './gitignoreGuard.js';
import { probeShell } from './platform/shellProbe.js';
import type { ProgressNotifier, ProgressPayload } from './progress/progressEmitter.js';
import { openDatabase, Storage } from './storage/index.js';
import { attachAllResources } from './resources/index.js';
import { attachAllTools, TOOLS } from './tools/index.js';
import { RESOURCES } from './resources/index.js';

// Side-effect imports: each tool/resource file calls `registerToolModule` /
// `registerResourceModule` at import time. Listing them here is what makes
// them visible to the server. Phases 6–12 will append more.
import './tools/securityScanFull.js';
import './tools/scanSast.js';
import './tools/scanSecrets.js';
import './tools/scanDeps.js';
import './tools/scanContainers.js';
import './tools/scanIac.js';
import './tools/bugHunt.js';
import './tools/qualityCheck.js';
import './tools/reviewPr.js';
import './tools/depsAudit.js';
import './tools/depsUpdatePlan.js';
import './tools/complianceCheck.js';
import './tools/generateSbom.js';
import './tools/detectStack.js';
import './tools/initProject.js';
import './tools/observabilitySetup.js';
import './tools/perfCheck.js';
import './tools/setBaseline.js';
import './tools/suppressFinding.js';
import './tools/diffScans.js';
import './tools/auditExecutive.js';
import './tools/checkToolchain.js';
import './tools/installToolchain.js';
// Phase 14 extras:
import './tools/licenseCompatibility.js';
import './tools/riskScore.js';
import './tools/sbomDiff.js';
import './tools/regressionAlert.js';
import './tools/suggestFix.js';
import './tools/triageFindings.js';
import './tools/precommitInstall.js';
import './tools/registerCustomRules.js';
import './tools/healthStatus.js';
import './tools/reportExport.js';
import './tools/complianceEvidence.js';
import './tools/createGithubIssues.js';
import './tools/installHostContext.js';
// WordPress + .NET (Phase 15):
import './tools/scanWordpress.js';
import './tools/wpAudit.js';
import './tools/wpVulnCheck.js';
// Phase 16 — extended WP / .NET / cross-cutting:
import './tools/wpCronAudit.js';
import './tools/wpRecommendHardening.js';
import './tools/wpPluginCheck.js';
import './tools/wpRestAudit.js';
import './tools/bulkAuditWordpressSites.js';
import './tools/wpDescribeSetup.js';
import './tools/scanDotnetSecrets.js';
import './tools/dotnetTargetFrameworkCheck.js';
import './tools/dotnetEfcoreAudit.js';
import './tools/dotnetDescribeSetup.js';
import './tools/prioritizeFindings.js';
// AI-agent supply chain (Phase 17):
import './tools/scanSkill.js';

import './resources/scans.js';
import './resources/findings.js';
import './resources/misc.js';
import './resources/wp.js';
import './resources/dotnet.js';

const SERVER_NAME = 'dev-guardian';
const SERVER_VERSION = '0.1.0';

async function main(): Promise<void> {
  const projectPath = resolve(process.cwd());

  const { db, path: dbPath, warning: storageWarning } = openDatabase({ projectPath });
  const storage = new Storage(db);
  logErr(`db opened: ${dbPath}`);
  if (storageWarning) logErr(`db warning: ${storageWarning}`);

  // Reap any scans left running by a previous process.
  const reaped = storage.scans.reapRunning();
  if (reaped > 0) logErr(`reaped ${reaped} orphaned scan(s)`);

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

  // Ensure .guardian/ is git-ignored in the target project.
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

  installShutdownHooks(mcp, storage);

  await mcp.connect(new StdioServerTransport());
  logErr('listening on stdio');
}

function resolveScriptsDir(): string {
  // server.js (built) lives at  <plugin>/mcp/dist/server.js
  // server.ts (dev)    lives at  <plugin>/mcp/src/server.ts
  // From either, `../../scripts` resolves to <plugin>/scripts.
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '..', '..', 'scripts');
}

function installShutdownHooks(mcp: McpServer, storage: Storage): void {
  const shutdown = (signal: string): void => {
    logErr(`received ${signal}; shutting down`);
    try {
      storage.close();
    } catch {
      /* ignore */
    }
    void mcp.close().finally(() => {
      process.exit(0);
    });
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

function logErr(line: string): void {
  process.stderr.write(`[dev-guardian] ${line}\n`);
}

main().catch((err) => {
  logErr(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
