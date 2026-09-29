/**
 * `health_status` — server diagnostics. Useful when something feels off
 * and the model wants to introspect.
 *
 * Reports:
 *   - uptime (process)
 *   - ONE project's last scan + how long ago, and how many scans it has
 *     (`project_path`, default: the server's working directory)
 *   - DB file path + size
 *   - chosen shell label
 *   - concurrency limiter state
 *   - count of registered tools / resources
 *
 * The scan fields used to be `scans.getLatest()` and `listHistory(1000)`:
 * the newest scan of whichever project scanned last, and a count of every
 * project's scans capped at 1000. One database holds every project, so
 * "last scan: 2 minutes ago" was routinely another project's (Task 24).
 */

import { existsSync, statSync } from 'node:fs';
import type { PluginContext } from '../context.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { resolveVersion } from '../platform/version.js';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import { RESOURCES } from '../resources/index.js';
import { serverProjectPath } from '../resources/paging.js';
import { ProjectPath } from '../schemas.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, TOOLS, type ToolModule } from './index.js';

const startedAt = Date.now();

// Same shared resolver server.ts and report/sarif.ts already use — was a
// second hardcoded '0.1.0' here, independent of (and just as stale as) the
// one report/sarif.ts carried; resolved once, not per call, same "read
// once, reuse many times" shape as those two.
const SERVER_VERSION = resolveVersion();

const tool: ToolModule = {
  name: 'health_status',
  title: 'Server health',
  description:
    'Return server uptime, DB info, shell choice, in-flight scan count, tool/resource counts, and ' +
    "one project's last scan and scan count (project_path, default: the server's working " +
    'directory). Read-only.',
  inputSchema: { project_path: ProjectPath },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string };
  // A diagnostic must answer even when the server runs somewhere no scan
  // would (a home directory): only an EXPLICIT path is validated.
  let projectPath: string;
  if (inp.project_path === undefined || inp.project_path.length === 0) {
    projectPath = serverProjectPath();
  } else {
    try {
      projectPath = resolveProjectPath(inp.project_path).path;
    } catch (e) {
      return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
    }
  }
  const latest = ctx.storage.scans.getLatestForProject(projectPath);
  const limiter = getScanLimiter();
  const dbPath = (ctx.storage as unknown as { rawHandle: () => { name: string } })
    .rawHandle()
    .name;
  let dbSizeBytes: number | null = null;
  if (dbPath && dbPath !== ':memory:' && existsSync(dbPath)) {
    try {
      dbSizeBytes = statSync(dbPath).size;
    } catch {
      /* ignore */
    }
  }

  return {
    ok: true,
    server: {
      name: 'dev-guardian',
      version: SERVER_VERSION,
      uptime_seconds: Math.floor((Date.now() - startedAt) / 1000),
      node_version: process.version,
      platform: process.platform,
    },
    project_path: projectPath,
    storage: {
      db_path: dbPath,
      db_size_bytes: dbSizeBytes,
      // This project's scans, any status and type — never another project's.
      total_scans: ctx.storage.scans.countForProject(projectPath),
      ...(ctx.storage.runtimeMeta.get('shell_choice') !== null
        ? { shell_label: ctx.shell?.label ?? 'unknown' }
        : {}),
    },
    last_scan: latest
      ? {
          scan_id: latest.scan_id,
          scan_type: latest.scan_type,
          started_at: latest.started_at,
          age_seconds: Math.floor((Date.now() - new Date(latest.started_at).getTime()) / 1000),
          status: latest.status,
        }
      : null,
    concurrency: {
      in_flight: limiter.inFlight,
      queued: limiter.queued,
    },
    registry: {
      tools: TOOLS.length,
      resources: RESOURCES.length,
    },
    storage_warning: ctx.storageWarning ?? null,
    suppressions: activeSuppressions(ctx, projectPath),
  };
}

/**
 * The suppressions active now that apply to `projectPath`: its own, and
 * those with no project, which match EVERY project (rows written before
 * migration 011, and whatever an older build still inserts). A database a
 * user trusts is theirs, so those are legitimate — but a mass suppression is
 * how findings disappear without a trace, so how many apply is said here.
 */
function activeSuppressions(
  ctx: PluginContext,
  projectPath: string,
): { active: number; this_project: number; all_projects: number } {
  let own = 0;
  let global = 0;
  for (const s of ctx.storage.suppressions.listActive()) {
    if (s.project_path === undefined) global += 1;
    else if (s.project_path === projectPath) own += 1;
  }
  return { active: own + global, this_project: own, all_projects: global };
}
