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
 *   - whether the plugin's guardrail hooks started in this session (`hooks`,
 *     `hooks_warning`): the session mark SessionStart leaves, read through
 *     `hooks/heartbeat.ts` — the only reader of it there is
 *   - what the last `dev-guardian selftest` of this install found (`selftest`,
 *     `selftest_warning`): the saved result, validated as it is read
 *     (`selftest/store.ts`) — installed is not detecting
 *
 * The scan fields used to be `scans.getLatest()` and `listHistory(1000)`:
 * the newest scan of whichever project scanned last, and a count of every
 * project's scans capped at 1000. One database holds every project, so
 * "last scan: 2 minutes ago" was routinely another project's (Task 24).
 */

import { existsSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PluginContext } from '../context.js';
import { hooksStatus, hostPidsOf, pluginServerExpected, type HooksStatus } from '../hooks/heartbeat.js';
import { userDataDir } from '../hooks/userDataDir.js';
import { resolveVersion } from '../platform/version.js';
import { getScanLimiter } from '../runners/concurrencyLimiter.js';
import { RESOURCES } from '../resources/index.js';
import { serverProjectPath } from '../resources/paging.js';
import { futureNoteOf } from '../history/openSet.js';
import { ProjectPath } from '../schemas.js';
import { installPaths, selftestCommand } from '../selftest/paths.js';
import { selftestStatus, type SelftestStatus } from '../selftest/store.js';
import type { ToolResult } from '../types.js';
import { defineTool, listedTools, registerToolModule, type ToolInput } from './index.js';
import { toolProjectPath } from './projectArg.js';

const startedAt = Date.now();

// Same shared resolver server.ts and report/sarif.ts already use — was a
// second hardcoded '0.1.0' here, independent of (and just as stale as) the
// one report/sarif.ts carried; resolved once, not per call, same "read
// once, reuse many times" shape as those two.
const SERVER_VERSION = resolveVersion();

const inputSchema = { project_path: ProjectPath };

const tool = defineTool({
  name: 'health_status',
  title: 'Server health',
  description:
    "Server uptime, database, shell, in-flight scans, tool counts, one project's last scan. " +
    'Warnings (or null): `storage_warning` — a per-user fallback is used, not .guardian/guardian.db: the user ' +
    'runs the `db adopt` command it names; never run it yourself. `hooks_warning` — no hook started this ' +
    'session, nothing is guarded (`hooks.state`). `selftest_warning` — a scanner read its canary and reported ' +
    'nothing, 0 findings prove nothing. Tell the user. `suppressions.all_projects` hide findings in every ' +
    'project. `storage.future_dated_scans_ignored`, `future_dated_note`: future-dated scans, in no count.',
  inputSchema,
  handler: async (input, ctx) => handler(input, ctx),
});

registerToolModule(tool);

async function handler(
  inp: ToolInput<typeof inputSchema>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  // A diagnostic must answer even when the server runs somewhere no scan
  // would (a home directory): only an EXPLICIT path is validated.
  const explicit = inp.project_path !== undefined && inp.project_path.length > 0;
  const projectPath = explicit ? toolProjectPath(inp.project_path) : serverProjectPath();
  if (typeof projectPath !== 'string') return projectPath;
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

  const hooks = sessionHooks(ctx);
  const selftest = lastSelftest();

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
      // Scans dated in the future: in no count, list or "latest" here, or anywhere.
      future_dated_scans_ignored: ctx.storage.scans.countFutureDated(projectPath),
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
      tools: listedTools().length,
      resources: RESOURCES.length,
    },
    storage_warning: ctx.storageWarning ?? null,
    hooks: hooks.hooks,
    hooks_warning: hooks.warning,
    selftest: selftest.selftest,
    selftest_warning: selftest.warning,
    ...futureNoteOf(ctx.storage, projectPath),
    suppressions: activeSuppressions(ctx, projectPath),
  };
}

/** A name or a version the client gave of itself: printable ASCII, and short. */
const clientText = (text: string): string => text.replace(/[^ -~]/g, '?').trim().slice(0, 60);

/**
 * Whether the plugin's guardrail hooks started in this session — about the
 * session, so it does not depend on `project_path`. The hooks are expected
 * when Claude Code started this server as the plugin's own
 * (`CLAUDE_PLUGIN_ROOT` names the root it runs from); the session's project is
 * the one Claude Code names, and the host process the one that started this
 * server. A diagnostic must answer: anything that goes wrong here is
 * `unknown`, never a failed call.
 */
function sessionHooks(ctx: PluginContext): { hooks: HooksStatus; warning: string | null } {
  try {
    const named = ctx.clientInfo?.();
    const client = named === undefined ? undefined : { name: clientText(named.name), version: clientText(named.version) };
    const sessionProject = process.env['CLAUDE_PROJECT_DIR']?.trim() ?? '';
    return hooksStatus({
      expected: pluginServerExpected(process.env, dirname(ctx.scriptsDir)),
      dataDir: userDataDir(),
      projectRoot: sessionProject !== '' ? sessionProject : serverProjectPath(),
      hostPids: hostPidsOf(process.env, process.ppid),
      serverStartedAt: startedAt,
      ...(client !== undefined ? { client } : {}),
    });
  } catch (error) {
    return {
      hooks: { state: 'unknown', reason: `the hooks' state could not be read: ${error instanceof Error ? error.message : String(error)}` },
      warning: null,
    };
  }
}

/**
 * What the last `dev-guardian selftest` of this install found — about the
 * machine, so it does not depend on `project_path`. Read from the data
 * directory, validated as it is read (`selftest/store.ts`): no result, or a
 * file that is not one, is `never_run` — with the command line the user runs,
 * this install's own. A result of another plugin version, or an old one, is
 * `stale`. The warning is for a control that read its canary and reported
 * nothing, or that detected in the run before and does not now. A diagnostic
 * must answer: anything that goes wrong here is `never_run` with a note.
 */
function lastSelftest(): { selftest: SelftestStatus; warning: string | null } {
  let command = 'node cli/dev-guardian.mjs selftest';
  try {
    const paths = installPaths();
    command = selftestCommand(paths.cliPath);
    return selftestStatus({ dataDir: userDataDir(), pluginVersion: SERVER_VERSION, command });
  } catch (error) {
    return {
      selftest: {
        state: 'never_run',
        command,
        note: `the saved selftest result could not be read: ${error instanceof Error ? error.message : String(error)}`,
      },
      warning: null,
    };
  }
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
