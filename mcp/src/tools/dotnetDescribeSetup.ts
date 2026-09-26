/**
 * `dotnet_describe_setup` — analog of wp_describe_setup, for .NET.
 *
 * Aggregates, for ONE project (`project_path`, default: the server's working
 * directory): the latest dotnet_target_framework_check, scan_dotnet_secrets,
 * dotnet_efcore_audit and SAST scan, plus the project's open .NET-relevant
 * findings. Pure read.
 *
 * Every read is project-scoped (Task 24). It used to take "the latest scan
 * of type X" from the 50 newest rows of the whole database, and its findings
 * from `findings.listOpen()` — the single newest completed scan of ANY
 * project and ANY type — so another project's EOL frameworks and SCS
 * findings answered for this one, and an SBOM run afterwards read as "no
 * open findings".
 */

import type { PluginContext } from '../context.js';
import { findLatestUsable, openSetForProject } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import type { ScanRecord, ScanType, ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const tool: ToolModule = {
  name: 'dotnet_describe_setup',
  title: '.NET posture summary',
  description:
    "Aggregate read of one project's accumulated .NET state (project_path, default: the server's " +
    'working directory): latest dotnet_target_framework_check (EOL frameworks), ' +
    'scan_dotnet_secrets, dotnet_efcore_audit, deps_audit if a NuGet lockfile exists. Plus open ' +
    '.NET-relevant findings. No scanner spawn.',
  inputSchema: { project_path: ProjectPath },
  handler: async (input, ctx) => handler(input, ctx),
};

registerToolModule(tool);

async function handler(
  input: Record<string, unknown>,
  ctx: PluginContext,
): Promise<ToolResult<Record<string, unknown>>> {
  const inp = input as { project_path?: string };
  let projectPath: string;
  try {
    projectPath = resolveProjectPath(inp.project_path).path;
  } catch (e) {
    return { ok: false, error: { code: 'not_a_git_repo', message: (e as Error).message } };
  }

  // The target-framework check reports through `meta`, so its scanner
  // coverage does not disqualify it; the others are finding scans, and one
  // that measured nothing is passed over (its zero is not a result).
  const tfm = findLatest(ctx, projectPath, 'dotnet_target_framework', false);
  const secrets = findLatest(ctx, projectPath, 'dotnet_secrets', true);
  const efcore = findLatest(ctx, projectPath, 'dotnet_efcore_audit', true);
  const sastScan = findLatest(ctx, projectPath, 'sast', true);

  const open = openSetForProject(ctx.storage, projectPath).findings;
  const dotnetFindings = open.filter(
    (f) =>
      f.tool === 'security-code-scan' ||
      f.tool === 'scan_dotnet_secrets' ||
      f.tool === 'dotnet_efcore_audit' ||
      f.rule_id?.startsWith('SCS'),
  );

  return {
    ok: true,
    project_path: projectPath,
    audits: {
      target_framework_check: tfm
        ? {
            scan_id: tfm.scan_id,
            project_count:
              (tfm.meta as { project_count?: number } | undefined)?.project_count ?? 0,
            eol_count: (tfm.meta as { eol_count?: number } | undefined)?.eol_count ?? 0,
            legacy_count:
              (tfm.meta as { legacy_count?: number } | undefined)?.legacy_count ?? 0,
          }
        : null,
      secrets_scan: secrets
        ? {
            scan_id: secrets.scan_id,
            files_scanned:
              (secrets.meta as { files_scanned?: number } | undefined)?.files_scanned ?? 0,
            findings_count:
              (secrets.meta as { findings_count?: number } | undefined)?.findings_count ?? 0,
          }
        : null,
      efcore_audit: efcore
        ? {
            scan_id: efcore.scan_id,
            findings_count:
              (efcore.meta as { findings_count?: number } | undefined)?.findings_count ?? 0,
          }
        : null,
      sast_latest: sastScan
        ? {
            scan_id: sastScan.scan_id,
            captured_at: sastScan.started_at,
          }
        : null,
    },
    open_dotnet_findings_count: dotnetFindings.length,
    open_critical: dotnetFindings.filter((f) => f.severity === 'critical').length,
    open_high: dotnetFindings.filter((f) => f.severity === 'high').length,
    recommended_next:
      !tfm ? 'Run `dotnet_target_framework_check` to find EOL frameworks.'
      : !secrets ? 'Run `scan_dotnet_secrets` to find MS-specific secrets in configs.'
      : !efcore ? 'If you use EF Core, run `dotnet_efcore_audit` for risky migration patterns.'
      : dotnetFindings.length > 0 ? 'Open .NET findings exist. Try `triage_findings` + `suggest_fix`.'
      : 'Posture looks clean. Consider running `scan_sast` again if code changed.',
  };
}

/** The project's newest unscoped completed scan of `type` — one project-scoped query. */
function findLatest(
  ctx: PluginContext,
  projectPath: string,
  type: ScanType,
  skipCoverageNone: boolean,
): ScanRecord | null {
  return findLatestUsable(ctx.storage, projectPath, [type], { skipCoverageNone }).scan;
}
