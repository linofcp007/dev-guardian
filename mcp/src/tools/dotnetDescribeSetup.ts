/**
 * `dotnet_describe_setup` — analog of wp_describe_setup, for .NET.
 *
 * Aggregates: latest dotnet_target_framework_check, scan_dotnet_secrets,
 * dotnet_efcore_audit, plus open .NET-relevant findings. Pure read.
 */

import type { PluginContext } from '../context.js';
import type { ToolResult } from '../types.js';
import { registerToolModule, type ToolModule } from './index.js';

const tool: ToolModule = {
  name: 'dotnet_describe_setup',
  title: '.NET posture summary',
  description:
    'Aggregate read of accumulated .NET state: latest dotnet_target_framework_check (EOL frameworks), ' +
    'scan_dotnet_secrets, dotnet_efcore_audit, deps_audit if a NuGet lockfile exists. Plus open ' +
    '.NET-relevant findings. No scanner spawn.',
  inputSchema: {},
  handler: async (_input, ctx) => handler(ctx),
};

registerToolModule(tool);

async function handler(ctx: PluginContext): Promise<ToolResult<Record<string, unknown>>> {
  const tfm = findLatest(ctx, 'dotnet_target_framework');
  const secrets = findLatest(ctx, 'dotnet_secrets');
  const efcore = findLatest(ctx, 'dotnet_efcore_audit');
  const sastScan = findLatest(ctx, 'sast');

  const open = ctx.storage.findings.listOpen();
  const dotnetFindings = open.filter(
    (f) =>
      f.tool === 'security-code-scan' ||
      f.tool === 'scan_dotnet_secrets' ||
      f.tool === 'dotnet_efcore_audit' ||
      f.rule_id?.startsWith('SCS'),
  );

  return {
    ok: true,
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

function findLatest(
  ctx: PluginContext,
  type: string,
): ReturnType<typeof ctx.storage.scans.getById> {
  const history = ctx.storage.scans.listHistory(50);
  const row = history.find((s) => s.scan_type === type && s.status === 'completed');
  return row ? ctx.storage.scans.getById(row.scan_id) : null;
}
