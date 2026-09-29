/**
 * `scan_deps` — dependency CVE + license scan.
 *
 * Runs Trivy fs with both `vuln` and `license` scanners and writes the
 * JSON report to `.guardian/reports/deps-<scan>/deps.json`. The Trivy
 * parser splits the output into Findings (one per vulnerability + one per
 * risky license) plus CVE rows the factory persists into `cves`.
 *
 * Stack-specific deeper audits (`npm audit`, `pip-audit`, etc.) live in
 * `deps_audit` (Phase 7) so they can also report fix counts.
 *
 * `packages` (`/guardian-postinstall`: "what did the packages I just added
 * bring in?") narrows the RESPONSE to those packages, like `bug_hunt`'s
 * `categories`: dependencies are resolved per manifest and lockfile, so Trivy
 * still reads the whole project, and every finding is still recorded. A named
 * package with no finding is listed as such — which is "Trivy reported
 * nothing for it", never "it was verified clean".
 *
 * The project's `.guardianignore` reaches Trivy as `--skip-dirs` /
 * `--skip-files` (`platform/guardianIgnore.ts`), so the lockfiles of a
 * deliberately vulnerable fixture tree are not read at all.
 */

import { join } from 'node:path';
import { z } from 'zod';
import { dependencyCoordinates } from '../fingerprint/findingIdentity.js';
import { trivySkipArgs } from '../platform/guardianIgnore.js';
import { trivyParser } from '../runners/scannerParsers/trivy.js';
import { judgeTrivyFs, runTrivy } from '../runners/trivyRun.js';
import { Force, ProjectPath, SeverityMin } from '../schemas.js';
import type { Finding, ToolRun } from '../types.js';
import { registerToolModule } from './index.js';
import {
  ensureReportDir,
  readJsonSafe,
  scannerAvailable,
} from './scanHelpers.js';
import {
  makeScanTool,
  type ResponseView,
  type ScannerInvocation,
  type ScanToolBaseInput,
} from './scanToolFactory.js';

type ScanDepsInput = ScanToolBaseInput & { packages?: string[] };

registerToolModule(
  makeScanTool<ScanDepsInput>({
    name: 'scan_deps',
    title: 'Dependency vuln + license scan',
    description:
      'Run Trivy fs with vuln+license scanners. Findings carry CVE id, severity, ' +
      'and fix version; CVEs are also indexed for the guardian://cves/active resource. ' +
      '`packages` narrows the response to those packages (every finding is still recorded; ' +
      '`package_filter` counts what was withheld and names requested packages with no finding). ' +
      '.guardianignore paths are excluded from the results, and skipped by Trivy where they can be ' +
      'named exactly.',
    scan_type: 'deps',
    category: 'security',
    supportsAutoFix: false,
    // `packages` filters the response (see `packagesView`): one scan serves
    // every filter over the same tree.
    responseOnlyInputs: ['packages'],
    responseView: (input, findings, scanId) => packagesView(input.packages, findings, scanId),
    inputSchema: {
      project_path: ProjectPath,
      severity_min: SeverityMin,
      force: Force,
      packages: z
        .array(z.string().min(1).max(214))
        .min(1)
        .max(500)
        .optional()
        .describe(
          'Show only findings for these package names in the response (case-insensitive). Trivy still ' +
            'reads every manifest and the scan records every finding; `package_filter.not_found` names ' +
            'requested packages with no finding.',
        ),
    },
    invoke: async (_input, ctx): Promise<ScannerInvocation> => {
      const reportDir = ensureReportDir(ctx.projectPath, ctx.scanId, 'deps');
      const tools_run: ToolRun[] = [];
      const missing_tools: string[] = [];
      const parser_inputs: ScannerInvocation['parser_inputs'] = [];

      const trivyBin = await scannerAvailable('trivy');
      if (!trivyBin) {
        tools_run.push({ name: 'trivy', status: 'skipped', reason: 'not_installed' });
        missing_tools.push('trivy');
        return {
          outcome: 'completed',
          tools_run,
          missing_tools,
          parser_inputs,
          report_paths: [reportDir],
        };
      }

      const outFile = join(reportDir, 'deps.json');
      // Never in the project, never its trivy.yaml (runners/trivyRun.ts).
      const result = await runTrivy({
        args: ['fs', '--scanners', 'vuln,license', '--format', 'json', '--output', outFile, '--quiet', ...trivySkipArgs(ctx.exclusions)],
        target: ctx.projectPath,
        workDir: reportDir,
        ignoreFrom: ctx.projectPath,
        env: ctx.scriptEnv,
        signal: ctx.signal,
        onLog: ctx.onLog,
      });

      const raw = readJsonSafe(outFile);
      if (raw) parser_inputs.push({ parser: trivyParser, input: raw });

      // The one judgement scan_deps, deps_audit and scan_wordpress share
      // (runners/trivyRun.ts#judgeTrivyFs): every manifest in the tree Trivy
      // read nothing for is a named gap.
      const judged = judgeTrivyFs({ projectPath: ctx.projectPath, raw, run: result, exclusions: ctx.exclusions });
      tools_run.push(judged.toolRun);
      missing_tools.push(...judged.missing);
      const extras: Record<string, unknown> = {};
      if (judged.gaps.length > 0) extras['manifest_coverage_gaps'] = judged.gaps;

      return {
        outcome: result.outcome,
        tools_run,
        missing_tools,
        parser_inputs,
        report_paths: [reportDir],
        ...(Object.keys(extras).length > 0 ? { extras } : {}),
      };
    },
  }),
);

/** The package a dependency finding is about: a CVE's `pkg@version`, a licence's `pkg:<name>`. */
export function packageOfFinding(f: Finding): string | null {
  const coords = dependencyCoordinates(f);
  if (coords !== null) return coords.name;
  if (f.snippet?.startsWith('pkg:') === true) return f.snippet.slice('pkg:'.length);
  return null;
}

/**
 * `packages` as a view over the stored findings — see the module comment.
 * Null when no filter was asked for. Exported for tests.
 */
export function packagesView(
  packages: readonly string[] | undefined,
  findings: readonly Finding[],
  scanId: string,
): ResponseView | null {
  if (packages === undefined || packages.length === 0) return null;
  const wanted = new Set(packages.map((p) => p.toLowerCase()));
  const found = new Set<string>();
  const visible: Finding[] = [];
  for (const f of findings) {
    const name = packageOfFinding(f)?.toLowerCase();
    if (name !== undefined && wanted.has(name)) {
      visible.push(f);
      found.add(name);
    }
  }
  const withheld = findings.length - visible.length;
  const notFound = packages.filter((p) => !found.has(p.toLowerCase()));
  const notes: string[] = [];
  if (withheld > 0) {
    notes.push(
      `packages ${JSON.stringify(packages)} withheld ${withheld} finding(s) from this response only; they are ` +
        `recorded in scan ${scanId}, and baselines and diffs against it include them.`,
    );
  }
  if (notFound.length > 0) {
    notes.push(
      `No finding for ${notFound.join(', ')}: Trivy reported nothing for them — not vulnerable or ` +
        'licence-flagged, or in no manifest it read. That is not proof the package was scanned.',
    );
  }
  return {
    visible,
    disclosure: { package_filter: { packages: [...packages], withheld, not_found: notFound } },
    warning: notes.length > 0 ? notes.join(' ') : null,
  };
}
