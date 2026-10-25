/**
 * `scan_skill` — vet an AI agent skill / MCP server / agent BEFORE installing
 * it. dev-guardian's answer to the supply-chain question for the agent
 * ecosystem: "is this third-party skill safe to install?" — distinct from the
 * rest of the suite, which audits the code you ship.
 *
 * Accepts a directory, a single file, a .zip, or a git/HTTP(S) URL. Runs the
 * full skill-audit pipeline (pattern rules across 16 threat categories, a
 * YARA-style signature engine, taint-light source→sink, hidden-Unicode
 * detection, MCP manifest checks, and OSV.dev dependency CVE lookups), then
 * rolls everything up into a single 0–100 risk score and an install
 * recommendation (SAFE → DO NOT INSTALL).
 *
 * Standalone tool (not the scan-tool factory): it targets arbitrary
 * artifacts rather than the current git project, so it owns its own target
 * resolution, persistence and report writing.
 */

import { createHash, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { ensureReportDir } from './scanHelpers.js';
import { join } from 'node:path';
import { z } from 'zod';
import type { PluginContext } from '../context.js';
import type { ToolCallMeta } from './index.js';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { toSarif } from '../report/sarif.js';
import { filterFindings } from '../severity/filter.js';
import { analyzeSkill } from '../skillaudit/analyze.js';
import { ingestTarget, type UnreadEntry } from '../skillaudit/ingest.js';
import {
  RECOMMENDATIONS,
  THREAT_CATEGORY_META,
  type Recommendation,
} from '../skillaudit/taxonomy.js';
import { SeverityMin } from '../schemas.js';
import type { ScanCoverage, ToolResult, ToolRun } from '../types.js';
import { defineTool, registerToolModule, type ToolInput } from './index.js';
import { computeCoverage } from './scanCoverage.js';
import { topFindings } from '../severity/counts.js';

const inputSchema = {
  target: z
    .string()
    .min(1)
    .optional()
    .describe(
      'A directory, file, .zip or git/HTTP(S) URL. Default: the current project.',
    ),
  check_deps: z
    .boolean()
    .optional()
    .default(true)
    .describe('Query OSV.dev for known CVEs in declared dependencies (degrades offline).'),
  write_reports: z
    .boolean()
    .optional()
    .default(true)
    .describe('Write report.sarif + report.json under .guardian/reports/ for CI/IDE.'),
  severity_min: SeverityMin,
  fail_on: z
    .enum(RECOMMENDATIONS)
    .optional()
    .describe(
      '`passed` is false when the recommendation is this band or worse.',
    ),
};

const RECOMMENDATION_TEXT: Record<Recommendation, string> = {
  SAFE: 'No significant risk signals. Safe to install after a normal review.',
  REVIEW: 'Minor signals found. Skim the flagged items before installing.',
  CAUTION:
    'Multiple risk signals. Install only from a trusted author and only after reviewing each finding.',
  DO_NOT_INSTALL:
    'High-risk signals detected. Do not install unless every finding has a clear, benign explanation.',
};

const RECOMMENDATION_RANK: Record<Recommendation, number> = {
  SAFE: 0,
  REVIEW: 1,
  CAUTION: 2,
  DO_NOT_INSTALL: 3,
};

const tool = defineTool({
  name: 'scan_skill',
  title: 'Vet an AI skill, MCP server or plugin before install',
  description:
    'Audit a third-party AI skill, MCP server, plugin or agent before installing it (a directory, file, ' +
    '.zip or git/HTTP(S) URL): prompt injection, exfiltration, privilege escalation, excessive agency, ' +
    'tool poisoning, dangerous code, taint flows — the commands in instruction files and hook / plugin / ' +
    'MCP configs scored like scripts — and OSV CVEs of its dependencies. Returns a 0-100 risk score and ' +
    'SAFE, REVIEW, CAUTION or DO_NOT_INSTALL. What it could not read or look up is named in missing_tools ' +
    '(coverage partial), and the verdict is then never SAFE.',
  inputSchema,
  handler: (input, ctx, callMeta) => handler(input, ctx, callMeta),
});

registerToolModule(tool);

async function handler(
  inp: ToolInput<typeof inputSchema>,
  ctx: PluginContext,
  callMeta?: ToolCallMeta,
): Promise<ToolResult<Record<string, unknown>>> {

  // Resolve where reports + the DB live (current project / cwd).
  let basePath: string;
  try {
    basePath = resolveProjectPath(undefined).path;
  } catch (e) {
    if (e instanceof InvalidProjectPathError) basePath = process.cwd();
    else throw e;
  }

  const target = inp.target ?? basePath;

  const ingest = await ingestTarget(target);
  if (!ingest.ok) {
    return { ok: false, error: { code: ingest.code, message: ingest.message } };
  }

  try {
    const analyzeOpts: Parameters<typeof analyzeSkill>[1] = {
      checkDeps: inp.check_deps !== false,
      symlinks: ingest.symlinks,
    };
    if (callMeta?.signal) analyzeOpts.signal = callMeta.signal;
    const report = await analyzeSkill(ingest.files, analyzeOpts);

    const findings = filterFindings(report.findings, inp.severity_min);

    // Persist as a scan so status / trend / diff / report_export see it —
    // which is exactly why what is stored is `report.findings`, not the
    // filtered `findings`. `severity_min` thins THIS reply; a baseline or a
    // diff taken against this scan must still know what the audit found.
    // Same rule, same reason as `scanToolFactory.ts`'s own `bulkInsert` —
    // see the comment there.
    const scanId = randomUUID();
    const treeHash = hashFiles(ingest.files.map((f) => `${f.relPath}:${f.bytes}`));
    ctx.storage.scans.insert({
      scan_id: scanId,
      scan_type: 'skill_audit',
      project_path: target,
      tree_hash: treeHash,
      ...(inp.severity_min !== undefined ? { meta: { severity_min: inp.severity_min } } : {}),
    });
    if (report.findings.length > 0) {
      ctx.storage.findings.bulkInsert(
        report.findings.map((f) => ({ ...f, scan_id: scanId })),
      );
    }

    // What was not read, and what was not looked up, is a named gap — never
    // part of a clean verdict. The score covered only what was read: a
    // package truncated by 4000 decoy files, a payload in a UTF-16 script or
    // a native addon, a dependency past OSV's first 200 all read SAFE before.
    const nothingRead = report.files_scanned === 0;
    const passStatus: ToolRun['status'] = nothingRead ? 'skipped' : 'ok';
    const passReason = nothingRead ? { reason: 'no text file in the target to read' } : {};
    const toolsRun: ToolRun[] = [
      { name: 'guardian-scanskill:patterns', status: passStatus, ...passReason },
      { name: 'guardian-scanskill:yara', status: passStatus, ...passReason },
      { name: 'guardian-scanskill:taint', status: passStatus, ...passReason },
    ];
    const missingTools: string[] = [];
    const gaps: string[] = [];
    if (ingest.truncated) {
      const reason = `the walk stopped at its caps after ${report.files_scanned} files: the rest of the package was not read`;
      toolsRun.push({ name: 'guardian-scanskill:walk', status: 'failed', reason });
      missingTools.push('guardian-scanskill:walk');
      gaps.push(reason);
    }
    if (ingest.unread.length > 0) {
      const reason = unreadSummary(ingest.unread);
      toolsRun.push({ name: 'guardian-scanskill:unread', status: 'failed', reason });
      missingTools.push('guardian-scanskill:unread');
      gaps.push(reason);
    }
    if (report.osv) {
      const osv = report.osv;
      if (!osv.online) {
        const reason = osv.error ?? 'offline';
        toolsRun.push({ name: 'osv.dev', status: 'skipped', reason });
        missingTools.push('osv.dev');
        gaps.push(`dependencies not checked for known CVEs (osv.dev: ${reason})`);
      } else if (osv.unqueried > 0) {
        const reason =
          `${osv.queried} of ${osv.queried + osv.unqueried} declared dependencies looked up; ` +
          `the other ${osv.unqueried} were not`;
        toolsRun.push({ name: 'osv.dev', status: 'ok', reason });
        missingTools.push('osv.dev');
        gaps.push(`osv.dev: ${reason}`);
      } else {
        toolsRun.push({ name: 'osv.dev', status: 'ok' });
      }
    }
    const coverage = computeCoverage(toolsRun, missingTools);
    const recommendation = coverageFloor(report.score.recommendation, coverage);
    const recommendationText =
      recommendation === report.score.recommendation
        ? RECOMMENDATION_TEXT[recommendation]
        : 'Not everything was read or looked up, and the score covers only what was: review what is listed ' +
          'in missing_tools (or vet a copy without it) before installing.';
    const coverageWarning =
      coverage === 'full'
        ? null
        : `⚠️ scan_skill: coverage ${coverage} — ${gaps.join('; ')}. The verdict covers only what was read; ` +
          'it is never SAFE while any of this is unread.';

    const reportPaths: string[] = [];
    if (inp.write_reports !== false) {
      try {
        // A verified real directory of the project's, or a temp one
        // (`ensureReportDir`): never created through a `.guardian` link.
        const outDir = ensureReportDir(basePath, scanId, 'skill-audit');
        const sarifPath = join(outDir, 'report.sarif');
        const jsonPath = join(outDir, 'report.json');
        writeFileSync(sarifPath, toSarif(findings, { toolName: 'guardian-scanskill' }), 'utf8');
        writeFileSync(
          jsonPath,
          JSON.stringify(
            {
              target,
              kind: ingest.kind,
              risk_score: report.score.score,
              recommendation,
              coverage,
              missing_tools: missingTools,
              unread: ingest.unread,
              category_breakdown: report.category_breakdown,
              osv: report.osv,
              findings,
            },
            null,
            2,
          ),
          'utf8',
        );
        reportPaths.push(outDir);
      } catch {
        /* report writing is best-effort */
      }
    }

    ctx.storage.scans.finalize({
      scan_id: scanId,
      status: 'completed',
      tools_run: toolsRun,
      missing_tools: missingTools,
      ...(reportPaths[0] ? { report_dir: reportPaths[0] } : {}),
      meta: {
        risk_score: report.score.score,
        recommendation,
        target,
        kind: ingest.kind,
        category_breakdown: report.category_breakdown,
        files_scanned: report.files_scanned,
        executable_files: report.executable_files,
        unread: ingest.unread,
        osv_online: report.osv?.online ?? null,
        osv_vulnerable_packages: report.osv?.vulnerable_packages.length ?? 0,
      },
    });

    // A gate never passes on a package that was not all read.
    const passed =
      inp.fail_on === undefined
        ? true
        : coverage === 'full' && RECOMMENDATION_RANK[recommendation] < RECOMMENDATION_RANK[inp.fail_on];

    return {
      ok: true,
      scan_id: scanId,
      target,
      kind: ingest.kind,
      risk_score: report.score.score,
      recommendation,
      recommendation_text: recommendationText,
      passed,
      coverage,
      tools_run: toolsRun,
      missing_tools: missingTools,
      ...(ingest.unread.length > 0
        ? { unread: ingest.unread.slice(0, RESPONSE_UNREAD_ENTRIES), unread_total: ingest.unread.length }
        : {}),
      findings_count: findings.length,
      findings_by_severity: report.score.by_severity,
      category_breakdown: nonZeroBreakdown(report.category_breakdown),
      top_findings: topFindings(findings, 12),
      files_scanned: report.files_scanned,
      executable_files: report.executable_files,
      hidden_unicode_files: report.hidden_unicode_files,
      skipped_files: ingest.skipped,
      truncated: ingest.truncated,
      osv: report.osv
        ? {
            online: report.osv.online,
            queried: report.osv.queried,
            ...(report.osv.unqueried > 0 ? { unqueried: report.osv.unqueried } : {}),
            vulnerable_packages: report.osv.vulnerable_packages.length,
            ...(report.osv.error ? { error: report.osv.error } : {}),
          }
        : null,
      report_paths: reportPaths,
      warnings: coverageWarning === null ? ingest.warnings : [coverageWarning, ...ingest.warnings],
    };
  } finally {
    ingest.cleanup();
  }
}

/** How many `unread` entries a response carries; the scan row keeps them all. */
const RESPONSE_UNREAD_ENTRIES = 20;

/** `node_modules/ (installed dependencies…)`, `x.node (native code…)`, … — the first few, and how many in all. */
function unreadSummary(unread: readonly UnreadEntry[]): string {
  const shown = unread.slice(0, 5).map((u) => `${u.relPath} (${u.why})`);
  const more = unread.length > shown.length ? `, and ${unread.length - shown.length} more` : '';
  return `${unread.length} not read: ${shown.join(', ')}${more}`;
}

/**
 * The recommendation once coverage is counted: never SAFE when anything was
 * not read or looked up, and at least CAUTION when nothing was read at all
 * while something was left unread — a package of one native binary.
 */
function coverageFloor(fromScore: Recommendation, coverage: ScanCoverage): Recommendation {
  const floor: Recommendation = coverage === 'none' ? 'CAUTION' : coverage === 'partial' ? 'REVIEW' : 'SAFE';
  return RECOMMENDATION_RANK[fromScore] >= RECOMMENDATION_RANK[floor] ? fromScore : floor;
}

function nonZeroBreakdown(
  breakdown: Record<string, number>,
): Array<{ category: string; label: string; count: number }> {
  const out: Array<{ category: string; label: string; count: number }> = [];
  for (const [category, count] of Object.entries(breakdown)) {
    if (count > 0) {
      const meta = THREAT_CATEGORY_META[category as keyof typeof THREAT_CATEGORY_META];
      out.push({ category, label: meta?.label ?? category, count });
    }
  }
  return out.sort((a, b) => b.count - a.count);
}

function hashFiles(parts: string[]): string {
  const h = createHash('sha256');
  for (const p of [...parts].sort()) h.update(p).update('\n');
  return h.digest('hex').slice(0, 32);
}
