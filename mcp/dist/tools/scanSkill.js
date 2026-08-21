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
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { InvalidProjectPathError, resolveProjectPath } from '../platform/projectPath.js';
import { toSarif } from '../report/sarif.js';
import { filterFindings } from '../severity/filter.js';
import { analyzeSkill } from '../skillaudit/analyze.js';
import { ingestTarget } from '../skillaudit/ingest.js';
import { RECOMMENDATIONS, THREAT_CATEGORY_META, } from '../skillaudit/taxonomy.js';
import { SeverityMin } from '../schemas.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    target: z
        .string()
        .min(1)
        .optional()
        .describe('What to vet: a local directory, a single file, a .zip, or a git/HTTP(S) URL. ' +
        'Defaults to the current project directory (audit the skill you are standing in).'),
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
        .describe('If set, the result `passed` flag is false when the recommendation is at or worse than this ' +
        'band (e.g. fail_on="CAUTION"). Lets a caller gate installs.'),
};
const RECOMMENDATION_TEXT = {
    SAFE: 'No significant risk signals. Safe to install after a normal review.',
    REVIEW: 'Minor signals found. Skim the flagged items before installing.',
    CAUTION: 'Multiple risk signals. Install only from a trusted author and only after reviewing each finding.',
    DO_NOT_INSTALL: 'High-risk signals detected. Do not install unless every finding has a clear, benign explanation.',
};
const RECOMMENDATION_RANK = {
    SAFE: 0,
    REVIEW: 1,
    CAUTION: 2,
    DO_NOT_INSTALL: 3,
};
const tool = {
    name: 'scan_skill',
    title: 'Vet an AI skill / MCP server / agent before install',
    description: 'Security-audit a third-party AI agent skill, MCP server, or agent artifact BEFORE installing it. ' +
        'Accepts a directory, file, .zip, or git/HTTP(S) URL. Detects prompt injection, data exfiltration, ' +
        'privilege escalation, supply-chain risk, excessive agency, output-handling issues, system-prompt ' +
        'leakage, memory poisoning, tool misuse, rogue-agent behaviour, trigger abuse, dangerous code, ' +
        'taint flows, signature matches, and MCP least-privilege / tool-poisoning — plus OSV.dev CVE ' +
        'lookups on declared dependencies. Returns a 0-100 risk score and an install recommendation ' +
        '(SAFE / REVIEW / CAUTION / DO_NOT_INSTALL).',
    inputSchema,
    handler: (input, ctx, callMeta) => handler(input, ctx, callMeta),
};
registerToolModule(tool);
async function handler(input, ctx, callMeta) {
    const inp = input;
    // Resolve where reports + the DB live (current project / cwd).
    let basePath;
    try {
        basePath = resolveProjectPath(undefined).path;
    }
    catch (e) {
        if (e instanceof InvalidProjectPathError)
            basePath = process.cwd();
        else
            throw e;
    }
    const target = inp.target ?? basePath;
    const ingest = await ingestTarget(target);
    if (!ingest.ok) {
        return { ok: false, error: { code: ingest.code, message: ingest.message } };
    }
    try {
        const analyzeOpts = {
            checkDeps: inp.check_deps !== false,
        };
        if (callMeta?.signal)
            analyzeOpts.signal = callMeta.signal;
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
            ctx.storage.findings.bulkInsert(report.findings.map((f) => ({ ...f, scan_id: scanId })));
        }
        const reportPaths = [];
        if (inp.write_reports !== false) {
            const outDir = join(basePath, '.guardian', 'reports', `skill-audit-${scanId.slice(0, 8)}`);
            try {
                mkdirSync(outDir, { recursive: true });
                const sarifPath = join(outDir, 'report.sarif');
                const jsonPath = join(outDir, 'report.json');
                writeFileSync(sarifPath, toSarif(findings, { toolName: 'guardian-scanskill' }), 'utf8');
                writeFileSync(jsonPath, JSON.stringify({
                    target,
                    kind: ingest.kind,
                    risk_score: report.score.score,
                    recommendation: report.score.recommendation,
                    category_breakdown: report.category_breakdown,
                    osv: report.osv,
                    findings,
                }, null, 2), 'utf8');
                reportPaths.push(outDir);
            }
            catch {
                /* report writing is best-effort */
            }
        }
        const toolsRun = [
            { name: 'guardian-scanskill:patterns', status: 'ok' },
            { name: 'guardian-scanskill:yara', status: 'ok' },
            { name: 'guardian-scanskill:taint', status: 'ok' },
        ];
        if (report.osv) {
            toolsRun.push({
                name: 'osv.dev',
                status: report.osv.online ? 'ok' : 'skipped',
                ...(report.osv.online ? {} : { reason: report.osv.error ?? 'offline' }),
            });
        }
        ctx.storage.scans.finalize({
            scan_id: scanId,
            status: 'completed',
            tools_run: toolsRun,
            missing_tools: [],
            ...(reportPaths[0] ? { report_dir: reportPaths[0] } : {}),
            meta: {
                risk_score: report.score.score,
                recommendation: report.score.recommendation,
                target,
                kind: ingest.kind,
                category_breakdown: report.category_breakdown,
                files_scanned: report.files_scanned,
                executable_files: report.executable_files,
                osv_online: report.osv?.online ?? null,
                osv_vulnerable_packages: report.osv?.vulnerable_packages.length ?? 0,
            },
        });
        const passed = inp.fail_on === undefined
            ? true
            : RECOMMENDATION_RANK[report.score.recommendation] < RECOMMENDATION_RANK[inp.fail_on];
        return {
            ok: true,
            scan_id: scanId,
            target,
            kind: ingest.kind,
            risk_score: report.score.score,
            recommendation: report.score.recommendation,
            recommendation_text: RECOMMENDATION_TEXT[report.score.recommendation],
            passed,
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
                    vulnerable_packages: report.osv.vulnerable_packages.length,
                    ...(report.osv.error ? { error: report.osv.error } : {}),
                }
                : null,
            report_paths: reportPaths,
            warnings: ingest.warnings,
        };
    }
    finally {
        ingest.cleanup();
    }
}
function nonZeroBreakdown(breakdown) {
    const out = [];
    for (const [category, count] of Object.entries(breakdown)) {
        if (count > 0) {
            const meta = THREAT_CATEGORY_META[category];
            out.push({ category, label: meta?.label ?? category, count });
        }
    }
    return out.sort((a, b) => b.count - a.count);
}
function topFindings(findings, limit) {
    const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return [...findings]
        .sort((a, b) => order[b.severity] - order[a.severity] || a.fingerprint.localeCompare(b.fingerprint))
        .slice(0, limit);
}
function hashFiles(parts) {
    const h = createHash('sha256');
    for (const p of [...parts].sort())
        h.update(p).update('\n');
    return h.digest('hex').slice(0, 32);
}
//# sourceMappingURL=scanSkill.js.map