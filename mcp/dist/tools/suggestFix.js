/**
 * `suggest_fix` — gather context for the calling model to synthesise a
 * patch.
 *
 * IMPORTANT: this tool does NOT call any LLM. The CALLING model (the one
 * that triggered the tool) is the AI. Our job is to assemble the
 * structured context it needs to write a good fix:
 *
 *   - the finding itself (rule, severity, message, snippet)
 *   - the surrounding source code (±20 lines around the finding)
 *   - any prior fixes for the same rule_id, derived from suppressions
 *     metadata and history
 *   - links to docs (OWASP / CWE when in the rule metadata)
 *
 * The model then proposes the patch in its response. This separation
 * keeps us LLM-agnostic and free.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
const inputSchema = {
    project_path: ProjectPath,
    finding_fingerprint: z
        .string()
        .regex(/^[0-9a-f]{64}$/)
        .describe('Fingerprint of the finding to gather context for.'),
    context_lines: z
        .number()
        .int()
        .min(0)
        .max(200)
        .optional()
        .describe('How many lines of source context to include around the finding. Default 20.'),
};
const tool = {
    name: 'suggest_fix',
    title: 'Gather fix context for the model',
    description: 'Assemble structured context about a finding (source snippet, surrounding lines, rule metadata, ' +
        'prior suppressions for the same rule_id) so the calling model can propose a patch. This tool ' +
        'never calls an external LLM — the model that invoked it does the synthesis.',
    inputSchema,
    handler: async (input, ctx) => handler(input, ctx),
};
registerToolModule(tool);
async function handler(input, ctx) {
    const inp = input;
    let projectPath;
    try {
        projectPath = resolveProjectPath(inp.project_path).path;
    }
    catch (e) {
        return failDomain('not_a_git_repo', e.message);
    }
    const contextLines = inp.context_lines ?? 20;
    // Locate the finding via the latest scan that carries it.
    const latest = ctx.storage.scans.getLatest();
    const finding = latest
        ? ctx.storage.findings
            .listByScan(latest.scan_id)
            .find((f) => f.fingerprint === inp.finding_fingerprint)
        : null;
    if (!finding) {
        return failDomain('unknown_scan_id', `Finding ${inp.finding_fingerprint} not in the latest scan.`);
    }
    // Pull the surrounding source.
    let surrounding_source = null;
    let source_start_line = 0;
    let source_end_line = 0;
    if (finding.file_path) {
        const abs = join(projectPath, finding.file_path);
        if (existsSync(abs)) {
            try {
                const raw = readFileSync(abs, 'utf8');
                const lines = raw.split(/\r?\n/);
                const start = Math.max(0, (finding.line_start ?? 1) - 1 - contextLines);
                const end = Math.min(lines.length, (finding.line_end ?? finding.line_start ?? 1) + contextLines);
                source_start_line = start + 1;
                source_end_line = end;
                const slice = lines.slice(start, end);
                surrounding_source = slice
                    .map((l, i) => {
                    const lineNo = start + 1 + i;
                    const marker = lineNo >= (finding.line_start ?? -1) && lineNo <= (finding.line_end ?? -1)
                        ? '>>'
                        : '  ';
                    return `${marker} ${String(lineNo).padStart(5)}: ${l}`;
                })
                    .join('\n');
            }
            catch {
                /* swallow */
            }
        }
    }
    // Prior suppressions for the same rule_id (historical "we've decided this
    // is fine" pattern) — useful for the model to know "the team has
    // suppressed similar findings; consider that pattern".
    const priorSuppressions = finding.rule_id
        ? ctx.storage.suppressions
            .listActive()
            .filter((s) => s.finding_fingerprint !== finding.fingerprint)
            .slice(0, 10)
        : [];
    return {
        ok: true,
        finding: {
            fingerprint: finding.fingerprint,
            tool: finding.tool,
            rule_id: finding.rule_id ?? null,
            severity: finding.severity,
            category: finding.category,
            subcategory: finding.subcategory ?? null,
            title: finding.title,
            message: finding.message ?? null,
            file_path: finding.file_path ?? null,
            line_range: finding.line_start !== undefined
                ? { start: finding.line_start, end: finding.line_end ?? finding.line_start }
                : null,
        },
        surrounding_source,
        source_start_line,
        source_end_line,
        prior_related_suppressions: priorSuppressions.map((s) => ({
            reason: s.reason,
            created_at: s.created_at,
            ...(s.expires_at !== undefined ? { expires_at: s.expires_at } : {}),
        })),
        docs_hint: 'If the rule_id or message references CWE/OWASP, link to the official write-up in the proposed fix.',
        instructions_for_model: 'Propose a unified-diff patch (or describe the minimal edit) that addresses this finding ' +
            'without changing unrelated behaviour. Reference the line range, explain the fix, and call out ' +
            'any side effects the maintainer should review.',
    };
}
function failDomain(code, message) {
    return { ok: false, error: { code, message } };
}
//# sourceMappingURL=suggestFix.js.map