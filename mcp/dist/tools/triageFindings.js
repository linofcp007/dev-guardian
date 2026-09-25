/**
 * `triage_findings` — heuristic suggestions for findings the calling model
 * should consider suppressing.
 *
 * No LLM calls — we apply boring, well-known patterns:
 *   - Findings in test files (`test/`, `tests/`, `__tests__/`, `*.spec.*`)
 *   - Findings in generated / vendored code (`vendor/`, `node_modules/`,
 *     `dist/`, `build/`, `generated/`, `*.min.js`)
 *   - Findings in fixtures / mocks
 *   - Findings already-suppressed-by-fingerprint (just surface them so the
 *     model knows)
 *
 * Output buckets each finding into one of:
 *   - likely_false_positive (high confidence pattern match)
 *   - probably_safe (path-based hint)
 *   - keep (no heuristic fired — model should review)
 *
 * Reads `project_path`'s open set (default: the server's working directory)
 * — every finding-producing scan type's newest usable scan, suppressions
 * removed (`history/openSet.ts`). It used to read the single latest scan in
 * the whole database: another project's, or an SBOM with no findings.
 *
 * Response size: `summary` carries the true counts; each bucket carries at
 * most {@link ITEMS_PER_BUCKET} entries and `truncated` says which were cut.
 *
 * Resource cost: zero scanners, no I/O beyond storage queries.
 */
import { describeOpenSet, openSetForProject } from '../history/openSet.js';
import { resolveProjectPath } from '../platform/projectPath.js';
import { ProjectPath } from '../schemas.js';
import { registerToolModule } from './index.js';
/** Entries returned per bucket; `summary` counts are never capped. */
const ITEMS_PER_BUCKET = 50;
const TEST_PATTERNS = [
    /(^|\/)tests?\//i,
    /(^|\/)__tests__\//i,
    /\.spec\.(ts|js|tsx|jsx|py|rb|go|rs)$/i,
    /\.test\.(ts|js|tsx|jsx|py|rb|go|rs)$/i,
    /(^|\/)test_[^/]+\.py$/i,
];
const GENERATED_PATTERNS = [
    /(^|\/)vendor\//i,
    /(^|\/)node_modules\//i,
    /(^|\/)dist\//i,
    /(^|\/)build\//i,
    /(^|\/)generated\//i,
    /(^|\/)gen\//i,
    /\.min\.(js|css)$/i,
    /\.generated\.(ts|js|py)$/i,
];
const FIXTURE_PATTERNS = [
    /(^|\/)fixtures?\//i,
    /(^|\/)mocks?\//i,
    /(^|\/)stubs?\//i,
    /(^|\/)examples?\//i,
];
const tool = {
    name: 'triage_findings',
    title: 'Heuristic triage of findings',
    description: "Bucket one project's open findings (project_path, default: the server's working directory; " +
        'the newest usable scan of every finding-producing type, suppressions removed) into ' +
        'likely_false_positive / probably_safe / keep using path-based heuristics (test files, ' +
        'generated code, fixtures). True counts in `summary`, at most 50 entries per bucket, ' +
        '`truncated` naming the buckets that were cut. No LLM call — the model that invoked the tool ' +
        'decides whether to call suppress_finding on the suggestions.',
    inputSchema: { project_path: ProjectPath },
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
        return { ok: false, error: { code: 'not_a_git_repo', message: e.message } };
    }
    const set = openSetForProject(ctx.storage, projectPath);
    const open = set.findings;
    const likely_false_positive = [];
    const probably_safe = [];
    const keep = [];
    for (const f of open) {
        const path = f.file_path ?? '';
        const bucket = classifyByPath(f, path);
        if (bucket === 'likely_fp') {
            likely_false_positive.push(toBucket(f, 'matches test/fixture pattern'));
        }
        else if (bucket === 'safe') {
            probably_safe.push(toBucket(f, 'in vendored/generated/build artefact'));
        }
        else {
            keep.push(toBucket(f, 'no heuristic fired'));
        }
    }
    return {
        ok: true,
        summary: {
            total: open.length,
            likely_false_positive: likely_false_positive.length,
            probably_safe: probably_safe.length,
            keep: keep.length,
        },
        likely_false_positive: likely_false_positive.slice(0, ITEMS_PER_BUCKET),
        probably_safe: probably_safe.slice(0, ITEMS_PER_BUCKET),
        keep: keep.slice(0, ITEMS_PER_BUCKET),
        truncated: {
            likely_false_positive: likely_false_positive.length > ITEMS_PER_BUCKET,
            probably_safe: probably_safe.length > ITEMS_PER_BUCKET,
            keep: keep.length > ITEMS_PER_BUCKET,
        },
        open_set: describeOpenSet(set),
        instructions_for_model: 'For each entry in `likely_false_positive`, consider calling `suppress_finding` with the ' +
            'suggested_suppression_reason. Be more conservative with `probably_safe` — review one before ' +
            'batch-suppressing. Never auto-suppress severity=critical without explicit human approval.',
    };
}
function classifyByPath(_f, path) {
    if (!path)
        return 'keep';
    if (TEST_PATTERNS.some((p) => p.test(path)))
        return 'likely_fp';
    if (FIXTURE_PATTERNS.some((p) => p.test(path)))
        return 'likely_fp';
    if (GENERATED_PATTERNS.some((p) => p.test(path)))
        return 'safe';
    return 'keep';
}
function toBucket(f, reason) {
    return {
        fingerprint: f.fingerprint,
        file_path: f.file_path ?? null,
        severity: f.severity,
        title: f.title,
        rule_id: f.rule_id ?? null,
        reason,
        suggested_suppression_reason: `triage_findings: ${reason}`,
    };
}
//# sourceMappingURL=triageFindings.js.map