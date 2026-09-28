/**
 * Semgrep `--json` output parser.
 *
 * Maps each entry in `results[]` to a single Finding:
 *   - severity:    extra.severity (INFO/WARNING/ERROR) → info/medium/high,
 *                  bumped to `critical` for security rules.
 *   - category:    extra.metadata.category when present, else heuristic on
 *                  the check_id; falls back to 'quality'.
 *   - subcategory: extra.metadata.subcategory or heuristic
 *   - rule_id:     check_id
 *   - file_path:   path, normalised to project-relative POSIX
 *   - line range:  start.line .. end.line
 *   - snippet:     extra.lines, clamped to 1 KB by `makeFinding`
 *   - fix_available: true when `extra.fix` (autofix string) exists
 */
import { CONTAINER_PROJECT_ROOT } from '../dockerScanner.js';
import { redactCredentialSnippet } from '../../redaction/secretFindingRedaction.js';
import { localRuleIdNormalizer } from '../semgrepRuleIds.js';
import { asArray, getNumber, getProp, getString, makeFinding, normalizeSeverity, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const SEMGREP_TOOL_NAME = 'semgrep';
export const semgrepParser = {
    name: SEMGREP_TOOL_NAME,
    parse(input, ctx = {}) {
        const root = parseInputAsJson(input);
        const results = asArray(getProp(root, 'results'));
        const findings = [];
        for (const raw of results) {
            const finding = mapResult(raw, ctx);
            if (finding)
                findings.push(finding);
        }
        return { findings, cves: [] };
    },
};
/**
 * {@link semgrepParser} for a run that passed these `--config` values: a
 * rule from one of their local files is stored under the id
 * `runners/semgrepRuleIds.ts` gives it — a project rule's id from the
 * project root, a plugin pack's rule's own id, any other file's as Semgrep
 * spells it — never under the path of the machine it ran on (`rule_id` is
 * part of a finding's identity). `rules.projectPath` defaults to the parse
 * context's project, `rules.cwd` (Semgrep's working directory) to the
 * project. Registry ids are passed through unchanged.
 */
export function semgrepParserFor(configs, rules = {}) {
    return {
        name: SEMGREP_TOOL_NAME,
        parse: (input, ctx = {}) => {
            const projectPath = rules.projectPath ?? ctx.project_path;
            const normalize = localRuleIdNormalizer(configs, {
                ...rules,
                ...(projectPath !== undefined ? { projectPath } : {}),
            });
            return semgrepParser.parse(input, { ...ctx, semgrep_rule_id: normalize });
        },
    };
}
function mapResult(raw, ctx) {
    const extra = getProp(raw, 'extra');
    const start = getProp(raw, 'start');
    const end = getProp(raw, 'end');
    const metadata = getProp(extra, 'metadata');
    const reportedId = getString(raw, 'check_id');
    const checkId = reportedId === undefined ? undefined : (ctx.semgrep_rule_id?.(reportedId) ?? reportedId);
    const message = getString(extra, 'message');
    const filePath = getString(raw, 'path');
    if (!checkId || !filePath)
        return null;
    const severity = mapSeverity(getString(extra, 'severity'), metadata);
    const category = mapCategory(metadata, checkId);
    const subcategory = mapSubcategory(metadata, checkId);
    const lineStart = getNumber(start, 'line');
    const lineEnd = getNumber(end, 'line') ?? lineStart;
    const fixAvailable = getString(extra, 'fix') !== undefined ||
        Array.isArray(getProp(extra, 'fixed_lines'));
    const input = {
        tool: SEMGREP_TOOL_NAME,
        rule_id: checkId,
        severity,
        category,
        title: shortenTitle(message, checkId),
        fix_available: fixAvailable,
        file_path: relativePath(filePath, ctx.project_path),
    };
    if (message !== undefined)
        input.message = message;
    if (subcategory !== undefined)
        input.subcategory = subcategory;
    if (lineStart !== undefined)
        input.line_start = lineStart;
    if (lineEnd !== undefined)
        input.line_end = lineEnd;
    const snippet = getString(extra, 'lines');
    if (snippet !== undefined)
        input.snippet = snippet;
    // The registry secrets family (and any other rule/subcategory naming a
    // credential) reports the real matched text in `extra.lines` when the
    // caller is logged in or running via Docker — the anonymous "requires
    // login" placeholder is the only case that redacts itself. Redacted here,
    // at the source, rather than trusted to a later step.
    return redactCredentialSnippet(makeFinding(input));
}
/**
 * Project-relative POSIX path. A path still absolute under the container
 * mount after relativising against the host project is a Docker-fallback
 * result (`/src/app.js`) and loses the mount prefix, so it reads exactly as
 * the native run of the same tree would (`app.js`) — fingerprints, dedupe
 * and baselines all key on it. A native run can never produce such a path:
 * every file it reports lies under the project path, which the first step
 * already removed (a project that genuinely lives at `/src` included).
 */
function relativePath(filePath, projectPath) {
    const rel = toRelativeIfPossible(filePath, projectPath);
    const mount = `${CONTAINER_PROJECT_ROOT}/`;
    return rel.startsWith(mount) ? rel.slice(mount.length) : rel;
}
function mapSeverity(rawSeverity, metadata) {
    // Semgrep's three-level severity is too coarse for security rules; if the
    // rule self-identifies as security, bump ERROR → critical so it actually
    // shows up in the critical bucket.
    const base = normalizeSeverity(rawSeverity);
    const cat = getString(metadata, 'category')?.toLowerCase();
    if (base === 'high' && (cat === 'security' || cat === 'vulnerability'))
        return 'critical';
    return base;
}
function mapCategory(metadata, checkId) {
    const explicit = getString(metadata, 'category')?.toLowerCase();
    if (explicit) {
        if (explicit === 'security' || explicit === 'vulnerability')
            return 'security';
        if (explicit === 'performance')
            return 'performance';
        // `correctness` is a bug class. It used to sit in the quality branch
        // above this one too, which matched first, so the bug mapping written
        // for it never ran.
        if (explicit === 'bug' || explicit === 'correctness')
            return 'bug';
        if (explicit === 'best-practice' || explicit === 'maintainability')
            return 'quality';
    }
    // Heuristic on the check_id string.
    const lowered = checkId.toLowerCase();
    if (/(security|audit|sqli|xss|injection|secret|crypto|csrf|ssrf|deserial|path[-_]traversal)/i.test(lowered)) {
        return 'security';
    }
    if (/(perf|performance|n-plus-one|slow)/i.test(lowered))
        return 'performance';
    if (/(bug|race|null|undefined|nullable|off[-_]by[-_]one)/i.test(lowered))
        return 'bug';
    return 'quality';
}
function mapSubcategory(metadata, checkId) {
    const explicit = getString(metadata, 'subcategory');
    if (explicit)
        return explicit.toLowerCase();
    const owasp = getString(metadata, 'owasp');
    if (owasp)
        return owasp.toLowerCase().split(':')[0];
    // Try the last segment of the check_id as a coarse subcategory.
    const parts = checkId.split('.');
    const last = parts.at(-1);
    return last && last !== checkId ? last : undefined;
}
function shortenTitle(message, checkId) {
    if (message && message.length > 0) {
        const firstLine = message.split(/\r?\n/)[0] ?? message;
        return firstLine.length > 140 ? firstLine.slice(0, 137) + '…' : firstLine;
    }
    return checkId;
}
//# sourceMappingURL=semgrep.js.map