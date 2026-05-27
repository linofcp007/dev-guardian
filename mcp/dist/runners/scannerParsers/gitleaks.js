/**
 * gitleaks JSON output parser.
 *
 * gitleaks emits a top-level array. Every entry is a secret finding —
 * category is always `security`, subcategory always `secret`, severity
 * always `high` (gitleaks does not categorise; a leaked secret is a leaked
 * secret).
 *
 * We never persist the secret itself: gitleaks runs with `--redact`, and
 * we additionally strip the `Match` / `Secret` fields when assembling the
 * snippet — only the rule id and surrounding context survive.
 */
import { asArray, getNumber, getProp, getString, makeFinding, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const GITLEAKS_TOOL_NAME = 'gitleaks';
export const gitleaksParser = {
    name: GITLEAKS_TOOL_NAME,
    parse(input, ctx = {}) {
        const root = parseInputAsJson(input);
        const items = Array.isArray(root) ? root : asArray(getProp(root, 'findings'));
        const findings = [];
        for (const item of items) {
            const finding = mapItem(item, ctx);
            if (finding)
                findings.push(finding);
        }
        return { findings, cves: [] };
    },
};
function mapItem(raw, ctx) {
    const ruleId = getString(raw, 'RuleID') ?? getString(raw, 'rule_id');
    const file = getString(raw, 'File') ?? getString(raw, 'file');
    if (!ruleId || !file)
        return null;
    const description = getString(raw, 'Description') ?? getString(raw, 'description');
    const lineStart = getNumber(raw, 'StartLine') ??
        getNumber(raw, 'startLine') ??
        getNumber(raw, 'Line');
    const lineEnd = getNumber(raw, 'EndLine') ?? lineStart;
    const commit = getString(raw, 'Commit') ?? getString(raw, 'commit');
    const input = {
        tool: GITLEAKS_TOOL_NAME,
        rule_id: ruleId,
        severity: 'high',
        category: 'security',
        subcategory: 'secret',
        title: description ?? `Possible secret matching rule '${ruleId}'`,
        file_path: toRelativeIfPossible(file, ctx.project_path),
        fix_available: false,
    };
    if (lineStart !== undefined)
        input.line_start = lineStart;
    if (lineEnd !== undefined)
        input.line_end = lineEnd;
    // Snippet is rule + commit (when present). The actual secret bytes are
    // never copied into our DB even if gitleaks was somehow run without
    // `--redact`.
    input.snippet = commit ? `rule=${ruleId};commit=${commit}` : `rule=${ruleId}`;
    return makeFinding(input);
}
//# sourceMappingURL=gitleaks.js.map