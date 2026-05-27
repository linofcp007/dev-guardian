/**
 * Bandit (`-f json`) output parser.
 *
 * Bandit scans Python source for security issues. The top-level JSON
 * carries a `results` array of issues, each with `issue_severity` and
 * `issue_confidence` (both LOW/MEDIUM/HIGH). Our severity mapping uses
 * `issue_severity` directly; `issue_confidence` lands in the message so
 * the model can weigh confidence when reasoning.
 */
import { asArray, getNumber, getProp, getString, makeFinding, normalizeSeverity, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const BANDIT_TOOL_NAME = 'bandit';
export const banditParser = {
    name: BANDIT_TOOL_NAME,
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
function mapResult(raw, ctx) {
    const testId = getString(raw, 'test_id');
    const file = getString(raw, 'filename');
    if (!testId || !file)
        return null;
    const testName = getString(raw, 'test_name');
    const issueText = getString(raw, 'issue_text');
    const confidence = getString(raw, 'issue_confidence');
    const line = getNumber(raw, 'line_number');
    const lineRange = asArray(getProp(raw, 'line_range'));
    const code = getString(raw, 'code');
    const severity = normalizeSeverity(getString(raw, 'issue_severity'));
    const lineStart = line ?? (typeof lineRange[0] === 'number' ? lineRange[0] : undefined);
    const lastRange = lineRange.at(-1);
    const lineEnd = typeof lastRange === 'number' ? lastRange : lineStart;
    const message = confidence && issueText
        ? `${issueText} (confidence: ${confidence.toLowerCase()})`
        : issueText;
    const input = {
        tool: BANDIT_TOOL_NAME,
        rule_id: testId,
        severity,
        category: 'security',
        subcategory: testName,
        title: issueText ?? `Bandit ${testId}: ${testName ?? 'issue'}`,
        file_path: toRelativeIfPossible(file, ctx.project_path),
        fix_available: false,
    };
    if (message !== undefined)
        input.message = message;
    if (lineStart !== undefined)
        input.line_start = lineStart;
    if (lineEnd !== undefined)
        input.line_end = lineEnd;
    if (code !== undefined)
        input.snippet = code;
    return makeFinding(input);
}
//# sourceMappingURL=bandit.js.map