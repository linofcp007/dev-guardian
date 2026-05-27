/**
 * PHPCS `--report=json` parser.
 *
 * Top-level shape:
 *   {
 *     "totals": { "errors": N, "warnings": M, … },
 *     "files": {
 *       "src/foo.php": {
 *         "errors": 3,
 *         "warnings": 1,
 *         "messages": [
 *           { "message": "...", "source": "WordPress.Security.EscapeOutput.OutputNotEscaped",
 *             "severity": 5, "line": 10, "column": 5, "type": "ERROR" }
 *         ]
 *       }
 *     }
 *   }
 *
 * Severity mapping (PHPCS 1-5 numeric):
 *   >=5 → high, >=3 → medium, else low.
 *
 * Category:
 *   `source` starts with `WordPress.Security.` → security
 *   `source` starts with `Generic.Files.` / `Squiz.` / `PEAR.` → quality
 *   otherwise → quality
 */
import { getNumber, getProp, getString, makeFinding, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const PHPCS_TOOL_NAME = 'phpcs';
export const phpcsParser = {
    name: PHPCS_TOOL_NAME,
    parse(input, ctx = {}) {
        const root = parseInputAsJson(input);
        const files = getProp(root, 'files');
        const findings = [];
        if (!files || typeof files !== 'object')
            return { findings, cves: [] };
        for (const [filePath, rawFileEntry] of Object.entries(files)) {
            const messages = getProp(rawFileEntry, 'messages');
            if (!Array.isArray(messages))
                continue;
            for (const m of messages) {
                const finding = mapMessage(filePath, m, ctx);
                if (finding)
                    findings.push(finding);
            }
        }
        return { findings, cves: [] };
    },
};
function mapMessage(filePath, raw, ctx) {
    const source = getString(raw, 'source');
    const message = getString(raw, 'message');
    if (!source || !message)
        return null;
    const sev = getNumber(raw, 'severity');
    const severity = mapSeverity(sev);
    const category = mapCategory(source);
    const lineStart = getNumber(raw, 'line');
    // PHPCS doesn't always emit `end_line`; reuse start.
    const lineEnd = lineStart;
    const input = {
        tool: PHPCS_TOOL_NAME,
        rule_id: source,
        severity,
        category,
        subcategory: source.split('.').slice(0, 3).join('.'), // e.g. WordPress.Security.EscapeOutput
        title: message,
        message,
        file_path: toRelativeIfPossible(filePath, ctx.project_path),
        fix_available: getString(raw, 'fixable')?.toLowerCase() === 'true' || raw === undefined ? false : false,
    };
    if (lineStart !== undefined)
        input.line_start = lineStart;
    if (lineEnd !== undefined)
        input.line_end = lineEnd;
    return makeFinding(input);
}
function mapSeverity(n) {
    if (n === undefined)
        return 'low';
    if (n >= 5)
        return 'high';
    if (n >= 3)
        return 'medium';
    return 'low';
}
function mapCategory(source) {
    if (source.startsWith('WordPress.Security.'))
        return 'security';
    if (source.startsWith('WordPress.DB.'))
        return 'security'; // SQL prep
    if (source.startsWith('WordPress.XSS.'))
        return 'security';
    return 'quality';
}
//# sourceMappingURL=phpcs.js.map