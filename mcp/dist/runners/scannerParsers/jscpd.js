/**
 * jscpd JSON parser.
 *
 * jscpd's report is `{ statistics: …, duplicates: [{firstFile, secondFile, …}] }`.
 * We emit one Finding per duplicate pair, anchored at `firstFile`, with the
 * message linking to `secondFile`. Severity is fixed at `low` (duplication
 * is a smell, not a bug); category is `quality`, subcategory `duplicate`.
 */
import { asArray, getNumber, getProp, getString, makeFinding, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const JSCPD_TOOL_NAME = 'jscpd';
export const jscpdParser = {
    name: JSCPD_TOOL_NAME,
    parse(input, ctx = {}) {
        const root = parseInputAsJson(input);
        const findings = [];
        for (const dup of asArray(getProp(root, 'duplicates'))) {
            const finding = mapDuplicate(dup, ctx);
            if (finding)
                findings.push(finding);
        }
        return { findings, cves: [] };
    },
};
function mapDuplicate(raw, ctx) {
    const first = getProp(raw, 'firstFile');
    const second = getProp(raw, 'secondFile');
    const firstPath = getString(first, 'name');
    if (!firstPath)
        return null;
    const lines = getNumber(raw, 'lines');
    const tokens = getNumber(raw, 'tokens');
    const format = getString(raw, 'format');
    const firstStart = getNumber(first, 'start');
    const firstEnd = getNumber(first, 'end');
    const secondPath = getString(second, 'name');
    const secondStart = getNumber(second, 'start');
    const secondEnd = getNumber(second, 'end');
    const fragment = getString(raw, 'fragment');
    const title = lines !== undefined
        ? `Duplicated ${lines} line(s)${format ? ' (' + format + ')' : ''}`
        : 'Code duplication';
    const message = secondPath
        ? `Mirror at ${toRelativeIfPossible(secondPath, ctx.project_path)}:${secondStart ?? '?'}-${secondEnd ?? '?'}`
        : undefined;
    const input = {
        tool: JSCPD_TOOL_NAME,
        rule_id: 'duplicate-code',
        severity: 'low',
        category: 'quality',
        subcategory: 'duplicate',
        title,
        file_path: toRelativeIfPossible(firstPath, ctx.project_path),
        fix_available: false,
    };
    if (message !== undefined)
        input.message = message;
    if (firstStart !== undefined)
        input.line_start = firstStart;
    if (firstEnd !== undefined)
        input.line_end = firstEnd;
    if (fragment !== undefined) {
        input.snippet = fragment;
    }
    else if (tokens !== undefined) {
        input.snippet = `tokens=${tokens}`;
    }
    return makeFinding(input);
}
//# sourceMappingURL=jscpd.js.map