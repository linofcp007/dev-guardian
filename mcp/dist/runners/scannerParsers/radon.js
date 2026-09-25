/**
 * radon `cc -j` (cyclomatic complexity) parser.
 *
 * The report maps each file to a list of blocks — functions, classes, and
 * methods — or to `{ "error": "…" }` when radon could not parse the file.
 * radon lists a method twice (nested under its class's `methods` and again at
 * the top level with a `classname`), so only top-level functions and methods
 * are read, once each; a class's own score is the average of its methods and
 * adds nothing.
 *
 * Only rank C or worse (complexity above 10, radon's own "moderate" line) is a
 * finding: C is `low`, D `medium`, E and F `high`. The rule id is the same for
 * every rank, so a function that gets more complex keeps its identity instead
 * of reading as one finding resolved and another introduced.
 */
import { asArray, getNumber, getString, makeFinding, parseInputAsJson, toRelativeIfPossible, } from './index.js';
export const RADON_TOOL_NAME = 'radon';
const RANK_SEVERITY = { C: 'low', D: 'medium', E: 'high', F: 'high' };
export const radonParser = {
    name: RADON_TOOL_NAME,
    parse(input, ctx = {}) {
        const findings = [];
        for (const [file, blocks] of fileEntries(input)) {
            const seen = new Set();
            for (const block of asArray(blocks)) {
                const finding = mapBlock(block, file, ctx, seen);
                if (finding)
                    findings.push(finding);
            }
        }
        return { findings, cves: [] };
    },
};
/** `<file>: <error>` for every file radon reported it could not analyse. */
export function radonErrors(input) {
    const out = [];
    for (const [file, value] of fileEntries(input)) {
        const error = getString(value, 'error');
        if (error !== undefined)
            out.push(`${file}: ${error}`);
    }
    return out;
}
function fileEntries(input) {
    const root = parseInputAsJson(input);
    if (root === null || typeof root !== 'object' || Array.isArray(root))
        return [];
    return Object.entries(root);
}
function mapBlock(raw, file, ctx, seen) {
    const type = getString(raw, 'type');
    if (type !== 'function' && type !== 'method')
        return null;
    const rank = getString(raw, 'rank') ?? '';
    const severity = RANK_SEVERITY[rank];
    if (severity === undefined)
        return null;
    const name = getString(raw, 'name') ?? '(anonymous)';
    const className = getString(raw, 'classname');
    const qualified = className ? `${className}.${name}` : name;
    const line = getNumber(raw, 'lineno');
    const key = `${qualified}:${String(line)}`;
    if (seen.has(key))
        return null;
    seen.add(key);
    const complexity = getNumber(raw, 'complexity');
    const title = `Cyclomatic complexity ${String(complexity ?? '?')} (rank ${rank}) in ${type} ${qualified}`;
    const input = {
        tool: RADON_TOOL_NAME,
        rule_id: 'cyclomatic-complexity',
        severity,
        category: 'quality',
        subcategory: 'complexity',
        title,
        message: `${title}. Split it into smaller functions; radon ranks above B are hard to test exhaustively.`,
        file_path: toRelativeIfPossible(file, ctx.project_path),
        fix_available: false,
    };
    const endLine = getNumber(raw, 'endline');
    if (line !== undefined)
        input.line_start = line;
    if (endLine !== undefined)
        input.line_end = endLine;
    return makeFinding(input);
}
//# sourceMappingURL=radon.js.map