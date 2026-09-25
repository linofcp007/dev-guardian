/**
 * staticcheck `-f json` parser.
 *
 * staticcheck prints one JSON object per line: `{ code, severity, location:
 * { file, line, column }, end, message }`. `severity` is `error` (`medium`)
 * or `warning` (`low`). Entries with code `compile` mean the package did not
 * type-check, so staticcheck could not analyse it: those are reported through
 * {@link staticcheckErrors}, never as findings about the code.
 *
 * `subcategory` is the `quality_check` category: ST1003 ("poorly chosen
 * identifier") is `naming`, everything else `smell`.
 */
import { getNumber, getProp, getString, makeFinding, toRelativeIfPossible, } from './index.js';
export const STATICCHECK_TOOL_NAME = 'staticcheck';
const NAMING_CODES = new Set(['ST1003']);
export const staticcheckParser = {
    name: STATICCHECK_TOOL_NAME,
    parse(input, ctx = {}) {
        const findings = [];
        for (const entry of entries(input)) {
            const finding = mapEntry(entry, ctx);
            if (finding)
                findings.push(finding);
        }
        return { findings, cves: [] };
    },
};
/** `<file>:<line>: <message>` for every `compile` entry. */
export function staticcheckErrors(input) {
    const out = [];
    for (const entry of entries(input)) {
        if (getString(entry, 'code') !== 'compile')
            continue;
        const location = getProp(entry, 'location');
        out.push(`${getString(location, 'file') ?? '(unknown file)'}:${String(getNumber(location, 'line') ?? '?')}: ` +
            (getString(entry, 'message') ?? 'compile error'));
    }
    return out;
}
/** JSON-lines input (or an already-parsed array) as a list of objects. */
function entries(input) {
    if (Array.isArray(input))
        return input;
    if (typeof input !== 'string')
        return [];
    const out = [];
    for (const line of input.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('{'))
            continue;
        try {
            out.push(JSON.parse(trimmed));
        }
        catch {
            /* not a staticcheck line */
        }
    }
    return out;
}
function mapEntry(raw, ctx) {
    const code = getString(raw, 'code');
    if (!code || code === 'compile')
        return null;
    const location = getProp(raw, 'location');
    const file = getString(location, 'file');
    if (!file)
        return null;
    const message = getString(raw, 'message') ?? `${code} violation`;
    const line = getNumber(location, 'line');
    const endLine = getNumber(getProp(raw, 'end'), 'line');
    const input = {
        tool: STATICCHECK_TOOL_NAME,
        rule_id: code,
        severity: getString(raw, 'severity') === 'error' ? 'medium' : 'low',
        category: 'quality',
        subcategory: NAMING_CODES.has(code) ? 'naming' : 'smell',
        title: message,
        message: `${code}: ${message}`,
        file_path: toRelativeIfPossible(file, ctx.project_path),
        fix_available: false,
    };
    if (line !== undefined)
        input.line_start = line;
    // staticcheck writes `end: { line: 0 }` when it has no end position.
    const end = endLine !== undefined && endLine > 0 ? endLine : line;
    if (end !== undefined)
        input.line_end = end;
    return makeFinding(input);
}
//# sourceMappingURL=staticcheck.js.map