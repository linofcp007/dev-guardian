/**
 * Scanner parser interface and shared helpers.
 *
 * Each parser converts a single scanner's raw output (string or already-
 * parsed JSON) into the canonical `ParserOutput` shape:
 *   - `findings[]` — what the scan-tool factory persists into `findings`
 *   - `cves[]`     — only populated by parsers that yield package CVEs
 *                    (currently just Trivy)
 *
 * Parsers must be pure functions over their input: no I/O, no global state,
 * no time. Anything tool-side (scan_id, project_path resolution) is the
 * caller's responsibility.
 *
 * Severity normalization: every parser maps its scanner-native severity to
 * one of {info, low, medium, high, critical}. Unknown / missing severities
 * default to `medium` — neither suppressed nor escalated — and the parser
 * may flag them via the `subcategory` if it matters.
 */
import { computeFingerprint } from '../../fingerprint/findingFingerprint.js';
import { classifyTaxonomy } from '../../frameworks/taxonomy.js';
/**
 * Convert backslashes to forward slashes and strip a Windows drive prefix.
 * Idempotent for already-POSIX paths.
 */
export function toPosixPath(p) {
    if (!p)
        return p;
    return p.replace(/^[a-zA-Z]:/, '').replace(/\\/g, '/');
}
/**
 * If a scanner reports an absolute path, try to express it as
 * project-relative when we know the project root. Falls back to the
 * scanner's value when the path is outside the project.
 */
export function toRelativeIfPossible(filePath, projectPath) {
    if (!filePath || !projectPath)
        return toPosixPath(filePath);
    const posixFile = toPosixPath(filePath);
    const posixRoot = toPosixPath(projectPath).replace(/\/$/, '');
    if (posixFile.startsWith(`${posixRoot}/`)) {
        return posixFile.slice(posixRoot.length + 1);
    }
    if (posixFile === posixRoot)
        return '';
    return posixFile;
}
/**
 * Limit a snippet to 1 KB before storage. Long snippets bloat the DB and
 * give diminishing context for the model; the fingerprint already uses the
 * 1-KB cap so we stay consistent.
 */
const SNIPPET_MAX_BYTES = 1024;
export function clampSnippet(snippet) {
    if (snippet === undefined || snippet === null)
        return undefined;
    if (snippet.length === 0)
        return undefined;
    return snippet.length > SNIPPET_MAX_BYTES ? snippet.slice(0, SNIPPET_MAX_BYTES) : snippet;
}
/**
 * Constructor for a Finding that auto-computes the fingerprint and applies
 * the defaults required by the strict `Finding` type. Parsers should always
 * go through this helper rather than building findings by hand.
 *
 * `taxonomy` is what the scanner said about the weakness — CWEs and OWASP
 * labels, as strings or lists, raw (`frameworks/taxonomy.ts`
 * `classifyTaxonomy` normalises them and derives the 2025 categories). It
 * sets `cwe`/`owasp` and is deliberately NOT part of the fingerprint: a
 * scanner that starts naming a CWE must not turn a stored finding into a new
 * one.
 */
export function makeFinding(input) {
    const snippet = clampSnippet(input.snippet);
    const fingerprintInput = {
        tool: input.tool,
    };
    if (input.rule_id !== undefined)
        fingerprintInput.rule_id = input.rule_id;
    if (input.file_path !== undefined)
        fingerprintInput.file_path = input.file_path;
    if (input.line_start !== undefined)
        fingerprintInput.line_start = input.line_start;
    if (input.line_end !== undefined)
        fingerprintInput.line_end = input.line_end;
    if (snippet !== undefined)
        fingerprintInput.snippet = snippet;
    const fingerprint = computeFingerprint(fingerprintInput);
    const finding = {
        fingerprint,
        tool: input.tool,
        severity: input.severity,
        category: input.category,
        title: input.title,
        fix_available: input.fix_available ?? false,
    };
    if (input.rule_id !== undefined)
        finding.rule_id = input.rule_id;
    if (input.subcategory !== undefined)
        finding.subcategory = input.subcategory;
    if (input.message !== undefined)
        finding.message = input.message;
    if (input.file_path !== undefined)
        finding.file_path = input.file_path;
    if (input.line_start !== undefined)
        finding.line_start = input.line_start;
    if (input.line_end !== undefined)
        finding.line_end = input.line_end;
    if (snippet !== undefined)
        finding.snippet = snippet;
    if (input.taxonomy !== undefined) {
        const { cwe, owasp } = classifyTaxonomy(input.taxonomy);
        if (cwe !== undefined)
            finding.cwe = cwe;
        if (owasp !== undefined)
            finding.owasp = owasp;
    }
    const aliases = cleanAliases(input.vuln_aliases, input.rule_id);
    if (aliases.length > 0)
        finding.vuln_aliases = aliases;
    return finding;
}
function cleanAliases(raw, ruleId) {
    const seen = new Set(ruleId === undefined ? [] : [ruleId.trim().toUpperCase()]);
    const out = [];
    for (const value of raw ?? []) {
        if (typeof value !== 'string')
            continue;
        const id = value.trim();
        if (id === '' || seen.has(id.toUpperCase()))
            continue;
        seen.add(id.toUpperCase());
        out.push(id);
    }
    return out;
}
/**
 * The weakness every finding of a class is by definition, whatever its
 * scanner calls it: a known-vulnerable dependency is CWE-1395 (Dependency on
 * Vulnerable Third-Party Component), a committed secret CWE-798 (Use of
 * Hard-coded Credentials). OWASP Top 10:2025 maps them to A03 and A07.
 */
export const DEPENDENCY_CWE = 'CWE-1395';
export const SECRET_CWE = 'CWE-798';
/**
 * A known-vulnerable dependency's taxonomy: CWE-1395 plus whatever CWEs its
 * advisory names (the flaw inside the package), and OWASP A03 ONLY. The
 * advisory's CWE-79 is a flaw in someone else's code that the project
 * inherits through its supply chain, not the project's own injection bug,
 * so it is recorded in `cwe` and never counted under A05.
 */
export function dependencyTaxonomy(advisoryCwes = []) {
    return { cwe: [DEPENDENCY_CWE, ...advisoryCwes], owasp: ['A03:2025'], deriveOwasp: false };
}
/**
 * Standard scanner severity strings → canonical `Severity`. Scanners differ
 * in casing and vocabulary; this is the lookup table they all bottom out
 * through.
 */
export function normalizeSeverity(raw) {
    if (!raw)
        return 'medium';
    const normalized = raw.toString().trim().toLowerCase();
    switch (normalized) {
        case 'info':
        case 'informational':
        case 'unknown':
        case 'note':
            return 'info';
        case 'low':
        case 'minor':
            return 'low';
        case 'medium':
        case 'moderate':
        case 'warning':
            return 'medium';
        case 'high':
        case 'error':
        case 'major':
            return 'high';
        case 'critical':
        case 'severe':
        case 'blocker':
            return 'critical';
        default:
            return 'medium';
    }
}
/**
 * Safely access a nested property without making callers wade through
 * `as Record<string, unknown>` casts.
 */
export function getProp(obj, key) {
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        return obj[key];
    }
    return undefined;
}
export function getString(obj, key) {
    const v = getProp(obj, key);
    return typeof v === 'string' ? v : undefined;
}
export function getNumber(obj, key) {
    const v = getProp(obj, key);
    return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}
export function asArray(value) {
    return Array.isArray(value) ? value : [];
}
export function parseInputAsJson(input) {
    if (typeof input !== 'string')
        return input;
    if (input.trim() === '')
        return null;
    try {
        return JSON.parse(input);
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=index.js.map