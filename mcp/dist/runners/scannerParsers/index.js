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
    return finding;
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