/**
 * Stable fingerprint for a finding.
 *
 * Same finding produces the same fingerprint across:
 *   - re-runs (deterministic order, deterministic hash)
 *   - platforms (file path normalized to POSIX before hashing)
 *   - small snippet edits (snippet capped at 1 KB before SHA-1)
 *
 * Different findings produce different fingerprints because they differ in
 * at least one of (tool, rule_id, file_path, line range, snippet bytes).
 *
 * Severity is intentionally NOT part of the fingerprint — the same finding
 * can be re-classified by a scanner update without changing identity.
 */
import { createHash } from 'node:crypto';
const SNIPPET_MAX_BYTES = 1024;
export function computeFingerprint(input) {
    const pathPosix = normalizePathPosix(input.file_path ?? '');
    const lineStart = Number.isFinite(input.line_start) ? Number(input.line_start) : 0;
    const lineEnd = Number.isFinite(input.line_end) ? Number(input.line_end) : 0;
    const snippetTrimmed = (input.snippet ?? '').slice(0, SNIPPET_MAX_BYTES);
    const snippetHash = sha1(snippetTrimmed);
    const payload = JSON.stringify({
        tool: input.tool.toLowerCase(),
        rule_id: input.rule_id ?? '',
        file_path_norm: pathPosix,
        line_start: lineStart,
        line_end: lineEnd,
        snippet_hash: snippetHash,
    });
    return sha256(payload);
}
function normalizePathPosix(p) {
    if (p === '')
        return '';
    // Strip drive letter prefix entirely so c:\src\app.ts and /src/app.ts (the
    // same project mounted differently) hash to the same fingerprint.
    const stripped = p.replace(/^[a-zA-Z]:/, '').replace(/\\/g, '/');
    // Collapse duplicate slashes and trailing slashes.
    return stripped.replace(/\/+/g, '/').replace(/\/$/, '');
}
function sha1(s) {
    return createHash('sha1').update(s).digest('hex');
}
function sha256(s) {
    return createHash('sha256').update(s).digest('hex');
}
//# sourceMappingURL=findingFingerprint.js.map