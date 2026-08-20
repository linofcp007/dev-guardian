/**
 * The provenance header `init_project` stamps onto the configs it copies.
 *
 * ---- Why a header AND a manifest, rather than either alone -----------
 *
 * The header is for the human who opens `.semgrep.yml` six months later and
 * wants to know where the file came from and whether editing it is allowed.
 * It cannot be the whole mechanism: one of the four files `init_project`
 * installs is `renovate.json`, and JSON has no comment syntax. Renovate reads
 * that file with a strict JSON parser, so a `//` line would break the very
 * tool the file configures. Three of four files could carry a header and the
 * fourth could not, which is not a mechanism — it is three special cases.
 *
 * The manifest (`configdrift/manifest.ts`) is therefore the mechanism, and
 * this header is an affordance layered on top wherever the format permits it.
 *
 * ---- Why the block is self-delimiting --------------------------------
 *
 * Hashing has to compare the user's file against the *shipped* file, and the
 * shipped file has no header. So the header must be strippable, exactly, with
 * no heuristics that could eat a line the user wrote. A start marker alone is
 * not enough: `stripProvenanceHeader` would then have to guess where the
 * block ends, and guessing wrong silently truncates a config. An explicit end
 * line makes the removal a match rather than a guess, and a start line with
 * no matching end is left alone (see the test that types the marker by hand).
 */
/** Present on both delimiter lines; the string drift detection keys on. */
export const PROVENANCE_MARKER = 'dev-guardian:managed';
/** Marks the last line of the block. */
export const PROVENANCE_END_MARKER = `end ${PROVENANCE_MARKER}`;
/**
 * How far into a file we look for the closing delimiter. A real header is
 * five lines; a file whose first line happens to contain the marker and whose
 * closing line is 200 lines down is not our header, and treating it as one
 * would delete the user's content from the hash.
 */
const MAX_HEADER_LINES = 12;
/**
 * The line-comment prefix for a target path, or `null` when the format has
 * none.
 *
 * Driven by extension rather than by an allow-list of the four current
 * targets, so a fifth config added to a profile is covered without a second
 * edit here.
 */
export function commentPrefixFor(targetPath) {
    const lower = targetPath.toLowerCase();
    if (lower.endsWith('.json'))
        return null;
    if (lower.endsWith('.yml') ||
        lower.endsWith('.yaml') ||
        lower.endsWith('.toml') ||
        lower.endsWith('.cfg') ||
        lower.endsWith('.ini')) {
        return '#';
    }
    return null;
}
/**
 * The stamped block, ending in a blank line so the config body underneath
 * starts cleanly. Deliberately free of a timestamp: the manifest records
 * that, and a value that changes on every copy would make the header itself a
 * source of spurious diffs in the user's repository.
 */
export function buildProvenanceHeader(input) {
    const p = input.prefix;
    return [
        `${p} ${PROVENANCE_MARKER} — installed by dev-guardian init_project`,
        `${p} source: configs/${input.source}  |  plugin version: ${input.pluginVersion}`,
        `${p} This file is yours. dev-guardian never overwrites it once you have`,
        `${p} edited it. Provenance and drift tracking: .dev-guardian/configs.json`,
        `${p} ${PROVENANCE_END_MARKER}`,
        '',
        '',
    ].join('\n');
}
/**
 * Removes a stamped block from the top of `text`, plus the single blank line
 * `buildProvenanceHeader` puts after it. Returns `text` unchanged when there
 * is no complete block to remove.
 */
export function stripProvenanceHeader(text) {
    const lines = text.split('\n');
    const first = lines[0];
    if (first === undefined || !first.includes(PROVENANCE_MARKER))
        return text;
    const limit = Math.min(lines.length, MAX_HEADER_LINES);
    for (let i = 0; i < limit; i += 1) {
        const line = lines[i];
        if (line === undefined)
            continue;
        if (!line.includes(PROVENANCE_END_MARKER))
            continue;
        let start = i + 1;
        if (lines[start] === '')
            start += 1; // the blank separator we emit
        return lines.slice(start).join('\n');
    }
    return text;
}
//# sourceMappingURL=header.js.map