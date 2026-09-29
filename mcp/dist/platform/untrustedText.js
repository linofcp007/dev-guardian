/**
 * Text that came from the scanned repository, made safe to show — to the
 * model, in an MCP response, and to a person, in the CLI's human output.
 *
 * A rule message, a snippet, a file name, a reason or a title derived from
 * scanned content can carry characters that render as nothing or reorder
 * what does: a right-to-left override (U+202E) makes `gpj.exe` read as
 * `exe.jpg`, a zero-width space splits a word a reviewer searches for, an
 * ESC starts a terminal escape sequence. JSON escapes the C0 controls and
 * nothing else, so a bidi control or a zero-width character reached the
 * model as itself.
 *
 * {@link untrustedText} writes each such code point as a visible `\u{XXXX}`:
 *
 *   - the C0 controls (U+0000–U+001F) and DEL, except `\n` and `\t` — and
 *     except nothing in a single-line field (a path, a name, an id: see
 *     {@link untrustedValue}), where a line break is itself the anomaly;
 *   - the C1 controls (U+0080–U+009F);
 *   - every `Default_Ignorable_Code_Point` (zero-width characters, variation
 *     selectors, tag characters, the Hangul fillers, the soft hyphen, …) and
 *     every `Bidi_Control` (U+202A–202E, U+2066–2069, U+200E/F, U+061C);
 *   - the interlinear annotation controls U+FFF9–FFFB and the line and
 *     paragraph separators U+2028/2029.
 *
 * The one exemption is the one `mcpaudit/rules.ts` already makes, for the
 * same reason: an invisible code point that belongs where it is — VS15/VS16
 * after an emoji or on a keycap, a zero-width joiner inside an emoji
 * sequence, an ideographic variation selector after a CJK ideograph, and the
 * tag sequence of the three RGI subdivision flags. Every other character —
 * a Japanese file name, an accented letter, an emoji — passes unchanged.
 *
 * Only the RESPONSE is escaped: stored findings keep their bytes, so a
 * fingerprint, a baseline or a diff is unaffected.
 */
import { isLegitimateInvisible, subdivisionFlagTags } from './invisibleChars.js';
/** Everything {@link untrustedText} may escape, as one class (the exemptions are decided per match). */
const UNSAFE = /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u{FFF9}-\u{FFFB}\p{Default_Ignorable_Code_Point}\p{Bidi_Control}]/gu;
const UNSAFE_TEST = /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u{FFF9}-\u{FFFB}\p{Default_Ignorable_Code_Point}\p{Bidi_Control}]/u;
/** A code point that may be exempt, depending on its neighbours. */
const MAYBE_LEGITIMATE = /[\u200D\uFE0E\uFE0F\u{E0020}-\u{E007F}\u{E0100}-\u{E01EF}]/u;
function escape(code) {
    return `\\u{${code.toString(16).toUpperCase().padStart(4, '0')}}`;
}
/** The code point that ENDS at UTF-16 offset `end` (exclusive), or undefined. */
function codePointBefore(s, end) {
    if (end <= 0)
        return undefined;
    const low = s.charCodeAt(end - 1);
    if (low >= 0xdc00 && low <= 0xdfff && end >= 2) {
        const high = s.charCodeAt(end - 2);
        if (high >= 0xd800 && high <= 0xdbff)
            return s.codePointAt(end - 2);
    }
    return low;
}
/** UTF-16 offsets of the tag characters of an RGI subdivision flag (🏴 + `gbeng` / `gbsct` / `gbwls` + cancel). */
function exemptFlagOffsets(s) {
    const out = new Set();
    if (!s.includes('\u{1F3F4}'))
        return out;
    const points = [];
    const offsets = [];
    let offset = 0;
    for (const ch of s) {
        const cp = ch.codePointAt(0) ?? 0;
        points.push(cp);
        offsets.push(offset);
        offset += ch.length;
    }
    for (const index of subdivisionFlagTags(points)) {
        const o = offsets[index];
        if (o !== undefined)
            out.add(o);
    }
    return out;
}
/** `text` with every unsafe code point written as a visible `\u{XXXX}` — see the module doc. */
export function untrustedText(text, options = {}) {
    if (!UNSAFE_TEST.test(text))
        return text;
    const multiline = options.multiline !== false;
    let flags = null;
    return text.replace(UNSAFE, (ch, offset) => {
        const code = ch.codePointAt(0) ?? 0;
        if (multiline && (code === 0x0a || code === 0x09))
            return ch;
        if (MAYBE_LEGITIMATE.test(ch)) {
            flags ??= exemptFlagOffsets(text);
            if (flags.has(offset))
                return ch;
            if (isLegitimateInvisible(code, codePointBefore(text, offset), text.codePointAt(offset + ch.length)))
                return ch;
        }
        return escape(code);
    });
}
/**
 * Keys whose value is a single line — a path, a file, a name, an id, a
 * title, a URL — where a line break is escaped too. Matched on the key's
 * last `_`-separated word, so `file_path`, `rule_id` and `target_path` all
 * are; an array under such a key is a list of them (`files`, `paths`).
 */
const SINGLE_LINE_KEY = /(?:^|_)(?:paths?|files?|names?|ids?|titles?|urls?|uris?|targets?|packages?|fingerprints?)$/i;
/**
 * `value` with every string in it — object keys included, at any depth —
 * passed through {@link untrustedText}. Numbers, booleans and null are
 * returned as they are; the structure is copied, never mutated.
 */
export function untrustedValue(value) {
    return walk(value, true);
}
function walk(value, multiline) {
    if (typeof value === 'string')
        return untrustedText(value, { multiline });
    if (Array.isArray(value))
        return value.map((v) => walk(v, multiline));
    if (value !== null && typeof value === 'object') {
        // Only plain data reaches a response; anything else (a Date) goes as is.
        const proto = Object.getPrototypeOf(value);
        if (proto !== Object.prototype && proto !== null)
            return value;
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            out[untrustedText(k, { multiline: false })] = walk(v, !SINGLE_LINE_KEY.test(k));
        }
        return out;
    }
    return value;
}
//# sourceMappingURL=untrustedText.js.map