/**
 * PowerShell's quoting, respelled for the POSIX reader (`splitShell`) — so the
 * shell guard and the install parser can read a PowerShell tool's command the
 * way PowerShell does, and not only the way a POSIX shell would. Under POSIX
 * quoting a Windows path ending in `\"` (`Remove-Item "C:\Users\"`) escapes
 * the closing quote and swallows the rest of the command.
 *
 * Pure, no imports: the hook dispatcher loads the compiled copy from
 * `mcp/dist/hooks/` in an install with no `node_modules`.
 */
/** Characters PowerShell separates words on that a POSIX shell does not (NBSP, NEL, the Unicode spaces). */
const UNICODE_SPACE = /[\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\f\v]/;
/** `text` as a POSIX single-quoted word. */
function posixSingle(text) {
    return `'${text.replace(/'/g, "'\\''")}'`;
}
/**
 * The command as PowerShell reads it, respelled for a POSIX reader
 * (`splitShell`): in `'…'`, `''` is one literal quote; in `"…"`, a backtick
 * escapes the next character, `""` is one quote and a backslash is literal;
 * outside quotes, a backtick escapes the next character and a backtick at the
 * end of a line continues it, a backslash is literal, an unquoted comma
 * separates the elements of an array (each one its own argument to a native
 * command) and a Unicode space separates words. Everything else is left as it
 * is — this is a reading for install vetting, not a PowerShell parser.
 */
export function powershellAsPosix(text) {
    let out = '';
    let i = 0;
    while (i < text.length) {
        const ch = text.charAt(i);
        if (ch === "'" || ch === '"') {
            let lit = '';
            let j = i + 1;
            while (j < text.length) {
                const c = text.charAt(j);
                if (ch === '"' && c === '`' && j + 1 < text.length) {
                    lit += text.charAt(j + 1);
                    j += 2;
                    continue;
                }
                if (c === ch) {
                    if (text.charAt(j + 1) === ch) {
                        lit += ch;
                        j += 2;
                        continue;
                    }
                    break;
                }
                lit += c;
                j += 1;
            }
            out += posixSingle(lit);
            i = j + 1;
            continue;
        }
        if (ch === '`') {
            const next = text.charAt(i + 1);
            if (next === '\n')
                i += 2;
            else if (next === '\r' && text.charAt(i + 2) === '\n')
                i += 3;
            else {
                if (next !== '')
                    out += posixSingle(next);
                i += 2;
                continue;
            }
            out += ' ';
            continue;
        }
        if (ch === '\\')
            out += '\\\\';
        else if (ch === ',' || UNICODE_SPACE.test(ch))
            out += ' ';
        else
            out += ch;
        i += 1;
    }
    return out;
}
//# sourceMappingURL=powershellText.js.map