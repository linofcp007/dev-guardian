/**
 * Which pip requirements files are safe to hand to an installer the user did
 * not ask for — create_fix_pr's pip step and its `deps_audit` re-scan, whose
 * `pip-audit` installs every requirement into a temporary virtualenv (and
 * builds any sdist it fetches). An ALLOWLIST, failing closed (review of 3.0,
 * W2E): the first version matched pip's grammar with regular expressions and
 * was bypassed a dozen ways, each confirmed against pip 26's own parser —
 * `--index` (optparse takes any unique prefix of `--index-url`), `-egit+…`
 * glued, `-e "git+…"` quoted, a `\r`, `\f` or U+2028 that pip's
 * `str.splitlines` breaks a line on, `--ind\` + `ex-url` (pip joins
 * continuations with nothing between), a UTF-16 or `coding: utf-7` file, an
 * include in quotes, `\\host\share\pkg.tar.gz` (on Windows, `pip` reaches
 * the share and sends the user's credentials to it), `file://host/share/…`.
 *
 * So nothing is recognised as bad. A requirements file is installable only
 * when every logical line — decoded, split and joined exactly as
 * `pip/_internal/req/req_file.py` does — is:
 *
 *   - blank, or a comment;
 *   - a plain PEP 508 requirement with no URL: a name, optional extras,
 *     optional version specifiers, optional markers — and, on the same line,
 *     only `--hash=<algorithm>:<hex>` (hash-pinned files are what
 *     `pip-compile --generate-hashes` writes);
 *   - an include, `-r` / `--requirement` / `-c` / `--constraint` spelled out
 *     in full, of a relative path that stays inside the checkout — which is
 *     then checked the same way;
 *   - `--require-hashes`, `--pre`, `--prefer-binary`, `--only-binary <v>` or
 *     `--no-binary <v>` spelled out in full: they choose no source.
 *
 * Anything else — every other option or any abbreviation, a glued short
 * option, a quote or a backslash among the options, an `@`, a URL or a VCS
 * prefix, a local, UNC or `file:` path, `${VAR}` (pip substitutes the
 * environment), a character pip and this reader might split differently, an
 * encoding other than UTF-8 or ASCII, an include past the bound or out of the
 * checkout, a file that cannot be read — is refused, and named: the file,
 * the line, what it is, and for a URL only `scheme://host` (userinfo, path
 * and query never shown: `deploy:pa@ss-S3CRET@evil.invalid` used to leak
 * `ss-S3CRET`). `test/unit/fixpr/pipAllowlist.test.ts` holds this to pip's
 * own parser on a corpus of bypasses: every input where pip sees an index,
 * find-links, trusted host, URL, VCS or editable requirement is refused.
 */
import { dirname, relative, resolve, sep } from 'node:path';
import { describeReadRefusal, isWithinDir, readProjectBytes } from '../platform/projectFs.js';
/** Files one check follows, includes included. */
export const MAX_REQUIREMENT_FILES = 200;
/** One requirements file is read up to this size; a real one is a few KB. */
export const MAX_REQUIREMENTS_BYTES = 4 * 1024 * 1024;
/** `<file>:<line>: <kind> (<host>)` — the one wording every refusal and note uses. */
export function describePipRefusal(r) {
    const where = r.line > 0 ? `${r.file}:${r.line}` : r.file;
    const extra = [r.detail, r.host].filter((x) => x !== undefined && x !== '');
    return `${where}: ${r.kind}${extra.length > 0 ? ` (${extra.join(', ')})` : ''}`;
}
// ------------------------------------------------------------------ decoding, as pip does
/**
 * The text pip would parse, or why this reader will not parse it. pip:
 * a BOM wins (UTF-8, UTF-32, UTF-16, in that order — `BOM_UTF16_LE` is a
 * prefix of `BOM_UTF32_LE`); else a PEP 263 `coding:` comment in one of the
 * first two lines; else UTF-8, falling back to the LOCALE's encoding. Only
 * UTF-8 (with or without a BOM), UTF-16 with a BOM and ASCII are decoded
 * here; anything else would be read differently by pip, and is refused.
 */
export function decodeRequirements(bytes) {
    const starts = (sig) => sig.every((b, i) => bytes[i] === b);
    const strict = (enc, data) => {
        try {
            return { ok: true, text: new TextDecoder(enc, { fatal: true, ignoreBOM: true }).decode(data) };
        }
        catch {
            return { ok: false, detail: `not valid ${enc.toUpperCase()}` };
        }
    };
    if (starts([0xef, 0xbb, 0xbf]))
        return strict('utf-8', bytes.subarray(3));
    if (starts([0xff, 0xfe, 0x00, 0x00]) || starts([0x00, 0x00, 0xfe, 0xff]))
        return { ok: false, detail: 'UTF-32' };
    if (starts([0xff, 0xfe]))
        return strict('utf-16le', bytes.subarray(2));
    if (starts([0xfe, 0xff]))
        return strict('utf-16be', bytes.subarray(2));
    // A PEP 263 declaration in the first two lines (split on b"\n", as pip does).
    let lineStart = 0;
    for (let n = 0; n < 2 && lineStart <= bytes.length; n++) {
        const nl = bytes.indexOf(0x0a, lineStart);
        const line = bytes.subarray(lineStart, nl < 0 ? bytes.length : nl);
        if (line[0] === 0x23) {
            const m = /coding[:=]\s*([-\w.]+)/.exec(line.toString('latin1'));
            if (m?.[1] !== undefined) {
                const codec = m[1].toLowerCase().replace(/[-\s]/g, '_');
                if (!['utf_8', 'utf8', 'u8', 'utf', 'ascii', 'us_ascii', '646'].includes(codec)) {
                    return { ok: false, detail: `declared coding ${m[1].slice(0, 20)}` };
                }
                break;
            }
        }
        if (nl < 0)
            break;
        lineStart = nl + 1;
    }
    // pip falls back to the locale's encoding when UTF-8 fails: unknowable here.
    return strict('utf-8', bytes);
}
/**
 * Characters this reader refuses rather than risk splitting or trimming a
 * line differently from pip: control characters but tab and the line breaks
 * `\n` and `\r`; C1 controls (U+0085 is a line break to `str.splitlines`);
 * every other Unicode space or separator (Python's `\s` and JavaScript's
 * disagree on U+001C–U+001F and U+FEFF); zero-width and bidirectional
 * formatting characters.
 */
const UNUSUAL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028-\u202f\u205f-\u2064\u2066-\u206f\u3000\ufeff]/;
// ------------------------------------------------------------------ lines, as pip does
/** pip's `COMMENT_RE.match`: the line starts with `#`, or whitespace then `#`. */
const COMMENT_START = /^(?:[ \t]*)#/;
/** pip's `COMMENT_RE.sub('', …)`: from the first `#` at the start or after whitespace, to the end. */
const COMMENT = /(^|[ \t]+)#.*$/;
/**
 * The logical lines pip parses, with the number of each one's first physical
 * line: `str.splitlines` (here only `\n`, `\r\n` and `\r` remain — the rest
 * were refused as unusual), `join_lines` — a line ending in `\` is joined to
 * the next with NOTHING between (`--ind\` + `ex-url` is `--index-url`), every
 * `\` at either end of a joined line stripped, and a comment line never
 * joined — then `ignore_comments`.
 */
export function* logicalLines(text) {
    const physical = text.split(/\r\n|\r|\n/);
    if (physical.length > 0 && physical[physical.length - 1] === '' && /[\r\n]$/.test(text))
        physical.pop();
    let joined = [];
    let first = 0;
    const finish = function* (n, raw) {
        const stripped = raw.replace(COMMENT, '').trim();
        if (stripped !== '')
            yield { line: n, text: stripped };
    };
    for (let i = 0; i < physical.length; i++) {
        let line = physical[i] ?? '';
        const isComment = COMMENT_START.test(line);
        if (!line.endsWith('\\') || isComment) {
            if (isComment)
                line = ` ${line}`;
            if (joined.length > 0) {
                joined.push(line);
                yield* finish(first, joined.join(''));
                joined = [];
            }
            else {
                yield* finish(i + 1, line);
            }
        }
        else {
            if (joined.length === 0)
                first = i + 1;
            joined.push(line.replace(/^\\+|\\+$/g, ''));
        }
    }
    if (joined.length > 0)
        yield* finish(first, joined.join(''));
}
// ------------------------------------------------------------------ one logical line
/** A PEP 508 name. */
const NAME = '[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?';
const VERSION_CLAUSE = '(?:~=|===|==|!=|<=|>=|<|>)[ \\t]*[A-Za-z0-9_.*+!-]+';
const VERSIONS = `${VERSION_CLAUSE}(?:[ \\t]*,[ \\t]*${VERSION_CLAUSE})*`;
/** Markers: comparisons of environment names and quoted literals — nothing that names a place. */
const MARKER = `[A-Za-z0-9_ \\t.<>=!~"'(),*+-]*`;
/** A plain requirement with no URL: name, extras, versions (bare or in parentheses), markers. */
const PLAIN_REQUIREMENT = new RegExp(`^${NAME}[ \\t]*(?:\\[[ \\t]*(?:${NAME}(?:[ \\t]*,[ \\t]*${NAME})*)?[ \\t]*\\])?[ \\t]*` +
    `(?:${VERSIONS}|\\([ \\t]*${VERSIONS}[ \\t]*\\))?[ \\t]*(?:;${MARKER})?$`);
/** A name pip takes for an archive on disk, whatever PEP 508 says. */
const ARCHIVE = /\.(zip|whl|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tar\.lz|tlz)$/i;
/** A hash option on a requirement line, as `pip-compile --generate-hashes` writes it. */
const HASH_VALUE = /^[a-z0-9]+:[0-9a-fA-F]+$/;
/** A `--only-binary` / `--no-binary` value: `:all:`, `:none:` or package names. */
const BINARY_VALUE = /^[A-Za-z0-9_.,:-]+$/;
/** VCS schemes pip knows, and the `git+…` / `hg+…` / `svn+…` / `bzr+…` forms. */
const VCS = /^(?:git|hg|svn|bzr)(?:\+[a-z0-9.+-]*)?:/i;
/** pip's long options in a requirements file, for naming an abbreviation by what it would mean. */
const LONG_OPTIONS = [
    ['--index-url', 'index option'],
    ['--extra-index-url', 'index option'],
    ['--no-index', 'index option'],
    ['--find-links', 'find-links option'],
    ['--trusted-host', 'trusted-host option'],
    ['--editable', 'editable requirement'],
    ['--requirement', 'option'],
    ['--constraint', 'option'],
    ['--hash', 'option'],
    ['--config-settings', 'option'],
    ['--use-feature', 'option'],
];
const SHORT_OPTIONS = {
    i: 'index option',
    f: 'find-links option',
    e: 'editable requirement',
};
/** What a refused option token means to pip. */
function optionKind(token) {
    if (token.startsWith('--')) {
        const name = token.split('=')[0] ?? token;
        const matches = LONG_OPTIONS.filter(([full]) => full.startsWith(name));
        return matches.length === 1 ? (matches[0]?.[1] ?? 'option') : 'option';
    }
    return SHORT_OPTIONS[token.charAt(1)] ?? 'option';
}
/** `scheme://host` of a URL, parsed properly — userinfo, port, path and query never shown. */
export function urlHost(url) {
    const unc = /^(?:\\\\|\/\/)([^\\/]+)/.exec(url);
    if (unc?.[1] !== undefined)
        return /^[A-Za-z0-9._:[\]-]{1,253}$/.test(unc[1]) ? `\\\\${unc[1]}` : '\\\\(unparseable host)';
    try {
        const u = new URL(url);
        const scheme = u.protocol.replace(/:$/, '');
        if (!/^[a-z][a-z0-9+.-]{0,30}$/i.test(scheme))
            return '(unparseable URL)';
        const host = u.hostname;
        // No host: only a file: URL means something here — any other `scheme:` may be a user name (`deploy:S3CRET@…`).
        if (host === '')
            return scheme.toLowerCase() === 'file' ? 'file:' : '(no host)';
        return /^[A-Za-z0-9._:[\]-]{1,253}$/.test(host) ? `${scheme}://${host}` : `${scheme}://(unparseable host)`;
    }
    catch {
        return '(unparseable URL)';
    }
}
/** pip's `--trusted-host host[:port]`: the host alone, through the URL parser so a `user:pw@` never survives. */
function bareHost(value) {
    try {
        const host = new URL(`http://${value}`).hostname;
        return /^[A-Za-z0-9._:[\]-]{1,253}$/.test(host) ? host : '(unparseable host)';
    }
    catch {
        return '(unparseable host)';
    }
}
/** A `file:` URL: a local path, or — with a host other than `localhost` — a network path (Windows opens `\\host\…`). */
function fileUrl(url) {
    const host = urlHost(url);
    return host === 'file:' || /^file:\/\/localhost$/i.test(host) ? { kind: 'local path', host: 'file:' } : { kind: 'network path', host };
}
/** Why a requirement string is not a plain one, or null when it is. Exported for manifests (`pythonProject.ts`). */
export function judgeRequirement(req) {
    const beforeMarker = req.split(';', 1)[0] ?? req;
    const at = beforeMarker.indexOf('@');
    // A URL first (its userinfo holds `@` too); a direct reference is `name @ url`, and a name has no `:`.
    const startsWithScheme = /^\s*[a-z][a-z0-9+.-]*:/i.test(beforeMarker);
    if (at >= 0 && !startsWithScheme) {
        const url = beforeMarker.slice(at + 1).trim();
        if (/^file:/i.test(url))
            return fileUrl(url);
        const kind = VCS.test(url) ? 'VCS requirement' : /^(?:\\\\|\/\/)/.test(url) ? 'network path' : 'direct reference';
        return { kind, host: urlHost(url) };
    }
    const s = beforeMarker.trim();
    if (/^(?:\\\\|\/\/)/.test(s))
        return { kind: 'network path', host: urlHost(s) };
    if (VCS.test(s))
        return { kind: 'VCS requirement', host: urlHost(s) };
    if (/^[a-z][a-z0-9+.-]*:/i.test(s)) {
        if (/^file:/i.test(s))
            return fileUrl(s);
        return /^[A-Za-z]:[\\/]/.test(s) ? { kind: 'local path' } : { kind: 'URL requirement', host: urlHost(s) };
    }
    if (/[\\/]/.test(s) || s.startsWith('.') || s.startsWith('~') || ARCHIVE.test(s))
        return { kind: 'local path' };
    return PLAIN_REQUIREMENT.test(req.trim()) ? null : { kind: 'not a plain requirement' };
}
/** pip's `break_args_options`: tokens split on single spaces; the args are those before the first `-…` token. */
function judgeLine(text) {
    if (text.includes('${'))
        return { ok: false, refusal: { kind: 'environment variable', detail: 'pip substitutes ${…} from the environment' } };
    const tokens = text.split(' ');
    const firstOption = tokens.findIndex((t) => t.startsWith('-'));
    const args = (firstOption < 0 ? tokens : tokens.slice(0, firstOption)).join(' ');
    const optionText = firstOption < 0 ? '' : tokens.slice(firstOption).join(' ');
    // A network path among the options (`-r \\host\share\x.txt`) is named by its host before the escape rule refuses it.
    const unc = optionText
        .split(/[ \t=]+/)
        .map((t) => t.replace(/^["']+/, ''))
        .find((t) => /^(?:\\\\|\/\/)[^\\/]/.test(t));
    if (unc !== undefined)
        return { ok: false, refusal: { kind: 'network path', host: urlHost(unc) } };
    if (/["']/.test(optionText))
        return { ok: false, refusal: { kind: 'quoted or escaped option' } };
    if (optionText.includes('\\')) {
        // Measured with pip 26.2.1: `-r reqs\base.txt` opens `reqsbase.txt` — its shlex takes the backslash as an escape.
        return {
            ok: false,
            refusal: { kind: 'quoted or escaped option', detail: 'pip reads a backslash here as an escape, so the file it opens is not the one written' },
        };
    }
    const opts = optionText.split(/[ \t]+/).filter((t) => t !== '');
    if (args.trim() !== '') {
        const bad = judgeRequirement(args);
        if (bad !== null)
            return { ok: false, refusal: bad };
        // On a requirement line, only its hashes.
        for (let i = 0; i < opts.length; i++) {
            const t = opts[i] ?? '';
            if (t.startsWith('--hash=') && HASH_VALUE.test(t.slice('--hash='.length)))
                continue;
            if (t === '--hash' && HASH_VALUE.test(opts[i + 1] ?? '')) {
                i += 1;
                continue;
            }
            return { ok: false, refusal: refusedOption(opts, i) };
        }
        return { ok: true, includes: [] };
    }
    const includes = [];
    for (let i = 0; i < opts.length; i++) {
        const t = opts[i] ?? '';
        if (t === '--require-hashes' || t === '--pre' || t === '--prefer-binary')
            continue;
        // `-rreqs/base.txt`: pip's optparse takes a value glued to a short option (measured: it opens reqs/base.txt).
        const valued = /^(--only-binary|--no-binary|--requirement|--constraint)=(.*)$/.exec(t) ?? /^(-r|-c)(.+)$/.exec(t);
        const name = valued?.[1] ?? t;
        if (['--only-binary', '--no-binary', '--requirement', '--constraint', '-r', '-c'].includes(name)) {
            const value = valued?.[2] ?? opts[i + 1];
            if (valued === null)
                i += 1;
            if (value === undefined || value === '')
                return { ok: false, refusal: { kind: 'option', detail: `${name} with no value` } };
            if (name === '--only-binary' || name === '--no-binary') {
                if (!BINARY_VALUE.test(value))
                    return { ok: false, refusal: { kind: 'option', detail: name } };
                continue;
            }
            includes.push(value);
            continue;
        }
        return { ok: false, refusal: refusedOption(opts, i) };
    }
    return { ok: true, includes };
}
/** The option's own name, for a refusal — never its value. */
function optionName(token) {
    if (token.startsWith('--'))
        return (token.split('=')[0] ?? token).slice(0, 40);
    return token.slice(0, 2);
}
/**
 * A refused option, with the host its value names when it names one: the
 * value after `=`, glued to a short option, or the next token. Only
 * `scheme://host` (or a bare host, sanitised) is ever shown.
 */
function refusedOption(opts, i) {
    const t = opts[i] ?? '';
    const kind = optionKind(t);
    const value = t.startsWith('--') ? (t.includes('=') ? t.slice(t.indexOf('=') + 1) : opts[i + 1]) : t.length > 2 ? t.slice(2) : opts[i + 1];
    let host;
    if (value !== undefined && kind === 'trusted-host option' && !value.includes('://'))
        host = bareHost(value);
    else if (value !== undefined && /^(?:[a-z][a-z0-9+.-]*:|\\\\|\/\/)/i.test(value))
        host = urlHost(value);
    return { kind, detail: optionName(t), ...(host !== undefined ? { host } : {}) };
}
// ------------------------------------------------------------------ files and includes
/** Why an include cannot be followed inside the checkout, or null. */
function judgeInclude(target) {
    if (/^(?:\\\\|\/\/)/.test(target))
        return { kind: 'network path', host: urlHost(target) };
    if (/^[a-z][a-z0-9+.-]*:/i.test(target) && !/^[A-Za-z]:[\\/]/.test(target))
        return { kind: 'include of a URL', host: urlHost(target) };
    // An absolute path is opened as written (measured: `-r C:/…/reqs/base.txt` reads that file) — followed, and
    // held to the checkout like any other include. A drive-relative `C:x`, a rooted `/x` on Windows (on whichever
    // drive is current) and `~` are paths this check cannot place.
    if (/^[A-Za-z]:(?![\\/])/.test(target) || target.startsWith('~'))
        return { kind: 'include out of the checkout' };
    if (process.platform === 'win32' && /^[\\/](?![\\/])/.test(target))
        return { kind: 'include out of the checkout' };
    return null;
}
/** Refusals reported at most, per check. */
const MAX_REFUSALS = 50;
/**
 * Every requirements file pip would read from `starts` (paths relative to
 * `projectDir`), includes followed as pip resolves them (relative to the
 * including file) and read within `checkoutRoot` through
 * `platform/projectFs.ts` — and every line of them this allowlist does not
 * admit. `stopAtFirst`: stop at the first refusal (create_fix_pr only needs
 * to know whether to refuse).
 */
export function checkRequirements(projectDir, starts, checkoutRoot = projectDir, opts = {}) {
    const refusals = [];
    const read = [];
    const shown = (abs) => relative(projectDir, abs).split(sep).join('/');
    const queue = [...new Set(starts)].map((f) => ({ abs: resolve(projectDir, f) }));
    const seen = new Set();
    const refuse = (r) => {
        if (refusals.length < MAX_REFUSALS)
            refusals.push(r);
        return opts.stopAtFirst === true || refusals.length >= MAX_REFUSALS;
    };
    /** A refusal of the file itself: charged to the including line when there is one. */
    const refuseFile = (item, kind, detail) => {
        if (item.from === undefined)
            return refuse({ file: shown(item.abs), line: 0, kind, ...(detail !== undefined ? { detail } : {}) });
        const target = /^[\w./-]{1,120}$/.test(item.from.target) ? item.from.target : '(an include)';
        return refuse({ file: item.from.file, line: item.from.line, kind, detail: detail !== undefined ? `${target}: ${detail}` : target });
    };
    for (let item = queue.shift(); item !== undefined; item = queue.shift()) {
        const abs = item.abs;
        const key = process.platform === 'win32' ? abs.toLowerCase() : abs;
        if (seen.has(key))
            continue;
        if (seen.size >= MAX_REQUIREMENT_FILES) {
            if (refuseFile(item, 'too many files', `more than ${MAX_REQUIREMENT_FILES} requirements files`))
                break;
            continue;
        }
        seen.add(key);
        if (!isWithinDir(checkoutRoot, abs)) {
            if (refuseFile(item, 'include out of the checkout'))
                break;
            continue;
        }
        const got = readProjectBytes(checkoutRoot, abs, MAX_REQUIREMENTS_BYTES);
        // Not there: pip fails on it, and installs nothing from it.
        if (got.status === 'absent')
            continue;
        if (got.status === 'refused') {
            if (refuseFile(item, 'unreadable', describeReadRefusal(got.reason)))
                break;
            continue;
        }
        const decoded = decodeRequirements(got.bytes);
        if (!decoded.ok) {
            if (refuseFile(item, 'encoding', decoded.detail))
                break;
            continue;
        }
        const file = shown(abs);
        read.push(file);
        const unusual = UNUSUAL.exec(decoded.text);
        if (unusual !== null) {
            const line = decoded.text.slice(0, unusual.index).split(/\r\n|\r|\n/).length;
            const code = unusual[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0');
            if (refuse({ file, line, kind: 'unusual character', detail: `U+${code}` }))
                break;
            continue;
        }
        let stop = false;
        for (const { line, text } of logicalLines(decoded.text)) {
            const verdict = judgeLine(text);
            if (!verdict.ok) {
                if (refuse({ file, line, ...verdict.refusal })) {
                    stop = true;
                    break;
                }
                continue;
            }
            for (const target of verdict.includes) {
                const bad = judgeInclude(target);
                if (bad !== null) {
                    if (refuse({ file, line, ...bad })) {
                        stop = true;
                        break;
                    }
                    continue;
                }
                queue.push({ abs: resolve(dirname(abs), target), from: { file, line, target } });
            }
            if (stop)
                break;
        }
        if (stop)
            break;
    }
    return { refusals, read };
}
/** The kinds that name where pip installs from — what `deps_audit` names as honoured. */
export const INDEX_KINDS = new Set(['index option', 'find-links option', 'trusted-host option']);
export const SOURCE_KINDS = new Set([
    'editable requirement',
    'direct reference',
    'URL requirement',
    'VCS requirement',
    'network path',
    'local path',
    'source table',
    'dynamic dependencies',
]);
//# sourceMappingURL=pipRequirements.js.map