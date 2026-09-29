/**
 * Ensure the target project's `.gitignore` excludes every `.guardian`
 * directory's contents (`**\/.guardian/*`) while re-including its
 * `baseline.json` (`!**\/.guardian/baseline.json`).
 *
 * Called once at server startup (after the storage is opened, so we know
 * which project root we're operating on). Idempotent: a project with the
 * current form already in place is left alone.
 *
 * **Why `.guardian/*`, never bare `.guardian/`.** The CI gate needs a
 * COMMITTED `.guardian/baseline.json` (`ci/baseline.ts`), but git cannot
 * re-include a file under a directory that is itself excluded —
 * `!.guardian/baseline.json` is silently powerless once anything upstream of
 * it excludes `.guardian/` as a directory, regardless of line order. `*`
 * excludes the directory's CONTENTS instead of the directory itself, which
 * is what makes the per-file negation below it able to do anything at all.
 *
 * **Why `**\/`.** A pattern with a slash anywhere but at its end matches
 * from the `.gitignore`'s own directory only, so `.guardian/*` covers the
 * root and nothing below it — while the bare `.guardian/` it replaced, having
 * no inner slash, matched at every depth. A tool pointed at a subdirectory
 * (a monorepo's `packages/api`) keeps its database and reports in
 * `packages/api/.guardian/`; once an earlier, unreleased build of this guard
 * upgraded a project's `.guardian/` to the root-only pair, that directory
 * showed up in `git status` as untracked, one `git add -A` away from being
 * committed — this repository's own `mcp/.guardian/` did. `**\/` matches at
 * every depth the way the bare line did, and lets a sub-project commit its
 * own baseline.
 *
 * **Upgrading, not just detecting.** Every earlier release of this tool
 * wrote the bare `.guardian/` line (or one of its `/.guardian`,
 * `.guardian`, `/.guardian/` spellings), and that unreleased build the
 * root-only `.guardian/*` + `!.guardian/baseline.json` pair — a project that
 * already has either needs it REMOVED, not merely supplemented: appending the
 * new block below an old bare line changes nothing, because the bare line
 * still excludes the directory outright. So an upgrade pass runs whenever any
 * legacy line survives, regardless of whether the new block is also already
 * present.
 *
 * **The legacy pair, not just the entry.** Every shape this tool has ever
 * written (`created`: the header and its entry lines; `added`: the same lines
 * appended after a blank line) put the `# dev-guardian outputs` HEADER
 * directly above the first entry. Dropping only the entry line left the old
 * header behind, and the new block appended below it duplicated the
 * header. The upgrade removes a legacy entry's paired header too, when it is
 * the line immediately above it — never any OTHER occurrence of that exact
 * comment, since nothing else in this file ever writes it.
 *
 * **Line endings.** An upgrade/append re-splits the file into lines and
 * rejoins them, and every line it keeps goes back with the ending it came
 * with — a CRLF `.gitignore` (Windows default; also common wherever
 * `core.autocrlf` is on) rewritten with a bare `\n` comes back as LF, and
 * git then shows the WHOLE file as changed for what was functionally a
 * two-line edit; a MIXED file rewritten in any one ending shows every line
 * of the other. The lines this adds (and a last line that had no ending)
 * take the file's dominant ending — the more frequent one, a tie going to
 * whichever appears first (`dominantEol`). A brand-new file (`created`) has
 * no existing convention to follow and keeps the plain `\n` it always used.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describeReadRefusal, describeWriteRefusal, projectEntryKind, readProjectBytes, writeProjectFile, } from './platform/projectFs.js';
const HEADER = '# dev-guardian outputs';
const ENTRY = '**/.guardian/*';
const BASELINE_NEGATION = '!**/.guardian/baseline.json';
/**
 * Every line an earlier release wrote that the current block replaces: the
 * bare directory spellings, which defeat the negation, and the root-only pair
 * an unreleased build wrote, which stopped ignoring a `.guardian` below the root.
 */
const OLD_DIRECTORY_PATTERNS = new Set([
    '.guardian',
    '.guardian/',
    '/.guardian',
    '/.guardian/',
    '.guardian/*',
    '!.guardian/baseline.json',
]);
/** The largest `.gitignore` this reads; a real one is a few KB. */
export const MAX_GITIGNORE_BYTES = 4 * 1024 * 1024;
function fromWriteFailure(w) {
    return {
        updated: false,
        reason: w.reason === 'failed' ? 'unwritable' : 'refused',
        detail: describeWriteRefusal(w.reason, w.detail),
    };
}
/**
 * Brings the project's `.gitignore` to the current block — see the module
 * doc. It runs at server STARTUP, on whatever directory the host started the
 * server in, before any tool call: a freshly cloned repository's
 * `.gitignore` is the repository's to choose, link or FIFO or not. So the
 * path is `lstat`ed first and a link — a dangling one, one to `/dev/zero`,
 * one to `~/.gitconfig`, even one that stays inside the project — or
 * anything but a regular file is left alone and reported `refused`; the file
 * is read through `platform/projectFs.ts` (bounded, regular files only) and
 * written back through a temp file renamed over it.
 */
export function ensureGuardianIgnored(projectPath) {
    const gitignorePath = join(projectPath, '.gitignore');
    if (!existsSync(join(projectPath, '.git'))) {
        return { updated: false, reason: 'not_a_repo' };
    }
    const kind = projectEntryKind(gitignorePath);
    if (kind === 'link') {
        return { updated: false, reason: 'refused', detail: describeWriteRefusal('link') };
    }
    if (kind === 'directory' || kind === 'other') {
        return { updated: false, reason: 'refused', detail: describeWriteRefusal('not-a-regular-file') };
    }
    try {
        if (kind === 'absent') {
            const w = writeProjectFile(projectPath, '.gitignore', `${HEADER}\n${ENTRY}\n${BASELINE_NEGATION}\n`, {
                mode: 'create',
            });
            return w.ok ? { updated: true, reason: 'created' } : fromWriteFailure(w);
        }
        const read = readProjectBytes(projectPath, '.gitignore', MAX_GITIGNORE_BYTES);
        if (read.status !== 'ok') {
            return {
                updated: false,
                reason: 'refused',
                detail: read.status === 'absent' ? 'it disappeared while being read' : describeReadRefusal(read.reason),
            };
        }
        // Bytes, not the text reader: a byte-order mark the file starts with is
        // written back as it was.
        const original = read.bytes.toString('utf8');
        const eol = dominantEol(original);
        const withEndings = splitLines(original);
        const lines = withEndings.map((l) => l.text);
        const hasOldPattern = lines.some((l) => OLD_DIRECTORY_PATTERNS.has(l.trim()));
        // Every old bare line is dropped outright — see the module comment on
        // why its mere presence elsewhere in the file defeats the negation,
        // however the rest of the file reads. Both `created` and `added` (the
        // only two shapes any earlier release ever wrote) put the HEADER line
        // directly above the bare entry — drop that paired header too, or the
        // block appended below duplicates it.
        const toDrop = new Set();
        lines.forEach((line, i) => {
            if (!OLD_DIRECTORY_PATTERNS.has(line.trim()))
                return;
            toDrop.add(i);
            const prev = lines[i - 1];
            if (prev !== undefined && prev.trim() === HEADER)
                toDrop.add(i - 1);
        });
        const kept = lines.filter((_, i) => !toDrop.has(i));
        const hasEntry = kept.some((l) => l.trim() === ENTRY);
        const hasNegation = kept.some((l) => l.trim() === BASELINE_NEGATION);
        if (!hasOldPattern && hasEntry && hasNegation) {
            return { updated: false, reason: 'already_present' };
        }
        const missing = [];
        if (!hasEntry)
            missing.push(ENTRY);
        if (!hasNegation)
            missing.push(BASELINE_NEGATION);
        // Trailing blank lines (and a trailing stray `\r`) go; the last line kept
        // ends in its own ending, or the dominant one when it had none.
        const body = withEndings.filter((_, i) => !toDrop.has(i));
        for (let last = body.pop(); last !== undefined; last = body.pop()) {
            const text = last.text.replace(/\r+$/, '');
            if (text === '')
                continue;
            body.push({ text, eol: last.eol === '' ? eol : last.eol });
            break;
        }
        const next = body.map((l) => l.text + l.eol).join('') +
            (missing.length > 0 ? `${HEADER}${eol}${missing.join(eol)}${eol}` : '');
        const w = writeProjectFile(projectPath, '.gitignore', next, { mode: 'replace' });
        if (!w.ok)
            return fromWriteFailure(w);
        return { updated: true, reason: hasOldPattern ? 'upgraded' : 'added' };
    }
    catch (e) {
        return { updated: false, reason: 'unwritable', detail: e.message };
    }
}
/** `content.split(/\r?\n/)`, keeping each line's own ending. */
function splitLines(content) {
    const out = [];
    const re = /\r?\n/g;
    let start = 0;
    for (let m = re.exec(content); m !== null; m = re.exec(content)) {
        out.push({ text: content.slice(start, m.index), eol: m[0] });
        start = m.index + m[0].length;
    }
    out.push({ text: content.slice(start), eol: '' });
    return out;
}
/** The file's dominant line ending: the more frequent, a tie going to the first; LF when it has none. */
function dominantEol(content) {
    const crlf = content.split('\r\n').length - 1;
    const lf = content.split('\n').length - 1 - crlf;
    if (crlf !== lf)
        return crlf > lf ? '\r\n' : '\n';
    const first = content.indexOf('\n');
    return first > 0 && content[first - 1] === '\r' ? '\r\n' : '\n';
}
//# sourceMappingURL=gitignoreGuard.js.map