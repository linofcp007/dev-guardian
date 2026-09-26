/**
 * Ensure the target project's `.gitignore` excludes `.guardian/*` while
 * re-including `.guardian/baseline.json`.
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
 * **Upgrading, not just detecting.** Every earlier release of this tool
 * wrote the bare `.guardian/` line (or one of its `/.guardian`,
 * `.guardian`, `/.guardian/` spellings) — a project that already has one
 * needs it REMOVED, not merely supplemented: appending the new block below
 * an old bare line changes nothing, because the bare line still excludes
 * the directory outright. So `alreadyIgnored` is followed by an upgrade
 * pass whenever any of the old spellings survives, regardless of whether
 * the new block is also already present.
 *
 * **The legacy pair, not just the entry.** Both shapes this tool has ever
 * written (`created`: `${HEADER}\n${ENTRY}\n`; `added`: the same two lines
 * appended after a blank line) put the `# dev-guardian outputs` HEADER
 * directly above the bare entry. Dropping only the entry line left the old
 * header behind, and the new block appended below it duplicated the
 * header. The upgrade removes a bare entry's paired header too, when it is
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

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const HEADER = '# dev-guardian outputs';
const ENTRY = '.guardian/*';
const BASELINE_NEGATION = '!.guardian/baseline.json';

/** Every bare spelling this tool has ever written for the old, unfixed entry. */
const OLD_DIRECTORY_PATTERNS: ReadonlySet<string> = new Set([
  '.guardian',
  '.guardian/',
  '/.guardian',
  '/.guardian/',
]);

export interface GitignoreGuardResult {
  updated: boolean;
  reason: 'already_present' | 'added' | 'created' | 'upgraded' | 'not_a_repo' | 'unwritable';
}

export function ensureGuardianIgnored(projectPath: string): GitignoreGuardResult {
  const gitignorePath = join(projectPath, '.gitignore');
  if (!existsSync(join(projectPath, '.git'))) {
    return { updated: false, reason: 'not_a_repo' };
  }
  try {
    if (!existsSync(gitignorePath)) {
      writeFileSync(gitignorePath, `${HEADER}\n${ENTRY}\n${BASELINE_NEGATION}\n`, 'utf8');
      return { updated: true, reason: 'created' };
    }

    const original = readFileSync(gitignorePath, 'utf8');
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
    const toDrop = new Set<number>();
    lines.forEach((line, i) => {
      if (!OLD_DIRECTORY_PATTERNS.has(line.trim())) return;
      toDrop.add(i);
      const prev = lines[i - 1];
      if (prev !== undefined && prev.trim() === HEADER) toDrop.add(i - 1);
    });
    const kept = lines.filter((_, i) => !toDrop.has(i));
    const hasEntry = kept.some((l) => l.trim() === ENTRY);
    const hasNegation = kept.some((l) => l.trim() === BASELINE_NEGATION);

    if (!hasOldPattern && hasEntry && hasNegation) {
      return { updated: false, reason: 'already_present' };
    }

    const missing: string[] = [];
    if (!hasEntry) missing.push(ENTRY);
    if (!hasNegation) missing.push(BASELINE_NEGATION);

    // Trailing blank lines (and a trailing stray `\r`) go; the last line kept
    // ends in its own ending, or the dominant one when it had none.
    const body = withEndings.filter((_, i) => !toDrop.has(i));
    for (let last = body.pop(); last !== undefined; last = body.pop()) {
      const text = last.text.replace(/\r+$/, '');
      if (text === '') continue;
      body.push({ text, eol: last.eol === '' ? eol : last.eol });
      break;
    }
    const next =
      body.map((l) => l.text + l.eol).join('') +
      (missing.length > 0 ? `${HEADER}${eol}${missing.join(eol)}${eol}` : '');
    writeFileSync(gitignorePath, next, 'utf8');
    return { updated: true, reason: hasOldPattern ? 'upgraded' : 'added' };
  } catch {
    return { updated: false, reason: 'unwritable' };
  }
}

/** A line of the file and the ending it had there (`''` for a last line without one). */
interface Line {
  text: string;
  eol: string;
}

/** `content.split(/\r?\n/)`, keeping each line's own ending. */
function splitLines(content: string): Line[] {
  const out: Line[] = [];
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
function dominantEol(content: string): '\r\n' | '\n' {
  const crlf = content.split('\r\n').length - 1;
  const lf = content.split('\n').length - 1 - crlf;
  if (crlf !== lf) return crlf > lf ? '\r\n' : '\n';
  const first = content.indexOf('\n');
  return first > 0 && content[first - 1] === '\r' ? '\r\n' : '\n';
}
