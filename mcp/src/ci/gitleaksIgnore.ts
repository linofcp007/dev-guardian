/**
 * The project's `.gitleaksignore`, applied to the CI gate's full-content
 * secrets pass (`ci/runScans.ts`, review 12 finding 11) in the form that pass
 * cannot read.
 *
 * gitleaks writes a history finding's fingerprint as
 * `<commit>:<file>:<rule>:<line>`, and a team accepts a committed secret — a
 * test fixture's private key — by pasting that line into `.gitleaksignore`.
 * The full-content pass reads files, not commits: gitleaks matches its
 * findings against the `<file>:<rule>:<line>` form only, so every such key
 * came back as new whenever a pull request touched its file (and the
 * baseline never held it: the history pass had honoured the entry).
 *
 * A full-content finding is accepted by a history-form entry of its rule
 * that names its file when the file at that commit, from the entry's line,
 * holds the finding's lines — whitespace aside, as many lines as the finding
 * spans: the same secret, wherever it now sits. A secret replaced in place is
 * other lines, and stays new. Paths are the repository's in an entry, the
 * project's in a finding (`git rev-parse --show-prefix` joins them). The file
 * is read from the scanned tree, as gitleaks reads it — so under a pull
 * request it is the pull request's own, unless `--reset-exclusions-from`
 * restored the base's (docs/ci.md).
 *
 * Never throws: an entry, a commit or a file that cannot be read accepts
 * nothing.
 */

import { readProjectTextOrUndefined } from '../platform/projectFs.js';
import { git } from '../runners/git.js';
import type { Finding } from '../types.js';

/** The largest `.gitleaksignore` read. */
const MAX_IGNORE_BYTES = 4 * 1024 * 1024;

/** The largest file, in the tree or at a commit, compared. */
const MAX_FILE_BYTES = 16 * 1024 * 1024;

/** At most this many (commit, file) blobs read per run. */
const MAX_BLOBS = 500;

/** One history-form entry: `<commit>:<file>:<rule>:<line>`. */
interface HistoryIgnore {
  commit: string;
  /** Repository-relative, `/`-separated. */
  file: string;
  rule: string;
  line: number;
}

/**
 * The history-form entries of a `.gitleaksignore` text. A comment, a blank
 * line and a file-form entry (`<file>:<rule>:<line>`, which gitleaks applies
 * to the files pass itself) are left out. A file name may hold `:`.
 */
export function parseHistoryIgnores(text: string): HistoryIgnore[] {
  const out: HistoryIgnore[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const m = /^([0-9a-f]{7,64}):(.+):([^:\s]+):(\d+)$/i.exec(line);
    if (m?.[1] === undefined || m[2] === undefined || m[3] === undefined || m[4] === undefined) continue;
    out.push({ commit: m[1].toLowerCase(), file: m[2].split('\\').join('/'), rule: m[3], line: Number(m[4]) });
  }
  return out;
}

/** Lines `from`..`from + count - 1` (1-based) of `text`, whitespace removed; null when out of range. */
function span(text: string, from: number, count: number): string | null {
  const lines = text.split(/\r?\n/);
  if (from < 1 || from + count - 1 > lines.length) return null;
  return lines.slice(from - 1, from - 1 + count).join('\n').replace(/\s+/g, '');
}

/**
 * The findings of `findings` (full-content gitleaks findings of the project
 * at `projectPath`) that a history-form entry of its `.gitleaksignore`
 * accepts (see the module comment).
 */
export async function acceptedByHistoryIgnores(projectPath: string, findings: readonly Finding[]): Promise<Set<Finding>> {
  const out = new Set<Finding>();
  if (findings.length === 0) return out;
  const text = readProjectTextOrUndefined(projectPath, '.gitleaksignore', MAX_IGNORE_BYTES);
  const entries = text === undefined ? [] : parseHistoryIgnores(text);
  if (entries.length === 0) return out;
  const shown = await git(projectPath, ['rev-parse', '--show-prefix']);
  if (shown.exitCode !== 0) return out;
  const prefix = shown.stdout.trim();

  const blobs = new Map<string, Promise<string | null>>();
  const blob = (commit: string, file: string): Promise<string | null> => {
    const key = `${commit}\n${file}`;
    let read = blobs.get(key);
    if (read === undefined) {
      if (blobs.size >= MAX_BLOBS) return Promise.resolve(null);
      // `<commit>:<path>` without `./` is the repository's path.
      read = git(projectPath, ['cat-file', 'blob', `${commit}:${file}`]).then((r) =>
        r.exitCode === 0 && r.stdout.length <= MAX_FILE_BYTES ? r.stdout : null,
      );
      blobs.set(key, read);
    }
    return read;
  };

  for (const f of findings) {
    const start = f.line_start;
    if (start === undefined) continue;
    const count = Math.max(1, (f.line_end ?? start) - start + 1);
    const path = (f.file_path ?? '').split('\\').join('/');
    const candidates = entries.filter((e) => e.rule === f.rule_id && e.file === `${prefix}${path}`);
    if (candidates.length === 0) continue;
    const here = readProjectTextOrUndefined(projectPath, path, MAX_FILE_BYTES);
    const lines = here === undefined ? null : span(here, start, count);
    if (lines === null) continue;
    for (const e of candidates) {
      const then = await blob(e.commit, e.file);
      if (then !== null && span(then, e.line, count) === lines) {
        out.add(f);
        break;
      }
    }
  }
  return out;
}
