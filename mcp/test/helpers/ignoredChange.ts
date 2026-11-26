/**
 * One change both diff steps read — the suppressions it adds and the tests it
 * weakens — partly in directories the project's `.guardianignore` leaves out.
 * The suppressions pass skips what the file lists, in the CLI's
 * `scan --diff-base` (`ciRunScans.test.ts`) and `review_pr`
 * (`reviewPr.test.ts`) alike (review 1 of 3.17.0, R1-DG-D-1, narrowed by
 * review 2, R2-DG-D-1): only the control file under `src/` is reported — not
 * the file the change moves INTO a left-out directory either (a rename git
 * reads). The weakened-tests step reads as it did in 3.16.1: `review_pr`'s
 * scan-tool factory drops a test of a left-out path, the CLI reports every one
 * (a focused test there still blocks). Both keep the test file of a left-out
 * directory the change deletes whole (`legacy/`): a path that is no longer in
 * the project is not one the file declares
 * (`platform/guardianIgnore.ts#projectPathTest`). The directive lines come
 * from the suppression cases: no test source holds a bare one.
 */

import { caseText, suppressionCase } from './suppressionCases.js';

const TEST = (name: string, skip: boolean): string => `it${skip ? '.skip' : ''}('${name}', () => { expect(1).toBe(1); });\n`;

/** Ten plain lines: moved with one line added, git reads the file as a rename. */
const MOVED = Array.from({ length: 10 }, (_, i) => `v${String(i)} = ${String(i)}\n`).join('');

/** The base commit's files. */
export const IGNORED_BASE: Readonly<Record<string, string>> = {
  '.guardianignore': 'vendor/\nthird_party/\nlegacy/\n',
  'src/app.py': 'x = 1\n',
  'src/moved.py': MOVED,
  'src/c.test.js': TEST('c', false),
  'third_party/lib/a.test.js': TEST('a', false),
  'legacy/old.test.js': TEST('old', false),
};

/** The file the change moves into `vendor/` (left out) with a bare directive added: remove `from`, and stage both paths. */
export const MOVED_INTO_IGNORED = { from: 'src/moved.py', to: 'vendor/moved.py' } as const;

/** The change: files written over the base (then `legacy/` is removed whole, and {@link MOVED_INTO_IGNORED}'s `from`). */
export function ignoredChange(): Record<string, string> {
  const bare = suppressionCase('Semgrep: a comment').lines[0] ?? '';
  return {
    'vendor/lib/x.py': `${bare}\n`,
    [MOVED_INTO_IGNORED.to]: `${MOVED}${bare}\n`,
    'third_party/gen.ts': `${caseText(suppressionCase('ESLint: the whole file, every rule'))}export const x = 1;\n`,
    'third_party/lib/a.test.js': TEST('a', true),
    'src/b.py': `${bare}\n`,
    'src/c.test.js': TEST('c', true),
  };
}

/** The directory the change deletes whole. */
export const DELETED_DIR = 'legacy';

/** What each reports, as `rule path:line severity` (a deletion has no line). */
export const REPORTED = {
  /** Both: the pass never reads a path the file lists. */
  suppressions: ['scanner-suppression-added src/b.py:1 medium'],
  /** `review_pr`: its factory's result filter drops the left-out test. */
  integrityReview: ['test-file-deleted legacy/old.test.js:- medium', 'test-skipped src/c.test.js:1 medium'],
  /** The CLI, as in 3.16.1: every path's. */
  integrityCli: ['test-file-deleted legacy/old.test.js:- medium', 'test-skipped src/c.test.js:1 medium', 'test-skipped third_party/lib/a.test.js:1 medium'],
} as const;

/** A finding as {@link REPORTED} spells it. */
export function rowOf(f: { rule_id?: string; file_path?: string; line_start?: number; severity: string }): string {
  return `${f.rule_id ?? ''} ${f.file_path ?? ''}:${f.line_start !== undefined ? String(f.line_start) : '-'} ${f.severity}`;
}

/**
 * Review 2 of 3.17.0, R2-DG-D-3: a regeneration of a left-out tree changes
 * more files than the pass's 500-file bound, each with a token (`# noqa`), and
 * the change adds one bare directive under `src/`. The pass lists only what
 * `.guardianignore` keeps, before its bound: `src/z.py` is read and reported,
 * the reason counts that one file, and no note counts a left-out one.
 */
const GENERATED = 600;

const generated = (i: number): string => `gen/m${String(i).padStart(4, '0')}.py`;

/** The base commit's files of the bound's shape. */
export function capBase(): Record<string, string> {
  const files: Record<string, string> = { '.guardianignore': 'gen/\n', 'src/z.py': 'x = 1\n' };
  for (let i = 0; i < GENERATED; i += 1) files[generated(i)] = 'x = 1\n';
  return files;
}

/** The change over {@link capBase}: every generated file given a token, `src/z.py` a bare directive. */
export function capChange(): Record<string, string> {
  const token = suppressionCase('noqa: every code').lines[0] ?? '';
  const files: Record<string, string> = { 'src/z.py': `${suppressionCase('Semgrep: a comment').lines[0] ?? ''}\n` };
  for (let i = 0; i < GENERATED; i += 1) files[generated(i)] = `${token}\n`;
  return files;
}

/** What the pass reports over the bound's shape, and how its reason starts. */
export const CAP_REPORTED = ['scanner-suppression-added src/z.py:1 medium'];
export const CAP_REASON = /^read 1 changed file\(s\) with a suppression token from [0-9a-f]{12} to /;
