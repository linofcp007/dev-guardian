/**
 * One change both diff steps read — the suppressions it adds and the tests it
 * weakens — partly in directories the project's `.guardianignore` leaves out:
 * the CLI's `scan --diff-base` (`ciRunScans.test.ts`) and `review_pr`
 * (`reviewPr.test.ts`) must report the same (review 1 of 3.17.0, R1-DG-D-1).
 * Only the control files under `src/` are reported, and the test file of a
 * left-out directory the change deletes whole (`legacy/`): a path that is no
 * longer in the project is not one the file declares, so every scan keeps it
 * (`platform/guardianIgnore.ts#projectPathTest`). The directive lines come
 * from the suppression cases: no test source holds a bare one.
 */

import { caseText, suppressionCase } from './suppressionCases.js';

const TEST = (name: string, skip: boolean): string => `it${skip ? '.skip' : ''}('${name}', () => { expect(1).toBe(1); });\n`;

/** The base commit's files. */
export const IGNORED_BASE: Readonly<Record<string, string>> = {
  '.guardianignore': 'vendor/\nthird_party/\nlegacy/\n',
  'src/app.py': 'x = 1\n',
  'src/c.test.js': TEST('c', false),
  'third_party/lib/a.test.js': TEST('a', false),
  'legacy/old.test.js': TEST('old', false),
};

/** The change: files written over the base (`legacy/` is then removed whole). */
export function ignoredChange(): Record<string, string> {
  const bare = suppressionCase('Semgrep: a comment').lines[0] ?? '';
  return {
    'vendor/lib/x.py': `${bare}\n`,
    'third_party/gen.ts': `${caseText(suppressionCase('ESLint: the whole file, every rule'))}export const x = 1;\n`,
    'third_party/lib/a.test.js': TEST('a', true),
    'src/b.py': `${bare}\n`,
    'src/c.test.js': TEST('c', true),
  };
}

/** The directory the change deletes whole. */
export const DELETED_DIR = 'legacy';

/** What both report, as `rule path:line severity` (a deletion has no line). */
export const REPORTED_BY_BOTH = {
  suppressions: ['scanner-suppression-added src/b.py:1 medium'],
  integrity: ['test-file-deleted legacy/old.test.js:- medium', 'test-skipped src/c.test.js:1 medium'],
} as const;

/** A finding as {@link REPORTED_BY_BOTH} spells it. */
export function rowOf(f: { rule_id?: string; file_path?: string; line_start?: number; severity: string }): string {
  return `${f.rule_id ?? ''} ${f.file_path ?? ''}:${f.line_start !== undefined ? String(f.line_start) : '-'} ${f.severity}`;
}
