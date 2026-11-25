/**
 * The suppressions pass's cases (`test/fixtures/suppressions/examples.json`),
 * for every test that needs a directive line: read from the fixture folder,
 * which the pass never reads, so no test source holds a bare directive that
 * Semgrep or gitleaks would honour in a string (dev-guardian's own branches
 * are read by the pass too).
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface SuppressionCase {
  name: string;
  row: string;
  path: string;
  lines: string[];
  /** The 1-based lines that are added; all of them when absent. */
  added?: number[];
  /** Lines the same change removes. */
  removed?: string[];
  /** One letter per directive read on the added lines: M, L (a finding), N (named), R (reasoned), C (carried). */
  out: string;
}

export const SUPPRESSION_FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'suppressions');

export const SUPPRESSION_CASES: readonly SuppressionCase[] = (
  JSON.parse(readFileSync(join(SUPPRESSION_FIXTURES, 'examples.json'), 'utf8')) as { cases: SuppressionCase[] }
).cases;

/** The case of that name. */
export function suppressionCase(name: string): SuppressionCase {
  const c = SUPPRESSION_CASES.find((x) => x.name === name);
  if (c === undefined) throw new Error(`no suppression case named ${name}`);
  return c;
}

/** The case's lines as one file's text, LF-ended. */
export function caseText(c: SuppressionCase): string {
  return `${c.lines.join('\n')}\n`;
}
