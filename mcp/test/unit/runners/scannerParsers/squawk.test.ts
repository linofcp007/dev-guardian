/**
 * squawk's `--reporter json` (`runners/scannerParsers/squawk.ts`). The report below is squawk 2.71.0's own: the
 * snapshot of `display_violations_json` in crates/squawk/src/reporter.rs (two `ALTER TABLE … ADD COLUMN … NOT NULL`
 * statements after a blank line, so the first is on line 1 counted from 0), and `skip_lint_on_syntax_error`'s.
 */

import { describe, expect, it } from 'vitest';
import { squawkParser } from '../../../../src/runners/scannerParsers/squawk.js';

const LOCK = {
  file: 'main.sql',
  line: 1,
  column: 3,
  level: 'Warning',
  message: 'missing `set lock_timeout` before potentially slow `access exclusive` lock operations',
  note: 'statement requires: `access exclusive` lock; blocking: reads, writes, schema changes',
  help: 'configure a `lock_timeout` before this statement',
  rule_name: 'require-lock-timeout',
  column_end: 63,
  line_end: 1,
};
const REQUIRED = {
  file: 'main.sql',
  line: 2,
  column: 23,
  level: 'Warning',
  message: 'adding a new column that is `not null` and has no default value to an existing table effectively makes it required',
  note: null,
  help: 'make the field nullable or add a non-volatile default',
  rule_name: 'adding-required-field',
  column_end: 56,
  line_end: 2,
};
const SYNTAX = {
  file: 'test.sql',
  line: 0,
  column: 36,
  level: 'Error',
  message: 'missing comma',
  note: null,
  help: null,
  rule_name: 'syntax-error',
  column_end: 36,
  line_end: 0,
};

describe('squawk parser', () => {
  it('maps each violation: low, migration-safety, the rule its id, the line counted from 1, the note and help said', () => {
    const { findings } = squawkParser.parse(JSON.stringify([LOCK, REQUIRED]), { project_path: '/repo' });
    expect(findings.map((f) => [f.rule_id, f.severity, f.category, f.subcategory, f.file_path, f.line_start, f.line_end])).toEqual([
      ['require-lock-timeout', 'low', 'bug', 'migration-safety', 'main.sql', 2, 2],
      ['adding-required-field', 'low', 'bug', 'migration-safety', 'main.sql', 3, 3],
    ]);
    expect(findings[0]?.title).toBe(LOCK.message);
    expect(findings[0]?.message).toContain('statement requires: `access exclusive` lock');
    expect(findings[0]?.message).toContain('configure a `lock_timeout` before this statement');
    expect(findings[0]?.message).toContain('https://squawkhq.com/docs/require-lock-timeout');
    expect(findings[1]?.message).not.toContain('(null)');
  });

  it("squawk's Error level is no severity of the code: every violation is low", () => {
    const { findings } = squawkParser.parse(JSON.stringify([{ ...LOCK, level: 'Error' }]));
    expect(findings.map((f) => f.severity)).toEqual(['low']);
  });

  it('a syntax-error is no finding (the file is named partial by the run); unknown fields and junk are ignored', () => {
    const { findings } = squawkParser.parse(JSON.stringify([SYNTAX, { ...REQUIRED, extra: 1 }, { file: 'x.sql' }, 7, null]));
    expect(findings.map((f) => f.rule_id)).toEqual(['adding-required-field']);
    expect(squawkParser.parse('not json').findings).toEqual([]);
    expect(squawkParser.parse('').findings).toEqual([]);
  });
});
