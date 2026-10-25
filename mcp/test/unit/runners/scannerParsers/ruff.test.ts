import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ruffParser, ruffSyntaxErrors } from '../../../../src/runners/scannerParsers/ruff.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/ruff.json');

describe('ruffParser', () => {
  it('produces one Finding per ruff entry', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings).toHaveLength(3);
  });

  it('classifies S* codes as security/high', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    const s = findings.find((f) => f.rule_id === 'S301');
    expect(s?.severity).toBe('high');
    expect(s?.category).toBe('security');
  });

  it('classifies F* codes as quality/medium', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    const f = findings.find((f) => f.rule_id === 'F401');
    expect(f?.severity).toBe('medium');
    expect(f?.category).toBe('quality');
  });

  it('classifies W* codes as quality/low', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    const w = findings.find((f) => f.rule_id === 'W291');
    expect(w?.severity).toBe('low');
  });

  it('sets fix_available based on the presence of a fix payload', () => {
    const { findings } = ruffParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings.find((f) => f.rule_id === 'F401')?.fix_available).toBe(true);
    expect(findings.find((f) => f.rule_id === 'S301')?.fix_available).toBe(false);
  });
});

/**
 * 3.6.1. `code.startsWith('S')` also matched flake8-simplify (SIM),
 * flake8-self (SLF) and flake8-slots (SLOT): every SIM102 became a high
 * security finding. The family is the code's letters, compared whole.
 */
describe('ruffParser: rule families', () => {
  const entry = (code: string): Record<string, unknown> => ({
    code,
    filename: 'src/app.py',
    location: { row: 1, column: 1 },
    end_location: { row: 1, column: 2 },
    message: code,
    fix: null,
  });
  it.each([
    ['S301', 'high', 'security'],
    ['S105', 'high', 'security'],
    ['SIM102', 'low', 'quality'],
    ['SLF001', 'low', 'quality'],
    ['SLOT000', 'low', 'quality'],
    ['F401', 'medium', 'quality'],
    ['FBT001', 'low', 'quality'],
    ['FURB101', 'low', 'quality'],
    ['E501', 'medium', 'quality'],
    ['ERA001', 'low', 'quality'],
    ['B006', 'medium', 'quality'],
    ['BLE001', 'low', 'quality'],
    ['ARG001', 'medium', 'quality'],
  ])('%s is %s / %s', (code, severity, category) => {
    const [f] = ruffParser.parse(JSON.stringify([entry(code)])).findings;
    expect(f?.severity).toBe(severity);
    expect(f?.category).toBe(category);
  });
});

/**
 * 3.6.1. A file Ruff could not parse is not linted — and its syntax errors
 * were no gap: Ruff 0.5 – 0.12 report them with `code: null` (the parser
 * dropped them, run ok), 0.13 and later with `code: "invalid-syntax"` (a low
 * finding), before 0.5 as E999. Ruff is not installed here: the shapes are
 * hand-made from Ruff's own JSON renderer snapshots
 * (`…json__tests__syntax_errors.snap` at tags 0.12.0 and 0.17.2, read
 * 2026-10-25).
 */
describe('ruffSyntaxErrors', () => {
  const syntax = (code: string | null, message: string): Record<string, unknown> => ({
    cell: null,
    code,
    end_location: { column: 1, row: 2 },
    filename: '/proj/src/broken.py',
    fix: null,
    location: { column: 15, row: 1 },
    message,
    noqa_row: null,
    url: null,
  });
  const report = JSON.stringify([
    syntax(null, 'SyntaxError: Expected one or more symbol names after import'),
    syntax('invalid-syntax', "Expected ')', found newline"),
    { ...syntax('E999', 'SyntaxError: invalid syntax'), filename: '/proj/old.py' },
    { code: 'F401', filename: '/proj/src/ok.py', location: { row: 1, column: 1 }, message: "'os' imported but unused" },
  ]);

  it('names each unparsed file once, project-relative, as a Syntax error', () => {
    expect(ruffSyntaxErrors(report, '/proj')).toEqual([
      { file: 'src/broken.py', type: 'Syntax error', message: 'SyntaxError: Expected one or more symbol names after import' },
      { file: 'old.py', type: 'Syntax error', message: 'SyntaxError: invalid syntax' },
    ]);
  });

  it('none of them is a finding', () => {
    expect(ruffParser.parse(report, { project_path: '/proj' }).findings.map((f) => f.rule_id)).toEqual(['F401']);
  });

  it('a report with no syntax error names none', () => {
    expect(ruffSyntaxErrors(readFileSync(FIXTURE, 'utf8'))).toEqual([]);
  });
});
