/**
 * eslint / radon / staticcheck parsers — `quality_check` used to run all three,
 * keep their output, and throw it away ("recognised but not parsed"), so a
 * project full of lint errors and 50-branch functions reported a clean
 * quality scan. These pin what each report turns into.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { eslintFatalErrors, eslintParser } from '../../../../src/runners/scannerParsers/eslint.js';
import { radonErrors, radonParser } from '../../../../src/runners/scannerParsers/radon.js';
import {
  staticcheckErrors,
  staticcheckParser,
} from '../../../../src/runners/scannerParsers/staticcheck.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(here, '../../../fixtures/scanners');
const read = (name: string): string => readFileSync(resolve(FIX, name), 'utf8');

describe('eslintParser', () => {
  it('turns every rule message into a quality finding with a project-relative path', () => {
    const { findings } = eslintParser.parse(read('eslint.json'), { project_path: 'C:\\proj' });
    expect(findings.map((f) => f.rule_id).sort()).toEqual(['camelcase', 'complexity', 'no-unused-vars']);
    const unused = findings.find((f) => f.rule_id === 'no-unused-vars');
    expect(unused?.tool).toBe('eslint');
    expect(unused?.category).toBe('quality');
    expect(unused?.file_path).toBe('src/app.js');
    expect(unused?.line_start).toBe(3);
    // ESLint severity 2 (error) outranks 1 (warning).
    expect(unused?.severity).toBe('medium');
    expect(findings.find((f) => f.rule_id === 'camelcase')?.severity).toBe('low');
  });

  it('files naming and complexity rules under their quality category', () => {
    const { findings } = eslintParser.parse(read('eslint.json'), { project_path: 'C:\\proj' });
    expect(findings.find((f) => f.rule_id === 'camelcase')?.subcategory).toBe('naming');
    expect(findings.find((f) => f.rule_id === 'complexity')?.subcategory).toBe('complexity');
    expect(findings.find((f) => f.rule_id === 'no-unused-vars')?.subcategory).toBe('smell');
  });

  it('never turns a fatal parse error into a finding, and reports it separately', () => {
    const { findings } = eslintParser.parse(read('eslint.json'), { project_path: 'C:\\proj' });
    expect(findings.some((f) => f.file_path === 'src/broken.js')).toBe(false);
    expect(eslintFatalErrors(read('eslint.json'))).toEqual([
      'C:\\proj\\src\\broken.js: Parsing error: Unexpected token )',
    ]);
  });

  it('returns nothing for input that is not an ESLint JSON report', () => {
    expect(eslintParser.parse('not json').findings).toEqual([]);
    expect(eslintParser.parse('{"a":1}').findings).toEqual([]);
  });
});

describe('radonParser', () => {
  it('reports functions and methods of rank C or worse, once each', () => {
    const { findings } = radonParser.parse(read('radon-cc.json'));
    const names = findings.map((f) => f.title);
    expect(findings).toHaveLength(3);
    expect(names.some((t) => t.includes('tiny'))).toBe(false);
    // `run` is listed twice by radon (nested under the class and flat); one finding.
    expect(names.filter((t) => t.includes('Engine.run'))).toHaveLength(1);
    const monster = findings.find((f) => f.title.includes('monster'));
    expect(monster?.severity).toBe('high');
    expect(monster?.subcategory).toBe('complexity');
    expect(monster?.file_path).toBe('pkg/heavy.py');
    expect(monster?.line_start).toBe(210);
    expect(monster?.line_end).toBe(400);
    expect(findings.find((f) => f.title.includes('parse'))?.severity).toBe('low');
    expect(findings.find((f) => f.title.includes('Engine.run'))?.severity).toBe('medium');
  });

  it('keeps the rule id stable across ranks, so a complexity change is not a new finding', () => {
    const { findings } = radonParser.parse(read('radon-cc.json'));
    expect(new Set(findings.map((f) => f.rule_id))).toEqual(new Set(['cyclomatic-complexity']));
  });

  it('reports files radon could not parse', () => {
    expect(radonErrors(read('radon-cc.json'))).toEqual([
      'pkg/broken.py: invalid syntax (<unknown>, line 3)',
    ]);
  });
});

describe('staticcheckParser', () => {
  it('parses JSON lines into findings with project-relative paths', () => {
    const { findings } = staticcheckParser.parse(read('staticcheck.jsonl'), {
      project_path: '/home/u/proj',
    });
    expect(findings.map((f) => f.rule_id).sort()).toEqual(['SA4006', 'ST1003', 'U1000']);
    const sa = findings.find((f) => f.rule_id === 'SA4006');
    expect(sa?.tool).toBe('staticcheck');
    expect(sa?.file_path).toBe('main.go');
    expect(sa?.line_start).toBe(12);
    expect(sa?.severity).toBe('medium');
    expect(findings.find((f) => f.rule_id === 'ST1003')?.subcategory).toBe('naming');
    expect(findings.find((f) => f.rule_id === 'U1000')?.subcategory).toBe('smell');
    expect(findings.find((f) => f.rule_id === 'U1000')?.severity).toBe('low');
  });

  it('reports compile errors separately instead of as findings', () => {
    const { findings } = staticcheckParser.parse(read('staticcheck.jsonl'));
    expect(findings.some((f) => f.rule_id === 'compile')).toBe(false);
    expect(staticcheckErrors(read('staticcheck.jsonl'))).toEqual([
      '/home/u/proj/bad.go:3: expected declaration, found oops',
    ]);
  });

  it('ignores lines that are not JSON objects', () => {
    expect(staticcheckParser.parse('garbage\n\n{"nope":true}\n').findings).toEqual([]);
  });
});
