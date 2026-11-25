/**
 * The suppressions pass's reader (`testintegrity/suppressions.ts`), on the
 * cases of `test/fixtures/suppressions/examples.json`: one per directive's
 * bare and reasoned forms, the scanners' own readings (Semgrep inside a
 * string, Bandit and gosec in comments only), the literal doubts, the reason
 * rule, carried directives — and dev-spec-driven's launcher, which reads as
 * counts only. The cases live in a fixture folder the pass never reads, so no
 * test source holds a bare directive (dev-guardian's own branches are read by
 * the pass too).
 *
 * What must STILL hold, beside this file: every test of the test-integrity
 * pass (`detect.test.ts`, `testIntegrityGit.test.ts`) is unchanged.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  detectSuppressions,
  mayHoldSuppression,
  PICKAXE_ERE,
  readLines,
  SUPPRESSION_ROWS,
  SUPPRESSIONS_TOOL,
  suppressionLanguageOf,
  type SuppressionFile,
} from '../../../src/testintegrity/suppressions.js';
import { SUPPRESSION_CASES as CASES, SUPPRESSION_FIXTURES as FIXTURES, suppressionCase, type SuppressionCase as Case } from '../../helpers/suppressionCases.js';

function fileOf(c: Case): SuppressionFile {
  return {
    path: c.path,
    added: (c.added ?? c.lines.map((_, i) => i + 1)).map((line) => ({ line, text: c.lines[line - 1] ?? '' })),
    removed: (c.removed ?? []).map((text) => ({ line: 1, text })),
    after: c.lines.join('\n'),
  };
}

/** M / L per finding, then N, R, C per count — sorted: the order of directives on a line does not matter. */
function outOf(files: readonly SuppressionFile[]): string {
  const { findings, counts } = detectSuppressions(files);
  const letters =
    findings.map((f) => (f.severity === 'medium' ? 'M' : f.severity === 'low' ? 'L' : '?')).join('') +
    'N'.repeat(counts.named) +
    'R'.repeat(counts.reasoned) +
    'C'.repeat(counts.carried);
  return [...letters].sort().join('');
}

const sorted = (s: string): string => [...s].sort().join('');

describe('the suppressions table, case by case', () => {
  it.each(CASES.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    expect(outOf([fileOf(c)])).toBe(sorted(c.out));
  });

  it('every row has a case, and every case names a row', () => {
    const ids = new Set(SUPPRESSION_ROWS.map((r) => r.id));
    expect(CASES.filter((c) => !ids.has(c.row)).map((c) => c.name)).toEqual([]);
    const covered = new Set(CASES.filter((c) => c.out !== '').map((c) => c.row));
    expect([...ids].filter((id) => !covered.has(id))).toEqual([]);
  });

  // The -G listing and the rows can only drift apart if a row reads a line no token names: then git never lists the
  // file. Every case's line that the reader takes for a directive holds one of ITS row's own tokens.
  it("every directive the reader finds holds one of its row's own tokens, and so the pickaxe", () => {
    const tokens = new Map(SUPPRESSION_ROWS.map((r) => [r.id, r.tokens.map((t) => new RegExp(t))]));
    const missed: string[] = [];
    for (const c of CASES.filter((x) => /[MLNRC]/.test(x.out))) {
      const lines = (c.added ?? c.lines.map((_, i) => i + 1)).map((n) => c.lines[n - 1] ?? '');
      const own = tokens.get(c.row) ?? [];
      if (!lines.some((l) => own.some((t) => t.test(l)))) missed.push(`${c.name} (own token)`);
      if (!lines.some((l) => mayHoldSuppression(l))) missed.push(`${c.name} (pickaxe)`);
    }
    expect(missed).toEqual([]);
  });

  it("the pickaxe is literals, bracket classes and optional characters joined by | — git's ERE and V8 read it alike", () => {
    for (const token of PICKAXE_ERE.split('|')) {
      // No `\s`, `\b`, `\d`, `\w`, lookaround or group: what POSIX ERE spells differently or not at all.
      expect(token, token).not.toMatch(/\\[sbdwSBDW]|\(\?|[()]/);
    }
    expect(PICKAXE_ERE.split('|').length).toBe(new Set(SUPPRESSION_ROWS.flatMap((r) => r.tokens)).size);
  });
});

describe('the findings', () => {
  const one = (path: string, ...lines: string[]): ReturnType<typeof detectSuppressions> =>
    detectSuppressions([{ path, added: lines.map((text, i) => ({ line: i + 1, text })), removed: [], after: lines.join('\n') }]);
  const byName = suppressionCase;

  it("a scanner's bare blanket form: scanner-suppression-added medium, on its line, with no snippet (a gitleaks:allow line holds a secret)", () => {
    const c = byName('gitleaks: a comment');
    const { findings } = detectSuppressions([fileOf(c)]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      tool: SUPPRESSIONS_TOOL,
      rule_id: 'scanner-suppression-added',
      severity: 'medium',
      category: 'quality',
      subcategory: 'suppression',
      file_path: 'cfg/a.py',
      line_start: 1,
      line_end: 1,
    });
    expect(findings[0]?.snippet).toBeUndefined();
    expect(findings[0]?.title).not.toContain('not-a-real-token');
    expect(findings[0]?.message).toMatch(/dev-guardian's gate included/);
  });

  it("a linter's: suppression-added, medium for the whole file and every rule, low for a line", () => {
    const file = detectSuppressions([fileOf(byName('ESLint: the whole file, every rule'))]).findings;
    expect(file.map((f) => `${f.rule_id ?? ''} ${f.severity}`)).toEqual(['suppression-added medium']);
    expect(file[0]?.title).toMatch(/for the whole file and every rule/);
    const line = detectSuppressions([fileOf(byName('noqa: every code'))]).findings;
    expect(line.map((f) => `${f.rule_id ?? ''} ${f.severity}`)).toEqual(['suppression-added low']);
    expect(line[0]?.title).toMatch(/for every rule on its line/);
  });

  it("each title names the directive in its tool's own form", () => {
    const labels: Array<[string, string]> = [
      ['PHPStan: the next line', '`@phpstan-ignore-next-line`'],
      ['phpcs: ignoreFile', '`phpcs:ignoreFile`'],
      ['phpcs: disable', '`phpcs:disable`'],
      ['phpcs: ignore a line', '`phpcs:ignore`'],
      ['Rust: the whole crate', '`#![allow(…)]`'],
      ['oxlint: the next line, every rule', '`oxlint-disable-next-line`'],
      ['ESLint: a line, every rule', '`eslint-disable-line`'],
      ['TypeScript: @ts-expect-error outside a test', '`@ts-expect-error`'],
      ['C#: the whole assembly, a rule', '`[assembly: SuppressMessage]`'],
      ['Kotlin: the whole file', '`@file:Suppress`'],
      ['Pylint: skip-file', '`# pylint: skip-file`'],
      ['Pylint: all', '`# pylint: disable`'],
      ['staticcheck: the whole file, no reason', '`//lint:file-ignore`'],
      ['Semgrep: a comment', '`nosemgrep`'],
    ];
    for (const [name, label] of labels) {
      const titles = detectSuppressions([fileOf(byName(name))]).findings.map((f) => f.title);
      expect(titles.length, name).toBe(1);
      expect(titles[0], name).toContain(label);
    }
  });

  it('nothing is high, in any case', () => {
    const all = CASES.flatMap((c) => detectSuppressions([fileOf(c)]).findings);
    expect(all.length).toBeGreaterThan(20);
    expect(all.filter((f) => f.severity !== 'medium' && f.severity !== 'low')).toEqual([]);
  });

  it("dev-spec-driven's launcher (.specs/guardian.cjs, 1.40) reads as counts only: three rule-naming nosemgrep lines, no finding", () => {
    const text = readFileSync(join(FIXTURES, 'guardian.cjs'), 'utf8');
    const { findings, counts } = one('.specs/guardian.cjs', ...text.split('\n'));
    expect(findings).toEqual([]);
    expect(counts.added).toBe(3);
    expect(counts.named + counts.reasoned).toBe(3);
  });

  it('a file whose text was not read: its added lines are not judged, and counted unread', () => {
    const c = byName('ESLint: the whole file, every rule');
    const r = detectSuppressions([{ ...fileOf(c), after: null }]);
    expect(r.findings).toEqual([]);
    expect(r.counts).toMatchObject({ files: 1, unread: 1, added: 0 });
  });

  it('a file whose diff and text disagree on a line: that line is not read', () => {
    const r = detectSuppressions([{ path: 'src/a.ts', added: [{ line: 1, text: '/* eslint-disable */' }], removed: [], after: 'const x = 1;' }]);
    expect(r.findings).toEqual([]);
  });

  it('a removed directive in another file carries the added one (a file moved without git mv)', () => {
    const c = byName('ESLint: the whole file, every rule');
    const r = detectSuppressions([
      { path: 'src/old.ts', added: [], removed: [{ line: 1, text: c.lines[0] ?? '' }], after: null },
      fileOf({ ...c, path: 'src/new.ts' }),
    ]);
    expect(r.findings).toEqual([]);
    expect(r.counts).toMatchObject({ carried: 1, added: 0, files: 2, unread: 0 });
  });

  it('a CRLF file reads as an LF one', () => {
    const c = byName('noqa: every code');
    const r = detectSuppressions([{ ...fileOf(c), after: `${c.lines.join('\r\n')}\r\n` }]);
    expect(r.findings.map((f) => f.severity)).toEqual(['low']);
  });
});

describe('the languages read, and the lexer', () => {
  it('by extension and name; anything else is not read', () => {
    expect(
      ['a.ts', 'a.vue', 'a.py', 'a.go', 'a.rs', 'A.java', 'A.kt', 'A.cs', 'a.php', 'a.rb', 'a.sh', 'a.cpp', 'a.h', 'main.tf', 'ci.yml', 'Dockerfile', 'Dockerfile.dev', 'api.dockerfile'].map(
        (p) => suppressionLanguageOf(`src/${p}`),
      ),
    ).toEqual(['js', 'html', 'py', 'go', 'rs', 'jvm', 'jvm', 'cs', 'php', 'rb', 'sh', 'c', 'c', 'tf', 'yaml', 'docker', 'docker', 'docker']);
    expect(['README.md', 'a.json', '.env', 'a.txt', 'Makefile'].map((p) => suppressionLanguageOf(p))).toEqual([null, null, null, null, null]);
  });

  it('a block comment over several lines: the lines after its first continue it', () => {
    const lines = readLines('/* a\n b\n c */ x();\n', 'js');
    expect(lines.map((l) => ({ cont: l.comments[0]?.cont ?? null, unclosed: l.comments[0]?.unclosed ?? null, code: l.code.trim() }))).toEqual([
      { cont: false, unclosed: true, code: '' },
      { cont: true, unclosed: true, code: '' },
      { cont: true, unclosed: false, code: 'x();' },
      { cont: null, unclosed: null, code: '' },
    ]);
  });

  it('strings are blanked in the code, at the same positions', () => {
    const [l] = readLines('foo("a // b", `c`); // d', 'js');
    expect(l?.code).toBe('foo(        ,    );     ');
    expect(l?.comments.map((c) => c.start)).toEqual([22]);
  });
});
