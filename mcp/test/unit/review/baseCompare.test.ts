/**
 * `review/baseCompare.ts` (3.18.0, DG-12): review_pr's Semgrep findings
 * judged against a run over the same files at the merge base, by the CI
 * gate's own matcher — `preexisting` only on positive evidence, listed (never
 * read from an absence), and the base targets from a real `--name-status -M`
 * listing. Findings: the committed Semgrep fixture's result, through the real
 * parser and the real identities over in-memory files.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { assignIdentities } from '../../../src/fingerprint/findingIdentity.js';
import { classifyAgainstBase, baseTargetsOf, PREEXISTING_LISTED, type BaseComparison, type LineRange } from '../../../src/review/baseCompare.js';
import { parseNameStatus } from '../../../src/runners/git.js';
import { banditParser } from '../../../src/runners/scannerParsers/bandit.js';
import { semgrepParser } from '../../../src/runners/scannerParsers/semgrep.js';
import { topFindings } from '../../../src/severity/counts.js';
import type { Finding } from '../../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures', 'scanners');
const TEMPLATE = (JSON.parse(readFileSync(join(FIXTURES, 'semgrep.json'), 'utf8')) as { results: Array<Record<string, unknown>> }).results[0] ?? {};
const SINK = 'res.send(req.query.q);';

/** A Semgrep report with one result per [path, line], the fixture's express-xss result moved there. */
function report(at: Array<[string, number, string?]>): string {
  return JSON.stringify({
    results: at.map(([path, line, severity]) => ({
      ...TEMPLATE,
      path,
      start: { line, col: 5 },
      end: { line, col: 5 + SINK.length },
      extra: { ...(TEMPLATE['extra'] as Record<string, unknown>), lines: SINK, ...(severity !== undefined ? { severity } : {}) },
    })),
    errors: [],
    paths: { scanned: [...new Set(at.map(([p]) => p))] },
  });
}

/** Findings of `raw`, with identities read from `files` (path → text), as the factory computes them. */
function identified(raw: string, files: Record<string, string>): Finding[] {
  return assignIdentities(semgrepParser.parse(raw).findings, { readSource: (p) => files[p.replace(/\\/g, '/')] ?? null });
}

/** A file whose line `n` is the sink, every other line its own text. */
function source(lines: number, sinks: number[], salt = ''): string {
  return Array.from({ length: lines }, (_x, i) => (sinks.includes(i + 1) ? `  ${SINK}` : `const v${i}${salt} = ${i};`)).join('\n') + '\n';
}

/** Without `addedLines`, no file was diffed: the identity alone decides (an added file's case). */
function compared(
  head: Finding[],
  base: Finding[],
  over: { renamedFrom?: Map<string, string>; unknownFiles?: Set<string>; addedLines?: Map<string, LineRange[]> } = {},
): Extract<BaseComparison, { compared: true }> {
  const r = classifyAgainstBase(head, {
    compared: true,
    base_sha: 'a'.repeat(40),
    findings: base,
    renamedFrom: over.renamedFrom ?? new Map(),
    unknownFiles: over.unknownFiles ?? new Set(),
    addedLines: over.addedLines ?? new Map(),
  });
  if (!r.compared) throw new Error('expected a comparison');
  return r;
}

/** A report of `rule`'s results at [path, line, flagged text] — the fixture's result with that id and text. */
function reportOf(rule: string, at: Array<[string, number, string]>): string {
  return JSON.stringify({
    results: at.map(([path, line, text]) => ({
      ...TEMPLATE,
      check_id: rule,
      path,
      start: { line, col: 3 },
      end: { line, col: 3 + text.trim().length },
      extra: { ...(TEMPLATE['extra'] as Record<string, unknown>), lines: text },
    })),
    errors: [],
    paths: { scanned: [...new Set(at.map(([p]) => p))] },
  });
}

/** The 1-based numbers of the lines of `text` that read `line`. */
const linesOf = (text: string, line: string): number[] => text.split('\n').flatMap((l, i) => (l === line ? [i + 1] : []));

describe('classifyAgainstBase: preexisting only on positive evidence', () => {
  it('the same sink at a shifted line is preexisting; an edited sink line is introduced', () => {
    const base = identified(report([['src/app.js', 12]]), { 'src/app.js': source(20, [12]) });
    const shifted = identified(report([['src/app.js', 13]]), { 'src/app.js': `// a line above\n${source(20, [12])}` });
    const r = compared(shifted, base);
    expect(r.counts).toEqual({ introduced: 0, preexisting: 1, unknown: 0, not_compared: 0 });
    expect(r.preexisting).toEqual(shifted);
    expect(r.preexisting_by_severity.critical + r.preexisting_by_severity.high).toBe(1);

    const editedText = source(20, [12]).replace(`  ${SINK}`, '  res.send(req.query.q + tail);');
    const edited = identified(report([['src/app.js', 12]]), { 'src/app.js': editedText });
    expect(compared(edited, base).counts).toEqual({ introduced: 1, preexisting: 0, unknown: 0, not_compared: 0 });
  });

  it('a renamed file is preexisting through the path it had at the merge base, and introduced without it', () => {
    const base = identified(report([['src/app.js', 12]]), { 'src/app.js': source(20, [12]) });
    const moved = identified(report([['lib/app.js', 12]]), { 'lib/app.js': source(20, [12]) });
    expect(compared(moved, base, { renamedFrom: new Map([['lib/app.js', 'src/app.js']]) }).counts.preexisting).toBe(1);
    expect(compared(moved, base).counts).toEqual({ introduced: 1, preexisting: 0, unknown: 0, not_compared: 0 });
  });

  it('a file the base run could not measure: its new findings are unknown, never preexisting', () => {
    const head = identified(report([['src/app.js', 12]]), { 'src/app.js': source(20, [12]) });
    const r = compared(head, [], { unknownFiles: new Set(['src/app.js']) });
    expect(r.counts).toEqual({ introduced: 0, preexisting: 0, unknown: 1, not_compared: 0 });
    expect(r.preexisting).toEqual([]);
  });

  it('a base side that could not be read compares nothing', () => {
    const head = identified(report([['src/app.js', 12]]), { 'src/app.js': source(20, [12]) });
    expect(classifyAgainstBase(head, { compared: false, reason: 'no merge base' })).toEqual({ compared: false, reason: 'no merge base' });
  });

  it('a group of identical sinks grows from 2 to 3: exactly one introduced', () => {
    const base = identified(report([['src/app.js', 5], ['src/app.js', 15]]), { 'src/app.js': source(20, [5, 15]) });
    const head = identified(report([['src/app.js', 2], ['src/app.js', 6], ['src/app.js', 16]]), {
      'src/app.js': source(21, [2, 6, 16]),
    });
    expect(compared(head, base).counts).toEqual({ introduced: 1, preexisting: 2, unknown: 0, not_compared: 0 });
  });

  it('another scanner’s findings are not compared, and never listed', () => {
    const bandit = banditParser.parse(readFileSync(join(FIXTURES, 'bandit.json'), 'utf8')).findings;
    const head = [...identified(report([['src/app.js', 12]]), { 'src/app.js': source(20, [12]) }), ...assignIdentities(bandit)];
    const base = identified(report([['src/app.js', 12]]), { 'src/app.js': source(20, [12]) });
    const r = compared(head, [...base, ...assignIdentities(bandit)]);
    expect(r.counts).toEqual({ introduced: 0, preexisting: 1, unknown: 0, not_compared: bandit.length });
    expect(r.preexisting.every((f) => f.tool === 'semgrep')).toBe(true);
  });

  it(`12 preexisting findings: the ${PREEXISTING_LISTED} listed are preexisting, worst first, whatever floor a response applies`, () => {
    const sinks = Array.from({ length: 12 }, (_x, i) => 3 + i * 3);
    const at = sinks.map((line, i): [string, number, string] => ['src/app.js', line, i < 4 ? 'WARNING' : 'ERROR']);
    const base = identified(report(at), { 'src/app.js': source(40, sinks) });
    const headAt = at.map(([p, line, sev]): [string, number, string] => [p, line + 1, sev]);
    const head = identified(report(headAt), { 'src/app.js': `// above\n${source(40, sinks)}` });
    const r = compared(head, base);
    expect(r.counts.preexisting).toBe(12);
    expect(r.preexisting).toHaveLength(PREEXISTING_LISTED);
    expect(r.preexisting).toEqual(topFindings(head, PREEXISTING_LISTED));
    const preexisting = new Set(head);
    for (const f of r.preexisting) expect(preexisting.has(f)).toBe(true);
    // Any finding top_findings shows of these, at any floor, is listed: its rank among them is at most its rank overall.
    for (const floor of ['info', 'medium', 'high', 'critical'] as const) {
      const order = ['info', 'low', 'medium', 'high', 'critical'];
      const shown = topFindings(head.filter((f) => order.indexOf(f.severity) >= order.indexOf(floor)), 10);
      for (const f of shown) expect(r.preexisting).toContain(f);
    }
  });
});

// 3.18.0 review 1 (DGBASE-2 / DGBASE-3): the identity alone called a new finding "the same" as an old one; a finding
// on a line the change added is introduced, whatever it matches. The reviewer's three shapes; the added ranges are
// those `git diff -U0` gives for each pair (the e2e reads them from git itself).
describe('classifyAgainstBase: a finding on a line the change added is introduced', () => {
  const H = ["const jwt = require('jsonwebtoken');", "const { exec } = require('child_process');"];
  const text = (...l: string[]): string => `${[...H, ...l].join('\n')}\n`;
  const JWT = 'javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret';
  const EXEC = 'fixture.exec-call';
  const sinkAt = (rule: string, path: string, body: string, line: string): Finding[] =>
    identified(reportOf(rule, linesOf(body, line).map((n): [string, number, string] => [path, n, line])), { [path]: body });

  it('a new hard-coded secret in a new function, the old one removed: introduced, though a credential rule keys it without its line', () => {
    const before = text('function login(u) {', "  return jwt.sign({ u }, 'old-literal-1');", '}', 'module.exports = { login };');
    const after = text(
      'function login(u) {',
      '  return jwt.sign({ u }, process.env.JWT_SECRET);',
      '}',
      'function adminToken() {',
      "  return jwt.sign({ admin: true }, 'brand-new-admin-literal');",
      '}',
      'module.exports = { login, adminToken };',
    );
    const base = sinkAt(JWT, 'auth.js', before, "  return jwt.sign({ u }, 'old-literal-1');");
    const head = sinkAt(JWT, 'auth.js', after, "  return jwt.sign({ admin: true }, 'brand-new-admin-literal');");
    expect(head.map((f) => f.line_start)).toEqual([7]);
    // What the identity alone says (the 3.18.0 review's mislabel): the same finding.
    expect(compared(head, base).counts.preexisting).toBe(1);
    const r = compared(head, base, { addedLines: new Map([['auth.js', [{ start: 4, end: 4 }, { start: 6, end: 9 }]]]) });
    expect(r.counts).toEqual({ introduced: 1, preexisting: 0, unknown: 0, not_compared: 0 });
    expect(r.preexisting).toEqual([]);
  });

  it('a new flagged line identical to an old one, put above it: the added one introduced, the old one preexisting', () => {
    const before = text('function a(cmd) {', '  exec(cmd);', '}', 'module.exports = { a };');
    const after = text('function fresh(req) {', '  const cmd = req.query.c;', '  exec(cmd);', '}', 'function a(cmd) {', '  exec(cmd);', '}', 'module.exports = { a, fresh };');
    const base = sinkAt(EXEC, 'twice.js', before, '  exec(cmd);');
    const head = sinkAt(EXEC, 'twice.js', after, '  exec(cmd);');
    expect(head.map((f) => f.line_start)).toEqual([5, 8]);
    // The identity alone: the new line took the old one's occurrence.
    expect(compared(head, base).preexisting.map((f) => f.line_start)).toEqual([5]);
    const r = compared(head, base, { addedLines: new Map([['twice.js', [{ start: 3, end: 6 }, { start: 10, end: 10 }]]]) });
    expect(r.counts).toEqual({ introduced: 1, preexisting: 1, unknown: 0, not_compared: 0 });
    expect(r.preexisting.map((f) => f.line_start)).toEqual([8]);
  });

  it('the limit, pinned: a flagged line the diff kept reads preexisting, even when the function around it was replaced', () => {
    const before = text('function old(cmd) {', '  exec(cmd);', '}', 'module.exports = { old };');
    const after = text('function handler(req) {', '  const cmd = req.query.c;', '  exec(cmd);', '}', 'module.exports = { handler };');
    const base = sinkAt(EXEC, 'mv.js', before, '  exec(cmd);');
    const head = sinkAt(EXEC, 'mv.js', after, '  exec(cmd);');
    // git keeps `  exec(cmd);` and `}` (the longest common run): only the header, the new line and the export are added.
    const r = compared(head, base, { addedLines: new Map([['mv.js', [{ start: 3, end: 4 }, { start: 7, end: 7 }]]]) });
    expect(r.counts).toEqual({ introduced: 0, preexisting: 1, unknown: 0, not_compared: 0 });
  });

  it('any added line of a finding counts, a finding with no line in a compared file is never kept, and an added line beats unknown', () => {
    const body = source(20, [12]);
    const base = identified(report([['src/app.js', 12]]), { 'src/app.js': body });
    const spanning = identified(report([['src/app.js', 12]]), { 'src/app.js': body }).map((f) => ({ ...f, line_start: 10, line_end: 12 }));
    const added = new Map([['src/app.js', [{ start: 12, end: 12 }]]]);
    expect(compared(spanning, base, { addedLines: added }).counts.introduced).toBe(1);
    expect(compared(spanning, base, { addedLines: new Map([['src/app.js', [{ start: 13, end: 14 }]]]) }).counts.preexisting).toBe(1);
    const lineless = identified(report([['src/app.js', 12]]), { 'src/app.js': body }).map((f) => {
      const { line_start: _s, line_end: _e, ...rest } = f;
      return rest as Finding;
    });
    expect(compared(lineless, base, { addedLines: new Map([['src/app.js', []]]) }).counts.introduced).toBe(1);
    const head = identified(report([['src/app.js', 12]]), { 'src/app.js': source(20, [12], 'x') });
    expect(compared(head, [], { unknownFiles: new Set(['src/app.js']), addedLines: added }).counts).toEqual({
      introduced: 1,
      preexisting: 0,
      unknown: 0,
      not_compared: 0,
    });
  });
});

describe('baseTargetsOf: the files the base run reads', () => {
  it('from a real listing: modified (M and T) under their own path, renamed under the old one; added, copied and deleted never', () => {
    const dir = makeTempDir('base-targets-');
    const git = (...args: string[]): string => {
      const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
      if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
      return r.stdout;
    };
    git('init', '-q');
    const long = Array.from({ length: 30 }, (_x, i) => `line ${i}`).join('\n') + '\n';
    writeFileSync(join(dir, 'mod.js'), long);
    writeFileSync(join(dir, 'old name.js'), long + 'renamed\n');
    writeFileSync(join(dir, 'gone.js'), long + 'gone\n');
    writeFileSync(join(dir, 'typed.js'), long + 'typed\n');
    writeFileSync(join(dir, 'quiet.js'), long + 'quiet\n');
    git('add', '-A');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD').trim();
    writeFileSync(join(dir, 'mod.js'), long + 'more\n');
    writeFileSync(join(dir, 'quiet.js'), long + 'quiet, edited\n');
    git('mv', 'old name.js', 'new name.js');
    git('rm', '-q', 'gone.js');
    writeFileSync(join(dir, 'added.js'), 'fresh\n');
    // A type change through the index: no symlink on disk, on any platform.
    const blob = git('hash-object', '-w', '--stdin').trim();
    git('update-index', '--cacheinfo', `120000,${blob},typed.js`);
    git('add', 'mod.js', 'quiet.js', 'added.js');
    git('commit', '-qm', 'change');
    const listing = git('diff', '-z', '--name-status', '-M', '--relative', `${base}..HEAD`, '--');
    const letters = listing.split('\0').filter((x) => /^[A-Z]\d*$/.test(x)).map((x) => x[0]);
    expect(new Set(letters)).toEqual(new Set(['A', 'D', 'M', 'R', 'T']));
    const withResults = new Set(['mod.js', 'new name.js', 'added.js', 'typed.js', 'gone.js']);
    const targets = baseTargetsOf(parseNameStatus(listing), withResults, () => true);
    expect([...targets].sort()).toEqual([
      ['mod.js', 'mod.js'],
      ['new name.js', 'old name.js'],
      ['typed.js', 'typed.js'],
    ]);
    // A file with no head result is never read at base; one the review leaves out (.guardianignore) neither.
    expect(baseTargetsOf(parseNameStatus(listing), withResults, (p) => p !== 'mod.js').has('mod.js')).toBe(false);
    expect(baseTargetsOf(parseNameStatus(listing), new Set(['added.js']), () => true).size).toBe(0);
    expect([...baseTargetsOf(parseNameStatus(listing), withResults, () => true).keys()]).not.toContain('quiet.js');
  });
});
