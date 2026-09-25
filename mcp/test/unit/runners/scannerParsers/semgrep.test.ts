import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { semgrepParser } from '../../../../src/runners/scannerParsers/semgrep.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/semgrep.json');

function readFixture(): string {
  return readFileSync(FIXTURE, 'utf8');
}

describe('semgrepParser', () => {
  it('returns one Finding per result entry', () => {
    const { findings, cves } = semgrepParser.parse(readFixture());
    expect(findings).toHaveLength(3);
    expect(cves).toEqual([]);
  });

  it('upgrades security ERROR findings to critical', () => {
    const { findings } = semgrepParser.parse(readFixture());
    const xss = findings.find((f) => f.rule_id?.includes('express-xss'));
    expect(xss?.severity).toBe('critical');
    expect(xss?.category).toBe('security');
  });

  it('maps performance WARNING to medium and category=performance', () => {
    const { findings } = semgrepParser.parse(readFixture());
    const perf = findings.find((f) => f.rule_id?.endsWith('list-comprehension'));
    expect(perf?.severity).toBe('medium');
    expect(perf?.category).toBe('performance');
  });

  it('marks fix_available=true when extra.fix is present', () => {
    const { findings } = semgrepParser.parse(readFixture());
    const perf = findings.find((f) => f.rule_id?.endsWith('list-comprehension'));
    expect(perf?.fix_available).toBe(true);
  });

  it('produces stable fingerprints across re-parses', () => {
    const a = semgrepParser.parse(readFixture()).findings.map((f) => f.fingerprint);
    const b = semgrepParser.parse(readFixture()).findings.map((f) => f.fingerprint);
    expect(a).toEqual(b);
  });

  it('accepts already-parsed JSON in addition to raw strings', () => {
    const obj = JSON.parse(readFixture()) as unknown;
    const a = semgrepParser.parse(readFixture()).findings.length;
    const b = semgrepParser.parse(obj).findings.length;
    expect(a).toBe(b);
  });

  it('returns empty arrays on garbage input', () => {
    expect(semgrepParser.parse('not json').findings).toEqual([]);
    expect(semgrepParser.parse(null).findings).toEqual([]);
    expect(semgrepParser.parse({}).findings).toEqual([]);
  });
});

function oneResult(overrides: { path?: string; check_id?: string; category?: string }): string {
  return JSON.stringify({
    results: [
      {
        check_id: overrides.check_id ?? 'rules.some-rule',
        path: overrides.path ?? 'src/app.js',
        start: { line: 3 },
        end: { line: 3 },
        extra: {
          severity: 'WARNING',
          message: 'msg',
          lines: 'x',
          ...(overrides.category ? { metadata: { category: overrides.category } } : {}),
        },
      },
    ],
    errors: [],
  });
}

describe('semgrepParser — Docker and native runs agree', () => {
  // The Docker fallback mounts the project at /src and scans `/src`, so
  // Semgrep reports `/src/app/x.js`; a native run of the same tree reports a
  // path under the project. Both must land as the same project-relative path
  // — the fingerprint, dedupe and baseline all key on it.
  it('strips the /src/ mount prefix to the same relative path a native run gives', () => {
    const project = process.platform === 'win32' ? 'C:\\Users\\me\\proj' : '/home/me/proj';
    const native = semgrepParser.parse(
      oneResult({ path: `${project.replace(/\\/g, '/')}/src/app.js` }),
      { project_path: project },
    ).findings[0];
    const docker = semgrepParser.parse(oneResult({ path: '/src/src/app.js' }), {
      project_path: project,
    }).findings[0];
    expect(native?.file_path).toBe('src/app.js');
    expect(docker?.file_path).toBe('src/app.js');
    expect(docker?.fingerprint).toBe(native?.fingerprint);
  });

  it('leaves a native project that really lives at /src alone', () => {
    const f = semgrepParser.parse(oneResult({ path: '/src/app.js' }), { project_path: '/src' })
      .findings[0];
    expect(f?.file_path).toBe('app.js');
  });
});

describe('semgrepParser — category mapping', () => {
  it("maps metadata.category 'correctness' to bug, not quality", () => {
    const f = semgrepParser.parse(oneResult({ category: 'correctness' })).findings[0];
    expect(f?.category).toBe('bug');
  });

  it.each([
    ['best-practice', 'quality'],
    ['maintainability', 'quality'],
    ['bug', 'bug'],
    ['security', 'security'],
    ['performance', 'performance'],
  ])("still maps '%s' to %s", (category, expected) => {
    expect(semgrepParser.parse(oneResult({ category })).findings[0]?.category).toBe(expected);
  });
});
