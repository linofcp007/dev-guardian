/**
 * govulncheck's run judged, and its stream parsed (`runners/govulncheckRun.ts`,
 * `scannerParsers/govulncheck.ts`). The reports under
 * `fixtures/scanners/govulncheck/` are govulncheck v1.9.0's own (Go 1.26.10,
 * golang:1.26-bookworm, 2026-10-24) over `fixtures/govulncheck/project`, with
 * `GOWORK=off govulncheck -format json ./...` in each module, trimmed to the
 * `config`, `SBOM` and `finding` messages and the `osv` entries those name:
 *
 *   - `project.json`: the root module — GO-2022-1059 at all three levels (the
 *     module required, `x/text/language` imported, `ParseAcceptLanguage`
 *     called from web/langs.go:7), two more vulnerabilities required only;
 *   - `tools.json`: the nested module with no dependency — no finding;
 *   - `broken.stderr.txt`: the nested module that does not type-check (exit 1).
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { goModuleDirs, govulncheckMessages, judgeGovulncheck } from '../../../src/runners/govulncheckRun.js';
import { govulncheckParser } from '../../../src/runners/scannerParsers/govulncheck.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import { withTrivySeverity } from '../../../src/tools/depsAudit.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(resolve(here, '../../fixtures/scanners/govulncheck', name), 'utf8');

const run = (exitCode: number | null, stdout: string, stderr = '', outcome: 'completed' | 'failed' | 'timed_out' = 'completed') => ({
  outcome,
  exitCode,
  stdout,
  stderr,
});

describe('goModuleDirs', () => {
  it('every directory with a go.mod, never under vendor, testdata, a dot or an underscore directory', () => {
    expect(
      goModuleDirs(['go.mod', 'tools/go.mod', 'broken/go.mod', 'vendor/x/go.mod', 'a/testdata/go.mod', '.cache/go.mod', '_old/go.mod', 'go.sum', 'b\\c\\go.mod']),
    ).toEqual(['.', 'b/c', 'broken', 'tools']);
  });
});

describe('govulncheckMessages', () => {
  it('reads the pretty-printed stream, braces inside strings included', () => {
    expect(govulncheckMessages('{\n  "a": "{x}"\n}\n{"b": {"c": 1}}\n')).toEqual([{ a: '{x}' }, { b: { c: 1 } }]);
  });

  it('anything else is not a stream', () => {
    expect(govulncheckMessages('not json')).toBeNull();
    expect(govulncheckMessages('{"a": 1')).toBeNull();
    expect(govulncheckMessages('{"a": 1}}')).toBeNull();
  });
});

describe('judgeGovulncheck', () => {
  it('the root module: ok, one vulnerability called, two required and not called', () => {
    const r = judgeGovulncheck(run(0, fixture('project.json')));
    expect(r.ok).toBe(true);
    expect(r.counts).toEqual({ called: 1, imported: 0, required: 2 });
  });

  it('a module with nothing vulnerable: ok, nothing counted', () => {
    expect(judgeGovulncheck(run(0, fixture('tools.json'))).counts).toEqual({ called: 0, imported: 0, required: 0 });
  });

  it('a module that does not type-check: failed, with the go error named', () => {
    const r = judgeGovulncheck(run(1, '', fixture('broken.stderr.txt')));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('exit 1: govulncheck: loading packages: /src/broken/b.go:4:23: undefined: undefinedThing');
  });

  it('no config message, or an unfinished run: failed', () => {
    expect(judgeGovulncheck(run(0, '{"progress": {"message": "x"}}'))).toEqual({ ok: false, reason: 'govulncheck wrote no JSON report' });
    expect(judgeGovulncheck(run(null, '', '', 'timed_out')).reason).toBe('did not finish (timed_out)');
  });
});

describe('govulncheckParser', () => {
  it('the called vulnerability only, at the project’s own call site, its aliases kept', () => {
    const { findings } = govulncheckParser.parse({ moduleDir: '.', report: fixture('project.json') });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      tool: 'govulncheck',
      rule_id: 'GO-2022-1059',
      severity: 'medium',
      category: 'security',
      subcategory: 'dependency',
      file_path: 'web/langs.go',
      line_start: 7,
      snippet: 'golang.org/x/text@v0.3.7',
      vuln_aliases: ['CVE-2022-32149', 'GHSA-69ch-w2m2-3vjp'],
      fix_available: true,
    });
    expect(findings[0]?.message).toContain(
      'example.com/govulnfixture/web.Langs calls golang.org/x/text/language.ParseAcceptLanguage, which is vulnerable (GO-2022-1059); fixed in v0.3.8',
    );
  });

  it('a nested module’s positions are placed under its directory', () => {
    const { findings } = govulncheckParser.parse({ moduleDir: 'services/api', report: fixture('project.json') });
    expect(findings[0]?.file_path).toBe('services/api/web/langs.go');
  });
});

describe('withTrivySeverity', () => {
  const govuln = govulncheckParser.parse({ moduleDir: '.', report: fixture('project.json') }).findings;
  const trivy = (id: string, severity: 'high' | 'low') =>
    makeFinding({ tool: 'trivy', rule_id: id, severity, category: 'security', subcategory: 'cve', title: id, file_path: 'go.mod' });

  it('takes the severity Trivy gave the same CVE', () => {
    const out = withTrivySeverity([...govuln, trivy('CVE-2022-32149', 'high')]);
    expect(out.find((f) => f.tool === 'govulncheck')?.severity).toBe('high');
  });

  it('keeps medium when Trivy did not report it, and never touches another tool', () => {
    const out = withTrivySeverity([...govuln, trivy('CVE-2099-0001', 'low')]);
    expect(out.find((f) => f.tool === 'govulncheck')?.severity).toBe('medium');
    expect(out.find((f) => f.tool === 'trivy')?.severity).toBe('low');
  });
});
