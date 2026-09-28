import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { pipAuditParser } from '../../../../src/runners/scannerParsers/pipAudit.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/pip-audit.json');

function read(): string {
  return readFileSync(FIXTURE, 'utf8');
}

describe('pipAuditParser', () => {
  it('emits one Finding per vuln entry', () => {
    const { findings } = pipAuditParser.parse(read());
    expect(findings).toHaveLength(2);
  });

  it('extracts the CVE alias into a scan_cves row, with the minimum SAFE fix version — never a downgrade', () => {
    // Fix round 1, CRITICAL item 1: installed 2.0.1, fix_versions is
    // ["1.11.27", "2.2.9", "3.0.1"] — 1.11.27 is an OLDER release branch's
    // backport, not a fix for a 2.0.1 install. The correct minimum fix
    // ABOVE 2.0.1 is 2.2.9, never fix_versions[0].
    const { cves } = pipAuditParser.parse(read());
    expect(cves).toHaveLength(1);
    const cve = cves[0];
    expect(cve?.cve_id).toBe('CVE-2019-19844');
    expect(cve?.package_name).toBe('django');
    expect(cve?.installed_version).toBe('2.0.1');
    expect(cve?.fixed_version).toBe('2.2.9');
  });

  it('leaves fixed_version unset when every candidate is at or below the installed version', () => {
    const raw = JSON.stringify({
      dependencies: [
        {
          name: 'somepkg',
          version: '2.0.1',
          vulns: [
            { id: 'PYSEC-2020-1', fix_versions: ['1.9.0'], aliases: ['CVE-2020-1'], description: 'x' },
          ],
        },
      ],
    });
    const { cves } = pipAuditParser.parse(raw);
    expect(cves).toHaveLength(1);
    expect(cves[0]?.fixed_version).toBeUndefined();
  });

  it('attributes findings to the real source file via an embedded __source_file, not a hardcoded requirements.txt', () => {
    const raw = JSON.parse(read()) as Record<string, unknown>;
    raw['__source_file'] = 'requirements/dev.txt';
    const { findings } = pipAuditParser.parse(JSON.stringify(raw));
    expect(findings.every((f) => f.file_path === 'requirements/dev.txt')).toBe(true);
  });

  it('falls back to ctx.source_file when no __source_file is embedded, and to requirements.txt when neither is given', () => {
    const { findings: viaCtx } = pipAuditParser.parse(read(), { source_file: 'pyproject.toml' });
    expect(viaCtx.every((f) => f.file_path === 'pyproject.toml')).toBe(true);
    const { findings: viaDefault } = pipAuditParser.parse(read());
    expect(viaDefault.every((f) => f.file_path === 'requirements.txt')).toBe(true);
  });

  it('marks fix_available=true only when fix_versions is non-empty', () => {
    const { findings } = pipAuditParser.parse(read());
    const django = findings.find((f) => f.snippet?.startsWith('django@'));
    const requests = findings.find((f) => f.snippet?.startsWith('requests@'));
    expect(django?.fix_available).toBe(true);
    expect(requests?.fix_available).toBe(false);
  });

  it('does not emit a CVE row for a vuln with no CVE alias', () => {
    const { cves } = pipAuditParser.parse(read());
    expect(cves.some((c) => c.package_name === 'requests')).toBe(false);
  });

  it('defaults severity to medium — pip-audit JSON carries no severity field', () => {
    const { findings } = pipAuditParser.parse(read());
    expect(findings.every((f) => f.severity === 'medium')).toBe(true);
  });

  it('returns nothing for empty/unparseable input', () => {
    expect(pipAuditParser.parse('')).toEqual({ findings: [], cves: [] });
    expect(pipAuditParser.parse('not json')).toEqual({ findings: [], cves: [] });
  });
});
