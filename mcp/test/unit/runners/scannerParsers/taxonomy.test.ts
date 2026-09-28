/**
 * CWE and OWASP Top 10:2025 on parsed findings — per parser, and never in
 * the fingerprint.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { banditParser } from '../../../../src/runners/scannerParsers/bandit.js';
import { dotnetScaParser } from '../../../../src/runners/scannerParsers/dotnetSca.js';
import { gitleaksParser } from '../../../../src/runners/scannerParsers/gitleaks.js';
import { makeFinding } from '../../../../src/runners/scannerParsers/index.js';
import { npmAuditParser } from '../../../../src/runners/scannerParsers/npmAudit.js';
import { pipAuditParser } from '../../../../src/runners/scannerParsers/pipAudit.js';
import { semgrepParser } from '../../../../src/runners/scannerParsers/semgrep.js';
import { trivyParser } from '../../../../src/runners/scannerParsers/trivy.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(resolve(here, '../../../fixtures/scanners', name), 'utf8');

describe('makeFinding', () => {
  it('keeps the taxonomy out of the fingerprint', () => {
    const base = { tool: 'semgrep', rule_id: 'r', severity: 'high' as const, category: 'security' as const, title: 't', file_path: 'a.js', line_start: 3, snippet: 'x' };
    const plain = makeFinding(base);
    const tagged = makeFinding({ ...base, taxonomy: { cwe: ['CWE-89'], owasp: ['A05:2025 - Injection'] } });
    expect(tagged.fingerprint).toBe(plain.fingerprint);
    expect(tagged.cwe).toEqual(['CWE-89']);
    expect(tagged.owasp).toEqual(['A05:2025']);
    expect(plain).not.toHaveProperty('cwe');
    expect(plain).not.toHaveProperty('owasp');
  });
});

function semgrepResult(metadata: Record<string, unknown>): string {
  return JSON.stringify({
    results: [
      {
        check_id: 'rules.r',
        path: 'src/app.js',
        start: { line: 3 },
        end: { line: 3 },
        extra: { severity: 'ERROR', message: 'm', lines: 'x', metadata },
      },
    ],
    errors: [],
  });
}

describe('semgrepParser', () => {
  // The registry's shape: lists, with the 2017 and 2021 editions beside 2025.
  it('reads metadata.cwe and metadata.owasp as lists — they used to be dropped', () => {
    const [f] = semgrepParser.parse(
      semgrepResult({
        category: 'security',
        cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
        owasp: ['A01:2017 - Injection', 'A03:2021 - Injection', 'A05:2025 - Injection'],
      }),
    ).findings;
    expect(f?.cwe).toEqual(['CWE-89']);
    expect(f?.owasp).toEqual(['A05:2025']);
  });

  it('reads them as single strings too', () => {
    const [f] = semgrepParser.parse(semgrepResult({ cwe: 'CWE-502: Deserialization of Untrusted Data', owasp: 'A08:2025 - Software or Data Integrity Failures' })).findings;
    expect(f?.cwe).toEqual(['CWE-502']);
    expect(f?.owasp).toEqual(['A08:2025']);
  });

  it('derives the 2025 category from the CWE when the rule gives only older editions', () => {
    const [f] = semgrepParser.parse(semgrepResult({ cwe: ['CWE-79'], owasp: ['A07:2017 - Cross-Site Scripting (XSS)', 'A03:2021 - Injection'] })).findings;
    expect(f?.owasp).toEqual(['A05:2025']);
  });

  it('never files a 2017 label under the 2025 category with the same number', () => {
    // The shipped fixture: "A07:2017 - Cross-Site Scripting (XSS)" and no CWE.
    const xss = semgrepParser.parse(fixture('semgrep.json')).findings.find((f) => f.rule_id?.includes('express-xss'));
    expect(xss).toBeDefined();
    expect(xss).not.toHaveProperty('owasp');
    expect(xss).not.toHaveProperty('cwe');
  });

  it('refuses a 2025 id under another category\'s title, and keeps what the CWE says', () => {
    const [f] = semgrepParser.parse(semgrepResult({ cwe: ['CWE-89'], owasp: ['A03:2025 - Injection'] })).findings;
    expect(f?.owasp).toEqual(['A05:2025']);
  });

  it('leaves the subcategory exactly as before when owasp is a list', () => {
    const [f] = semgrepParser.parse(semgrepResult({ owasp: ['A05:2025 - Injection'] })).findings;
    expect(f?.subcategory).toBe('r');
  });

  it('does not change the fingerprint of a rule that gains metadata', () => {
    const [before] = semgrepParser.parse(semgrepResult({ category: 'security' })).findings;
    const [after] = semgrepParser.parse(semgrepResult({ category: 'security', cwe: ['CWE-79'], owasp: ['A05:2025 - Injection'] })).findings;
    expect(after?.fingerprint).toBe(before?.fingerprint);
  });
});

describe('trivyParser', () => {
  function vuln(extra: Record<string, unknown>): string {
    return JSON.stringify({
      Results: [
        {
          Target: 'package-lock.json',
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-2024-1', PkgName: 'lodash', InstalledVersion: '4.17.20', Severity: 'HIGH', ...extra },
          ],
        },
      ],
    });
  }

  it('a vulnerable dependency is CWE-1395 (A03), plus the CweIDs of the advisory', () => {
    const [f] = trivyParser.parse(vuln({ CweIDs: ['CWE-79'] })).findings;
    expect(f?.cwe).toEqual(['CWE-79', 'CWE-1395']);
    expect(f?.owasp).toEqual(['A03:2025', 'A05:2025']);
  });

  it('without CweIDs it is still a vulnerable dependency', () => {
    const [f] = trivyParser.parse(vuln({})).findings;
    expect(f?.cwe).toEqual(['CWE-1395']);
    expect(f?.owasp).toEqual(['A03:2025']);
  });

  it('the fingerprint is the one stored before (suppressions name it)', () => {
    const [f] = trivyParser.parse(vuln({ CweIDs: ['CWE-79'] })).findings;
    const [g] = trivyParser.parse(vuln({})).findings;
    expect(f?.fingerprint).toBe(g?.fingerprint);
  });

  it('a secret is a hard-coded credential (CWE-798, A07); a license finding has no weakness', () => {
    const out = trivyParser.parse(
      JSON.stringify({
        Results: [
          {
            Target: 'app.env',
            Secrets: [{ RuleID: 'aws-access-key-id', Severity: 'CRITICAL', Title: 'AWS', StartLine: 1 }],
            Licenses: [{ PkgName: 'x', Name: 'GPL-3.0', Severity: 'HIGH' }],
          },
        ],
      }),
    ).findings;
    const secret = out.find((f) => f.subcategory === 'secret');
    const license = out.find((f) => f.category === 'license');
    expect(secret?.cwe).toEqual(['CWE-798']);
    expect(secret?.owasp).toEqual(['A07:2025']);
    expect(license).not.toHaveProperty('cwe');
    expect(license).not.toHaveProperty('owasp');
  });
});

describe('banditParser', () => {
  it('reads issue_cwe.id', () => {
    const [f] = banditParser.parse(
      JSON.stringify({
        results: [
          {
            test_id: 'B602',
            test_name: 'subprocess_popen_with_shell_equals_true',
            issue_severity: 'HIGH',
            issue_confidence: 'HIGH',
            issue_cwe: { id: 78, link: 'https://cwe.mitre.org/data/definitions/78.html' },
            issue_text: 'shell=True',
            filename: 'a.py',
            line_number: 3,
          },
        ],
      }),
    ).findings;
    expect(f?.cwe).toEqual(['CWE-78']);
    expect(f?.owasp).toEqual(['A05:2025']);
  });

  it('an empty issue_cwe ({}, Bandit\'s "no CWE") leaves both fields out', () => {
    const [f] = banditParser.parse(
      JSON.stringify({
        results: [{ test_id: 'B999', issue_severity: 'LOW', issue_cwe: {}, issue_text: 't', filename: 'a.py', line_number: 1 }],
      }),
    ).findings;
    expect(f).not.toHaveProperty('cwe');
    expect(f).not.toHaveProperty('owasp');
  });
});

describe('gitleaksParser', () => {
  it('every secret is a hard-coded credential (CWE-798, A07)', () => {
    const { findings } = gitleaksParser.parse(fixture('gitleaks.json'));
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.cwe).toEqual(['CWE-798']);
      expect(f.owasp).toEqual(['A07:2025']);
    }
  });
});

describe('dependency auditors', () => {
  it('npm audit: CWE-1395 plus the advisory\'s own CWEs', () => {
    const { findings } = npmAuditParser.parse(fixture('npm-audit.json'));
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.cwe).toContain('CWE-1395');
      expect(f.owasp).toContain('A03:2025');
    }
    // The fixture's advisories are prototype pollution — CWE-1321, in no
    // 2025 category, so they add a CWE and no category.
    expect(findings.some((f) => f.cwe?.includes('CWE-1321'))).toBe(true);
    for (const f of findings) expect(f.owasp).toEqual(['A03:2025']);
  });

  it('pip-audit: CWE-1395', () => {
    const { findings } = pipAuditParser.parse(fixture('pip-audit.json'));
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.cwe).toEqual(['CWE-1395']);
      expect(f.owasp).toEqual(['A03:2025']);
    }
  });

  it('dotnet list package --vulnerable: CWE-1395', () => {
    const { findings } = dotnetScaParser.parse(fixture('dotnet-list-vulnerable.json'));
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.cwe).toEqual(['CWE-1395']);
      expect(f.owasp).toEqual(['A03:2025']);
    }
  });
});
