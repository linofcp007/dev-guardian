import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { gosecParser } from '../../../../src/runners/scannerParsers/gosec.js';

const here = dirname(fileURLToPath(import.meta.url));
// Real gosec 2.30.0 output over fixtures/gosec/project mounted at /src (see gosecRun.test.ts).
const FIXTURE = resolve(here, '../../../fixtures/scanners/gosec/project.json');
const parse = () => gosecParser.parse(readFileSync(FIXTURE, 'utf8'), { project_path: '/src' });

describe('gosecParser', () => {
  it('one finding per issue, the #nosec one not reported, every one security', () => {
    const { findings, cves } = parse();
    expect(findings).toHaveLength(11);
    expect(cves).toEqual([]);
    expect(findings.every((f) => f.tool === 'gosec' && f.category === 'security')).toBe(true);
    // md5.Sum carries `#nosec G401`: gosec drops it, and so do we.
    expect(findings.some((f) => f.rule_id === 'G401')).toBe(false);
  });

  it('severity, CWE, project-relative path, line and confidence', () => {
    const g701 = parse().findings.find((f) => f.rule_id === 'G701');
    expect(g701).toMatchObject({
      severity: 'high',
      cwe: ['CWE-89'],
      file_path: 'main.go',
      line_start: 16,
      line_end: 16,
      // gosec names the sink in its details.
      title: 'SQL injection via taint analysis: (*database/sql.DB).Query',
    });
    expect(g701?.message).toBe('SQL injection via taint analysis: (*database/sql.DB).Query (confidence: high)');
    expect(parse().findings.find((f) => f.rule_id === 'G114')?.severity).toBe('medium');
  });

  it('the directory gosec’s own walk would skip is reported from', () => {
    const files = new Set(parse().findings.map((f) => f.file_path));
    expect(files).toEqual(new Set(['main.go', 'creds/creds.go', 'vendored/v.go']));
  });

  it('G101 is a credential finding: its snippet is redacted at the source', () => {
    const g101 = parse().findings.find((f) => f.rule_id === 'G101');
    expect(g101?.subcategory).toBe('hardcoded_credentials');
    expect(g101?.snippet ?? '').not.toContain('fixture-not-a-real-password');
    // Another rule keeps its snippet, line-number prefixes and all.
    expect(parse().findings.find((f) => f.rule_id === 'G701')?.snippet).toMatch(/^15: /);
  });

  it('a line span, a suppressed issue, and an issue missing its rule or file', () => {
    const json = JSON.stringify({
      Issues: [
        { rule_id: 'G304', severity: 'MEDIUM', confidence: 'HIGH', file: '/src/a.go', line: '10-12', details: 'x', cwe: { id: '22' } },
        { rule_id: 'G304', severity: 'MEDIUM', file: '/src/b.go', line: '3', nosec: true },
        { rule_id: 'G304', severity: 'MEDIUM', file: '/src/c.go', line: '3', suppressions: [{ kind: 'inSource', justification: 'x' }] },
        { severity: 'HIGH', file: '/src/d.go', line: '1' },
        { rule_id: 'G101', severity: 'HIGH', line: '1' },
      ],
    });
    const { findings } = gosecParser.parse(json, { project_path: '/src' });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ file_path: 'a.go', line_start: 10, line_end: 12, cwe: ['CWE-22'] });
  });
});
