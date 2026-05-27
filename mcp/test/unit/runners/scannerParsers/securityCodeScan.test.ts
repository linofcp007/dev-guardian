import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { securityCodeScanParser } from '../../../../src/runners/scannerParsers/securityCodeScan.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/security-code-scan.txt');

describe('securityCodeScanParser', () => {
  it('extracts only SCS-tagged warnings/errors, ignoring other build output', () => {
    const { findings } = securityCodeScanParser.parse(readFileSync(FIXTURE, 'utf8'));
    // 3 warnings + 1 error = 4 findings, the rest of the build log is noise.
    expect(findings).toHaveLength(4);
  });

  it('maps error rows to critical severity', () => {
    const { findings } = securityCodeScanParser.parse(readFileSync(FIXTURE, 'utf8'));
    const err = findings.find((f) => f.rule_id === 'SCS0029');
    expect(err?.severity).toBe('critical');
  });

  it('warnings default to high', () => {
    const { findings } = securityCodeScanParser.parse(readFileSync(FIXTURE, 'utf8'));
    const w = findings.find((f) => f.rule_id === 'SCS0006');
    expect(w?.severity).toBe('high');
  });

  it('tags subcategory by rule family', () => {
    const { findings } = securityCodeScanParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings.find((f) => f.rule_id === 'SCS0001')?.subcategory).toBe('sql-injection');
    expect(findings.find((f) => f.rule_id === 'SCS0006')?.subcategory).toBe('weak-crypto');
    expect(findings.find((f) => f.rule_id === 'SCS0029')?.subcategory).toBe('xss');
    expect(findings.find((f) => f.rule_id === 'SCS0011')?.subcategory).toBe('weak-crypto');
  });

  it('preserves file path + line number', () => {
    const { findings } = securityCodeScanParser.parse(readFileSync(FIXTURE, 'utf8'));
    const f = findings.find((x) => x.rule_id === 'SCS0029');
    expect(f?.file_path).toBe('src/Models/User.cs');
    expect(f?.line_start).toBe(110);
  });
});
