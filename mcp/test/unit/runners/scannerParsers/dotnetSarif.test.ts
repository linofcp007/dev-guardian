/**
 * `dotnetSarifParser` — the security findings of a Roslyn SARIF 2.1 build
 * log. The fixture is trimmed from a real `dotnet build
 * -p:ErrorLog=obj/x.sarif%2Cversion=2.1 -p:AnalysisModeSecurity=All` of a
 * class library using MD5 (SDK 10.0.401), plus one Security Code Scan result
 * and one suppressed result written by hand in the same shape.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  DOTNET_ANALYZERS_TOOL_NAME,
  dotnetSarifParser,
  sarifSecurityRuleCount,
} from '../../../../src/runners/scannerParsers/dotnetSarif.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = readFileSync(resolve(here, '../../../fixtures/scanners/dotnet-build.sarif.json'), 'utf8');

describe('dotnetSarifParser', () => {
  it('keeps Security-category analyzer results and Security Code Scan, drops the rest', () => {
    const { findings } = dotnetSarifParser.parse(FIXTURE, { project_path: 'C:/proj' });
    expect(findings.map((f) => [f.tool, f.rule_id])).toEqual([
      [DOTNET_ANALYZERS_TOOL_NAME, 'CA5351'],
      ['security-code-scan', 'SCS0005'],
    ]);
  });

  it('maps location, severity and message', () => {
    const { findings } = dotnetSarifParser.parse(FIXTURE, { project_path: 'C:/proj' });
    const md5 = findings[0];
    expect(md5).toMatchObject({
      category: 'security',
      severity: 'high',
      line_start: 1,
      title: 'H uses a broken cryptographic algorithm MD5',
      fix_available: false,
    });
    expect(md5?.file_path?.replace(/\\/g, '/')).toMatch(/LibA\/Class1\.cs$/);
  });

  it('never reports a result the project suppressed', () => {
    const { findings } = dotnetSarifParser.parse(FIXTURE, {});
    expect(findings.some((f) => f.message === 'suppressed MD5 use')).toBe(false);
  });

  it('accepts a UTF-8 BOM (Roslyn writes one) and tolerates junk', () => {
    expect(dotnetSarifParser.parse(`\uFEFF${FIXTURE}`, {}).findings).toHaveLength(2);
    expect(dotnetSarifParser.parse('not json', {}).findings).toEqual([]);
  });

  it('counts the security rules the SARIF says were loaded — zero means the analyzers never ran', () => {
    expect(sarifSecurityRuleCount(FIXTURE)).toBe(1);
    expect(sarifSecurityRuleCount(FIXTURE.replace(/"category": "Security"/g, '"category": "Performance"'))).toBe(0);
    expect(sarifSecurityRuleCount('not json')).toBe(0);
    const scsOnly = JSON.stringify({ runs: [{ tool: { driver: { rules: [{ id: 'SCS0005' }] } }, results: [] }] });
    expect(sarifSecurityRuleCount(scsOnly)).toBe(1);
  });

  it('falls back to the security rule-id ranges when the SARIF carries no rule metadata', () => {
    const bare = JSON.stringify({
      version: '2.1.0',
      runs: [{ results: [
        { ruleId: 'CA3001', level: 'warning', message: { text: 'sql' } },
        { ruleId: 'CA1822', level: 'note', message: { text: 'static' } },
      ] }],
    });
    expect(dotnetSarifParser.parse(bare, {}).findings.map((f) => f.rule_id)).toEqual(['CA3001']);
  });
});
