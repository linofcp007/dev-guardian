import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { dotnetScaParser } from '../../../../src/runners/scannerParsers/dotnetSca.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/dotnet-list-vulnerable.json');

function read(): string {
  return readFileSync(FIXTURE, 'utf8');
}

describe('dotnetScaParser', () => {
  it('emits one Finding per vulnerable package (top-level and transitive)', () => {
    const { findings } = dotnetScaParser.parse(read());
    expect(findings).toHaveLength(2);
  });

  it('reads the top-level package severity and advisory GHSA id', () => {
    const { findings } = dotnetScaParser.parse(read());
    const json = findings.find((f) => f.snippet?.startsWith('Newtonsoft.Json@'));
    expect(json?.severity).toBe('high');
    expect(json?.rule_id).toBe('GHSA-5crp-9r3c-p9vr');
    expect(json?.snippet).toBe('Newtonsoft.Json@12.0.1');
  });

  it('includes transitive packages (--include-transitive) as their own findings', () => {
    const { findings } = dotnetScaParser.parse(read());
    const transitive = findings.find((f) => f.snippet?.startsWith('System.Text.Encodings.Web@'));
    expect(transitive).toBeDefined();
    expect(transitive?.rule_id).toBe('GHSA-ghhp-997w-qr28');
  });

  it('normalises "Moderate" to the canonical "medium" severity', () => {
    const { findings } = dotnetScaParser.parse(read());
    const transitive = findings.find((f) => f.snippet?.startsWith('System.Text.Encodings.Web@'));
    expect(transitive?.severity).toBe('medium');
  });

  it('relativises the project path against project_path when provided', () => {
    const { findings } = dotnetScaParser.parse(read(), { project_path: '/repo' });
    expect(findings.every((f) => f.file_path === 'Test.csproj')).toBe(true);
  });

  it('emits no CVE rows — dotnet list package reports advisory URLs, not CVE ids', () => {
    const { cves } = dotnetScaParser.parse(read());
    expect(cves).toEqual([]);
  });

  it('returns nothing for empty/unparseable input', () => {
    expect(dotnetScaParser.parse('')).toEqual({ findings: [], cves: [] });
    expect(dotnetScaParser.parse('not json')).toEqual({ findings: [], cves: [] });
  });
});
