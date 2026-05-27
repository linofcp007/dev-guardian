import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { wpscanParser } from '../../../../src/runners/scannerParsers/wpscan.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../fixtures/scanners/wpscan.json');

describe('wpscanParser', () => {
  it('emits one Finding per vulnerability across core / plugins / themes', () => {
    const { findings, cves } = wpscanParser.parse(readFileSync(FIXTURE, 'utf8'));
    // 1 core + 1 contact-form-7 + 1 elementor + 1 stale-theme = 4 findings
    expect(findings).toHaveLength(4);
    // CVEs for each (4 CVE rows total)
    expect(cves).toHaveLength(4);
  });

  it('maps CVSS scores to severities', () => {
    const { findings } = wpscanParser.parse(readFileSync(FIXTURE, 'utf8'));
    const critical = findings.find((f) => /Contact Form/.test(f.title));
    expect(critical?.severity).toBe('critical'); // CVSS 9.1
    const medium = findings.find((f) => /Cross-Site Scripting/.test(f.title));
    expect(medium?.severity).toBe('medium'); // CVSS 6.1
  });

  it('tags subcategory by component type', () => {
    const { findings } = wpscanParser.parse(readFileSync(FIXTURE, 'utf8'));
    const core = findings.find((f) => /Cross-Site Scripting/.test(f.title));
    const plugin = findings.find((f) => /Contact Form/.test(f.title));
    const theme = findings.find((f) => /stale-theme/.test(f.title));
    expect(core?.subcategory).toBe('wordpress-core');
    expect(plugin?.subcategory).toBe('wordpress-plugin');
    expect(theme?.subcategory).toBe('wordpress-theme');
  });

  it('records fix_available when fixed_in is present', () => {
    const { findings } = wpscanParser.parse(readFileSync(FIXTURE, 'utf8'));
    expect(findings.every((f) => f.fix_available)).toBe(true);
  });

  it('extracts CVEs with fixed_version', () => {
    const { cves } = wpscanParser.parse(readFileSync(FIXTURE, 'utf8'));
    const cf7 = cves.find((c) => c.cve_id === 'CVE-2023-6449');
    expect(cf7?.package_name).toBe('contact-form-7');
    expect(cf7?.installed_version).toBe('5.7');
    expect(cf7?.fixed_version).toBe('5.7.7');
  });

  it('handles missing CVSS by falling back to label or medium', () => {
    const { findings } = wpscanParser.parse(readFileSync(FIXTURE, 'utf8'));
    const noCvss = findings.find((f) => /stale-theme/.test(f.title));
    // No CVSS, no severity label → default medium
    expect(noCvss?.severity).toBe('medium');
  });
});
