/**
 * The OWASP Top 10:2025 table and the CWE → category mapping, held to the
 * official pages (https://owasp.org/Top10/2025/, retrieved 2026-09-28): each
 * category page states how many CWEs it maps ("CWEs Mapped") and lists them.
 * The counts below are those pages' own figures, not a re-count of this
 * module, so a CWE dropped or added by a bad edit fails here.
 */

import { describe, expect, it } from 'vitest';
import {
  OWASP_2025_IDS,
  OWASP_TOP10_2025,
  owaspCategoryOfCwe,
  parseOwasp2025Label,
} from '../../../src/frameworks/owaspTop10_2025.js';
import { classifyTaxonomy, normalizeCwe } from '../../../src/frameworks/taxonomy.js';

describe('OWASP_TOP10_2025', () => {
  it('lists the ten 2025 categories in the official order, with the official titles', () => {
    expect(OWASP_TOP10_2025.map((c) => `${c.id} ${c.title}`)).toEqual([
      'A01:2025 Broken Access Control',
      'A02:2025 Security Misconfiguration',
      'A03:2025 Software Supply Chain Failures',
      'A04:2025 Cryptographic Failures',
      'A05:2025 Injection',
      'A06:2025 Insecure Design',
      'A07:2025 Authentication Failures',
      'A08:2025 Software or Data Integrity Failures',
      'A09:2025 Security Logging and Alerting Failures',
      'A10:2025 Mishandling of Exceptional Conditions',
    ]);
    expect(OWASP_2025_IDS).toEqual(OWASP_TOP10_2025.map((c) => c.id));
  });

  it('maps exactly as many CWEs to each category as its own page says ("CWEs Mapped")', () => {
    expect(OWASP_TOP10_2025.map((c) => c.cwes.length)).toEqual([40, 16, 6, 32, 37, 39, 36, 14, 5, 24]);
  });

  it('never maps one CWE to two categories', () => {
    const all = OWASP_TOP10_2025.flatMap((c) => c.cwes);
    expect(all).toHaveLength(249);
    expect(new Set(all).size).toBe(249);
  });

  it('links every category to its page on owasp.org', () => {
    for (const c of OWASP_TOP10_2025) {
      expect(c.url).toMatch(/^https:\/\/owasp\.org\/Top10\/2025\/A(0[1-9]|10)_2025-[A-Za-z_]+\/$/);
    }
  });
});

describe('owaspCategoryOfCwe', () => {
  // The 2021 list had Injection at A03 and XSS inside it; a table built from
  // memory of 2021 puts CWE-79 at A03, which in 2025 is supply chain.
  it.each([
    ['CWE-79', 'A05:2025'],
    ['CWE-89', 'A05:2025'],
    ['CWE-78', 'A05:2025'],
    ['CWE-918', 'A01:2025'], // SSRF folded into Broken Access Control in 2025
    ['CWE-22', 'A01:2025'],
    ['CWE-1395', 'A03:2025'],
    ['CWE-1104', 'A03:2025'],
    ['CWE-327', 'A04:2025'],
    ['CWE-611', 'A02:2025'],
    ['CWE-362', 'A06:2025'],
    ['CWE-798', 'A07:2025'],
    ['CWE-502', 'A08:2025'],
    ['CWE-532', 'A09:2025'],
    ['CWE-476', 'A10:2025'],
    ['CWE-390', 'A10:2025'],
  ])('%s → %s', (cwe, id) => {
    expect(owaspCategoryOfCwe(cwe)).toBe(id);
  });

  it('answers null for a CWE no 2025 category lists — never a guess', () => {
    expect(owaspCategoryOfCwe('CWE-1321')).toBeNull(); // prototype pollution
    expect(owaspCategoryOfCwe('CWE-193')).toBeNull(); // off-by-one
    expect(owaspCategoryOfCwe('not a cwe')).toBeNull();
  });
});

describe('parseOwasp2025Label', () => {
  it.each([
    ['A05:2025 - Injection', 'A05:2025'],
    ['A05:2025', 'A05:2025'],
    ['a05:2025-injection', 'A05:2025'],
    ['A01:2025 - Broken Access Control', 'A01:2025'],
    // Titles the Semgrep registry actually carries (p/default, 2026-09-28):
    ['A08:2025 - Software and Data Integrity Failures', 'A08:2025'],
    ['A09:2025 - Security Logging & Alerting Failures', 'A09:2025'],
    ['A10:2025 - Mishandling of Exceptional Conditions', 'A10:2025'],
  ])('%s → %s', (label, id) => {
    expect(parseOwasp2025Label(label)).toBe(id);
  });

  it.each([
    'A03:2021 - Injection',
    'A07:2017 - Cross-Site Scripting (XSS)',
    'A11:2025',
    'A00:2025',
    '',
    'Injection',
  ])('refuses %j (another edition, or no category)', (label) => {
    expect(parseOwasp2025Label(label)).toBeNull();
  });

  // Measured on the registry's p/default: one rule labels an injection
  // finding "A03:2025 - Injection" — the 2021 number with the 2025 year. The
  // id alone would file it under Software Supply Chain Failures.
  it('refuses a 2025 id whose title names a different category', () => {
    expect(parseOwasp2025Label('A03:2025 - Injection')).toBeNull();
    expect(parseOwasp2025Label('A07:2025 - Cross-Site Scripting')).toBeNull();
  });

  it('trims surrounding whitespace, a trailing newline included', () => {
    expect(parseOwasp2025Label('A05:2025 - Injection\n')).toBe('A05:2025');
    expect(parseOwasp2025Label('  A05:2025 - Injection  ')).toBe('A05:2025');
  });

  it('refuses anything that is not a string', () => {
    expect(parseOwasp2025Label(5)).toBeNull();
    expect(parseOwasp2025Label(null)).toBeNull();
    expect(parseOwasp2025Label(['A05:2025'])).toBeNull();
  });
});

describe('normalizeCwe', () => {
  it.each([
    ['CWE-89', 'CWE-89'],
    ['CWE-89: Improper Neutralization of Special Elements used in an SQL Command', 'CWE-89'],
    ['cwe-89', 'CWE-89'],
    ['CWE 89', 'CWE-89'],
    ['89', 'CWE-89'],
    [89, 'CWE-89'],
    ['CWE-0089', 'CWE-89'],
  ])('%j → %s', (raw, out) => {
    expect(normalizeCwe(raw)).toBe(out);
  });

  it.each([0, 'CWE-0', 'CWE-', 'foo', '', -3, 1.5, null, undefined, {}, ['CWE-89']])(
    'refuses %j',
    (raw) => {
      expect(normalizeCwe(raw)).toBeNull();
    },
  );
});

describe('classifyTaxonomy', () => {
  it('normalises, de-duplicates and sorts the CWEs, and derives the 2025 categories from them', () => {
    expect(classifyTaxonomy({ cwe: ['CWE-89: SQLi', 'cwe-79', 'CWE-89'] })).toEqual({
      cwe: ['CWE-79', 'CWE-89'],
      owasp: ['A05:2025'],
    });
  });

  it('keeps an explicit 2025 label and adds the categories its CWEs map to', () => {
    // CWE-732 is A01 in the official mapping; the rule's author filed it
    // under A02 (a registry docker-compose rule does exactly this).
    expect(
      classifyTaxonomy({ cwe: ['CWE-732'], owasp: ['A05:2021 - Security Misconfiguration', 'A02:2025 - Security Misconfiguration'] }),
    ).toEqual({ cwe: ['CWE-732'], owasp: ['A01:2025', 'A02:2025'] });
  });

  it('never turns a 2017 or 2021 label into a 2025 category', () => {
    expect(classifyTaxonomy({ owasp: ['A07:2017 - Cross-Site Scripting (XSS)', 'A03:2021 - Injection'] })).toEqual({});
  });

  it('leaves both fields out when nothing is known — unknown, not "no category"', () => {
    expect(classifyTaxonomy({})).toEqual({});
    expect(classifyTaxonomy({ cwe: [], owasp: [] })).toEqual({});
    expect(classifyTaxonomy({ cwe: ['nonsense'] })).toEqual({});
  });

  it('keeps a known CWE that maps to no 2025 category, with no OWASP field', () => {
    expect(classifyTaxonomy({ cwe: ['CWE-1321'] })).toEqual({ cwe: ['CWE-1321'] });
  });

  it('accepts a single string where a list is expected', () => {
    expect(classifyTaxonomy({ cwe: 'CWE-502', owasp: 'A08:2025 - Software or Data Integrity Failures' })).toEqual({
      cwe: ['CWE-502'],
      owasp: ['A08:2025'],
    });
  });
});
