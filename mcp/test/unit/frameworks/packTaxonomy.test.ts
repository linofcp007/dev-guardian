/**
 * Every rule of our own findings packs (base, bugfix-*, rgpd) states its
 * weakness as `metadata.cwe` and `metadata.owasp`, and the OWASP labels are
 * exactly what OWASP's own CWE mapping gives for those CWEs — so a pack can
 * never claim a category the official list does not, and the coverage
 * claims in `frameworks/coverage.ts` for bug_hunt and compliance_check are
 * read off the packs rather than asserted beside them.
 *
 * Pure YAML: no Semgrep. That the metadata changes nothing a rule matches is
 * held by the packs' own fixture suites and `semgrepPacks.test.ts`.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { OWASP_DETECTORS } from '../../../src/frameworks/coverage.js';
import { owasp2025Category, parseOwasp2025Label } from '../../../src/frameworks/owaspTop10_2025.js';
import { classifyTaxonomy, normalizeCwe } from '../../../src/frameworks/taxonomy.js';
import { MCP_ROOT } from '../../helpers/tsxNode.js';

const PACK_DIR = join(MCP_ROOT, '..', 'configs', 'semgrep');
const BUGFIX_PACKS = readdirSync(PACK_DIR).filter((f) => /^bugfix-.+\.yml$/.test(f)).sort();
const FINDINGS_PACKS = ['base.yml', ...BUGFIX_PACKS, 'rgpd.yml'];

interface Rule {
  id: string;
  metadata?: Record<string, unknown>;
}

function rulesOf(pack: string): Rule[] {
  const doc = parse(readFileSync(join(PACK_DIR, pack), 'utf8')) as { rules: Rule[] };
  return doc.rules;
}

function owaspOf(rule: Rule): string[] {
  const owasp = rule.metadata?.['owasp'];
  return Array.isArray(owasp) ? owasp.map((l) => parseOwasp2025Label(l) ?? `unparsed:${String(l)}`) : [];
}

describe('findings packs carry cwe/owasp metadata', () => {
  it('finds the packs', () => {
    expect(BUGFIX_PACKS.length).toBeGreaterThanOrEqual(7);
  });

  for (const pack of FINDINGS_PACKS) {
    describe(pack, () => {
      for (const rule of rulesOf(pack)) {
        it(`${rule.id}: lists, with OWASP exactly as OWASP maps the CWEs`, () => {
          const cwe = rule.metadata?.['cwe'];
          const owasp = rule.metadata?.['owasp'];
          // Lists, never bare strings: `semgrep.ts` derives a finding's
          // subcategory from a STRING `owasp`, and that must not change
          // under the pack's own findings.
          expect(Array.isArray(cwe)).toBe(true);
          expect(Array.isArray(owasp)).toBe(true);
          const cwes = cwe as unknown[];
          for (const entry of cwes) {
            expect(typeof entry).toBe('string');
            expect(String(entry)).toMatch(/^CWE-\d+: \S/);
            expect(normalizeCwe(entry)).not.toBeNull();
          }
          const derived = classifyTaxonomy({ cwe: cwes }).owasp ?? [];
          expect(owaspOf(rule)).toEqual(derived);
          // The label is the official one, word for word.
          for (const label of owasp as unknown[]) {
            const id = parseOwasp2025Label(label);
            expect(id).not.toBeNull();
            if (id !== null) expect(label).toBe(`${id} - ${owasp2025Category(id).title}`);
          }
        });
      }
    });
  }

  it('routes.yml is not a findings pack and gains no taxonomy', () => {
    for (const rule of rulesOf('routes.yml')) {
      expect(rule.metadata?.['cwe']).toBeUndefined();
      expect(rule.metadata?.['owasp']).toBeUndefined();
    }
  });
});

describe("coverage claims for our own packs are the packs' metadata", () => {
  const detector = (id: string) => OWASP_DETECTORS.find((d) => d.id === id);

  it('bug_hunt claims only categories every bugfix pack but bugfix-rs carries', () => {
    const claimed = detector('bugfix-packs')?.categories ?? [];
    expect(claimed.length).toBeGreaterThan(0);
    for (const id of claimed) {
      const carriers = BUGFIX_PACKS.filter((p) => rulesOf(p).some((r) => owaspOf(r).includes(id)));
      expect(carriers).toEqual(BUGFIX_PACKS.filter((p) => p !== 'bugfix-rs.yml'));
    }
  });

  it('compliance_check claims A09 (personal data in logs, four languages) and A01 (every rule)', () => {
    expect(detector('rgpd-pack')?.categories).toEqual(['A01:2025', 'A09:2025']);
    const rules = rulesOf('rgpd.yml');
    expect(rules.every((r) => owaspOf(r).includes('A01:2025'))).toBe(true);
    expect(rules.filter((r) => owaspOf(r).includes('A09:2025')).map((r) => r.id)).toEqual([
      'rgpd-pii-in-log-js',
      'rgpd-pii-in-log-php',
      'rgpd-pii-in-log-py',
      'rgpd-pii-in-log-cs',
    ]);
  });
});
