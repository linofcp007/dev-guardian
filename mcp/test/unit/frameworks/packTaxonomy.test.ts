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
import { countRuleReach, OWASP_DETECTORS } from '../../../src/frameworks/coverage.js';
import { owasp2025Category, parseOwasp2025Label } from '../../../src/frameworks/owaspTop10_2025.js';
import { classifyTaxonomy, normalizeCwe } from '../../../src/frameworks/taxonomy.js';
import { MCP_ROOT } from '../../helpers/tsxNode.js';

const PACK_DIR = join(MCP_ROOT, '..', 'configs', 'semgrep');
const BUGFIX_PACKS = readdirSync(PACK_DIR).filter((f) => /^bugfix-.+\.yml$/.test(f)).sort();
const FINDINGS_PACKS = ['base.yml', ...BUGFIX_PACKS, 'rgpd.yml'];

interface Rule {
  id: string;
  languages?: unknown;
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
  const reachOf = (id: string) => {
    const d = OWASP_DETECTORS.find((x) => x.id === id);
    const out: Record<string, unknown> = {};
    for (const [cat, reach] of Object.entries(d?.reach ?? {})) {
      if (reach?.kind === 'rules') out[cat] = { ...reach.perLanguage };
    }
    return out;
  };

  // The per-(category, language) rule counts `coverage.ts` records for the
  // packs are recounted here from the YAML: a rule added, removed or
  // re-labelled without updating the record fails this test.
  it('bug_hunt: the recorded reach is a recount of every bugfix pack', () => {
    const rules = BUGFIX_PACKS.flatMap((p) => rulesOf(p));
    expect(reachOf('bugfix-packs')).toEqual(countRuleReach(rules));
  });

  it('compliance_check: the recorded reach is a recount of rgpd.yml — A09 only, one CWE-532 rule per language', () => {
    const recount = countRuleReach(rulesOf('rgpd.yml'));
    expect(reachOf('rgpd-pack')).toEqual(recount);
    const one = { rules: 1, weaknesses: 1, sole: 'CWE-532' };
    expect(recount).toEqual({ 'A09:2025': { csharp: one, javascript: one, php: one, python: one, typescript: one } });
  });

  // The four tracker/embed rules are CWE-359, which OWASP files under A01,
  // but they are `generic` rules over templates: they count for no source
  // language, so the pack never claims A01 for a project.
  it('the RGPD tracker rules carry A01 as a finding category but reach no source language', () => {
    const trackers = rulesOf('rgpd.yml').filter((r) => !r.id.startsWith('rgpd-pii-in-log-'));
    expect(trackers).toHaveLength(4);
    for (const r of trackers) expect(owaspOf(r)).toEqual(['A01:2025']);
    expect(countRuleReach(trackers)).toEqual({});
  });
});
