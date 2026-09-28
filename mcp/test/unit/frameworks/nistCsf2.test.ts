/**
 * NIST CSF 2.0 ids, held to NIST's own export of the framework (CPRT,
 * `csf_2_0_0`, retrieved 2026-09-28): six functions and 22 categories. The
 * export also carries the twelve CSF 1.1 categories 2.0 withdrew (ID.BE,
 * PR.AC, …) — a table that includes any of them is citing a framework
 * version that no longer has it.
 */

import { describe, expect, it } from 'vitest';
import {
  CSF_CATEGORIES,
  CSF_FUNCTIONS,
  csfCategoriesOfOwasp,
  OWASP_TO_CSF,
} from '../../../src/frameworks/nistCsf2.js';
import { OWASP_2025_IDS } from '../../../src/frameworks/owaspTop10_2025.js';

describe('CSF 2.0 ids', () => {
  it('has the six functions, GOVERN first', () => {
    expect(CSF_FUNCTIONS.map((f) => `${f.id} ${f.title}`)).toEqual([
      'GV GOVERN',
      'ID IDENTIFY',
      'PR PROTECT',
      'DE DETECT',
      'RS RESPOND',
      'RC RECOVER',
    ]);
  });

  it('has exactly the 22 categories of CSF 2.0', () => {
    expect(CSF_CATEGORIES.map((c) => c.id)).toEqual([
      'GV.OC', 'GV.RM', 'GV.RR', 'GV.PO', 'GV.OV', 'GV.SC',
      'ID.AM', 'ID.RA', 'ID.IM',
      'PR.AA', 'PR.AT', 'PR.DS', 'PR.PS', 'PR.IR',
      'DE.CM', 'DE.AE',
      'RS.MA', 'RS.AN', 'RS.CO', 'RS.MI',
      'RC.RP', 'RC.CO',
    ]);
    for (const c of CSF_CATEGORIES) expect(c.id.startsWith(`${c.function}.`)).toBe(true);
  });

  it('cites none of the categories CSF 2.0 withdrew', () => {
    const withdrawn = ['ID.BE', 'ID.GV', 'ID.RM', 'ID.SC', 'PR.AC', 'PR.IP', 'PR.MA', 'PR.PT', 'DE.DP', 'RS.RP', 'RS.IM', 'RC.IM'];
    const cited = Object.values(OWASP_TO_CSF).flatMap((refs) => refs.flatMap((r) => [r.category, ...r.subcategories]));
    for (const w of withdrawn) expect(cited.some((id) => id === w || id.startsWith(`${w}-`))).toBe(false);
  });
});

describe('OWASP_TO_CSF (dev-guardian mapping)', () => {
  it('maps every 2025 category to at least one CSF category', () => {
    for (const id of OWASP_2025_IDS) expect(csfCategoriesOfOwasp(id).length).toBeGreaterThan(0);
  });

  it('only cites real categories, and subcategories of the category they are listed under', () => {
    const known = new Set(CSF_CATEGORIES.map((c) => c.id));
    for (const refs of Object.values(OWASP_TO_CSF)) {
      for (const r of refs) {
        expect(known.has(r.category)).toBe(true);
        for (const s of r.subcategories) expect(s).toMatch(new RegExp(`^${r.category.replace('.', '\\.')}-\\d{2}$`));
      }
    }
  });

  it('files every OWASP category under ID.RA-01 — a scan that looked for it identified vulnerabilities', () => {
    for (const id of OWASP_2025_IDS) {
      expect(OWASP_TO_CSF[id].some((r) => r.category === 'ID.RA' && r.subcategories.includes('ID.RA-01'))).toBe(true);
    }
  });
});
