/**
 * The Portuguese in this repo is European Portuguese, post-1990 spelling
 * (AO90): "utilizador", "ficheiro", "deteção", "projeto", "ação". Review 3.0
 * M5 found "Detecção" twice and "detecta" once — the Brazilian (and
 * pre-AO90) forms — in the skills. This test holds every Portuguese text the
 * plugin ships to a list of Brazilian markers: the skills, the commands, the
 * Portuguese README and the Semgrep packs, whose messages and comments are
 * written in Portuguese.
 *
 * Only words a European text never uses are listed, so a hit is a real one.
 * "ação" is NOT a marker (it is the AO90 form in both variants), and neither
 * is "baixar" (to lower — only the download sense is Brazilian).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT, allDocs } from './pluginDocs.js';

const BRAZILIAN: readonly [RegExp, string][] = [
  [/detecç/i, 'deteção'],
  [/\bdetect(a|am|ar|ado|ada|ados|adas|ou|ando)\b/i, 'deteta / detetar / detetado'],
  [/\busuári/i, 'utilizador'],
  [/\barquivos?\b/i, 'ficheiro'],
  [/\bvocê\b/i, 'tu (the skills address the model as tu)'],
  [/\bregistrar\b/i, 'registar'],
  [/\bgerenci/i, 'gerir'],
  [/\bseç(ão|ões)\b/i, 'secção'],
  [/\bequipe\b/i, 'equipa'],
  [/\btelas?\b/i, 'ecrã'],
  [/\bcelular\b/i, 'telemóvel'],
  [/\bcadastr/i, 'registo'],
  [/\b(de )?fato\b/i, 'facto'],
  [/\bcontato\b/i, 'contacto'],
  [/\bacessar\b/i, 'aceder'],
  [/\baplicativo/i, 'aplicação'],
  [/\b(deletar|checar)\b/i, 'apagar / verificar'],
  [/\b(está|estão|estou|estamos|estava)\s+[a-zà-ú]+ndo\b/i, 'está a fazer (not the gerund)'],
];

function portugueseTexts(): { rel: string; text: string }[] {
  const out = allDocs().map((d) => ({ rel: d.rel, text: d.text }));
  out.push({ rel: 'README.pt-PT.md', text: readFileSync(resolve(REPO_ROOT, 'README.pt-PT.md'), 'utf8') });
  const packs = resolve(REPO_ROOT, 'configs', 'semgrep');
  for (const f of readdirSync(packs).filter((n) => n.endsWith('.yml'))) {
    out.push({ rel: `configs/semgrep/${f}`, text: readFileSync(resolve(packs, f), 'utf8') });
  }
  return out;
}

describe('European Portuguese, AO90', () => {
  it.each(portugueseTexts().map((d) => [d.rel, d] as const))('%s: no Brazilian form', (_rel, doc) => {
    const hits: string[] = [];
    doc.text.split('\n').forEach((line, i) => {
      for (const [re, pt] of BRAZILIAN) {
        const m = re.exec(line);
        if (m) hits.push(`${i + 1}: "${m[0]}" → ${pt}`);
      }
    });
    expect(hits).toEqual([]);
  });
});
