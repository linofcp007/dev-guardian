/**
 * Instructions state the current rule, never the release history behind it.
 *
 * A model reads a skill, a command, the host rules or a tool description as
 * what to do now. "(update from 3.0.0)", "a database from before 3.1.0",
 * "earlier versions of this skill said…" and round-by-round measurement
 * tables cost context in every session and tell the model nothing it can act
 * on; the history belongs in CHANGELOG.md and the rule packs' comments.
 * guardian-bugfix alone carried 51 KB of it.
 *
 * So no model-facing prose names a dev-guardian release (`3.1.0`, "before
 * 3.1", "since 2.0"), says what an earlier version did, or counts review
 * rounds. Version numbers that are DATA stay: a package version in an example
 * (`lodash@4.17.20`, `Fix: >= 4.17.21`), a Node.js floor (`>= 22.13`), and the
 * sibling plugin a feature needs (`dev-spec-driven 1.29+`).
 *
 * KNOWN lists the offenders this branch could not edit — tool descriptions
 * are reworded in the tool-description pass — so the list can only shrink:
 * an entry that no longer matches fails too.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { RULES_BODY } from '../../../src/hostsetup/rulesTemplate.js';
import { TOOLS } from '../../../src/tools/index.js';
import { allDocs } from './pluginDocs.js';

beforeAll(async () => {
  await import('../../../src/registerAll.js');
});

/** A dev-guardian release, or a sentence about what an earlier one did. */
const HISTORY: readonly [RegExp, string][] = [
  [/(?<![\w@.=>-])(?:v)?[23]\.\d+\.\d+\b/, 'a dev-guardian release number'],
  [/\b(?:before|since|until|prior to|after|from|antes da|desde a|depois da|atualização da|a partir da)\s+(?:dev-guardian\s+)?v?[23]\.\d+\b/i, 'a release boundary'],
  [/\b(?:earlier|previous|older) versions? of\b|\bversões anteriores\b|\bused to (?:say|be)\b/i, 'what an earlier version did'],
  [/\brondas?\b|\breview rounds?\b|\bround \d+\b/i, 'review-round history'],
];

/** Lines whose version number is data, not history. */
const DATA = [/[\w-]@\d+\.\d+\.\d+/, />=\s*\d+\.\d+/, /\bdev-spec-driven \d+\.\d+\+/, /\bSARIF \d+\.\d+\.\d+/];

function hits(text: string): string[] {
  const out: string[] = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (DATA.some((re) => re.test(line))) return;
    for (const [re, why] of HISTORY) {
      const m = re.exec(line);
      if (m !== null) out.push(`${i + 1}: "${m[0]}" — ${why}`);
    }
  });
  return out;
}

/** Tool descriptions and titles still carrying history, until the tool-description pass rewrites them. */
const KNOWN: Record<string, readonly string[]> = {
  health_status: ['"a database from before 3.1.0" in the storage_warning sentence'],
};

describe('model-facing prose states the current rule, not the release history', () => {
  it.each(allDocs().map((d) => [d.rel, d.text] as const))('%s', (_rel, text) => {
    expect(hits(text)).toEqual([]);
  });

  it('the host rules template', () => {
    expect(hits(RULES_BODY)).toEqual([]);
  });

  it('tool titles and descriptions (only the known offenders, and each still offends)', () => {
    const found: Record<string, string[]> = {};
    for (const t of TOOLS) {
      const h = hits(`${t.title ?? ''}\n${t.description}`);
      if (h.length > 0) found[t.name] = h;
    }
    expect(Object.keys(found).sort()).toEqual(Object.keys(KNOWN).sort());
  });

  it('the matcher finds history and leaves data alone', () => {
    expect(hits('a database from before 3.1.0, or a copy')).not.toEqual([]);
    expect(hits('(atualização da 3.0.0)')).not.toEqual([]);
    expect(hits('Versões anteriores desta skill diziam')).not.toEqual([]);
    expect(hits('needs dev-spec-driven 1.29+ and Node.js >= 22.13')).toEqual([]);
    expect(hits('lodash@4.17.20 — CVE-2021-23337')).toEqual([]);
    expect(hits('what changed since v1.2?')).toEqual([]);
    expect(hits('Import a SARIF 2.1.0 log')).toEqual([]);
  });
});
