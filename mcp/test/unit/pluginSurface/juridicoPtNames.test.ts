/**
 * dev-guardian's prose against the juridico-pt names it may cite.
 *
 * `guardian-compliance` sends legal questions (fines, legal bases, contracts)
 * to the sibling plugin juridico-pt. It used to name a skill `advogado-pt`
 * that never existed; juridico-pt's commands are `/advogado`, `/rgpd`, …, and
 * its one skill is `juridico-pt`. So:
 *
 *   - no prose names `advogado-pt`;
 *   - every juridico-pt name the prose cites — `juridico-pt:<name>`, or a
 *     `/<command>` on a line that names juridico-pt — is in JURIDICO_PT_NAMES;
 *   - when a juridico-pt install (`<claude config>/plugins/cache/<marketplace>/juridico-pt/<version>`)
 *     is on this machine, each of those names is one of its command files or
 *     skill directories. With none, that part is skipped, and its title says why.
 */

import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { allDocs } from './pluginDocs.js';

/** The juridico-pt commands and skill dev-guardian cites (without the leading `/`). */
const JURIDICO_PT_NAMES: readonly string[] = ['juridico-pt', 'advogado', 'rgpd'];

function citations(text: string): string[] {
  const out = [...text.matchAll(/juridico-pt:([a-z0-9-]+)/g)].map((m) => m[1] ?? '');
  for (const line of text.split(/\r?\n/)) {
    if (!/juridico-pt/.test(line)) continue;
    out.push(...[...line.matchAll(/(?<![\w/.~:-])\/([a-z][a-z0-9-]*)(?![\w-])/g)].map((m) => m[1] ?? ''));
  }
  return out;
}

describe("dev-guardian's prose cites only real juridico-pt names", () => {
  const docs = allDocs();

  it('never names the advogado-pt skill, which does not exist', () => {
    expect(docs.filter((d) => /advogado-pt/.test(d.text)).map((d) => d.rel)).toEqual([]);
  });

  it('every juridico-pt name it cites is listed, and guardian-compliance cites them', () => {
    const known = new Set(JURIDICO_PT_NAMES);
    const bad = docs.flatMap((d) => citations(d.text).filter((n) => !known.has(n)).map((n) => `${d.rel}: ${n}`));
    expect(bad).toEqual([]);
    const compliance = docs.find((d) => d.rel === 'skills/guardian-compliance/SKILL.md')?.text ?? '';
    expect(citations(compliance)).toEqual(expect.arrayContaining(['advogado', 'rgpd']));
  });
});

function newestInstall(): string | null {
  const configDirs = [process.env['CLAUDE_CONFIG_DIR'], join(homedir(), '.claude')].filter(
    (d): d is string => d !== undefined && d !== '',
  );
  const found: { root: string; key: number[] }[] = [];
  for (const configDir of [...new Set(configDirs)]) {
    const cache = join(configDir, 'plugins', 'cache');
    if (!existsSync(cache)) continue;
    for (const marketplace of readdirSync(cache)) {
      const plugin = join(cache, marketplace, 'juridico-pt');
      if (!existsSync(plugin)) continue;
      for (const version of readdirSync(plugin)) {
        const root = join(plugin, version);
        if (existsSync(join(root, 'commands'))) {
          found.push({ root, key: version.split(/[.+-]/).map((p) => Number.parseInt(p, 10) || 0) });
        }
      }
    }
  }
  found.sort((a, b) => {
    for (let i = 0; i < 3; i++) if ((a.key[i] ?? 0) !== (b.key[i] ?? 0)) return (b.key[i] ?? 0) - (a.key[i] ?? 0);
    return 0;
  });
  return found[0]?.root ?? null;
}

const install = newestInstall();

describe(`the names against a live juridico-pt (${install ?? 'skipped: no juridico-pt install in <claude config>/plugins/cache'})`, () => {
  it.skipIf(install === null)('each listed name is one of its commands or skills', () => {
    if (install === null) return;
    const names = new Set([
      ...readdirSync(join(install, 'commands'))
        .filter((f) => f.endsWith('.md'))
        .map((f) => f.slice(0, -'.md'.length)),
      ...(existsSync(join(install, 'skills')) ? readdirSync(join(install, 'skills')) : []),
    ]);
    expect(JURIDICO_PT_NAMES.filter((n) => !names.has(n))).toEqual([]);
  });
});
