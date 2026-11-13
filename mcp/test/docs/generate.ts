/**
 * `tsx test/docs/generate.ts` — the last step of `npm run build`.
 *
 * Writes `docs/tools.md` (every registered tool and resource),
 * `docs/rule-packs.md` (every Semgrep pack and rule) and
 * `docs/hooks-known-limits.md` (every known limit of the guardrail hooks, from
 * `test/fixtures/hooks/known-limits.yml`) from `sources.ts` and
 * `knownLimits.ts` through `renderDocs.ts`. `docs.test.ts` fails when a committed page no
 * longer matches what this would write, so the fix for that failure is
 * always `npm run build`, never a hand edit.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { loadKnownLimits } from './knownLimits.js';
import { renderKnownLimitsDoc, renderRulePacksDoc, renderToolsDoc } from './renderDocs.js';
import { DOCS_DIR, loadPacks, loadRegistry } from './sources.js';

function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, 'utf8');
  console.log(`generated ${path}`);
}

const { tools, resources, folds } = await loadRegistry();
write(resolve(DOCS_DIR, 'tools.md'), renderToolsDoc(tools, resources, folds));
write(resolve(DOCS_DIR, 'rule-packs.md'), renderRulePacksDoc(loadPacks()));
write(resolve(DOCS_DIR, 'hooks-known-limits.md'), renderKnownLimitsDoc(loadKnownLimits()));
