/**
 * `tsx test/docs/generate.ts` — the last step of `npm run build`.
 *
 * Writes `docs/tools.md` (every registered tool and resource) and
 * `docs/rule-packs.md` (every Semgrep pack and rule) from `sources.ts`
 * through `renderDocs.ts`. `docs.test.ts` fails when a committed page no
 * longer matches what this would write, so the fix for that failure is
 * always `npm run build`, never a hand edit.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { renderRulePacksDoc, renderToolsDoc } from './renderDocs.js';
import { DOCS_DIR, loadPacks, loadRegistry } from './sources.js';

function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, 'utf8');
  console.log(`generated ${path}`);
}

const { tools, resources } = await loadRegistry();
write(resolve(DOCS_DIR, 'tools.md'), renderToolsDoc(tools, resources));
write(resolve(DOCS_DIR, 'rule-packs.md'), renderRulePacksDoc(loadPacks()));
