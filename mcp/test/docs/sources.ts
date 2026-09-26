/**
 * What the generated reference pages are rendered FROM: the registered MCP
 * surface and the Semgrep pack files. Shared by the writer (`generate.ts`,
 * run by `npm run build`) and the drift test (`docs.test.ts`), so both see
 * the same inputs.
 *
 * Reads `src/` (through tsx or vitest), never `dist/`: the pages describe the
 * source, and the test catches drift the moment the source changes, without
 * a build having run first.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

import { RESOURCES, type ResourceModule } from '../../src/resources/index.js';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import { enumerateClauses } from '../ablate/clauses.js';
import type { PackInput } from './renderDocs.js';

export const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
export const DOCS_DIR = resolve(REPO_ROOT, 'docs');
export const PACKS_DIR = resolve(REPO_ROOT, 'configs', 'semgrep');

interface RawRule {
  id?: unknown;
  severity?: unknown;
  languages?: unknown;
}

/** Every `configs/semgrep/*.yml`, parsed, with its clause inventory. */
export function loadPacks(dir: string = PACKS_DIR): PackInput[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.yml'))
    .sort()
    .map((file) => {
      const source = readFileSync(resolve(dir, file), 'utf8');
      const doc = parseYaml(source) as { rules?: RawRule[] } | null;
      const rules = (doc?.rules ?? []).map((r) => ({
        id: String(r.id),
        severity: String(r.severity),
        languages: Array.isArray(r.languages) ? r.languages.map(String) : [],
      }));
      const inventory = enumerateClauses(source).rules;
      const ids = inventory.map((r) => r.ruleId);
      if (ids.length !== rules.length || ids.some((id, i) => id !== rules[i]?.id)) {
        throw new Error(`${file}: the clause inventory and the parsed rules disagree on the rule list`);
      }
      return { file, rules, inventory };
    });
}

/** The full registry — importing `registerAll` is what populates it. */
export async function loadRegistry(): Promise<{ tools: readonly ToolModule[]; resources: readonly ResourceModule[] }> {
  await import('../../src/registerAll.js');
  return { tools: TOOLS, resources: RESOURCES };
}
