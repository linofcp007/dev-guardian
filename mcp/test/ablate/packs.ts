/**
 * The pack registry: which rule pack is ablated against which corpora.
 *
 * Axis 3 (does the clause raise the finding count on code nobody wrote as a
 * fixture?) needs a real-code corpus in a language the pack matches. That is
 * a property of the INVOCATION, recorded here per pack and overridable from
 * the command line, not a special case buried inside the harness: today only
 * the JS/TS pack has one, because `mcp/src` is the only large body of
 * not-written-as-a-fixture code in this repo and it is TypeScript.
 *
 * `base.yml` does contain JS/TS rules and would accept `mcp/src` as a corpus;
 * it is left off by default only because nobody has read that baseline yet.
 * Turn it on with `--real-code=../mcp/src` when someone is ready to triage
 * whatever it reports.
 *
 * `routes.yml` is deliberately absent: it is a route-inventory pack with no
 * `hits/` + `misses/` fixture pair, so axes 1 and 2 have nothing to measure
 * against. Give it a fixture corpus and it belongs here like the rest.
 */

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PackSpec } from './harness.js';

/** `<repo>/mcp/test/ablate/packs.ts` -> `<repo>`. */
export const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));

const config = (name: string): string => resolve(REPO_ROOT, 'configs', 'semgrep', `${name}.yml`);
const fixtures = (name: string): string => resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', name);

/** Real-code corpus for the JS/TS pack: this repo's own server sources. */
export const MCP_SRC = { label: 'mcp/src', dir: resolve(REPO_ROOT, 'mcp', 'src') } as const;

export const PACKS: readonly PackSpec[] = [
  {
    name: 'bugfix-js',
    config: config('bugfix-js'),
    fixtures: fixtures('bugfix-js'),
    hitsSubdir: 'hits',
    realCode: MCP_SRC,
  },
  { name: 'bugfix-py', config: config('bugfix-py'), fixtures: fixtures('bugfix-py'), hitsSubdir: 'hits' },
  { name: 'bugfix-go', config: config('bugfix-go'), fixtures: fixtures('bugfix-go'), hitsSubdir: 'hits' },
  { name: 'bugfix-java', config: config('bugfix-java'), fixtures: fixtures('bugfix-java'), hitsSubdir: 'hits' },
  { name: 'bugfix-cs', config: config('bugfix-cs'), fixtures: fixtures('bugfix-cs'), hitsSubdir: 'hits' },
  // Axis 3 is N/A: this repo holds no PHP outside this fixture tree. The PHP
  // pack WAS measured against a real corpus — WordPress 6.9, 1467 files, and
  // that measurement changed four verdicts (design of record §1) — but the
  // corpus is a 60 MB third-party download, not something to vendor here.
  // Point the harness at one with `--real-code=<dir>` when you have a WordPress
  // (or any PHP) tree on disk; without it the report prints N/A rather than
  // pretending the axis ran.
  { name: 'bugfix-php', config: config('bugfix-php'), fixtures: fixtures('bugfix-php'), hitsSubdir: 'hits' },
  { name: 'base', config: config('base'), fixtures: fixtures('base'), hitsSubdir: 'hits' },
];

export function packByName(name: string): PackSpec | undefined {
  return PACKS.find((p) => p.name === name);
}

export function packNames(): string[] {
  return PACKS.map((p) => p.name);
}
