/**
 * The hand-written JavaScript is type-checked (review of 3.3.0): the CLI, the
 * hook dispatcher and the build scripts were the only code no checker read —
 * and the CLI is what CI runs, the dispatcher what every tool call goes
 * through. `npm run lint` runs `tsc -p tsconfig.js.json` (allowJs, checkJs,
 * strict); the bundles they import are typed by their sources through
 * `dist/engine.d.ts` / `dist/hooks.d.ts` (`distSync.test.ts` holds those).
 *
 * Held here: the lint script runs it, the config checks every shipped `.mjs`
 * of `cli/` and `hooks/` and the scripts, and no file opts out.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MCP_ROOT } from '../../helpers/tsxNode.js';

const REPO_ROOT = join(MCP_ROOT, '..');

/** tsconfig.js.json without its comments (it is JSONC, as tsc reads it). */
function jsConfig(): { compilerOptions: Record<string, unknown>; include: string[]; exclude: string[] } {
  const text = readFileSync(join(MCP_ROOT, 'tsconfig.js.json'), 'utf8');
  return JSON.parse(text.replace(/^\s*\/\/.*$/gm, '')) as { compilerOptions: Record<string, unknown>; include: string[]; exclude: string[] };
}

/** Every `.mjs` directly in `dir`, relative to `mcp/`. */
function mjsIn(dir: string, prefix: string): string[] {
  return readdirSync(dir)
    .filter((n) => n.endsWith('.mjs'))
    .map((n) => `${prefix}/${n}`);
}

describe('the hand-written JavaScript is type-checked', () => {
  it('npm run lint runs tsc -p tsconfig.js.json', () => {
    const pkg = JSON.parse(readFileSync(join(MCP_ROOT, 'package.json'), 'utf8')) as { scripts: Record<string, string> };
    expect(pkg.scripts['lint']?.split(' && ')).toContain('tsc -p tsconfig.js.json');
  });

  it('checks JavaScript, strictly', () => {
    const { compilerOptions } = jsConfig();
    expect({ allowJs: compilerOptions['allowJs'], checkJs: compilerOptions['checkJs'], noEmit: compilerOptions['noEmit'] }).toEqual({
      allowJs: true,
      checkJs: true,
      noEmit: true,
    });
    const base = JSON.parse(readFileSync(join(MCP_ROOT, 'tsconfig.json'), 'utf8')) as { compilerOptions: Record<string, unknown> };
    expect(base.compilerOptions['strict']).toBe(true);
    // Nothing the base sets strict is turned off for the JavaScript.
    for (const key of ['strict', 'noImplicitAny', 'strictNullChecks', 'noUncheckedIndexedAccess']) expect(compilerOptions[key], key).toBeUndefined();
  });

  it('includes the CLI, the hook dispatcher and the scripts', () => {
    expect(jsConfig().include).toEqual(expect.arrayContaining(['../cli/*.mjs', '../hooks/*.mjs', 'scripts/*.mjs']));
    // Positive control: there is something to check in each.
    expect(mjsIn(join(REPO_ROOT, 'cli'), '../cli')).toContain('../cli/dev-guardian.mjs');
    expect(mjsIn(join(REPO_ROOT, 'hooks'), '../hooks')).toContain('../hooks/guardian-hook.mjs');
    expect(mjsIn(join(MCP_ROOT, 'scripts'), 'scripts').length).toBeGreaterThan(3);
  });

  it('no checked file opts out with @ts-nocheck', () => {
    const files = [
      ...mjsIn(join(REPO_ROOT, 'cli'), '../cli'),
      ...mjsIn(join(REPO_ROOT, 'hooks'), '../hooks'),
      ...mjsIn(join(MCP_ROOT, 'scripts'), 'scripts'),
    ];
    const optedOut = files.filter((f) => readFileSync(join(MCP_ROOT, f), 'utf8').includes('@ts-nocheck'));
    expect(optedOut).toEqual([]);
  });
});
