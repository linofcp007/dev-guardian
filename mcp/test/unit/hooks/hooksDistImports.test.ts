/**
 * The hook dispatcher (`hooks/guardian-hook.mjs`) imports compiled modules
 * straight from `mcp/dist/` in an install that has no `node_modules` — the
 * repository is the distribution (CLAUDE.md). A module it loads that reaches
 * a package, directly or through any file it imports, fails to load, and the
 * dispatcher fails OPEN: the guard it was loading is silently off. This walks
 * every module the dispatcher names, and everything they import, in the
 * committed `dist/`, and holds each import to a Node built-in or a relative
 * file — and every module under `dist/hooks/` to `dist/hooks/` itself: the
 * CLI's `check` and `--help` load them with `dist/storage/` absent
 * (`test/e2e/cliLazyStorage.test.ts`). Review of 3.0, W2E: the data
 * directory's resolution, once mirrored in `hooks/dataRegistry.ts` and
 * `storage/userData.ts`, is now one module, `hooks/userDataDir.ts` — a first
 * attempt that imported `storage/userData.js` from the hook broke the CLI.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const MCP = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const DISPATCHER = join(MCP, '..', 'hooks', 'guardian-hook.mjs');

/** Every `mcp/dist/...js` module the dispatcher names. */
function dispatcherEntries(): string[] {
  const text = readFileSync(DISPATCHER, 'utf8');
  const out = new Set<string>();
  for (const m of text.matchAll(/join\(DIST_HOOKS, '([^']+\.js)'\)/g)) out.add(join(MCP, 'dist', 'hooks', m[1] ?? ''));
  for (const m of text.matchAll(/join\(DIST_PKGVET, '([^']+\.js)'\)/g)) out.add(join(MCP, 'dist', 'pkgvet', m[1] ?? ''));
  for (const m of text.matchAll(/join\(PLUGIN_ROOT, 'mcp', 'dist', '([^']+)', '([^']+\.js)'\)/g)) {
    out.add(join(MCP, 'dist', m[1] ?? '', m[2] ?? ''));
  }
  return [...out].sort();
}

/** The specifiers a compiled ES module's text imports: static, re-export, bare and dynamic. */
function specifiers(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/(?:^|[;\s])(?:import|export)\s[^'"]*?\sfrom\s*['"]([^'"]+)['"]/g)) out.push(m[1] ?? '');
  for (const m of text.matchAll(/(?:^|[;\s])import\s*['"]([^'"]+)['"]/g)) out.push(m[1] ?? '');
  for (const m of text.matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g)) out.push(m[1] ?? '');
  return out;
}

describe('the modules the hook dispatcher loads need no node_modules', () => {
  const entries = dispatcherEntries();

  it('finds the dispatcher’s modules, dataRegistry.js and the registry reader among them', () => {
    const rel = entries.map((e) => relative(join(MCP, 'dist'), e).split('\\').join('/'));
    expect(rel).toEqual(expect.arrayContaining(['hooks/dataRegistry.js', 'hooks/bashGuard.js', 'storage/dbRegistry.js', 'pkgvet/hookDecision.js']));
  });

  it('import only Node built-ins and relative files, transitively', () => {
    const seen = new Set<string>();
    const bad: string[] = [];
    const queue = [...entries];
    for (let file = queue.shift(); file !== undefined; file = queue.shift()) {
      if (seen.has(file)) continue;
      seen.add(file);
      expect(existsSync(file), `${file} is not built`).toBe(true);
      for (const spec of specifiers(readFileSync(file, 'utf8'))) {
        if (spec.startsWith('node:')) continue;
        if (spec.startsWith('./') || spec.startsWith('../')) {
          queue.push(resolve(dirname(file), spec));
          continue;
        }
        bad.push(`${relative(MCP, file)} imports '${spec}'`);
      }
    }
    expect(seen.has(join(MCP, 'dist', 'hooks', 'userDataDir.js'))).toBe(true);
    expect(bad).toEqual([]);
  });

  it('a module under dist/hooks/ imports nothing outside dist/hooks/, transitively', () => {
    const hooksDir = join(MCP, 'dist', 'hooks');
    const inside = (f: string): boolean => !relative(hooksDir, f).startsWith('..');
    const outside: string[] = [];
    const seen = new Set<string>();
    const queue = entries.filter(inside);
    for (let file = queue.shift(); file !== undefined; file = queue.shift()) {
      if (seen.has(file)) continue;
      seen.add(file);
      for (const spec of specifiers(readFileSync(file, 'utf8'))) {
        if (!spec.startsWith('./') && !spec.startsWith('../')) continue;
        const target = resolve(dirname(file), spec);
        if (inside(target)) queue.push(target);
        else outside.push(`${relative(MCP, file)} imports '${spec}'`);
      }
    }
    expect(seen.has(join(hooksDir, 'dataRegistry.js'))).toBe(true);
    expect(outside).toEqual([]);
  });

  it('sees every import shape (positive control)', () => {
    const text = [
      "import { execa } from 'execa';",
      "import * as z from 'zod';",
      "export { a } from './a.js';",
      "import 'side-effect';",
      "const m = await import('yaml');",
      "import { readFileSync } from 'node:fs';",
    ].join('\n');
    expect(specifiers(text)).toEqual(['execa', 'zod', './a.js', 'node:fs', 'side-effect', 'yaml']);
  });
});
