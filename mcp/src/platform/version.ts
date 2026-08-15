/**
 * Resolve the version this build reports to any consumer that asks — the MCP
 * server's own `serverInfo.version` (`server.ts`) and every SARIF
 * `tool.driver.version` this project emits (`report/sarif.ts`), whether that
 * SARIF comes from an interactive `report_export`/`scan_skill` MCP tool call
 * or the headless CI path (`ci/report.ts`, via `cli/dev-guardian.mjs`). One
 * source of truth, read at runtime from `.claude-plugin/plugin.json` — the
 * file CLAUDE.md's own release checklist keeps in lock-step with
 * `mcp/package.json` and `marketplace.json` — instead of two independent
 * hardcoded fallbacks that can silently drift behind the release the moment
 * one is bumped and the other is not (exactly what happened to SARIF: it
 * still said `0.1.0` for a 1.3.0 release).
 *
 * Bundled/unbundled depth split: the identical structural problem
 * `scriptsDir.ts` documents and solves for `scripts/`, for the identical
 * reason. `server.ts` pulls this module in through `scripts/bundle.mjs`'s
 * esbuild bundle, which inlines every transitive import into ONE file,
 * `dist/server.js` — so at runtime, `import.meta.url` for code that started
 * life in THIS file is `dist/server.js`'s own URL, two directories under the
 * plugin root (`dist/` -> `mcp/` -> root). Every other path this module is
 * reached by — `ci/report.ts` and `report/sarif.ts`, both loaded from the
 * CLI as plain, unbundled `dist/ci/*.js` / `dist/report/*.js` imports; this
 * module's own test; and `server.ts` itself under `npm run dev`'s
 * `tsx src/server.ts` — loads this module as its own separate file, three
 * directories under the plugin root (`dist/platform/` or `src/platform/` ->
 * `dist`/`src` -> `mcp/` -> root). A fixed `..` count can only be right for
 * one of those two cases; trying both candidate depths for each filename,
 * and keeping whichever one actually parses, is right for both without
 * needing to know in advance which case applies.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const FALLBACK_VERSION = '0.0.0';

function readVersion(path: string): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as { version?: string };
    return parsed.version;
  } catch {
    return undefined; // missing file, unreadable, or malformed JSON — try the next candidate
  }
}

export function resolveVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    // .claude-plugin/plugin.json — the real release version — tried at both
    // depths before falling back to mcp/package.json at either depth, same
    // preference order the pre-lift server.ts-local version used.
    resolve(here, '..', '..', '.claude-plugin', 'plugin.json'), // bundled (dist/server.js) / tsx dev
    resolve(here, '..', '..', '..', '.claude-plugin', 'plugin.json'), // unbundled (this module's own file)
    resolve(here, '..', 'package.json'), // bundled / tsx dev — mcp/package.json (standalone npm use)
    resolve(here, '..', '..', 'package.json'), // unbundled — mcp/package.json
  ];
  for (const candidate of candidates) {
    const version = readVersion(candidate);
    if (version) return version;
  }
  return FALLBACK_VERSION;
}
