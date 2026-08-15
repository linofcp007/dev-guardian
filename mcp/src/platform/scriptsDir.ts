/**
 * Resolve the plugin's `scripts/` directory — the shell scripts every
 * script-invoking tool (`detect_stack`, `security_scan_full`, ...) runs.
 *
 * Shared by `server.ts` and `ci/runScans.ts` on purpose: two independent
 * copies of this arithmetic, one per caller's own file depth, is exactly
 * how a stray `..` gets introduced the day either file moves. But sharing
 * the FUNCTION does not mean a single fixed `..` count is correct for both
 * callers — this module's own `import.meta.url` means something different
 * depending on HOW a caller reaches it, for a reason specific to this
 * project's build (confirmed by inspecting the built `dist/server.js`, not
 * assumed):
 *
 *   - `server.ts` pulls this in through `scripts/bundle.mjs`'s esbuild
 *     bundle, which inlines every transitive import into ONE file,
 *     `dist/server.js`. `import.meta.url` is a runtime construct — esbuild
 *     does not (and cannot, without extra shimming it doesn't apply) rewrite
 *     it per original source file — so at runtime, for code that started
 *     life in THIS file, `import.meta.url` is `dist/server.js`'s own URL:
 *     two directories under the plugin root (`dist/` -> `mcp/` -> root).
 *     `storage/migrations/runner.ts#resolveMigrationsDir` hits the identical
 *     effect for the identical reason — see its own doc comment.
 *   - `ci/runScans.ts` reaches this as a normal, unbundled ES module import
 *     (plain `tsc` output — one real file per source file, same as dev
 *     under `tsx`/vitest). At runtime `import.meta.url` there is THIS
 *     file's own separate location, `dist/platform/scriptsDir.js` (or
 *     `src/platform/scriptsDir.ts` in dev) — three directories under the
 *     plugin root.
 *
 * A fixed `..` count can be right for exactly one of those two callers.
 * Probing for the directory that actually contains a real script is right
 * for both, and for dev/test execution too — the same fix, for the same
 * reason, `resolveMigrationsDir` already applies to the SQL migrations.
 */

import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * A script every checkout has had since `detect_stack` was introduced, and
 * the first one every scan pipeline invokes (`detectStack.ts`'s own
 * `SCRIPT_REL_PATH`). Used only to confirm a CANDIDATE directory really is
 * `scripts/` — not merely that something exists at that depth — which is
 * exactly the check a bare `existsSync(candidate)` would skip.
 */
const MARKER_SCRIPT = ['detect', 'detect-stack.sh'];

export function resolveScriptsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));

  // Bundled: this code is executing as part of dist/server.js, so `here` is
  // dist/ itself.
  const bundled = join(here, '..', '..', 'scripts');
  if (existsSync(join(bundled, ...MARKER_SCRIPT))) return bundled;

  // Unbundled: this code is executing as its own file, one directory
  // deeper than server.ts/server.js (src/platform/ or dist/platform/).
  const unbundled = join(here, '..', '..', '..', 'scripts');
  if (existsSync(join(unbundled, ...MARKER_SCRIPT))) return unbundled;

  // Neither checked out — a broken or unusual install. Return the unbundled
  // guess so a caller gets a deterministic path to report in its own error
  // (e.g. detect_stack's scanner_failed message), rather than `undefined`.
  return unbundled;
}
