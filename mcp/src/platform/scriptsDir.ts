/**
 * Resolve the plugin's `scripts/` directory — the shell scripts every
 * script-invoking tool (`detect_stack`, `security_scan_full`, ...) runs.
 *
 * Shared by `server.ts` and `ci/runScans.ts` on purpose: two independent
 * copies of this arithmetic, one per caller's own file depth, is exactly
 * how a stray `..` gets introduced the day either file moves. But a single
 * fixed `..` count is still not correct everywhere — this module's own
 * `import.meta.url` means something different depending on HOW it runs:
 *
 *   - Shipped, it runs inside an esbuild bundle (`scripts/bundle.mjs`):
 *     `dist/engine.js`, which the server and the CLI run, or `dist/hooks.js`.
 *     `import.meta.url` is a runtime construct — esbuild does not rewrite it
 *     per original source file — so for code that started life in THIS file
 *     it is the bundle's own URL: two directories under the plugin root
 *     (`dist/` -> `mcp/` -> root). `storage/migrations/runner.ts#resolveMigrationsDir`
 *     hits the identical effect for the identical reason.
 *   - Under tsx and vitest (`npm run dev`, every test) it runs as its own
 *     file, `src/platform/scriptsDir.ts` — three directories under the plugin
 *     root. (Until 3.3.0 tsc's per-file `dist/platform/` shipped too, at the
 *     same depth.)
 *
 * A fixed `..` count can be right for exactly one of those two shapes.
 * Probing for the directory that actually contains a real script is right
 * for both — the same fix, for the same reason, `resolveMigrationsDir`
 * already applies to the SQL migrations.
 */

import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * A script every checkout has had since `init_project` was introduced, and
 * still the first (and, as of the TypeScript port of stack detection, only)
 * one `init_project` invokes for its first-pass status (`initProject.ts`).
 * Used only to confirm a CANDIDATE directory really is `scripts/` — not
 * merely that something exists at that depth — which is exactly the check a
 * bare `existsSync(candidate)` would skip.
 *
 * Used to be `detect/detect-stack.sh`, `detect_stack`'s own script — retired
 * when stack detection was ported to TypeScript (no shell involved any
 * more); this marker moved to a script that is still real and still run.
 */
const MARKER_SCRIPT = ['scan', 'initial-scan.sh'];

export function resolveScriptsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));

  // Bundled: this code is executing as part of dist/engine.js (or dist/hooks.js), so `here` is
  // dist/ itself.
  const bundled = join(here, '..', '..', 'scripts');
  if (existsSync(join(bundled, ...MARKER_SCRIPT))) return bundled;

  // Unbundled: this code is executing as its own file, one directory
  // deeper than the bundles (src/platform/ under tsx or vitest).
  const unbundled = join(here, '..', '..', '..', 'scripts');
  if (existsSync(join(unbundled, ...MARKER_SCRIPT))) return unbundled;

  // Neither checked out — a broken or unusual install. Return the unbundled
  // guess so a caller gets a deterministic path to report in its own error
  // (e.g. detect_stack's scanner_failed message), rather than `undefined`.
  return unbundled;
}
