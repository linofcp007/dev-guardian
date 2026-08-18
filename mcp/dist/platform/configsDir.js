/**
 * Resolve the plugin's `configs/` directory — where `bug_hunt` finds its
 * always-on local Semgrep rules (`configs/semgrep/bugfix-js.yml`).
 *
 * Mirrors `resolveScriptsDir` (`./scriptsDir.ts`) exactly, for the identical
 * reason documented there: this file lives at the same depth
 * (`mcp/src/platform/`), so it is subject to the same two execution shapes,
 * and a fixed `..` count can only be right for one of them —
 *
 *   - `server.ts` pulls this in (transitively, via `bugHunt.ts`) through
 *     `scripts/bundle.mjs`'s esbuild bundle, which inlines every import into
 *     ONE file, `dist/server.js`. At runtime, for code that started life in
 *     THIS file, `import.meta.url` is then `dist/server.js`'s own URL — two
 *     directories under the plugin root (`dist/` -> `mcp/` -> root).
 *   - Every unit test (and `tsx`/plain `node` execution of the compiled
 *     output) reaches this as a normal, unbundled ES module import — one
 *     real file per source file. There, `import.meta.url` is THIS file's
 *     own separate location, `dist/platform/configsDir.js` (or
 *     `src/platform/configsDir.ts` in dev/test) — three directories under
 *     the plugin root.
 *
 * Probing for the directory that actually contains a real config file is
 * right for both shapes, and for dev/test execution too — see
 * `scriptsDir.ts`'s own doc comment for the fuller account of why a bare
 * `..` count broke.
 *
 * This is deliberately a SEPARATE resolver from `initProject.ts`'s own
 * (unexported, narrower) `resolveConfigsDir(scriptsDir)`, which derives the
 * configs directory from an already-resolved `ctx.plugin.scriptsDir`. That
 * shape is right for `init_project`, whose whole job is copying template
 * files the caller/tests may reasonably want to point elsewhere. It is
 * wrong for `bug_hunt`: its own integration tests fake `ctx.plugin.scriptsDir`
 * to a throwaway temp directory (to sandbox the shell scripts other scan
 * tools invoke), and nothing populates a fake `configs/semgrep/bugfix-js.yml`
 * next to it — so `bug_hunt` needs a resolver that finds the REAL, checked-in
 * rule file regardless of what a test (or an unusual host) sets `ctx` to.
 * That is exactly what an independent, `import.meta.url`-based probe gives.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
/**
 * Every checkout has had `configs/semgrep/base.yml` since `init_project`
 * shipped it as the `standard`/`paranoid` profile's baseline SAST config.
 * Used only to confirm a CANDIDATE directory really is `configs/` — not
 * merely that something exists at that depth — the same discipline
 * `scriptsDir.ts`'s own `MARKER_SCRIPT` applies.
 */
const MARKER_RULES = ['semgrep', 'base.yml'];
export function resolveConfigsDir() {
    const here = dirname(fileURLToPath(import.meta.url));
    // Bundled: this code is executing as part of dist/server.js, so `here` is
    // dist/ itself.
    const bundled = join(here, '..', '..', 'configs');
    if (existsSync(join(bundled, ...MARKER_RULES)))
        return bundled;
    // Unbundled: this code is executing as its own file, one directory
    // deeper than server.ts/server.js (src/platform/ or dist/platform/).
    const unbundled = join(here, '..', '..', '..', 'configs');
    if (existsSync(join(unbundled, ...MARKER_RULES)))
        return unbundled;
    // Neither checked out — a broken or unusual install. Return the unbundled
    // guess so a caller gets a deterministic path to report in its own error,
    // rather than `undefined` — same fallback discipline as resolveScriptsDir.
    return unbundled;
}
const BUGFIX_JS_RULES = ['semgrep', 'bugfix-js.yml'];
/**
 * Absolute path to `configs/semgrep/bugfix-js.yml`, or `null` when it is
 * missing.
 *
 * That only happens on a damaged or unusually pruned checkout — this repo
 * ships the file — but `bug_hunt` must never pass a `--config` that does not
 * resolve: Semgrep aborts the WHOLE scan when any `--config` fails to load,
 * which is exactly the failure mode that took `bug_hunt` down once already
 * when the `p/bugs` registry pack was retired (see `bugHunt.ts`'s header
 * comment and `semgrepConfigFailure.ts`). A local `--config` pointing at a
 * path that does not exist reproduces that same failure without even
 * needing the network. Returning `null` here lets the caller
 * (`buildPackList` in `bugHunt.ts`) omit the pack instead of passing a bad
 * path.
 */
export function resolveBugfixRules() {
    const path = join(resolveConfigsDir(), ...BUGFIX_JS_RULES);
    return existsSync(path) ? path : null;
}
//# sourceMappingURL=configsDir.js.map