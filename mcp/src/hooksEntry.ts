/**
 * The hooks bundle's entry: `scripts/bundle.mjs` builds this module into
 * `dist/hooks.js`, the one file `hooks/guardian-hook.mjs` loads from the
 * build (review 8, finding 3). The dispatcher used to import tsc's per-file
 * output — 27 modules of the 355 `dist/` shipped for it — and an install now
 * ships no per-file output at all.
 *
 * Each detector is behind its own loader, a dynamic `import()` the bundle
 * keeps lazy (esbuild wraps a module reached only that way in an initializer
 * that runs on the first call): an event evaluates only the detectors it uses
 * — every Bash call the shell guard and the install gate, every write the
 * write guards (review 8, item 17). The loaders resolve to the module's own
 * exports; the dispatcher checks each function it takes, and a missing or
 * damaged bundle fails open, with SessionStart naming the guards that are off.
 *
 * Nothing here may reach an npm package or `node:sqlite` at load time: the
 * hook runs on every tool call (`test/unit/hooks/hooksDistImports.test.ts`
 * holds the bundle's inputs to that).
 */

/** Every event: reading the hook configuration, and the paths a write reaches. */
export const loadConfigFile = () => import('./hooks/configFile.js');
export const loadGuardedPath = () => import('./hooks/guardedPath.js');

/** PreToolUse on Bash / PowerShell: the catastrophic-command guard, then install vetting behind its cheap gate. */
export const loadBashGuard = () => import('./hooks/bashGuard.js');
export const loadInstallGate = () => import('./pkgvet/mayInstall.js');
export const loadInstallVetting = () => import('./pkgvet/hookDecision.js');

/** The writes: the secret scan, the Claude Code settings guard and the database registry guard. */
export const loadSecretScan = () => import('./hooks/secretScan.js');
export const loadSettingsGuard = () => import('./hooks/settingsGuard.js');
export const loadDataRegistry = () => import('./hooks/dataRegistry.js');

/** SessionStart: hardened git for the briefing, and whether the project's database is registered. */
export const loadGitSafety = () => import('./platform/gitSafety.js');
export const loadDbRegistry = () => import('./storage/dbRegistry.js');
