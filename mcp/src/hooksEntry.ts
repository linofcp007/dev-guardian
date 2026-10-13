/**
 * The hooks bundle's entry: `scripts/bundle.mjs` builds this module into
 * `dist/hooks.js`, the one file `hooks/guardian-hook.mjs` loads from the
 * build (review 8, finding 3). The dispatcher used to import tsc's per-file
 * output — 27 modules of the 355 `dist/` shipped for it — and an install now
 * ships no per-file output at all.
 *
 * What every event needs — reading the hook configuration, and the paths a
 * write reaches — is in this file. Everything else is in one of four parts,
 * each a self-contained bundle of its own beside it (3.4.0), loaded by the
 * event that runs it: `dist/hooksBash.js` (the shell guard and the install
 * gate — every Bash call), `dist/hooksVet.js` (install vetting — a command that
 * may install), `dist/hooksWrite.js` (the write guards and the secret scan —
 * every write), `dist/hooksSession.js` (SessionStart's git, database registry
 * and engine check). 3.3.0's one-file bundle made every write parse all
 * 368 KB, the shell guard and `node:crypto` / `node:child_process` included
 * (PostToolUse 66 → 76 ms); a chunk per module (esbuild's code splitting)
 * made each event open a dozen files, slower still on Windows. The parts are
 * left to the runtime by the build (`scripts/bundleOptions.mjs`), and under
 * tsx and vitest they are the sources they re-export.
 *
 * The loaders resolve to the module's own exports; the dispatcher checks each
 * function it takes, and a missing or damaged bundle or part fails open, with
 * SessionStart naming the guards that are off.
 *
 * Nothing here may reach an npm package or `node:sqlite` at load time: the
 * hook runs on every tool call (`test/unit/hooks/hooksDistImports.test.ts`
 * holds the bundle's inputs to that).
 */

import * as configFile from './hooks/configFile.js';
import * as guardedPath from './hooks/guardedPath.js';

/** Every event: reading the hook configuration, and the paths a write reaches. */
export const loadConfigFile = async (): Promise<typeof configFile> => configFile;
export const loadGuardedPath = async (): Promise<typeof guardedPath> => guardedPath;

/** PreToolUse on Bash / PowerShell: the catastrophic-command guard, then install vetting behind its cheap gate. */
export const loadBashGuard = async () => (await import('./hooksBash.js')).bashGuard;
export const loadInstallGate = async () => (await import('./hooksBash.js')).installGate;
export const loadInstallVetting = async () => (await import('./hooksVet.js')).installVetting;

/** The writes: the secret scan, the Claude Code settings guard and the database registry guard. */
export const loadSecretScan = async () => (await import('./hooksWrite.js')).secretScan;
export const loadSettingsGuard = async () => (await import('./hooksWrite.js')).settingsGuard;
export const loadDataRegistry = async () => (await import('./hooksWrite.js')).dataRegistry;

/** SessionStart: hardened git for the briefing, whether the project's database is registered, and whether the engine bundle is whole. */
export const loadGitSafety = async () => (await import('./hooksSession.js')).gitSafety;
export const loadDbRegistry = async () => (await import('./hooksSession.js')).dbRegistry;
export const loadDistCheck = async () => (await import('./hooksSession.js')).distCheck;
