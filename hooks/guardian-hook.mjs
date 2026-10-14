#!/usr/bin/env node
/**
 * dev-guardian — unified hook dispatcher.
 *
 * One entry point for every guardian hook (declared in hooks/hooks.json).
 * Claude Code passes the hook payload as JSON on stdin; we switch on
 * `hook_event_name` (+ `tool_name`) and emit the documented
 * `hookSpecificOutput` JSON on stdout.
 *
 * Design rules:
 *   - **Dependency-free.** Imports only `node:` builtins plus the pure
 *     detectors in the self-contained bundle `../mcp/dist/hooks.js` (built
 *     from `mcp/src/hooksEntry.ts`; regex only, no native modules). This
 *     guarantees the hook runs in the *installed* plugin, where
 *     `mcp/node_modules` (storage is `node:sqlite`, no native deps — but
 *     still not shipped) is not present.
 *   - **Fail-open.** Any unexpected error → exit 0 with no output. A guardrail
 *     must never break the user's workflow. Set GUARDIAN_HOOKS_DEBUG=1 to see
 *     diagnostics on stderr.
 *   - **Fast.** Scans only the text just written / the command about to run,
 *     never the whole repo. The authoritative full scan stays in
 *     `scan_secrets` (gitleaks) via `/guardian-scan`.
 *   - **Quiet by default, opt-in blocking.** Secrets are *warned* on write;
 *     blocking writes is opt-in. Only catastrophic shell commands are denied
 *     by default. A project's `.guardian/hooks.config.json` may tune the
 *     advisory settings and make the guard stricter, never weaker (see
 *     `projectOverrides`); switching a protective hook off takes the
 *     user-level `~/.config/dev-guardian/hooks.json` or the environment
 *     (`GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0`, `GUARDIAN_PKG_VET=0`).
 */

import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import module from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// compile-cache:begin — the same in hooks/guardian-hook.mjs, cli/dev-guardian.mjs and
// dist/server.js (mcp/scripts/bundleOptions.mjs, SERVER_JS); hooksDispatcher.test.ts holds them equal.
/**
 * Where Node's on-disk compile cache may live: `undefined` for Node's own
 * default, `null` for no cache at all. Never a temp directory that is not
 * there (Node creates the cache's directory with every missing parent, and a
 * TMPDIR that is not there must stay not there). On Windows, Node's default
 * under the account's own `%TEMP%`. Elsewhere, a directory of this account's
 * own in the temp directory, made `0700` and used only when it is a directory
 * this account owns that nobody else can write: in a temp directory every
 * account shares (Linux's `/tmp`), Node's default `node-compile-cache/<version>-<uid>`
 * is used as it is found — another account can create it first, writable,
 * and plant compiled code this process then runs (measured, Node 22.13 and 24).
 *
 * @returns {string | null | undefined}
 */
function compileCacheDir() {
  const tmp = tmpdir();
  if (!existsSync(tmp)) return null;
  if (process.platform === 'win32') return undefined;
  const uid = process.getuid?.() ?? -1;
  const dir = join(tmp, `dev-guardian-node-compile-cache-${uid}`);
  try {
    mkdirSync(dir, { mode: 0o700 });
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code !== 'EEXIST') return null;
  }
  const st = lstatSync(dir);
  return st.isDirectory() && st.uid === uid && (st.mode & 0o077) === 0 ? dir : null;
}
try {
  const dir = compileCacheDir();
  if (dir !== null) module.enableCompileCache?.(dir);
} catch {
  /* no cache: it only runs slower */
}
// compile-cache:end

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/hooks
// The plugin root is derived from this file's own location rather than read
// from CLAUDE_PLUGIN_ROOT: hooks.json launches this file AS
// `${CLAUDE_PLUGIN_ROOT}/hooks/guardian-hook.mjs`, so the two agree whenever
// the variable is set, and this form also works when it is not (a manual run,
// `dev-guardian check`, the e2e tests).
const PLUGIN_ROOT = resolve(HERE, '..'); // <plugin>
const HOOKS_BUNDLE = join(PLUGIN_ROOT, 'mcp', 'dist', 'hooks.js');
const POPULAR_DIR = join(PLUGIN_ROOT, 'configs', 'popular-packages');

const DEBUG = process.env.GUARDIAN_HOOKS_DEBUG === '1';

/**
 * When this hook call started: package vetting's one deadline
 * (`GUARDIAN_PKG_VET_DEADLINE_MS`, 8 s by default) counts from here, so the
 * shell guard's own time comes out of it and the whole call stays well under
 * Claude Code's 15 s timeout (review I4).
 */
const HOOK_STARTED = Date.now();

/**
 * Types — the file is type-checked (`mcp/tsconfig.js.json`, `npm run lint`).
 * The bundle's are its source's: `mcp/dist/hooks.d.ts` re-exports
 * `mcp/src/hooksEntry.ts`'s, so the checker never reads the bundle itself.
 *
 * @typedef {import('../mcp/dist/hooks.js')} HooksBundle
 * @typedef {Exclude<keyof HooksBundle, never>} Loader
 * @typedef {Awaited<ReturnType<HooksBundle['loadConfigFile']>>} ConfigFileModule
 * @typedef {Awaited<ReturnType<HooksBundle['loadGuardedPath']>>} GuardedPathModule
 * @typedef {{ permissionDecision?: 'deny' | 'ask', permissionDecisionReason?: string, additionalContext?: string }} HookAnswer
 * @typedef {{ warn: boolean, block: boolean }} SecretsConfig
 * @typedef {{ block: boolean, warn: boolean }} BashConfig
 * @typedef {{
 *   enabled: boolean,
 *   sessionStart: boolean,
 *   secrets: SecretsConfig,
 *   bash: BashConfig,
 *   ignorePaths: string[],
 *   blockIgnorePaths: string[],
 *   userSecretBlock: boolean,
 *   ignoredProjectSettings: string[],
 *   invalidSettings: string[],
 *   unreadConfigFiles?: string[],
 *   ignoresEverything?: string,
 * }} HookConfig
 * @typedef {{ old_string?: unknown, new_string?: unknown, replace_all?: boolean }} SettingsEdit
 * @typedef {{ old_string: string, new_string: string, replace_all?: boolean }} TextEdit
 * @typedef {{ content: string, edits?: undefined, opaque?: undefined }
 *   | { edits: SettingsEdit[], content?: undefined, opaque?: undefined }
 *   | { opaque: string, content?: undefined, edits?: undefined }} SettingsChange
 *   `opaque`: a change whose result cannot be worked out (a regex replace, an
 *   argument no known key names) — only the call's own strings, joined.
 * @typedef {{
 *   path: string,
 *   text: string,
 *   config: string[],
 *   registry: string[],
 *   settings: Array<{ path: string, change: SettingsChange | null }>,
 *   unread?: string,
 *   fileTool?: boolean,
 *   maybe?: { paths: string[], change: SettingsChange, removes: boolean },
 * }} WriteDescription
 *   `unread`: why part of an MCP tool's arguments was not read; `fileTool`: its name names a file;
 *   `maybe`: a non-file tool's strings that may name a guarded file — asked about, never denied.
 * @typedef {Record<string, unknown>} ToolInput
 */

/** @param {string} msg */
function debug(msg) {
  if (DEBUG) process.stderr.write(`[guardian-hook] ${msg}\n`);
}

/**
 * Emit hookSpecificOutput JSON and exit 0.
 *
 * @param {string} eventName
 * @param {HookAnswer} extra
 * @returns {never}
 */
function emit(eventName, extra) {
  process.stdout.write(
    JSON.stringify({ hookSpecificOutput: { hookEventName: eventName, ...extra } }),
  );
  process.exit(0);
}

/**
 * Exit cleanly with no output (no-op / fail-open).
 *
 * @returns {never}
 */
function noop() {
  process.exit(0);
}

/**
 * `emit()` for any path that may have used the network: write the answer
 * (if any) and let the process end ON ITS OWN rather than through
 * `process.exit()`. Measured on Windows (Node 24): calling `process.exit()`
 * after a `fetch()` to a real registry aborts the process with
 * `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file
 * src\win\async.c` and exit code 127, every time — and a hook that exits
 * non-zero has its JSON ignored, so every package-vetting DENY would have
 * been silently dropped. Idle fetch sockets are unref'd, so the natural exit
 * is immediate; the unref'd timer is only a backstop in case something else
 * still holds the loop open — and even then it waits for the answer to have
 * been flushed to stdout (the write callback) before it exits, so the
 * backstop can never cut off the JSON it exists to deliver.
 *
 * The backstop runs {@link EXIT_GRACE_MS} after the answer was flushed, not 5 s
 * after the call (review 8, item 4): a connect the 3 s network budget aborted
 * on an unresponsive network still holds the loop, and Claude Code waits for
 * the process — the answer came at 3.2 s and the process ended at 8.2 s.
 * Measured with the grace at 250 ms: exit 0 at 3.5 s, no libuv assertion, and
 * a real-registry deny still exits 0.
 */
const EXIT_GRACE_MS = 250;

/**
 * @param {string} eventName
 * @param {HookAnswer | undefined} extra
 */
function respond(eventName, extra) {
  process.exitCode = 0;
  const backstop = () => setTimeout(() => process.exit(0), EXIT_GRACE_MS).unref();
  if (extra) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: eventName, ...extra } }), backstop);
  } else backstop();
}

/** @returns {Promise<Record<string, unknown>>} the payload, or `{}` when there is none or it is not a JSON object */
async function readStdin() {
  /** @type {Buffer[]} */
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try {
    const payload = JSON.parse(raw);
    return isPlainObject(payload) ? payload : {};
  } catch {
    return {};
  }
}

/**
 * The detectors' bundle, `mcp/dist/hooks.js` (`mcp/src/hooksEntry.ts`),
 * imported once per call. Each detector module is behind one of its `load*`
 * functions, which the bundle keeps lazy: an event evaluates only what it
 * uses (review 8, item 17). `pathToFileURL`, never `file://${…}` by
 * concatenation: a `#` in the install path read as a URL fragment, the import
 * failed, and the shell guard and the secret scan failed open (review M2). A
 * missing or damaged bundle rejects every {@link detector} call: each guard
 * then fails open, and SessionStart names the ones that are off.
 */
/** @type {Promise<HooksBundle> | undefined} */
let hooksBundle;

/**
 * The exports of one detector module, by its loader in the bundle (`loadBashGuard`, …).
 *
 * @template {Loader} L
 * @param {L} loader
 * @returns {Promise<Awaited<ReturnType<HooksBundle[L]>>>}
 */
async function detector(loader) {
  hooksBundle ??= import(pathToFileURL(HOOKS_BUNDLE).href);
  const bundle = await hooksBundle;
  const load = bundle[loader];
  if (typeof load !== 'function') throw new Error(`${loader} is missing from mcp/dist/hooks.js`);
  return /** @type {Promise<Awaited<ReturnType<HooksBundle[L]>>>} */ (load());
}

/**
 * How a hook configuration file is read: `readSmallJsonFile` from
 * `mcp/src/hooks/configFile.ts` (in the bundle), loaded in `main()` by `loadConfigReader`.
 * Given the directory the file lives under (the project, or the home
 * directory for the user-level file), it first walks the path's components
 * below it with `lstat` + `readlink` — never touching a link's target — and
 * refuses a file reached through a link to a UNC or device path, whose open
 * can wait minutes on the network. It then opens the path (a link is
 * followed; non-blocking on POSIX, so a FIFO opens at once), judges what it
 * OPENED with `fstat`, and reads only a regular file of at most 64 KiB, with
 * a leading byte-order mark stripped. The `existsSync` + `readFileSync` it
 * replaced read whatever was there: a FIFO or a link to `/dev/zero` at
 * `.guardian/hooks.config.json` blocked the hook until Claude Code killed it
 * at 15 s — and the tool call then ran unguarded (Task 23 fix round 2, N1).
 * Until it is loaded, and if it cannot be (no built `mcp/dist/hooks.js`),
 * every file reads as absent: the protective defaults.
 */
/** @type {ConfigFileModule['readSmallJsonFile']} */
let readSmallJsonFile = () => ({ status: 'absent' });
/**
 * `walkLinksUnder` from the same module — see `handleSessionStart`.
 *
 * @type {ConfigFileModule['walkLinksUnder']}
 */
let walkLinksUnder = () => ({ ok: true });
/**
 * `readSmallTextFile` from the same module — see `claudeSettingsWriteGuard`.
 *
 * @type {ConfigFileModule['readSmallTextFile']}
 */
let readSmallTextFile = () => undefined;
/**
 * `guardedPath` from `mcp/src/hooks/guardedPath.ts`: the file a write really
 * reaches — on Windows without an NTFS stream suffix or trailing dots and
 * spaces, and everywhere resolved through 8.3 names and links (review M1).
 * Until it is loaded, a path is taken as written.
 *
 * @type {GuardedPathModule['guardedPath']}
 */
let guardedPath = (p) => p;
/**
 * `hardLinkedTo` from the same module: which guarded file a path is a hard link to (review round 3, item 5).
 *
 * @type {GuardedPathModule['hardLinkedTo']}
 */
let hardLinkedTo = () => undefined;
/**
 * `isNetworkPath` from the same module: a path on the network or a device,
 * which no guard asks the filesystem about (review 8, item 13). Until it is
 * loaded, a `\\…` or `//…` path is one.
 *
 * @type {ConfigFileModule['isNetworkPath']}
 */
let isNetworkPath = (p) => /^[\\/]{2}/.test(String(p));
/**
 * `writesRegistry` from `mcp/src/hooks/dataRegistry.ts`: whether a write
 * reaches dev-guardian's registry of trusted databases (review 3.0 wave 2,
 * round 2). Loaded by the write guards only ({@link loadRegistryGuard}); until
 * it is, and if it cannot be, nothing does (fail-open, and SessionStart says
 * the guard is off).
 *
 * @type {(abs: string) => boolean}
 */
let writesRegistry = () => false;

/**
 * What every event needs: the configuration reader and the path resolution
 * the project root is found with. The guards themselves are imported by the
 * event that uses them, and only then (review 8, item 17).
 */
async function loadConfigReader() {
  try {
    const mod = await detector('loadConfigFile');
    if (typeof mod.readSmallJsonFile === 'function') readSmallJsonFile = mod.readSmallJsonFile;
    if (typeof mod.walkLinksUnder === 'function') walkLinksUnder = mod.walkLinksUnder;
    if (typeof mod.readSmallTextFile === 'function') readSmallTextFile = mod.readSmallTextFile;
    if (typeof mod.isNetworkPath === 'function') isNetworkPath = mod.isNetworkPath;
    const paths = await detector('loadGuardedPath');
    if (typeof paths.guardedPath === 'function') guardedPath = paths.guardedPath;
    if (typeof paths.hardLinkedTo === 'function') hardLinkedTo = paths.hardLinkedTo;
  } catch (err) {
    debug(`config reader unavailable — protective defaults: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function loadRegistryGuard() {
  try {
    const registry = await detector('loadDataRegistry');
    if (typeof registry.writesRegistry === 'function') writesRegistry = registry.writesRegistry;
  } catch (err) {
    debug(`registry guard unavailable (fail-open): ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * `databaseRegistration` from `mcp/src/storage/dbRegistry.ts`: whether a
 * project's `.guardian/guardian.db` is registered as the user's, read from
 * the user's own registry — the database itself is never opened here. Loaded
 * for SessionStart only; until then, and if it cannot be, `unknown` (no line).
 *
 * @type {(dbPath: string) => 'registered' | 'unregistered' | 'none' | 'unknown'}
 */
let databaseRegistration = () => 'unknown';

async function loadRegistryReader() {
  try {
    const mod = await detector('loadDbRegistry');
    if (typeof mod.databaseRegistration === 'function') databaseRegistration = mod.databaseRegistration;
  } catch (err) {
    debug(`registry reader unavailable: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** @type {Readonly<Record<string, string>>} */
const UNREAD_REASON = {
  'not-a-regular-file': 'not a regular file',
  'too-large': 'larger than 64 KiB',
  unreadable: 'unreadable',
  'remote-link': 'reached through a link to a network or device path',
};

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * The parsed JSON at `path`, or `undefined`. When `label` is given, a file
 * that exists but was refused or is not JSON is recorded in `unread`, which
 * SessionStart reports. `under` is the directory whose components below it
 * are checked for a network link first (see `readSmallJsonFile` above).
 *
 * @param {string} path
 * @param {string} label
 * @param {string[]} unread
 * @param {string} under
 * @returns {unknown}
 */
function readJsonFile(path, label, unread, under) {
  const r = readSmallJsonFile(path, undefined, under);
  if (r.status === 'ok') return r.value;
  if (r.status === 'refused') unread.push(`${label} was not read (${UNREAD_REASON[r.reason] ?? r.reason})`);
  else if (r.status === 'invalid') unread.push(`${label} was ignored (not valid JSON)`);
  return undefined;
}

/** @type {Readonly<Omit<HookConfig, 'blockIgnorePaths' | 'userSecretBlock' | 'ignoredProjectSettings' | 'invalidSettings'>>} */
const DEFAULT_CONFIG = {
  enabled: true,
  sessionStart: true,
  secrets: { warn: true, block: false },
  bash: { block: true, warn: true },
  // Path substrings whose edits are never secret-scanned, matched against the
  // path made RELATIVE TO THE PROJECT (see `isIgnoredPath` below) — never the
  // raw absolute path. `/hooks/` used to be a member of this same list and
  // matched anywhere in the absolute path, which silently skipped every
  // React `src/hooks/` directory (and anything under any ancestor directory
  // that merely happened to be named "hooks") in every project this hook
  // ever ran in. The plugin's OWN `hooks/` directory is skipped separately
  // now, by absolute prefix — see `isPluginOwnFile`.
  ignorePaths: ['/test/fixtures/', 'eval-vuln-fixture', '/.guardian/', '__fixtures__'],
};

/** `~/.config/dev-guardian/hooks.json` — see `loadConfig`'s own doc. */
function userConfigPath() {
  return join(homedir(), '.config', 'dev-guardian', 'hooks.json');
}

/**
 * The settings a configuration file may give, each only when it has the type
 * the hooks read it as — a boolean, or a list of strings for `ignorePaths`.
 *
 * @typedef {{
 *   enabled?: boolean,
 *   sessionStart?: boolean,
 *   secrets: Partial<SecretsConfig>,
 *   bash: Partial<BashConfig>,
 *   ignorePaths?: string[],
 * }} FileSettings
 */

/**
 * A configuration file's settings, read by type: a value of another type is
 * left out and named in `invalid`. The user-level file was merged in as it
 * was (review of 3.4.0's type check): `"ignorePaths": "/"` made every write's
 * `ignorePaths.some` throw, and the hook — failing open — said nothing of a
 * secret just written; `"enabled": "no"` was a truthy string.
 *
 * @param {Record<string, unknown>} file
 * @param {string[]} invalid the keys left out, as `"bash.block"`
 * @returns {FileSettings}
 */
function settingsOf(file, invalid) {
  /** @type {FileSettings} */
  const out = { secrets: {}, bash: {} };
  /**
   * @param {unknown} value
   * @param {string} key
   * @returns {boolean | undefined}
   */
  const bool = (value, key) => {
    if (value === undefined) return undefined;
    if (typeof value === 'boolean') return value;
    invalid.push(`"${key}"`);
    return undefined;
  };
  /**
   * @param {unknown} value
   * @param {string} key
   * @returns {Record<string, unknown>}
   */
  const section = (value, key) => {
    if (value === undefined || isPlainObject(value)) return value ?? {};
    invalid.push(`"${key}"`);
    return {};
  };
  const enabled = bool(file['enabled'], 'enabled');
  if (enabled !== undefined) out.enabled = enabled;
  const sessionStart = bool(file['sessionStart'], 'sessionStart');
  if (sessionStart !== undefined) out.sessionStart = sessionStart;
  const secrets = section(file['secrets'], 'secrets');
  const warn = bool(secrets['warn'], 'secrets.warn');
  if (warn !== undefined) out.secrets.warn = warn;
  const block = bool(secrets['block'], 'secrets.block');
  if (block !== undefined) out.secrets.block = block;
  const bash = section(file['bash'], 'bash');
  const bashBlock = bool(bash['block'], 'bash.block');
  if (bashBlock !== undefined) out.bash.block = bashBlock;
  const bashWarn = bool(bash['warn'], 'bash.warn');
  if (bashWarn !== undefined) out.bash.warn = bashWarn;
  const ignorePaths = file['ignorePaths'];
  if (Array.isArray(ignorePaths) && ignorePaths.every((p) => typeof p === 'string')) out.ignorePaths = ignorePaths;
  else if (ignorePaths !== undefined) invalid.push('"ignorePaths"');
  return out;
}

/**
 * Project config (`.guardian/hooks.config.json`) may only make the protective
 * hooks STRICTER, never weaker. A project file is something the assistant
 * itself can write — the Write/Edit guard below refuses it, and the shell
 * guard refuses the shell writes it can see, but a program that writes it by
 * its own means (a script run from disk, a path assembled at run time) is seen
 * by neither — so every setting that could switch a protective hook off is
 * ignored when it comes from there. The earlier version stripped only `"bash":{"block":false}`, and
 * `{"enabled": false}` in the same file still switched off the shell guard,
 * install vetting and the config write guard, even over
 * `GUARDIAN_HOOKS_BASH_BLOCK=1` (Task 23 fix round 1, C1).
 *
 * What a project file may set, by construction (an allowlist, so a key added
 * later is ignored until someone decides which side it is on):
 *   - `enabled: true`, `bash.block: true`, `bash.warn: true` — stricter or
 *     equal; the `false` forms are ignored and reported;
 *   - `secrets.block` — opt-in blocking, only ever stricter than the default;
 *   - `secrets.warn`, `sessionStart`, `ignorePaths` — advisory: they decide
 *     what the model is told, never what it is allowed to run.
 * There is no project-level switch for install vetting at all.
 *
 * Switching a protective hook off takes a person, outside the project: the
 * user-level config (`~/.config/dev-guardian/hooks.json`, whose keys win over
 * the project's), `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0` or
 * `GUARDIAN_PKG_VET=0`. Each ignored setting gets a debug-only stderr note
 * here, and SessionStart tells the model, once, that it was ignored.
 *
 * @param {FileSettings} project the project file's settings ({@link settingsOf})
 * @returns {{ overrides: FileSettings, ignored: string[] }}
 */
function projectOverrides(project) {
  /** @type {FileSettings} */
  const out = { secrets: { ...project.secrets }, bash: {} };
  /** @type {string[]} */
  const ignored = [];
  /**
   * @param {string} label
   * @param {string} debugLabel
   */
  const ignore = (label, debugLabel) => {
    ignored.push(label);
    debug(
      `ignoring ${debugLabel} from .guardian/hooks.config.json — a project file may not ` +
        'loosen the guardrails. Use the user-level config (~/.config/dev-guardian/hooks.json), ' +
        'GUARDIAN_HOOKS=off or GUARDIAN_HOOKS_BASH_BLOCK=0 instead.',
    );
  };

  if (project.enabled === false) ignore('"enabled": false', '"enabled":false');
  else if (project.enabled === true) out.enabled = true;

  if (project.bash.block === false) ignore('"bash.block": false', '"bash":{"block":false}');
  else if (project.bash.block === true) out.bash.block = true;
  if (project.bash.warn === false) ignore('"bash.warn": false', '"bash":{"warn":false}');
  else if (project.bash.warn === true) out.bash.warn = true;

  if (project.sessionStart !== undefined) out.sessionStart = project.sessionStart;
  if (project.ignorePaths !== undefined) out.ignorePaths = project.ignorePaths;

  return { overrides: out, ignored };
}

/**
 * @param {string} root
 * @param {string[]} unread files that could not be read, for SessionStart
 * @returns {HookConfig}
 */
function loadConfig(root, unread) {
  const projectRaw = readJsonFile(join(root, '.guardian', 'hooks.config.json'), '.guardian/hooks.config.json', unread, root);
  const userRaw = readJsonFile(userConfigPath(), '~/.config/dev-guardian/hooks.json', unread, homedir());
  /** @type {string[]} */
  const projectInvalid = [];
  /** @type {string[]} */
  const userInvalid = [];
  const projectFile = settingsOf(isPlainObject(projectRaw) ? projectRaw : {}, projectInvalid);
  const user = settingsOf(isPlainObject(userRaw) ? userRaw : {}, userInvalid);
  /** @type {string[]} */
  const invalidSettings = [];
  /**
   * @param {string} file
   * @param {string[]} keys
   */
  const named = (file, keys) => {
    if (keys.length > 0) invalidSettings.push(`in ${file}, ${keys.join(', ')} ${keys.length === 1 ? 'was' : 'were'} ignored (not of the type the hooks read)`);
  };
  named('.guardian/hooks.config.json', projectInvalid);
  named('~/.config/dev-guardian/hooks.json', userInvalid);
  const { overrides: project, ignored } = projectOverrides(projectFile);
  const userSecretBlock = user.secrets.block === true;

  /** @type {HookConfig} */
  const merged = {
    enabled: user.enabled ?? project.enabled ?? DEFAULT_CONFIG.enabled,
    sessionStart: user.sessionStart ?? project.sessionStart ?? DEFAULT_CONFIG.sessionStart,
    secrets: { ...DEFAULT_CONFIG.secrets, ...project.secrets, ...user.secrets },
    bash: { ...DEFAULT_CONFIG.bash, ...project.bash, ...user.bash },
    ignorePaths: user.ignorePaths ?? project.ignorePaths ?? DEFAULT_CONFIG.ignorePaths,
    // The paths the opt-in secret BLOCK skips. A project's `ignorePaths` is
    // advisory — it narrows the warning — and once also exempted paths from a
    // block the USER had enabled: `"ignorePaths": ["/"]` in a project file
    // switched that block off (final review M4). A user-enabled block now
    // honours only the user's own list, or the defaults; a block the project
    // itself enabled may still be narrowed by the same project's list.
    blockIgnorePaths: user.ignorePaths ?? (userSecretBlock ? DEFAULT_CONFIG.ignorePaths : (project.ignorePaths ?? DEFAULT_CONFIG.ignorePaths)),
    // The same rule for the project's `.guardian/hooks-allowlist.json`: it
    // silences the warning, but a block the USER enabled ignores it — `["AKIA"]`
    // there used to exempt every AWS key from that block (follow-up Part Y).
    // There is no user-level allowlist; a user-enabled block has none.
    userSecretBlock,
    ignoredProjectSettings: ignored,
    invalidSettings,
  };

  // Highest precedence: an explicit env var, checked last so it always wins.
  const envBlock = process.env.GUARDIAN_HOOKS_BASH_BLOCK;
  if (envBlock === '0' || envBlock === 'false') merged.bash.block = false;
  else if (envBlock === '1' || envBlock === 'true') merged.bash.block = true;

  // An `ignorePaths` entry (nearly) every path holds — `""`, `"/"`, which
  // begins every project-relative path, or `"."`, in every name with an
  // extension (review 12, finding 17) — silences the secret warnings, and the
  // model heard nothing of it (review of 3.4.0, plausible): SessionStart says so.
  const everything = merged.ignorePaths.filter((f) => f === '' || f === '/' || f === '.');
  if (everything.length > 0) {
    const from = user.ignorePaths !== undefined ? '~/.config/dev-guardian/hooks.json' : '.guardian/hooks.config.json';
    merged.ignoresEverything = `in ${from}, "ignorePaths" holds ${everything.map((f) => JSON.stringify(f)).join(' and ')}`;
  }

  return merged;
}

/**
 * @param {string} root
 * @param {string[]} unread
 * @returns {string[]}
 */
function loadAllowlist(root, unread) {
  const data = readJsonFile(join(root, '.guardian', 'hooks-allowlist.json'), '.guardian/hooks-allowlist.json', unread, root);
  /** @param {unknown[]} list */
  const strings = (list) => list.filter((x) => typeof x === 'string');
  if (Array.isArray(data)) return strings(data);
  if (isPlainObject(data) && Array.isArray(data['secrets'])) return strings(data['secrets']);
  return [];
}

/**
 * The plugin's version, from its own `plugin.json`, read directly: through the
 * configuration reader — which lives in the hooks bundle — a damaged bundle
 * made SessionStart say `v0.0.0` (review of 3.3.0).
 */
function pluginVersion() {
  try {
    const pj = JSON.parse(readFileSync(join(PLUGIN_ROOT, '.claude-plugin', 'plugin.json'), 'utf8'));
    return typeof pj?.version === 'string' ? pj.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

/** @param {number} ms */
function relativeTime(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `~${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `~${h}h ago`;
  const d = Math.floor(h / 24);
  return `~${d}d ago`;
}

/**
 * `git` in `cwd` through `execGit` from `mcp/src/platform/gitSafety.ts`: git
 * hardened against the project's own git configuration (review 3.0, W2E-git).
 * SessionStart's `git status` in a project opened for the first time — an
 * archive, a download — used to run that project's `core.fsmonitor` and
 * `post-index-change` hook. Its stdout, trimmed, or `''` when git did not
 * succeed. If the hardening cannot be loaded, no git runs at all: the
 * briefing loses its branch line, never its safety. Asynchronous (3.4.0), so
 * that its processes — the configuration read and the submodule listing side
 * by side, then the command — run while the guards' modules load.
 *
 * @param {string} cwd
 * @param {string[]} args
 * @returns {Promise<string>}
 */
async function git(cwd, args) {
  try {
    const mod = await detector('loadGitSafety');
    if (typeof mod.execGit !== 'function') return '';
    const r = await mod.execGit(cwd, args, { timeoutMs: 2000 });
    return r.failure === null && r.status === 0 ? r.stdout.trim() : '';
  } catch (err) {
    debug(`git hardening unavailable — git not run: ${err instanceof Error ? err.message : String(err)}`);
    return '';
  }
}

/**
 * Whether git can find a repository for `dir`: a `.git` at it or above it
 * (`lstat` only — a `.git` linked to a share is never opened), or the
 * environment naming one (`GIT_DIR`, `GIT_WORK_TREE`). Where there is none,
 * `git status` fails anyway: SessionStart starts no git process for nothing
 * (3.4.0 — three of them, about 190 ms on Windows, in every folder that is not
 * a repository).
 *
 * @param {string} dir
 */
function inGitRepository(dir) {
  if (process.env.GIT_DIR || process.env.GIT_WORK_TREE) return true;
  let at = resolve(dir);
  for (let i = 0; i < 256; i += 1) {
    if (presentNoFollow(join(at, '.git'))) return true;
    const parent = dirname(at);
    if (parent === at) return false;
    at = parent;
  }
  return true;
}

/**
 * Text inserted by a Write/Edit/MultiEdit/NotebookEdit tool call.
 *
 * @param {string} toolName
 * @param {ToolInput} input
 * @returns {string}
 */
function extractInsertedText(toolName, input) {
  /** @param {unknown} v */
  const text = (v) => (typeof v === 'string' ? v : '');
  switch (toolName) {
    case 'Write':
      return text(input['content']);
    case 'Edit':
      return text(input['new_string']);
    case 'MultiEdit': {
      const edits = input['edits'];
      return Array.isArray(edits) ? edits.map((e) => (isPlainObject(e) ? text(e['new_string']) : '')).join('\n') : '';
    }
    case 'NotebookEdit':
      return text(input['new_source']);
    default:
      return '';
  }
}

/** @param {unknown} p */
function normalizePath(p) {
  return String(p ?? '').replace(/\\/g, '/');
}

/**
 * Path substring matching, scoped to THE PROJECT rather than the raw
 * absolute path — see `DEFAULT_CONFIG.ignorePaths`'s own doc for why. A path
 * outside `cwd` (relative resolves to something starting with `..`) is left
 * as its normalized absolute form, which cfg.ignorePaths fragments (all
 * project-relative, like `/test/fixtures/`) will not match — this only
 * matters for the plugin's own files, and those are covered separately by
 * `isPluginOwnFile`, not by this function.
 *
 * @param {string} absolutePath
 * @param {string} root
 * @param {readonly string[]} ignorePaths
 */
function isIgnoredPath(absolutePath, root, ignorePaths) {
  if (!absolutePath) return false;
  const rel = normalizePath(relative(root, absolutePath));
  const withLeadingSlash = climbsOut(rel) || isAbsolute(rel) ? normalizePath(absolutePath) : `/${rel}`;
  return ignorePaths.some((frag) => withLeadingSlash.includes(frag));
}

/**
 * The plugin's OWN installation directory, matched by absolute prefix —
 * never a substring like the old `/hooks/` entry, which matched any
 * ancestor directory anywhere named "hooks" (a React `src/hooks/`, or a
 * project simply cloned under a directory called `hooks`) in every project.
 * Hardcoded, not part of `ignorePaths`: this is not something a project or
 * user config should be able to widen or narrow.
 *
 * @param {string} absolutePath
 */
function isPluginOwnFile(absolutePath) {
  if (!absolutePath) return false;
  const abs = normalizePath(resolve(absolutePath));
  const root = normalizePath(PLUGIN_ROOT);
  return abs === root || abs.startsWith(`${root}/`);
}

/**
 * Path-equality for the two files this hook refuses to let an assistant
 * write to (see `isGuardianOwnConfigFile`). Windows paths are
 * case-insensitive and this repo's own path has a space in it
 * (`CLAUDE SKILLS`), so this compares normalized, lower-cased absolute forms
 * rather than doing anything fancier.
 *
 * @param {string} a
 * @param {string} b
 */
function samePath(a, b) {
  return normalizePath(resolve(a)).toLowerCase() === normalizePath(resolve(b)).toLowerCase();
}

/**
 * The guard's own configuration: a project `.guardian/hooks*.json` (covers
 * `hooks.config.json` and `hooks-allowlist.json` alike — the allowlist can
 * silence a real secret warning just as effectively as downgrading `block`)
 * and the user-level `~/.config/dev-guardian/hooks.json`. An assistant
 * writing to either is exactly the loophole item 6 exists to close: closing
 * the wording of the deny message (see `handlePreToolUseBash`) does nothing
 * if the model can just edit the file directly instead of being told how.
 *
 * A project file matches by its absolute path, at any depth under the project
 * root or the cwd (review I5) — not only as `.guardian/hooks*.json` relative
 * to the cwd, which a session in a subdirectory stepped around.
 *
 * @param {string} filePath
 * @param {string} cwd
 * @param {string} root
 */
function isGuardianOwnConfigFile(filePath, cwd, root) {
  if (!filePath) return false;
  // Both sides as the filesystem spells them: a stream suffix, trailing dots
  // or an 8.3 name on the written path (review M1), and a link or a short name
  // in the home or project path, must not make the same file compare unequal.
  const abs = guardedPath(resolve(cwd, filePath));
  if (samePath(abs, guardedPath(userConfigPath()))) return true;
  const projectConfig = /(?:^|\/)\.guardian\/hooks[^/]*\.json$/i.test(normalizePath(abs));
  if (projectConfig) {
    if (isBelow(guardedPath(resolve(root)), abs) || isBelow(guardedPath(resolve(cwd)), abs)) return true;
  }
  // A network path is never resolved, and a share may lead back to this
  // machine by any name: its tail decides (review 8, item 19). An admin share
  // of this machine was mapped to its local path by `guardedPath` already.
  if (isNetworkPath(abs)) return projectConfig || /(?:^|\/)\.config\/dev-guardian\/hooks\.json$/i.test(normalizePath(abs));
  // A HARD link to one of them is the same file under another name, which no
  // path comparison sees (review round 3, item 5): compared by device + inode.
  const guarded = [userConfigPath()];
  for (const dir of new Set([resolve(root), resolve(cwd)])) {
    guarded.push(join(dir, '.guardian', 'hooks.config.json'), join(dir, '.guardian', 'hooks-allowlist.json'));
  }
  return hardLinkedTo(abs, guarded) !== undefined;
}

/**
 * Claude Code's managed settings on this platform — they win over every other
 * settings file (review 12, finding 7).
 */
function managedSettingsFiles() {
  if (process.platform === 'win32') {
    const programFiles = process.env.ProgramFiles ?? 'C:\\Program Files';
    const programData = process.env.ProgramData ?? 'C:\\ProgramData';
    return [join(programFiles, 'ClaudeCode', 'managed-settings.json'), join(programData, 'ClaudeCode', 'managed-settings.json')];
  }
  if (process.platform === 'darwin') return ['/Library/Application Support/ClaudeCode/managed-settings.json'];
  return ['/etc/claude-code/managed-settings.json'];
}

/**
 * Claude Code's settings files a Write could be a hard link to: the project's,
 * the user's (`~/.claude`), `CLAUDE_CONFIG_DIR`'s and the managed ones.
 *
 * @param {string} root
 */
function claudeSettingsFiles(root) {
  const dirs = [join(resolve(root), '.claude'), join(homedir(), '.claude')];
  if (process.env.CLAUDE_CONFIG_DIR) dirs.push(resolve(process.env.CLAUDE_CONFIG_DIR));
  return [...dirs.flatMap((d) => [join(d, 'settings.json'), join(d, 'settings.local.json')]), ...managedSettingsFiles()];
}

/**
 * Whether a `path.relative()` result climbs out of its directory: `..` or `..` and a separator, never
 * a name that starts with two dots (`..x`) — the same as `climbsOut` in `mcp/src/hooks/configFile.ts`.
 *
 * @param {string} rel
 */
function climbsOut(rel) {
  return rel === '..' || rel.startsWith('../') || rel.startsWith('..\\');
}

/**
 * `path` lies strictly below `dir`.
 *
 * @param {string} dir
 * @param {string} path
 */
function isBelow(dir, path) {
  const rel = relative(dir, path);
  return rel !== '' && !climbsOut(rel) && !isAbsolute(rel);
}

/**
 * Whether `path` exists, without following a link at it (`.git` linked to a share must not be opened).
 *
 * @param {string} path
 */
function presentNoFollow(path) {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * The project this hook call belongs to (review I5): `CLAUDE_PROJECT_DIR`,
 * which Claude Code sets for every hook, when it names a directory; else the
 * nearest ancestor of `cwd` holding `.guardian` or `.git`; else `cwd`. The
 * payload's `cwd` is wherever the session has `cd`-ed to — reading the
 * project's configuration from there, and guarding its hook configuration
 * relative to it, let `Write <proj>/.guardian/hooks-allowlist.json` through
 * from `<proj>/packages/api`, and switched a project-enabled `secrets.block`
 * off there.
 *
 * @param {string} cwd
 */
function projectRootOf(cwd) {
  const fromEnv = process.env.CLAUDE_PROJECT_DIR;
  if (fromEnv && existsSync(fromEnv)) return resolve(fromEnv);
  // Never the home directory or an ancestor of it, nor the temp dir itself
  // (review round 2): a stray `.guardian` there — this machine has one in
  // each — made every unmarked project below it take its configuration from
  // there. Compared as the filesystem spells them (8.3 names: %TEMP% is
  // often `C:\Users\ADMINI~1\…`).
  // Resolved only for a directory that has a marker (3.4.0): each is a
  // `realpath` and an 8.3 lookup, and a walk from a deep cwd with no marker
  // above it paid them at every level.
  /** @type {string | undefined} */
  let home;
  /** @type {string | undefined} */
  let temp;
  /** @param {string} dir */
  const excluded = (dir) => {
    home ??= guardedPath(resolve(homedir()));
    temp ??= guardedPath(resolve(tmpdir()));
    const d = guardedPath(dir);
    return samePath(d, home) || isBelow(d, home) || samePath(d, temp);
  };
  let dir = resolve(cwd);
  for (let i = 0; i < 256; i += 1) {
    if ((presentNoFollow(join(dir, '.guardian')) || presentNoFollow(join(dir, '.git'))) && !excluded(dir)) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(cwd);
}

/*
 * The detectors, each imported by the event that uses it and no other (review
 * 8, item 17: every Bash call loaded the secret scan, every write the 220 KB
 * shell guard). Through the bundle's loaders, so a missing/un-built dist
 * fails open rather than throwing at module load.
 */
async function loadSecretScan() {
  return (await detector('loadSecretScan')).scanForSecrets;
}

async function loadBashGuard() {
  return (await detector('loadBashGuard')).assessBashCommand;
}

/**
 * The guards the hooks load from the bundle, by loader, and what each one is called in a notice.
 *
 * @type {ReadonlyArray<{ loader: Loader, name: string, export: string }>}
 */
const GUARD_MODULES = [
  { loader: 'loadBashGuard', name: 'the shell guard', export: 'assessBashCommand' },
  { loader: 'loadSecretScan', name: 'the secret scan', export: 'scanForSecrets' },
  { loader: 'loadInstallVetting', name: 'package vetting', export: 'decideInstallCommand' },
  { loader: 'loadSettingsGuard', name: "the Claude Code settings guard", export: 'newlyLoosened' },
  { loader: 'loadDataRegistry', name: 'the database registry guard', export: 'writesRegistry' },
];

/**
 * SessionStart's check that every guard can actually run (review M2): each
 * one fails open when its module cannot be loaded, and until now the briefing
 * said "active" all the same. `null` when all load.
 *
 * @returns {Promise<string | null>}
 */
async function unloadableGuardsNotice() {
  /** @type {string[]} */
  const broken = [];
  let reason = '';
  const loaded = await Promise.allSettled(
    GUARD_MODULES.map(async (g) => {
      const mod = /** @type {Record<string, unknown>} */ (await detector(g.loader));
      if (typeof mod[g.export] !== 'function') throw new Error(`${g.export} missing`);
    }),
  );
  loaded.forEach((r, k) => {
    if (r.status === 'fulfilled') return;
    broken.push(GUARD_MODULES[k]?.name ?? 'a guard');
    /** @type {unknown} */
    const err = r.reason;
    reason = reason || (err instanceof Error ? (/** @type {NodeJS.ErrnoException} */ (err).code ?? err.message) : String(err));
  });
  if (broken.length === 0) return null;
  const list = broken.length === 1 ? broken[0] : `${broken.slice(0, -1).join(', ')} and ${broken[broken.length - 1]}`;
  return (
    `⚠️ dev-guardian: ${list} could not be loaded (${reason}) — ${broken.length === 1 ? 'it is' : 'they are'} OFF for this ` +
    `session (fail-open): nothing is checked by ${broken.length === 1 ? 'it' : 'them'}. The plugin's mcp/dist is missing or ` +
    'damaged; ask the user to reinstall or rebuild it.'
  );
}

/**
 * SessionStart's own checks, in the session part (`mcp/dist/hooksSession.js`):
 * the hardened git of the branch line, whether the project's database is
 * registered, and the engine's checksum. With that part damaged, the briefing
 * said "active" and dropped all three without a word (review of 3.4.0,
 * finding 12). `null` when it loads.
 *
 * @returns {Promise<string | null>}
 */
async function sessionPartNotice() {
  /** @type {ReadonlyArray<{ loader: Loader, export: string }>} */
  const parts = [
    { loader: 'loadGitSafety', export: 'execGit' },
    { loader: 'loadDbRegistry', export: 'databaseRegistration' },
    { loader: 'loadDistCheck', export: 'engineDamage' },
  ];
  const loaded = await Promise.allSettled(
    parts.map(async (p) => {
      const mod = /** @type {Record<string, unknown>} */ (await detector(p.loader));
      if (typeof mod[p.export] !== 'function') throw new Error(`${p.export} missing`);
    }),
  );
  const failed = loaded.find((r) => r.status === 'rejected');
  if (failed === undefined) return null;
  /** @type {unknown} */
  const err = failed.reason;
  const reason = err instanceof Error ? (/** @type {NodeJS.ErrnoException} */ (err).code ?? err.message) : String(err);
  return (
    `⚠️ dev-guardian: its session checks (mcp/dist/hooksSession.js) could not be loaded (${reason}) — this briefing has ` +
    'no branch line, no check that the project database is registered and no check of the engine bundle. The ' +
    "guardrails are not affected. The plugin's mcp/dist is damaged; ask the user to reinstall or rebuild it."
  );
}

// ─────────────────────────────── handlers ──────────────────────────────────

/**
 * The one place the model hears that a project file tried to loosen the
 * guardrails (see `projectOverrides`). Deliberately does not say how to switch
 * them off — the same rule as every deny message.
 *
 * @param {HookConfig} cfg
 * @returns {string | null}
 */
function ignoredSettingsNotice(cfg) {
  /** @type {string[]} */
  const lines = [];
  const ignored = cfg.ignoredProjectSettings;
  if (ignored.length > 0) {
    lines.push(
      `⚠️ .guardian/hooks.config.json asks to relax the guardrails (${ignored.join(', ')}) — ` +
        'ignored: a project file may only make them stricter. If this is intended, ask the user.',
    );
  }
  const unread = cfg.unreadConfigFiles ?? [];
  if (unread.length > 0) {
    lines.push(
      `⚠️ dev-guardian: ${unread.join('; ')} — none of its settings apply, and the guardrails keep their ` +
        'protective defaults.',
    );
  }
  if (cfg.invalidSettings.length > 0) {
    lines.push(`⚠️ dev-guardian: ${cfg.invalidSettings.join('; ')} — the default applies to each.`);
  }
  if (cfg.ignoresEverything !== undefined) {
    lines.push(
      `⚠️ dev-guardian: ${cfg.ignoresEverything}, which every path (or nearly every one) matches — a secret written ` +
        'to such a file is not warned about in this session.',
    );
  }
  return lines.length > 0 ? lines.join('\n') : null;
}

/**
 * SessionStart's check of the engine bundle, `mcp/dist/engine.js` — what the
 * MCP server and the CLI run, and the hooks do not (review of 3.3.0: with it
 * missing or cut short, the briefing still said "active"). Its size and
 * SHA-256 against the build's (`mcp/src/hooks/distCheck.ts`), the engine never
 * loaded; with the hooks bundle itself damaged, only a missing engine is told.
 * `null` when it is whole.
 */
async function engineNotice() {
  let damage;
  try {
    damage = (await detector('loadDistCheck')).engineDamage(join(PLUGIN_ROOT, 'mcp', 'dist'));
  } catch {
    damage = existsSync(join(PLUGIN_ROOT, 'mcp', 'dist', 'engine.js')) ? null : 'missing';
  }
  if (!damage) return null;
  return (
    `⚠️ dev-guardian: its engine, mcp/dist/engine.js, is ${damage} — the MCP tools and the dev-guardian CLI cannot ` +
    'run (the guardrail hooks do not use it). Ask the user to reinstall or rebuild the plugin.'
  );
}

/**
 * @param {string} root
 * @param {HookConfig} cfg
 * @returns {Promise<never>}
 */
async function handleSessionStart(root, cfg) {
  // git runs in processes of its own: started first, its three — the
  // configuration read and the submodule listing side by side, then `status`
  // — overlap the modules loading below (3.4.0). One git call for the branch
  // and the count (review 8, item 16): the porcelain v2 header names the
  // branch, and every other line is a change. `--ignore-submodules=dirty`: the
  // count does not go into a submodule's work tree, where that submodule's own
  // drivers would run (they are also neutralised by gitSafety); a submodule
  // whose commit moved still counts. Not in a folder git finds no repository
  // for, nor when the project turned the briefing off.
  const status =
    cfg.sessionStart && inGitRepository(root)
      ? git(root, ['status', '--porcelain=v2', '--branch', '--ignore-submodules=dirty'])
      : Promise.resolve('');
  // What the model must hear even when the project turned the briefing off:
  // settings it asked for that were ignored, guards that are not running, and
  // the briefing's own checks when they could not run.
  const [off, engine, session] = await Promise.all([unloadableGuardsNotice(), engineNotice(), sessionPartNotice()]);
  const guardsOff = off !== null;
  const notice = [ignoredSettingsNotice(cfg), off, engine, session].filter(Boolean).join('\n') || null;
  if (!cfg.sessionStart) {
    // The briefing is advisory and a project may turn it off — but not the
    // notice that the same project asked to loosen the guardrails.
    if (notice) emit('SessionStart', { additionalContext: notice });
    noop();
  }
  /** @type {string[]} */
  const lines = [];
  const guardianDir = join(root, '.guardian');
  const dbPath = join(guardianDir, 'guardian.db');
  // `existsSync`/`statSync` FOLLOW a link: `.guardian` linked to an
  // unreachable `\\host\share` would hold SessionStart past its timeout the
  // way it once held the config read. Walked first, with lstat + readlink only.
  const reachable = walkLinksUnder(root, dbPath).ok;
  const initialized = reachable ? existsSync(guardianDir) : true;
  const { branch, changed } = branchAndChanges(await status);

  const state = guardsOff
    ? 'running with guards OFF (see below)'
    : engine !== null
      ? 'guardrails active — its MCP tools and CLI cannot run (see below)'
      : session !== null
        ? 'guardrails active — its session checks could not run (see below)'
        : 'active';
  const head = `🛡️ dev-guardian ${state} (v${pluginVersion()})` + (branch ? ` · branch \`${branch}\`` : '');
  lines.push(head);
  if (changed > 0) lines.push(`${changed} uncommitted change(s) in the working tree.`);

  if (initialized) {
    let scanNote = '';
    try {
      if (reachable && existsSync(dbPath)) {
        const ageMs = Date.now() - statSync(dbPath).mtimeMs;
        scanNote = ` Last scan activity: ${relativeTime(ageMs)}.`;
      }
    } catch {
      /* ignore */
    }
    lines.push(`Project is guardian-initialized.${scanNote} Use /guardian-status for the dashboard, /guardian-scan before pushing.`);
    // Since 3.1.0 a project database is used only when it is registered as
    // the user's; one from 3.0.0 is not, until the user adopts it.
    if (reachable && databaseRegistration(dbPath) === 'unregistered') {
      const cli = join(PLUGIN_ROOT, 'cli', 'dev-guardian.mjs');
      lines.push(
        '⚠️ dev-guardian is not using .guardian/guardian.db: it is not registered as the user\'s (an older database, ' +
          `or one that came with the files). The user can review it with \`node "${cli}" db adopt ` +
          `--project "${root}"\` in a terminal and register it with --yes if it is theirs — never run that for them.`,
      );
    }
  } else if (looksLikeCode(root)) {
    // Said only where scanning could apply, and as something the user runs
    // (review 8, item 20): it used to come in every session of every folder,
    // and pushed the model to propose a setup nobody asked for.
    lines.push('Not yet guardian-initialized — the user can run /guardian-init to set up security and quality scanning.');
  }
  if (notice) lines.push(notice);

  emit('SessionStart', { additionalContext: lines.join('\n') });
}

/**
 * `git status --porcelain=v2 --branch`'s branch (none when detached or unknown) and number of changed entries.
 *
 * @param {string} status
 */
function branchAndChanges(status) {
  let branch = '';
  let changed = 0;
  for (const line of status.split('\n')) {
    if (line.startsWith('# branch.head ')) {
      const head = line.slice('# branch.head '.length).trim();
      branch = head === '(detached)' ? 'HEAD' : head;
    } else if (line !== '' && !line.startsWith('#')) changed += 1;
  }
  return { branch, changed };
}

/** What marks a folder as a code project: version control, or a manifest of a language dev-guardian scans. */
const CODE_MARKERS = [
  '.git', 'package.json', 'pyproject.toml', 'requirements.txt', 'setup.py', 'Pipfile', 'go.mod', 'Cargo.toml', 'pom.xml',
  'build.gradle', 'build.gradle.kts', 'composer.json', 'Gemfile', 'Dockerfile', 'global.json', 'Directory.Build.props',
];

/**
 * Whether `root` holds one of {@link CODE_MARKERS} — `lstat` only, a link is
 * never followed — or a .NET solution or project file (their names vary).
 *
 * @param {string} root
 */
function looksLikeCode(root) {
  if (CODE_MARKERS.some((name) => presentNoFollow(join(root, name)))) return true;
  try {
    return readdirSync(root)
      .slice(0, 2000)
      .some((name) => /\.(?:sln|slnx|csproj|fsproj|vbproj)$/i.test(name));
  } catch {
    return false;
  }
}

/**
 * @param {WriteDescription} write
 * @param {string} cwd
 * @param {string} root
 * @param {HookConfig} cfg
 * @param {string[]} allowlist
 * @returns {Promise<never>}
 */
async function handlePostToolUse(write, cwd, root, cfg, allowlist) {
  if (!cfg.secrets.warn) noop();
  const text = write.text;
  if (!text) noop();

  const rawPath = write.path;
  const absPath = rawPath ? resolve(cwd, rawPath) : '';
  if (absPath && (isPluginOwnFile(absPath) || isIgnoredPath(absPath, root, cfg.ignorePaths))) noop();

  const scanForSecrets = await loadSecretScan();
  const hits = scanForSecrets(text, { allowlist, minConfidence: 'medium' });
  if (hits.length === 0) noop();

  const where = rawPath ? ` in ${normalizePath(rawPath)}` : '';
  const list = hits
    .slice(0, 8)
    .map((h) => `  • ${h.title} (${h.confidence}) — line ${h.line}: ${h.preview}`)
    .join('\n');
  const context =
    `⚠️ dev-guardian: possible secret(s) just written${where}:\n${list}\n` +
    `If real, REMOVE it now, move it to an env var / secret manager, and rotate the credential — ` +
    `it may already be in your shell history or an editor swap file. ` +
    `Run \`/guardian-incident leak\` for the rotation checklist, or \`/guardian-scan\` for the authoritative gitleaks pass. ` +
    `False positive? add a substring to \`.guardian/hooks-allowlist.json\`.`;

  emit('PostToolUse', { additionalContext: context });
}

/**
 * Install-time package vetting for `npm i|install|add`, `pnpm add`, `yarn
 * add`, `bun add`, `pip install`, `uv add`, `uv pip install`, `poetry add`,
 * `composer require` and `dotnet add package`, and for the launchers that
 * download a package to run it (`npx`, `npm exec`, `pnpm dlx`, `yarn dlx`,
 * `bunx`, `uvx`, `uv tool install|run`, `pipx install|run`). The logic — command parsing,
 * the registry/OSV lookups under a 3 s total network budget and one 8 s
 * deadline for the whole hook call, the verdict and
 * the wording — lives in `mcp/src/pkgvet/hookDecision.ts` (in the bundle); this only calls
 * it. Returns `{ deny?, context? }`, or `null` when there is nothing to say
 * (no install command, every package clean) or anything at all went wrong:
 * a guardrail that cannot run lets the command through.
 *
 * Opt out with `GUARDIAN_PKG_VET=0` (vetting alone), or turn every hook off
 * with the user-level config's `"enabled": false` or `GUARDIAN_HOOKS=off` —
 * never from a project file, for the same reason the bash block cannot be
 * downgraded from one (see `projectOverrides`).
 *
 * @param {string} command
 * @param {string} cwd
 * @param {string} toolName
 * @param {ReadonlyArray<{ text: string, shell: 'bash' | 'powershell' }>} [nested]
 * @returns {Promise<{ deny?: string, context?: string } | null>}
 */
async function vetInstallCommand(command, cwd, toolName, nested = []) {
  if (process.env.GUARDIAN_PKG_VET === '0') return null;
  // A command that names no installer installs nothing: the vetting modules
  // are not even loaded (review 8, item 17 — `mcp/src/pkgvet/mayInstall.ts`).
  // Without the gate, every command is vetted, as before it. The scripts the
  // command hands a shell (`bash -c '…'`, `cmd /c …`, `echo '…' | sh` — the
  // shell guard's reading) count too: one of them may be base64 the command
  // line does not spell (review of 3.3.0).
  const gate = await detector('loadInstallGate').catch(() => undefined);
  const mayInstall = typeof gate?.mayInstall === 'function' ? gate.mayInstall : undefined;
  if (mayInstall !== undefined && !mayInstall(command) && !nested.some((s) => mayInstall(s.text))) return null;
  try {
    const mod = await detector('loadInstallVetting');
    // The PowerShell tool's commands are also read the way PowerShell reads
    // them (comma lists, backtick continuations) — see `parseInstallCommands`.
    const shell = toolName === 'PowerShell' ? 'powershell' : 'bash';
    return await mod.decideInstallCommand(command, { cwd, popularDir: POPULAR_DIR, shell, nested, startedAt: HOOK_STARTED });
  } catch (err) {
    debug(`package vetting skipped (fail-open): ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

/**
 * @param {ToolInput} input
 * @param {HookConfig} cfg
 * @param {string} cwd
 * @param {string} root
 * @param {string} toolName
 */
async function handlePreToolUseBash(input, cfg, cwd, root, toolName) {
  const command = input['command'];
  if (typeof command !== 'string' || !command) noop();

  // The PowerShell tool's commands are also read with PowerShell's quoting:
  // under POSIX quoting alone, `Remove-Item "C:\Users\" -Recurse -Force` hid
  // its path behind an escaped closing quote and read as ok. Where the session
  // runs: a guarded path spelled in full outside the project, the working
  // directory and home warns instead of being denied (review 8, item 14).
  // A shell guard that cannot be loaded fails open alone: package vetting,
  // in a part of its own, still runs (review of 3.4.0, finding 12 — a damaged
  // `hooksBash.js` took it down too, and SessionStart named only the shell guard).
  /** @type {ReturnType<Awaited<ReturnType<typeof loadBashGuard>>>} */
  let a = { level: 'ok', reasons: [], rules: [] };
  try {
    const assessBashCommand = await loadBashGuard();
    a = assessBashCommand(command, { shell: toolName === 'PowerShell' ? 'powershell' : 'bash', cwd, projectDir: root });
  } catch (err) {
    debug(`shell guard unavailable (fail-open): ${err instanceof Error ? err.message : String(err)}`);
  }

  if (a.level === 'block' && cfg.bash.block) {
    // Deliberately does not say HOW to turn this off (item 6) — that used to
    // name the exact project-file/key an assistant could write to disable
    // itself. It cannot be disabled from a project file at all now (see
    // `projectOverrides`), and the file that CAN change it is
    // one an assistant is refused permission to write — see
    // `guardianConfigWriteGuard`.
    // A rule that words its whole message (`db adopt --yes`: not catastrophic,
    // but the user's decision) is sent as it is.
    emit('PreToolUse', {
      permissionDecision: 'deny',
      permissionDecisionReason:
        a.denyMessage ??
        `dev-guardian blocked a catastrophic command: ${a.reasons.join('; ')}. ` +
          `If this is genuinely intended, run it yourself in a terminal — the user can adjust the ` +
          `guard settings if this should not be blocked.`,
    });
  }

  const notes = [];
  if ((a.level === 'warn' || (a.level === 'block' && !cfg.bash.block)) && cfg.bash.warn) {
    notes.push(`⚠️ dev-guardian: risky shell command — ${a.reasons.join('; ')}. Proceed only if this is intended.`);
  }

  // A command the catastrophic-command guard denied never reaches this
  // point (emit() exits), so it is never vetted. From here on the network
  // may have been used, so the answer goes out through respond(), never
  // emit()/noop() — see respond() for why.
  const vet = await vetInstallCommand(command, cwd, toolName, Array.isArray(a.scripts) ? a.scripts : []);
  if (vet?.deny) {
    return respond('PreToolUse', { permissionDecision: 'deny', permissionDecisionReason: vet.deny });
  }
  if (vet?.context) notes.push(vet.context);
  const context = notes.length > 0 ? { additionalContext: notes.join('\n') } : {};
  // The user's decision, not a hazard (review 8, C2: an agent-run `baseline
  // update`): Claude Code asks the user, showing them why. With the block
  // switched off it is only the warning above, as a block would be.
  if (a.ask && cfg.bash.block) {
    return respond('PreToolUse', { permissionDecision: 'ask', permissionDecisionReason: `dev-guardian: ${a.ask}.`, ...context });
  }
  return respond('PreToolUse', notes.length > 0 ? context : undefined);
}

/**
 * What a write tool call does, as the guards below read it: the path it
 * writes (`path`, for the secret scan and its ignore list), the text it
 * inserts, the paths the hook configuration guard and the registry guard
 * judge, and the change the settings guard judges. `null` for a call that
 * writes nothing the hooks can see.
 *
 * Claude Code's own tools: `Write`, `Edit`, `MultiEdit` (every guard) and
 * `NotebookEdit` (the registry and the secret scan, as before). And a
 * third-party MCP server's write tool (review 8, item 18) — hooks.json matches
 * an `mcp__<server>__<tool>` whose name holds a file verb (write, edit, create,
 * move, rename, copy, append, patch, replace, save, put, upload, insert,
 * delete, remove, unlink — and update, modify, apply, set, push as a word of
 * the name: {@link isMcpWriteTool}): `mcp__filesystem__write_file` wrote the
 * hook configuration, Claude Code's settings or a provider token past every
 * guard. Every string argument is read ({@link describeMcpWrite}).
 *
 * @param {string} toolName
 * @param {ToolInput} input
 * @returns {WriteDescription | null}
 */
function describeWrite(toolName, input) {
  /** @param {unknown} v */
  const str = (v) => (typeof v === 'string' && v !== '' ? v : undefined);
  switch (toolName) {
    case 'Write':
    case 'Edit':
    case 'MultiEdit': {
      const path = str(input['file_path']);
      if (path === undefined) return null;
      const content = input['content'];
      const edits = input['edits'];
      /** @type {SettingsChange | null} */
      const change =
        toolName === 'Write'
          ? typeof content === 'string'
            ? { content }
            : null
          : { edits: toolName === 'Edit' ? [input] : Array.isArray(edits) ? edits.filter(isPlainObject) : [] };
      // `~/…` and Git Bash's `/c/…` name the same file (review 12, finding 17).
      const paths = spellings(path);
      return { path, text: extractInsertedText(toolName, input), config: paths, registry: paths, settings: change ? paths.map((p) => ({ path: p, change })) : [] };
    }
    case 'NotebookEdit': {
      const path = str(input['notebook_path']);
      return path === undefined ? null : { path, text: extractInsertedText(toolName, input), config: [], registry: spellings(path), settings: [] };
    }
    default:
      return toolName.startsWith('mcp__') ? describeMcpWrite(toolName, input) : null;
  }
}

/** The argument names a third-party MCP write tool gives the path it writes (Serena's `relative_path`, JetBrains' `pathInProject` included). */
const MCP_DEST_KEYS = new Set([
  'path', 'file_path', 'filePath', 'filepath', 'file', 'filename', 'fileName', 'destination', 'dest', 'target', 'targetPath',
  'target_path', 'new_path', 'newPath', 'to', 'output', 'outputPath', 'output_path', 'notebook_path', 'uri', 'paths', 'files',
  'relative_path', 'relativePath', 'pathInProject', 'path_in_project', 'filename_path', 'absolute_path', 'absolutePath',
]);
/** …and the path a move or a rename takes away (a copy's is only read). */
const MCP_SOURCE_KEYS = new Set(['source', 'src', 'from', 'old_path', 'oldPath', 'sourcePath', 'source_path']);
/** …and the text it writes, whole. */
const MCP_TEXT_KEYS = ['content', 'contents', 'text', 'data', 'body', 'file_text', 'fileText', 'new_source', 'newContent', 'new_content'];
/**
 * …or as one edit: the text replaced and its replacement, at the top level (`str_replace_editor`, JetBrains, desktop-commander).
 *
 * @type {ReadonlyArray<readonly [string, string]>}
 */
const MCP_EDIT_PAIRS = [
  ['old_string', 'new_string'], ['old_str', 'new_str'], ['oldText', 'newText'], ['old_text', 'new_text'], ['oldString', 'newString'],
  ['search', 'replace'],
];
/** Keys that hold text, never a path: not judged as one. */
const MCP_TEXT_ONLY_KEYS = new Set([...MCP_TEXT_KEYS, ...MCP_EDIT_PAIRS.flat()]);
/**
 * Any other key that names a path by its own name — `target_file`, `PATH`,
 * `outDir`, `destFolder` — read as one whatever the tool is called.
 */
const MCP_PATH_KEY = /path|file|dir|folder|dest|target/i;
/**
 * A tool whose name names a file (`write_file`, `create_text_file`,
 * `push_files`, `move_path`): its other short strings are judged as paths it
 * may write too. One whose name does not — `create_issue`, `set_timezone`,
 * `update_page` — has its strings under path keys judged, never the rest
 * (review of 3.4.0, finding 13: a GitHub issue titled
 * `.claude/settings.json` was denied as a write of Claude Code's settings).
 */
const MCP_FILE_NOUN = /file|path|dir|folder|notebook|document/i;

/**
 * The verbs of an MCP tool's name that make it a write — what hooks.json's
 * matchers route here, and held to them by `hooksDispatcher.test.ts`. The file
 * verbs anywhere in the name, in any case (`WRITE_FILE`, `overwrite`); and
 * update, modify, apply, set and push (review of 3.3.0: `update_file`,
 * `modify_file`, `apply_diff`, `set_file_contents` were never routed) only as a
 * word of the name — after its start, `_`, `-` or a lower-case letter's camel
 * hump, and before its end, `_`, `-` or an upper-case letter — so that
 * `get_settings`, `reset_cache` and `dataset_list` are not writes.
 */
const MCP_WRITE_VERB = /write|edit|create|move|rename|copy|append|patch|replace|save|put|upload|insert|delete|remove|unlink/i;
const MCP_WORD_VERB =
  /(?:^|[_-])(?:update|modify|apply|set|push|UPDATE|MODIFY|APPLY|SET|PUSH|Update|Modify|Apply|Set|Push)(?=$|[A-Z_-])|[a-z0-9](?:Update|Modify|Apply|Set|Push)(?=$|[A-Z_-])/;

/**
 * An MCP tool's own name: what follows `mcp__<server>__`. The tool's name may
 * hold `__` itself (`mcp__srv__write__v2`), and hooks.json's matcher reads
 * past it; the last `__` gave `v2`, routed here and not judged (review of
 * 3.4.0, finding 13).
 *
 * @param {string} toolName
 */
function mcpToolPart(toolName) {
  const cut = toolName.indexOf('__', 'mcp__'.length + 1);
  return cut < 0 ? '' : toolName.slice(cut + 2);
}

/**
 * Whether `toolName` is a third-party MCP tool that writes files, by the verbs of its own name.
 *
 * @param {string} toolName
 */
function isMcpWriteTool(toolName) {
  if (!toolName.startsWith('mcp__')) return false;
  const verb = mcpToolPart(toolName);
  return MCP_WRITE_VERB.test(verb) || MCP_WORD_VERB.test(verb);
}

/** The deepest an MCP tool's arguments are read, and the most strings read from them. */
const MCP_ARG_DEPTH = 4;
const MCP_ARG_STRINGS = 256;
/** The most strings under no path key judged as paths a file tool may write. */
const MCP_LOOSE_PATHS = 32;
/** The longest string read as a path; a longer one, or one with a line break, is only text. */
const MCP_PATH_MAX = 4096;

/**
 * Every string in an MCP tool's arguments with the name of the key it is under
 * and the object holding it, to {@link MCP_ARG_DEPTH} levels and
 * {@link MCP_ARG_STRINGS} strings — and, when an argument lies past either,
 * which (`cut`): the call is then not wholly read, and never taken as silent
 * (review of 3.4.0, finding 13).
 *
 * @param {ToolInput} input
 * @returns {{ strings: Array<{ key: string, value: string, parent: Record<string, unknown> | undefined }>, cut: string | undefined }}
 */
function mcpStrings(input) {
  /** @type {Array<{ key: string, value: string, parent: Record<string, unknown> | undefined }>} */
  const out = [];
  /** @type {string | undefined} */
  let cut;
  /** @param {unknown} value */
  const holds = (value) =>
    typeof value === 'string' ? value !== '' : Array.isArray(value) ? value.length > 0 : isPlainObject(value) && Object.keys(value).length > 0;
  /**
   * @param {unknown} value
   * @param {string} key
   * @param {number} depth
   * @param {Record<string, unknown> | undefined} parent
   */
  const visit = (value, key, depth, parent) => {
    if (depth > MCP_ARG_DEPTH) {
      if (holds(value)) cut ??= `nested more than ${String(MCP_ARG_DEPTH)} levels deep`;
      return;
    }
    if (out.length >= MCP_ARG_STRINGS) {
      if (holds(value)) cut ??= `more than ${String(MCP_ARG_STRINGS)} strings`;
      return;
    }
    if (typeof value === 'string') {
      if (value !== '') out.push({ key, value, parent });
    } else if (Array.isArray(value)) {
      for (const item of value) visit(item, key, depth + 1, parent);
    } else if (isPlainObject(value)) {
      for (const [k, v] of Object.entries(value)) visit(v, k, depth + 1, value);
    }
  };
  visit(input, '', 0, undefined);
  return { strings: out, cut };
}

/**
 * A path as written and in the other spellings that name the same file: with
 * a leading `~` (`~/…`, `~\…`) as the home directory's — MCP servers expand it
 * (the filesystem server and desktop-commander do), and the
 * `~/.config/dev-guardian/hooks.json` they wrote passed the configuration and
 * registry guards (review of 3.4.0, finding 3) — and, on Windows, Git Bash's
 * `/c/…` (`/cygdrive/c/…`) as `C:/…` (review 12, finding 17: Write and Edit
 * expanded neither). Each is judged.
 *
 * @param {string} path
 * @returns {string[]}
 */
function spellings(path) {
  const out = [path];
  const m = /^~(?:[\\/]+|$)/.exec(path);
  if (m !== null) {
    const rest = path.slice(m[0].length).replace(/\\/g, '/');
    try {
      out.push(rest === '' ? homedir() : join(homedir(), rest));
    } catch {
      /* no home directory (no passwd entry): only as written */
    }
  }
  if (process.platform === 'win32') {
    const slashed = path.replace(/\\/g, '/');
    const msys = /^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/.exec(slashed);
    if (msys !== null) out.push(`${(msys[1] ?? '').toUpperCase()}:${slashed.slice(msys[0].length) || '/'}`);
  }
  return out;
}

/** The deepest an MCP call's arguments are looked through for a matching flag ({@link matchesOtherwise}). */
const MATCH_FLAG_DEPTH = 4;

/**
 * Whether an edit's old text is matched as something other than itself — a
 * regular expression, a glob, or ignoring case — so applying it as plain text
 * could give another result: a flag anywhere in the call, nested
 * (`options: {useRegex: true}`) or as a string (`isRegex: "true"`, `flags:
 * "i"`, `mode: "regex"`) (review 12, finding 15: only a top-level `true`
 * counted).
 *
 * @param {unknown} args
 * @param {number} [depth]
 * @returns {boolean}
 */
function matchesOtherwise(args, depth = 0) {
  if (depth > MATCH_FLAG_DEPTH) return false;
  if (Array.isArray(args)) return args.some((v) => matchesOtherwise(v, depth + 1));
  if (!isPlainObject(args)) return false;
  /** @param {unknown} v */
  const on = (v) => v === true || v === 1 || (typeof v === 'string' && !/^(?:|false|0|no|off|none|literal|plain|exact|text|string)$/i.test(v.trim()));
  /** @param {unknown} v */
  const off = (v) => v === false || v === 0 || (typeof v === 'string' && /^(?:false|0|no|off)$/i.test(v.trim()));
  return Object.entries(args).some(
    ([k, v]) =>
      (/regex|regexp|regular_?expression|pattern_?type|wildcard|glob/i.test(k) && on(v)) ||
      (/^(?:flags?|mode|match_?mode|search_?mode|syntax|match_?type)$/i.test(k) && on(v)) ||
      (/^(?:case_?sensitive|matchCase|match_case)$/i.test(k) && off(v)) ||
      (/^(?:ignore_?case|case_?insensitive)$/i.test(k) && on(v)) ||
      (typeof v === 'object' && v !== null && matchesOtherwise(v, depth + 1)),
  );
}

/**
 * A third-party MCP write tool's call, as {@link describeWrite} says it: every
 * string argument is read (review of 3.3.0 — Serena's `relative_path`,
 * JetBrains' `pathInProject` and `str_replace_editor`'s `file_text` / `new_str`
 * went unread, so their writes of Claude Code's settings or the hook
 * configuration passed). A path key (`path`, `relative_path`, …, any key that
 * names a path or a file — `target_file`; a `file://` URI too) is a path it
 * writes; the source of anything but a copy a path it takes away; and, for a
 * tool whose name names a file ({@link MCP_FILE_NOUN}), any other short,
 * single-line string is judged as a path it may write too. Every path is
 * judged as written and with a leading `~` expanded ({@link spellings}). The
 * text is the known content key, or the edits, or else every string that is
 * not a path. A change whose result cannot be worked out — a regex replace, a
 * move, strings no known key names — is `opaque`, and a write of Claude Code's
 * settings made that way is asked about (review of 3.4.0, finding 7). An
 * argument past the reading's limits makes the call `unread`.
 *
 * @param {string} toolName
 * @param {ToolInput} input
 * @returns {WriteDescription | null}
 */
function describeMcpWrite(toolName, input) {
  if (!isMcpWriteTool(toolName)) return null;
  const verb = mcpToolPart(toolName);
  const fileTool = MCP_FILE_NOUN.test(verb);
  /** @param {string} v */
  const asPath = (v) => {
    if (!/^file:\/\//i.test(v)) return v;
    try {
      return fileURLToPath(v);
    } catch {
      return undefined;
    }
  };
  const copies = /copy/i.test(verb);
  const removes = /delete|remove|unlink/i.test(verb);
  /** @type {Array<{ path: string, parent: Record<string, unknown> | undefined }>} */
  const dests = [];
  /** @type {string[]} */
  const sources = [];
  /** @type {string[]} */
  const others = [];
  /** @type {string[]} */
  const loose = [];
  /** A non-file tool's other strings that may name a guarded file: asked about, never denied (review 12, finding 6). */
  /** @type {string[]} */
  const maybe = [];
  const read = mcpStrings(input);
  let unread = read.cut;
  let fromFile = false;
  for (const { key, value, parent } of read.strings) {
    const path = value.length <= MCP_PATH_MAX && !/[\r\n]/.test(value) ? asPath(value) : undefined;
    if (MCP_TEXT_ONLY_KEYS.has(key)) {
      loose.push(value);
    } else if (MCP_SOURCE_KEYS.has(key)) {
      fromFile = true;
      if (path !== undefined && !copies) sources.push(...spellings(path));
    } else if (MCP_DEST_KEYS.has(key) || MCP_PATH_KEY.test(key)) {
      if (path !== undefined) for (const p of spellings(path)) dests.push({ path: p, parent });
    } else {
      loose.push(value);
      if (path === undefined) continue;
      if (!fileTool) {
        // Only a string that can name a guarded file — a `.json` or the registry — is looked up.
        if (maybe.length < MCP_LOOSE_PATHS && (/\.json$/i.test(path) || /registry/i.test(path))) maybe.push(...spellings(path));
        continue;
      }
      if (others.length < MCP_LOOSE_PATHS) others.push(...spellings(path));
      else unread ??= `more than ${String(MCP_LOOSE_PATHS)} strings that may be paths`;
    }
  }
  if (dests.length === 0 && sources.length === 0 && others.length === 0 && maybe.length === 0) {
    return unread === undefined ? null : { path: '', text: loose.join('\n'), config: [], registry: [], settings: [], unread, fileTool };
  }
  /** @type {string | undefined} */
  const content = MCP_TEXT_KEYS.map((k) => input[k]).find((v) => typeof v === 'string');
  const listed = input['edits'];
  /** @type {SettingsEdit[]} */
  const edits = (
    Array.isArray(listed)
      ? listed.filter(isPlainObject).map((e) => ({
          old_string: e['old_string'] ?? e['oldText'] ?? e['old_text'],
          new_string: e['new_string'] ?? e['newText'] ?? e['new_text'],
          replace_all: e['replace_all'] === true,
        }))
      : MCP_EDIT_PAIRS.map(([o, n]) => ({
          old_string: input[o],
          new_string: input[n],
          replace_all: input['replace_all'] === true || input['replaceAll'] === true,
        }))
  ).filter((e) => typeof e.old_string === 'string' && typeof e.new_string === 'string');
  // What no known key says — a regex and its replacement, a move — cannot be
  // applied: only the call's own strings are known (review of 3.4.0, finding 7).
  // A call that names nothing but the path (`get_update_status {path}`) brings
  // no content at all, and is judged as before: on nothing.
  /** @type {SettingsChange} */
  const change =
    content !== undefined
      ? { content }
      : edits.length > 0 && !matchesOtherwise(input) && !(Array.isArray(listed) && listed.some((e) => isPlainObject(e) && matchesOtherwise(e)))
        ? { edits }
        : loose.length > 0 || fromFile
          ? { opaque: loose.join('\n') }
          : { content: '' };
  /**
   * A path with its own text beside it (`push_files {files: [{path, content}]}`) is written with that text.
   *
   * @param {Record<string, unknown> | undefined} parent
   * @returns {SettingsChange}
   */
  const changeOf = (parent) => {
    const own = parent === undefined || parent === input ? undefined : MCP_TEXT_KEYS.map((k) => parent[k]).find((v) => typeof v === 'string');
    return own === undefined ? change : { content: own };
  };
  const text = content ?? (edits.length > 0 ? edits.map((e) => String(e.new_string)).join('\n') : loose.join('\n'));
  const written = [...dests.map((d) => d.path), ...others];
  return {
    path: written[0] ?? '',
    text,
    // Removing or moving the configuration away is refused like writing it; a copy's source is only read.
    config: [...written, ...sources],
    // Removing a registry entry only un-trusts a database; writing one is the user's decision.
    registry: removes ? [] : written,
    settings: removes ? [] : [...dests.map((d) => ({ path: d.path, change: changeOf(d.parent) })), ...others.map((path) => ({ path, change }))],
    ...(maybe.length === 0 ? {} : { maybe: { paths: maybe, change, removes } }),
    ...(unread === undefined ? {} : { unread }),
    fileTool,
  };
}

/**
 * Refuses to let an assistant Write/Edit/MultiEdit the guard's own
 * configuration (project `.guardian/hooks*.json` or the user-level
 * `~/.config/dev-guardian/hooks.json`) — item 6's other half. Gated by no
 * setting of its own — a downgrade of this exact check is what it exists to
 * prevent — and by nothing a project file can set; only the user-level
 * switches that turn EVERY hook off (`"enabled": false` in the user config,
 * `GUARDIAN_HOOKS=off`) skip it, like everything else in `main()`. It sees
 * the write tools ({@link describeWrite}); a shell write onto the same files is
 * the shell guard's (`guard-config-shell-write` in `bashGuard.ts`). Emits and
 * exits (via `emit`) when it applies; returns normally (so the caller
 * proceeds to the ordinary write handling) when it does not.
 *
 * @param {string} rawPath
 * @param {string} cwd
 * @param {string} root
 */
function guardianConfigWriteGuard(rawPath, cwd, root) {
  if (!rawPath || !isGuardianOwnConfigFile(rawPath, cwd, root)) return;
  emit('PreToolUse', {
    permissionDecision: 'deny',
    permissionDecisionReason:
      'dev-guardian: this file controls the guardrail hooks themselves. Ask the user to change it ' +
      'directly — an assistant is not allowed to edit its own guard configuration.',
  });
}

/**
 * Refuses an assistant's Write / Edit / MultiEdit / NotebookEdit (or an MCP
 * write) into dev-guardian's registry of trusted databases, `<user data
 * dir>/registry` (review 3.0 wave 2, round 2): an entry there is what `db
 * adopt --yes` writes, and which database to trust is the user's decision. The
 * path is compared as the filesystem opens it (NTFS stream suffixes, trailing
 * dots, 8.3 names, links) and a hard link to an entry by device and inode — see
 * `mcp/src/hooks/dataRegistry.ts`. Gated like `guardianConfigWriteGuard`.
 *
 * @param {string} rawPath
 * @param {string} cwd
 */
function guardianRegistryWriteGuard(rawPath, cwd) {
  if (!rawPath) return;
  let hit = false;
  try {
    hit = writesRegistry(resolve(cwd, rawPath));
  } catch (err) {
    debug(`registry guard skipped (fail-open): ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!hit) return;
  emit('PreToolUse', {
    permissionDecision: 'deny',
    permissionDecisionReason:
      "dev-guardian: this is dev-guardian's registry of trusted databases. Which database to trust is the user's " +
      `decision — ask them to run \`node "${join(PLUGIN_ROOT, 'cli', 'dev-guardian.mjs')}" db adopt\` themselves, in a terminal.`,
  });
}

/** The largest Claude Code settings file read to judge an edit of it. */
const SETTINGS_MAX_BYTES = 1024 * 1024;

/**
 * The directory whose components are walked before reading `abs` (see `readSmallJsonFile`).
 *
 * @param {string} abs
 * @param {string} cwd
 * @param {string} root
 * @returns {string | undefined}
 */
function walkRootFor(abs, cwd, root) {
  for (const base of [root, cwd, homedir()]) {
    const rel = relative(base, abs);
    if (rel && !climbsOut(rel) && !isAbsolute(rel)) return base;
  }
  return undefined;
}

/**
 * Refuses a write of Claude Code's own settings (`.claude/settings.json` /
 * `settings.local.json`, project or user level) whose RESULT switches
 * dev-guardian's hooks off — `"disableAllHooks": true`, an `env` entry
 * `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0|false`,
 * `GUARDIAN_PKG_VET=0`, `NODE_OPTIONS` or `GUARDIAN_PKG_VET_DEADLINE_MS`, or an
 * `enabledPlugins` entry turning dev-guardian off — that the file did not
 * already set (final review M5; `enabledPlugins`: follow-up Part Y; the
 * any-value variables: review of 3.4.0, finding 4). A new `env` `PATH`, `HOME`
 * or `USERPROFILE` is asked about (`newlyAsked`). Every other edit of those
 * files (permissions, other env vars, other hooks) passes: agents make them
 * legitimately. The new content is
 * the write's `content`, or its edits applied to the file on disk; when that
 * cannot be reproduced, the edit's own strings are compared instead. A file on
 * the network is not read (review 8, item 13): its edit is judged on its own
 * strings. Emits and exits when it denies. A change whose result cannot be
 * worked out at all (`opaque`: an MCP tool's regex replace, a move onto the
 * file) and whose own strings switch nothing off is the user's to confirm —
 * the reason is returned, and the caller asks once every guard that may deny
 * has run: `{"disableAllHooksX": true}` written, then `X"` replaced by `"`
 * through Serena's `replace_regex`, switched the hooks off in two allowed
 * steps (review of 3.4.0, finding 7). Any failure lets the call through
 * (fail-open).
 *
 * Each side is read once (`settingsVerdict`), under {@link SETTINGS_BUDGET_MS}:
 * a reading that runs past it asks rather than lets the hook run out its 15 s
 * — and the call through unjudged (review 12, finding 2). An edit that cannot
 * be applied to the file as it is — its old text not there, a regex or a
 * case-folding flag anywhere in the call (`options: {useRegex: true}`,
 * `flags: "i"`) — asks too (finding 15).
 *
 * `maybe`: the path is only a non-file MCP tool's argument that names the
 * settings (review 12, finding 6) — what would be denied is asked instead,
 * so a GitHub issue titled `.claude/settings.json` is never refused.
 *
 * @param {string} rawPath
 * @param {SettingsChange | null} change
 * @param {string} cwd
 * @param {string} root
 * @param {string} toolName
 * @param {boolean} [maybe]
 * @returns {Promise<string | undefined>} the reason to ask the user, when the result cannot be worked out
 */
async function claudeSettingsWriteGuard(rawPath, change, cwd, root, toolName, maybe = false) {
  if (!rawPath || !change) return undefined;
  // The file the write reaches (review M1: `settings.json::$DATA` IS
  // settings.json on Windows; round 3, item 5: a hard link to it is it too).
  // Then a cheap pre-check, so an ordinary edit never pays for the module import.
  const written = guardedPath(resolve(cwd, rawPath));
  const abs = hardLinkedTo(written, claudeSettingsFiles(root)) ?? written;
  if (!/settings(?:\.local)?\.json$/i.test(abs)) return undefined;
  /** @type {string[]} */
  let added = [];
  /** @type {string | undefined} */
  let ask;
  try {
    const guard = await detector('loadSettingsGuard');
    // With CLAUDE_CONFIG_DIR set, the user's settings live there, not in
    // ~/.claude (review round 2) — resolved the way the written path is.
    const configDir = process.env.CLAUDE_CONFIG_DIR ? guardedPath(resolve(process.env.CLAUDE_CONFIG_DIR)) : undefined;
    if (!guard.isClaudeSettingsPath(abs, configDir)) return undefined;
    const walkRoot = walkRootFor(abs, cwd, root);
    const before = isNetworkPath(abs) && walkRoot === undefined ? undefined : readSmallTextFile(abs, SETTINGS_MAX_BYTES, walkRoot);
    const where = normalizePath(rawPath);
    /** @type {[string | undefined, string]} what is compared: the file before and after, or the edit's own strings */
    let judged;
    if (typeof change.content === 'string') {
      judged = [before, change.content];
    } else if (typeof change.opaque === 'string') {
      judged = [before, change.opaque];
      ask =
        `dev-guardian: ${toolName} changes Claude Code's settings (${where}) in a way the guard cannot ` +
        'work out — a regular expression, a move, or arguments it does not know — and a change there can switch the ' +
        'guardrail hooks off. Confirm it only if you expected this change.';
    } else {
      const edits = (change.edits ?? []).filter(
        /**
         * @param {SettingsEdit} e
         * @returns {e is TextEdit}
         */
        (e) => e && typeof e.old_string === 'string' && typeof e.new_string === 'string',
      );
      let after = before;
      for (const e of edits) {
        if (after === undefined) break;
        after = guard.applyEdit(after, e.old_string, e.new_string, e.replace_all === true);
      }
      if (after !== undefined) judged = [before, after];
      else {
        judged = [edits.map((e) => e.old_string).join('\n'), edits.map((e) => e.new_string).join('\n')];
        // Asked when the file is there (or could not be read) and the edit does
        // not apply to it as plain text — a tool may match otherwise. On a file
        // that is not there, any edit fails.
        const there = before !== undefined || isNetworkPath(abs) || presentNoFollow(abs);
        if (there) ask =
          `dev-guardian: ${toolName}'s edit of Claude Code's settings (${where}) cannot be applied to the file as it ` +
          'is, so what it leaves there is not known — and a change there can switch the guardrail hooks off. Confirm it ' +
          'only if you expected this change.';
      }
    }
    const verdict =
      typeof guard.settingsVerdict === 'function'
        ? guard.settingsVerdict(...judged, { deadline: Date.now() + SETTINGS_BUDGET_MS })
        : { off: guard.newlyLoosened(...judged), ask: [] };
    added = verdict.off;
    if (verdict.late === true && added.length === 0) {
      ask ??=
        `dev-guardian: this change to Claude Code's settings (${where}) took too long to read in full, so whether it ` +
        'switches the guardrail hooks off is not known. Confirm it only if you expected this change.';
    }
    // `env` PATH, HOME, a proxy, NODE_* / GUARDIAN_*: which `node` the hooks start, where they look (findings 4 and 3).
    if (ask === undefined && verdict.ask.length > 0) {
      ask =
        `dev-guardian: this change to Claude Code's settings sets ${verdict.ask.join(', ').slice(0, 300)} — which decides the ` +
        'program the guardrail hooks start, the home they read their configuration from or how they reach the network. ' +
        'Confirm it only if you expected this change.';
    }
  } catch (err) {
    debug(`settings guard skipped (fail-open): ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
  if (added.length === 0) return ask;
  const reason =
    `dev-guardian: this change to Claude Code's settings would switch the guardrail hooks off (${added.join(', ')}). ` +
    'Ask the user to make it themselves — an assistant is not allowed to turn its own guardrails off.';
  if (maybe) {
    return (
      `dev-guardian: ${toolName}'s argument ${normalizePath(rawPath)} names Claude Code's settings, and the call's text ` +
      `would switch the guardrail hooks off there (${added.join(', ')}). If it writes that file, the user must make the ` +
      'change themselves; confirm it only if it does not.'
    );
  }
  emit('PreToolUse', { permissionDecision: 'deny', permissionDecisionReason: reason });
}

/** How long reading a settings change may take before the user is asked instead (`settingsVerdict`). */
const SETTINGS_BUDGET_MS = 4000;

/**
 * The question for an MCP write tool's call whose arguments were not all read
 * ({@link WriteDescription.unread}) — what was read passed every guard, but a
 * path past the limits could be a guarded file (review of 3.4.0, finding 13:
 * an argument five levels deep, or past 256 strings, was silently unread). A
 * tool whose name names a file is asked about; another one, whose strings are
 * judged only under path keys, gets a note.
 *
 * @param {WriteDescription} write
 * @param {string} toolName
 * @returns {HookAnswer | undefined}
 */
function unreadAnswer(write, toolName) {
  if (write.unread === undefined) return undefined;
  const what = `dev-guardian did not read all of ${toolName}'s arguments (${write.unread})`;
  return write.fileTool === true
    ? {
        permissionDecision: 'ask',
        permissionDecisionReason: `${what}, so a file it writes may be one the guardrails protect. Confirm it only if you expected this call.`,
      }
    : { additionalContext: `⚠️ ${what}: a path among them was not checked against the guardrails' protected files.` };
}

/**
 * The opt-in secret block (`secrets.block`): the deny reason when the write
 * holds a high-confidence provider token, else `undefined`.
 *
 * @param {WriteDescription} write
 * @param {string} cwd
 * @param {string} root
 * @param {HookConfig} cfg
 * @param {string[]} allowlist
 * @returns {Promise<string | undefined>}
 */
async function secretBlockReason(write, cwd, root, cfg, allowlist) {
  // Blocking on write is opt-in (secrets.block). Default path does nothing here
  // — PostToolUse already warns.
  if (!cfg.secrets.block) return undefined;
  const text = write.text;
  if (!text) return undefined;

  const rawPath = write.path;
  const absPath = rawPath ? resolve(cwd, rawPath) : '';
  // `blockIgnorePaths`, not `ignorePaths`: see `loadConfig`.
  if (absPath && (isPluginOwnFile(absPath) || isIgnoredPath(absPath, root, cfg.blockIgnorePaths))) return undefined;

  /** @type {Awaited<ReturnType<typeof loadSecretScan>>} */
  let scanForSecrets;
  try {
    scanForSecrets = await loadSecretScan();
  } catch (err) {
    // Fails open alone: the question a guard before it raised is still asked.
    debug(`secret scan unavailable (fail-open): ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
  // Block only on unambiguous, high-confidence provider tokens. The project
  // allowlist exempts from a block only when the project enabled it (see
  // `loadConfig`'s `userSecretBlock`).
  const hits = scanForSecrets(text, { allowlist: cfg.userSecretBlock ? [] : allowlist, minConfidence: 'high' });
  if (hits.length === 0) return undefined;

  const list = hits.slice(0, 6).map((h) => `${h.title} (line ${h.line})`).join(', ');
  // Deliberately does not say HOW to turn this off (item 6, fix round 1) —
  // that used to name the exact allowlist file and config key an assistant
  // could write to disable itself, and both are now denied outright by
  // `guardianConfigWriteGuard` anyway, which made the old wording not just a
  // disclosure risk but actively wrong (advice the model cannot act on).
  // Worded like `handlePreToolUseBash`'s own deny reason, for the same
  // reason: the user decides whether this should be allowed.
  return (
    `dev-guardian blocked writing a hard-coded secret to ${rawPath ? normalizePath(rawPath) : 'a file'}: ${list}. ` +
    `Use an environment variable or secret manager instead. If this is a false positive, the user ` +
    `can allow it or adjust the guard settings.`
  );
}

/**
 * The write guards in order — the configuration, Claude Code's settings, the
 * registry, the opt-in secret block — each denying (and exiting) when it
 * applies; then, when none did, the user's question about a change the
 * guards could not read, or the note.
 *
 * @param {WriteDescription} write
 * @param {string} toolName
 * @param {string} cwd
 * @param {string} root
 * @param {HookConfig} cfg
 * @param {string[]} allowlist
 * @returns {Promise<never>}
 */
async function handlePreToolUseWrite(write, toolName, cwd, root, cfg, allowlist) {
  for (const p of write.config) guardianConfigWriteGuard(p, cwd, root); // exits via emit() if it applies
  /** @type {string | undefined} */
  let ask;
  for (const { path, change } of write.settings) ask ??= await claudeSettingsWriteGuard(path, change, cwd, root, toolName); // likewise
  const maybe = write.maybe;
  if (write.registry.length > 0 || maybe !== undefined) await loadRegistryGuard();
  for (const p of write.registry) guardianRegistryWriteGuard(p, cwd); // likewise
  const secret = await secretBlockReason(write, cwd, root, cfg, allowlist);
  if (secret !== undefined) emit('PreToolUse', { permissionDecision: 'deny', permissionDecisionReason: secret });
  // A non-file tool's argument that names a guarded file (review 12, finding 6:
  // `save {location, data}`, `write {p, c}`, `write {args: [path, content]}`
  // were judged before the non-file rule and silent after it): the user decides.
  if (maybe !== undefined) ask ??= await maybeGuardedAsk(maybe, toolName, cwd, root);
  if (ask !== undefined) emit('PreToolUse', { permissionDecision: 'ask', permissionDecisionReason: ask });
  const unread = unreadAnswer(write, toolName);
  if (unread !== undefined) emit('PreToolUse', unread);
  noop();
}

/**
 * The question for a non-file MCP tool whose argument names a guarded file
 * ({@link WriteDescription.maybe}) — the hook configuration, the registry, or
 * Claude Code's settings with a change that would be asked about or denied —
 * else `undefined`. Never a deny: a GitHub issue titled
 * `.guardian/hooks.config.json` writes no file.
 *
 * @param {NonNullable<WriteDescription['maybe']>} maybe
 * @param {string} toolName
 * @param {string} cwd
 * @param {string} root
 * @returns {Promise<string | undefined>}
 */
async function maybeGuardedAsk(maybe, toolName, cwd, root) {
  /** @param {string} p @param {string} what */
  const named = (p, what) =>
    `dev-guardian: ${toolName}'s argument ${normalizePath(p)} names ${what}, which an assistant may not change. ` +
    'Confirm it only if this call does not write that file.';
  for (const p of maybe.paths) {
    if (isGuardianOwnConfigFile(p, cwd, root)) return named(p, "the guardrail hooks' own configuration");
    let registry = false;
    try {
      registry = !maybe.removes && writesRegistry(resolve(cwd, p));
    } catch {
      /* fail-open */
    }
    if (registry) return named(p, "dev-guardian's registry of trusted databases");
    if (!maybe.removes) {
      const settings = await claudeSettingsWriteGuard(p, maybe.change, cwd, root, toolName, true);
      if (settings !== undefined) return settings;
    }
  }
  return undefined;
}

// ─────────────────────────────────── main ──────────────────────────────────

async function main() {
  if (process.env.GUARDIAN_HOOKS === 'off') noop();

  const payload = await readStdin();
  const named = payload.hook_event_name ?? process.argv[2] ?? '';
  const event = typeof named === 'string' ? named : '';
  const toolName = typeof payload.tool_name === 'string' ? payload.tool_name : '';
  /** @type {ToolInput} */
  const input = isPlainObject(payload.tool_input) ? payload.tool_input : {};
  const cwd = typeof payload.cwd === 'string' && payload.cwd !== '' && existsSync(payload.cwd) ? payload.cwd : process.cwd();

  await loadConfigReader();
  /** @type {string[]} */
  const unread = [];
  // The project is its root, not wherever the session has cd-ed to (review I5).
  const root = projectRootOf(cwd);
  const cfg = loadConfig(root, unread);
  if (!cfg.enabled) noop();
  const allowlist = loadAllowlist(root, unread);
  cfg.unreadConfigFiles = unread;

  debug(`event=${event} tool=${toolName} cwd=${cwd} root=${root}`);

  switch (event) {
    case 'SessionStart':
      await loadRegistryReader();
      return handleSessionStart(root, cfg);
    case 'PostToolUse': {
      const write = describeWrite(toolName, input);
      return write === null ? noop() : handlePostToolUse(write, cwd, root, cfg, allowlist);
    }
    case 'PreToolUse': {
      if (toolName === 'Bash' || toolName === 'PowerShell') {
        return handlePreToolUseBash(input, cfg, cwd, root, toolName);
      }
      const write = describeWrite(toolName, input);
      if (write === null) return noop();
      return handlePreToolUseWrite(write, toolName, cwd, root, cfg, allowlist);
    }
    default:
      return noop();
  }
}

main().catch((err) => {
  debug(`fail-open: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  // Never break the host: exit 0 with no output on any error — through
  // respond(), not process.exit(), since the error may follow a fetch().
  respond('PreToolUse', undefined);
});
