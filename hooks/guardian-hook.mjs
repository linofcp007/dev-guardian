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
 *   - **Dependency-free.** Imports only `node:` builtins plus the pure,
 *     pre-compiled detectors in `../mcp/dist/hooks/*` (regex only, no native
 *     modules). This guarantees the hook runs in the *installed* plugin,
 *     where `mcp/node_modules` (storage is `node:sqlite`, no native deps —
 *     but still not shipped) is not present.
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

import { existsSync, lstatSync, readdirSync, statSync } from 'node:fs';
import module from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Node's on-disk compile cache for the detectors this hook imports on every
// call (review 8, dg-core 17): a no-op where Node lacks it, and a failure to
// write it changes nothing but the time.
try {
  module.enableCompileCache?.();
} catch {
  /* no cache: the hook only runs slower */
}

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/hooks
// The plugin root is derived from this file's own location rather than read
// from CLAUDE_PLUGIN_ROOT: hooks.json launches this file AS
// `${CLAUDE_PLUGIN_ROOT}/hooks/guardian-hook.mjs`, so the two agree whenever
// the variable is set, and this form also works when it is not (a manual run,
// `dev-guardian check`, the e2e tests).
const PLUGIN_ROOT = resolve(HERE, '..'); // <plugin>
const DIST_HOOKS = join(PLUGIN_ROOT, 'mcp', 'dist', 'hooks');
const DIST_PKGVET = join(PLUGIN_ROOT, 'mcp', 'dist', 'pkgvet');
const DIST_PLATFORM = join(PLUGIN_ROOT, 'mcp', 'dist', 'platform');
const POPULAR_DIR = join(PLUGIN_ROOT, 'configs', 'popular-packages');

const DEBUG = process.env.GUARDIAN_HOOKS_DEBUG === '1';

/**
 * When this hook call started: package vetting's one deadline
 * (`GUARDIAN_PKG_VET_DEADLINE_MS`, 8 s by default) counts from here, so the
 * shell guard's own time comes out of it and the whole call stays well under
 * Claude Code's 15 s timeout (review I4).
 */
const HOOK_STARTED = Date.now();

function debug(msg) {
  if (DEBUG) process.stderr.write(`[guardian-hook] ${msg}\n`);
}

/** Emit hookSpecificOutput JSON and exit 0. */
function emit(eventName, extra) {
  process.stdout.write(
    JSON.stringify({ hookSpecificOutput: { hookEventName: eventName, ...extra } }),
  );
  process.exit(0);
}

/** Exit cleanly with no output (no-op / fail-open). */
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

function respond(eventName, extra) {
  process.exitCode = 0;
  const backstop = () => setTimeout(() => process.exit(0), EXIT_GRACE_MS).unref();
  if (extra) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: eventName, ...extra } }), backstop);
  } else backstop();
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/**
 * How a hook configuration file is read: `readSmallJsonFile` from
 * `mcp/dist/hooks/configFile.js`, loaded in `main()` by `loadConfigReader`.
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
 * Until it is loaded, and if it cannot be (no built `mcp/dist`), every file
 * reads as absent: the protective defaults.
 */
let readSmallJsonFile = () => ({ status: 'absent' });
/** `walkLinksUnder` from the same module — see `handleSessionStart`. */
let walkLinksUnder = () => ({ ok: true });
/** `readSmallTextFile` from the same module — see `claudeSettingsWriteGuard`. */
let readSmallTextFile = () => undefined;
/**
 * `guardedPath` from `mcp/dist/hooks/guardedPath.js`: the file a write really
 * reaches — on Windows without an NTFS stream suffix or trailing dots and
 * spaces, and everywhere resolved through 8.3 names and links (review M1).
 * Until it is loaded, a path is taken as written.
 */
let guardedPath = (p) => p;
/** `hardLinkedTo` from the same module: which guarded file a path is a hard link to (review round 3, item 5). */
let hardLinkedTo = () => undefined;
/**
 * `isNetworkPath` from the same module: a path on the network or a device,
 * which no guard asks the filesystem about (review 8, item 13). Until it is
 * loaded, a `\\…` or `//…` path is one.
 */
let isNetworkPath = (p) => /^[\\/]{2}/.test(String(p));
/**
 * `writesRegistry` from `mcp/dist/hooks/dataRegistry.js`: whether a write
 * reaches dev-guardian's registry of trusted databases (review 3.0 wave 2,
 * round 2). Loaded by the write guards only ({@link loadRegistryGuard}); until
 * it is, and if it cannot be, nothing does (fail-open, and SessionStart says
 * the guard is off).
 */
let writesRegistry = () => false;

/**
 * What every event needs: the configuration reader and the path resolution
 * the project root is found with. The guards themselves are imported by the
 * event that uses them, and only then (review 8, item 17).
 */
async function loadConfigReader() {
  try {
    const mod = await import(pathToFileURL(join(DIST_HOOKS, 'configFile.js')).href);
    if (typeof mod.readSmallJsonFile === 'function') readSmallJsonFile = mod.readSmallJsonFile;
    if (typeof mod.walkLinksUnder === 'function') walkLinksUnder = mod.walkLinksUnder;
    if (typeof mod.readSmallTextFile === 'function') readSmallTextFile = mod.readSmallTextFile;
    if (typeof mod.isNetworkPath === 'function') isNetworkPath = mod.isNetworkPath;
    const paths = await import(pathToFileURL(join(DIST_HOOKS, 'guardedPath.js')).href);
    if (typeof paths.guardedPath === 'function') guardedPath = paths.guardedPath;
    if (typeof paths.hardLinkedTo === 'function') hardLinkedTo = paths.hardLinkedTo;
  } catch (err) {
    debug(`config reader unavailable — protective defaults: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function loadRegistryGuard() {
  try {
    const registry = await import(pathToFileURL(join(DIST_HOOKS, 'dataRegistry.js')).href);
    if (typeof registry.writesRegistry === 'function') writesRegistry = registry.writesRegistry;
  } catch (err) {
    debug(`registry guard unavailable (fail-open): ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * `databaseRegistration` from `mcp/dist/storage/dbRegistry.js`: whether a
 * project's `.guardian/guardian.db` is registered as the user's, read from
 * the user's own registry — the database itself is never opened here. Loaded
 * for SessionStart only; until then, and if it cannot be, `unknown` (no line).
 */
let databaseRegistration = () => 'unknown';

async function loadRegistryReader() {
  try {
    const mod = await import(pathToFileURL(join(PLUGIN_ROOT, 'mcp', 'dist', 'storage', 'dbRegistry.js')).href);
    if (typeof mod.databaseRegistration === 'function') databaseRegistration = mod.databaseRegistration;
  } catch (err) {
    debug(`registry reader unavailable: ${err instanceof Error ? err.message : String(err)}`);
  }
}

const UNREAD_REASON = {
  'not-a-regular-file': 'not a regular file',
  'too-large': 'larger than 64 KiB',
  unreadable: 'unreadable',
  'remote-link': 'reached through a link to a network or device path',
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * The parsed JSON at `path`, or `undefined`. When `label` is given, a file
 * that exists but was refused or is not JSON is recorded in `unread`, which
 * SessionStart reports. `under` is the directory whose components below it
 * are checked for a network link first (see `readSmallJsonFile` above).
 */
function readJsonFile(path, label, unread, under) {
  const r = readSmallJsonFile(path, undefined, under);
  if (r.status === 'ok') return r.value;
  if (label !== undefined && unread !== undefined) {
    if (r.status === 'refused') unread.push(`${label} was not read (${UNREAD_REASON[r.reason] ?? r.reason})`);
    else if (r.status === 'invalid') unread.push(`${label} was ignored (not valid JSON)`);
  }
  return undefined;
}

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
 */
function projectOverrides(projectFile) {
  const out = {};
  const ignored = [];
  const ignore = (label, debugLabel) => {
    ignored.push(label);
    debug(
      `ignoring ${debugLabel} from .guardian/hooks.config.json — a project file may not ` +
        'loosen the guardrails. Use the user-level config (~/.config/dev-guardian/hooks.json), ' +
        'GUARDIAN_HOOKS=off or GUARDIAN_HOOKS_BASH_BLOCK=0 instead.',
    );
  };

  if (projectFile.enabled === false) ignore('"enabled": false', '"enabled":false');
  else if (projectFile.enabled === true) out.enabled = true;

  const bash = projectFile.bash && typeof projectFile.bash === 'object' ? projectFile.bash : {};
  out.bash = {};
  if (bash.block === false) ignore('"bash.block": false', '"bash":{"block":false}');
  else if (bash.block === true) out.bash.block = true;
  if (bash.warn === false) ignore('"bash.warn": false', '"bash":{"warn":false}');
  else if (bash.warn === true) out.bash.warn = true;

  const secrets = projectFile.secrets && typeof projectFile.secrets === 'object' ? projectFile.secrets : {};
  out.secrets = {};
  if (typeof secrets.warn === 'boolean') out.secrets.warn = secrets.warn;
  if (typeof secrets.block === 'boolean') out.secrets.block = secrets.block;
  if (typeof projectFile.sessionStart === 'boolean') out.sessionStart = projectFile.sessionStart;
  if (Array.isArray(projectFile.ignorePaths)) out.ignorePaths = projectFile.ignorePaths;

  return { overrides: out, ignored };
}

/** Whether the user-level config itself switches the secret block on. */
function userEnablesSecretBlock(userFile) {
  return isPlainObject(userFile.secrets) && userFile.secrets.block === true;
}

function loadConfig(root, unread) {
  const projectRaw = readJsonFile(
    join(root, '.guardian', 'hooks.config.json'),
    '.guardian/hooks.config.json',
    unread,
    root,
  );
  const userRaw = readJsonFile(userConfigPath(), '~/.config/dev-guardian/hooks.json', unread, homedir());
  const projectFile = isPlainObject(projectRaw) ? projectRaw : {};
  const userFile = isPlainObject(userRaw) ? userRaw : {};
  const { overrides: project, ignored } = projectOverrides(projectFile);

  const merged = {
    ...DEFAULT_CONFIG,
    ...(project.enabled !== undefined ? { enabled: project.enabled } : {}),
    ...(project.sessionStart !== undefined ? { sessionStart: project.sessionStart } : {}),
    ...userFile,
    secrets: { ...DEFAULT_CONFIG.secrets, ...project.secrets, ...(userFile.secrets ?? {}) },
    bash: { ...DEFAULT_CONFIG.bash, ...project.bash, ...(userFile.bash ?? {}) },
    ignorePaths: userFile.ignorePaths ?? project.ignorePaths ?? DEFAULT_CONFIG.ignorePaths,
    // The paths the opt-in secret BLOCK skips. A project's `ignorePaths` is
    // advisory — it narrows the warning — and once also exempted paths from a
    // block the USER had enabled: `"ignorePaths": ["/"]` in a project file
    // switched that block off (final review M4). A user-enabled block now
    // honours only the user's own list, or the defaults; a block the project
    // itself enabled may still be narrowed by the same project's list.
    blockIgnorePaths:
      userFile.ignorePaths ??
      (userEnablesSecretBlock(userFile) ? DEFAULT_CONFIG.ignorePaths : (project.ignorePaths ?? DEFAULT_CONFIG.ignorePaths)),
    // The same rule for the project's `.guardian/hooks-allowlist.json`: it
    // silences the warning, but a block the USER enabled ignores it — `["AKIA"]`
    // there used to exempt every AWS key from that block (follow-up Part Y).
    // There is no user-level allowlist; a user-enabled block has none.
    userSecretBlock: userEnablesSecretBlock(userFile),
    ignoredProjectSettings: ignored,
  };

  // Highest precedence: an explicit env var, checked last so it always wins.
  const envBlock = process.env.GUARDIAN_HOOKS_BASH_BLOCK;
  if (envBlock === '0' || envBlock === 'false') merged.bash.block = false;
  else if (envBlock === '1' || envBlock === 'true') merged.bash.block = true;

  return merged;
}

function loadAllowlist(root, unread) {
  const data = readJsonFile(
    join(root, '.guardian', 'hooks-allowlist.json'),
    '.guardian/hooks-allowlist.json',
    unread,
    root,
  );
  if (Array.isArray(data)) return data.filter((x) => typeof x === 'string');
  if (data && Array.isArray(data.secrets)) return data.secrets.filter((x) => typeof x === 'string');
  return [];
}

function pluginVersion() {
  const pj = readJsonFile(join(PLUGIN_ROOT, '.claude-plugin', 'plugin.json'));
  return pj?.version ?? '0.0.0';
}

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
 * `execGitSync` from `mcp/dist/platform/gitSafety.js`: git hardened against
 * the project's own git configuration (review 3.0, W2E-git). SessionStart's
 * `git status` in a project opened for the first time — an archive, a
 * download — used to run that project's `core.fsmonitor` and
 * `post-index-change` hook. Until it is loaded, and if it cannot be, no git
 * runs at all: the briefing loses its branch line, never its safety.
 */
let execGitSync = null;

async function loadGitSafety() {
  try {
    const mod = await import(pathToFileURL(join(DIST_PLATFORM, 'gitSafety.js')).href);
    if (typeof mod.execGitSync === 'function') execGitSync = mod.execGitSync;
  } catch (err) {
    debug(`git hardening unavailable — git not run: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function git(cwd, args) {
  if (execGitSync === null) return '';
  try {
    const r = execGitSync(cwd, args, { timeoutMs: 2000 });
    return r.failure === null && r.status === 0 ? r.stdout.trim() : '';
  } catch {
    return '';
  }
}

/** Text inserted by a Write/Edit/MultiEdit/NotebookEdit tool call. */
function extractInsertedText(toolName, input) {
  if (!input || typeof input !== 'object') return '';
  switch (toolName) {
    case 'Write':
      return typeof input.content === 'string' ? input.content : '';
    case 'Edit':
      return typeof input.new_string === 'string' ? input.new_string : '';
    case 'MultiEdit':
      return Array.isArray(input.edits)
        ? input.edits.map((e) => (e && typeof e.new_string === 'string' ? e.new_string : '')).join('\n')
        : '';
    case 'NotebookEdit':
      return typeof input.new_source === 'string' ? input.new_source : '';
    default:
      return '';
  }
}

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
 */
function isIgnoredPath(absolutePath, root, ignorePaths) {
  if (!absolutePath) return false;
  const rel = normalizePath(relative(root, absolutePath));
  const withLeadingSlash = rel.startsWith('..') ? normalizePath(absolutePath) : `/${rel}`;
  return ignorePaths.some((frag) => withLeadingSlash.includes(frag));
}

/**
 * The plugin's OWN installation directory, matched by absolute prefix —
 * never a substring like the old `/hooks/` entry, which matched any
 * ancestor directory anywhere named "hooks" (a React `src/hooks/`, or a
 * project simply cloned under a directory called `hooks`) in every project.
 * Hardcoded, not part of `ignorePaths`: this is not something a project or
 * user config should be able to widen or narrow.
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
 * Claude Code's settings files a Write could be a hard link to: the project's,
 * the user's (`~/.claude`), and `CLAUDE_CONFIG_DIR`'s.
 */
function claudeSettingsFiles(root) {
  const dirs = [join(resolve(root), '.claude'), join(homedir(), '.claude')];
  if (process.env.CLAUDE_CONFIG_DIR) dirs.push(resolve(process.env.CLAUDE_CONFIG_DIR));
  return dirs.flatMap((d) => [join(d, 'settings.json'), join(d, 'settings.local.json')]);
}

/** `path` lies strictly below `dir`. */
function isBelow(dir, path) {
  const rel = relative(dir, path);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

/** Whether `path` exists, without following a link at it (`.git` linked to a share must not be opened). */
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
 */
function projectRootOf(cwd) {
  const fromEnv = process.env.CLAUDE_PROJECT_DIR;
  if (fromEnv && existsSync(fromEnv)) return resolve(fromEnv);
  // Never the home directory or an ancestor of it, nor the temp dir itself
  // (review round 2): a stray `.guardian` there — this machine has one in
  // each — made every unmarked project below it take its configuration from
  // there. Compared as the filesystem spells them (8.3 names: %TEMP% is
  // often `C:\Users\ADMINI~1\…`).
  const home = guardedPath(resolve(homedir()));
  const temp = guardedPath(resolve(tmpdir()));
  const excluded = (dir) => {
    const d = guardedPath(dir);
    return samePath(d, home) || isBelow(d, home) || samePath(d, temp);
  };
  let dir = resolve(cwd);
  for (let i = 0; i < 256; i += 1) {
    if (!excluded(dir) && (presentNoFollow(join(dir, '.guardian')) || presentNoFollow(join(dir, '.git')))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(cwd);
}

/*
 * The detectors, each imported by the event that uses it and no other (review
 * 8, item 17: every Bash call loaded the secret scan, every write the 220 KB
 * shell guard). Dynamic imports, so a missing/un-built dist fails open rather
 * than throwing at module load. `pathToFileURL`, never `file://${…}` by
 * concatenation: a `#` in the install path read as a URL fragment, the import
 * failed, and the shell guard and the secret scan failed open (review M2).
 */
async function loadSecretScan() {
  const secret = await import(pathToFileURL(join(DIST_HOOKS, 'secretScan.js')).href);
  return secret.scanForSecrets;
}

async function loadBashGuard() {
  const bash = await import(pathToFileURL(join(DIST_HOOKS, 'bashGuard.js')).href);
  return bash.assessBashCommand;
}

/** The guards whose compiled modules the hooks load, and what each one is called in a notice. */
const GUARD_MODULES = [
  { file: join(DIST_HOOKS, 'bashGuard.js'), name: 'the shell guard', export: 'assessBashCommand' },
  { file: join(DIST_HOOKS, 'secretScan.js'), name: 'the secret scan', export: 'scanForSecrets' },
  { file: join(DIST_PKGVET, 'hookDecision.js'), name: 'package vetting', export: 'decideInstallCommand' },
  { file: join(DIST_HOOKS, 'settingsGuard.js'), name: "the Claude Code settings guard", export: 'newlyLoosened' },
  { file: join(DIST_HOOKS, 'dataRegistry.js'), name: 'the database registry guard', export: 'writesRegistry' },
];

/**
 * SessionStart's check that every guard can actually run (review M2): each
 * one fails open when its module cannot be loaded, and until now the briefing
 * said "active" all the same. `null` when all load.
 */
async function unloadableGuardsNotice() {
  const broken = [];
  let reason = '';
  for (const g of GUARD_MODULES) {
    try {
      const mod = await import(pathToFileURL(g.file).href);
      if (typeof mod[g.export] !== 'function') throw new Error(`${g.export} missing`);
    } catch (err) {
      broken.push(g.name);
      reason = reason || (err instanceof Error ? (err.code ?? err.message) : String(err));
    }
  }
  if (broken.length === 0) return null;
  const list = broken.length === 1 ? broken[0] : `${broken.slice(0, -1).join(', ')} and ${broken[broken.length - 1]}`;
  return (
    `⚠️ dev-guardian: ${list} could not be loaded (${reason}) — ${broken.length === 1 ? 'it is' : 'they are'} OFF for this ` +
    `session (fail-open): nothing is checked by ${broken.length === 1 ? 'it' : 'them'}. The plugin's mcp/dist is missing or ` +
    'damaged; ask the user to reinstall or rebuild it.'
  );
}

// ─────────────────────────────── handlers ──────────────────────────────────

/**
 * The one place the model hears that a project file tried to loosen the
 * guardrails (see `projectOverrides`). Deliberately does not say how to switch
 * them off — the same rule as every deny message.
 */
function ignoredSettingsNotice(cfg) {
  const lines = [];
  const ignored = cfg.ignoredProjectSettings ?? [];
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
  return lines.length > 0 ? lines.join('\n') : null;
}

async function handleSessionStart(root, cfg) {
  // What the model must hear even when the project turned the briefing off:
  // settings it asked for that were ignored, and guards that are not running.
  const off = await unloadableGuardsNotice();
  const guardsOff = off !== null;
  const notice = [ignoredSettingsNotice(cfg), off].filter(Boolean).join('\n') || null;
  if (!cfg.sessionStart) {
    // The briefing is advisory and a project may turn it off — but not the
    // notice that the same project asked to loosen the guardrails.
    if (notice) emit('SessionStart', { additionalContext: notice });
    noop();
  }
  const lines = [];
  const guardianDir = join(root, '.guardian');
  const dbPath = join(guardianDir, 'guardian.db');
  // `existsSync`/`statSync` FOLLOW a link: `.guardian` linked to an
  // unreachable `\\host\share` would hold SessionStart past its timeout the
  // way it once held the config read. Walked first, with lstat + readlink only.
  const reachable = walkLinksUnder(root, dbPath).ok;
  const initialized = reachable ? existsSync(guardianDir) : true;
  await loadGitSafety();
  // One git call for the branch and the count (review 8, item 16): the
  // porcelain v2 header names the branch, and every other line is a change.
  // `--ignore-submodules=dirty`: the count does not go into a submodule's
  // work tree, where that submodule's own drivers would run (they are also
  // neutralised by gitSafety); a submodule whose commit moved still counts.
  const { branch, changed } = branchAndChanges(git(root, ['status', '--porcelain=v2', '--branch', '--ignore-submodules=dirty']));

  const state = guardsOff ? 'running with guards OFF (see below)' : 'active';
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

/** `git status --porcelain=v2 --branch`'s branch (none when detached or unknown) and number of changed entries. */
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
 * the wording — lives in `mcp/dist/pkgvet/hookDecision.js`; this only calls
 * it. Returns `{ deny?, context? }`, or `null` when there is nothing to say
 * (no install command, every package clean) or anything at all went wrong:
 * a guardrail that cannot run lets the command through.
 *
 * Opt out with `GUARDIAN_PKG_VET=0` (vetting alone), or turn every hook off
 * with the user-level config's `"enabled": false` or `GUARDIAN_HOOKS=off` —
 * never from a project file, for the same reason the bash block cannot be
 * downgraded from one (see `projectOverrides`).
 */
async function vetInstallCommand(command, cwd, toolName) {
  if (process.env.GUARDIAN_PKG_VET === '0') return null;
  // A command that names no installer installs nothing: the vetting modules
  // are not even loaded (review 8, item 17 — `mcp/src/pkgvet/mayInstall.ts`).
  // Without the gate, every command is vetted, as before it.
  const gate = await import(pathToFileURL(join(DIST_PKGVET, 'mayInstall.js')).href).catch(() => undefined);
  if (typeof gate?.mayInstall === 'function' && !gate.mayInstall(command)) return null;
  try {
    const mod = await import(pathToFileURL(join(DIST_PKGVET, 'hookDecision.js')).href);
    // The PowerShell tool's commands are also read the way PowerShell reads
    // them (comma lists, backtick continuations) — see `parseInstallCommands`.
    const shell = toolName === 'PowerShell' ? 'powershell' : 'bash';
    return await mod.decideInstallCommand(command, { cwd, popularDir: POPULAR_DIR, shell, startedAt: HOOK_STARTED });
  } catch (err) {
    debug(`package vetting skipped (fail-open): ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

async function handlePreToolUseBash(input, cfg, cwd, root, toolName) {
  const command = input?.command;
  if (typeof command !== 'string' || !command) noop();

  const assessBashCommand = await loadBashGuard();
  // The PowerShell tool's commands are also read with PowerShell's quoting:
  // under POSIX quoting alone, `Remove-Item "C:\Users\" -Recurse -Force` hid
  // its path behind an escaped closing quote and read as ok. Where the session
  // runs: a guarded path spelled in full outside the project, the working
  // directory and home warns instead of being denied (review 8, item 14).
  const a = assessBashCommand(command, { shell: toolName === 'PowerShell' ? 'powershell' : 'bash', cwd, projectDir: root });

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
  const vet = await vetInstallCommand(command, cwd, toolName);
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
 * delete, remove, unlink): `mcp__filesystem__write_file` wrote the hook
 * configuration, Claude Code's settings or a provider token past every guard.
 * Its path arguments are read by their usual names ({@link MCP_DEST_KEYS}; a
 * `file://` URI too), a move's or rename's source as a path it takes away, and
 * its text as `content` / `text` / `data` or `edits` (`oldText` / `newText`).
 */
function describeWrite(toolName, input) {
  if (!input || typeof input !== 'object') return null;
  const str = (v) => (typeof v === 'string' && v !== '' ? v : undefined);
  switch (toolName) {
    case 'Write':
    case 'Edit':
    case 'MultiEdit': {
      const path = str(input.file_path);
      if (path === undefined) return null;
      const change =
        toolName === 'Write'
          ? typeof input.content === 'string'
            ? { content: input.content }
            : null
          : { edits: toolName === 'Edit' ? [input] : Array.isArray(input.edits) ? input.edits : [] };
      return { path, text: extractInsertedText(toolName, input), config: [path], registry: [path], settings: change ? [{ path, change }] : [] };
    }
    case 'NotebookEdit': {
      const path = str(input.notebook_path);
      return path === undefined ? null : { path, text: extractInsertedText(toolName, input), config: [], registry: [path], settings: [] };
    }
    default:
      return toolName.startsWith('mcp__') ? describeMcpWrite(toolName, input) : null;
  }
}

/** The argument names a third-party MCP write tool gives the path it writes. */
const MCP_DEST_KEYS = [
  'path', 'file_path', 'filePath', 'filepath', 'file', 'filename', 'fileName', 'destination', 'dest', 'target', 'targetPath',
  'target_path', 'new_path', 'newPath', 'to', 'output', 'outputPath', 'output_path', 'notebook_path', 'uri',
];
/** …and the path a move or a rename takes away. */
const MCP_SOURCE_KEYS = ['source', 'src', 'from', 'old_path', 'oldPath', 'sourcePath', 'source_path'];
/** …and the text it writes. */
const MCP_TEXT_KEYS = ['content', 'contents', 'text', 'data', 'body', 'new_string', 'newText', 'new_source'];

/** The verbs of an MCP tool's name that make it a write — what hooks.json's matcher routes here. */
const MCP_WRITE_VERB = /write|edit|create|move|rename|copy|append|patch|replace|save|put|upload|insert|delete|remove|unlink/i;

function describeMcpWrite(toolName, input) {
  const verb = toolName.slice(toolName.lastIndexOf('__') + 2);
  if (!MCP_WRITE_VERB.test(verb)) return null;
  const asPath = (v) => {
    if (typeof v !== 'string' || v === '') return undefined;
    if (!/^file:\/\//i.test(v)) return v;
    try {
      return fileURLToPath(v);
    } catch {
      return undefined;
    }
  };
  const pathsOf = (keys) => {
    const out = [];
    for (const k of keys) {
      const v = input[k];
      for (const item of Array.isArray(v) ? v : [v]) {
        const p = asPath(item);
        if (p !== undefined) out.push(p);
      }
    }
    for (const k of ['paths', 'files']) {
      if (!Array.isArray(input[k])) continue;
      for (const item of input[k]) {
        const p = asPath(item);
        if (p !== undefined) out.push(p);
      }
    }
    return out;
  };
  const dests = pathsOf(MCP_DEST_KEYS);
  const moves = /move|rename/i.test(verb);
  const removes = /delete|remove|unlink/i.test(verb);
  const sources = moves ? pathsOf(MCP_SOURCE_KEYS) : [];
  if (dests.length === 0 && sources.length === 0) return null;
  const content = MCP_TEXT_KEYS.map((k) => input[k]).find((v) => typeof v === 'string');
  const edits = Array.isArray(input.edits)
    ? input.edits
        .map((e) => ({
          old_string: e?.old_string ?? e?.oldText ?? e?.old_text,
          new_string: e?.new_string ?? e?.newText ?? e?.new_text,
          replace_all: e?.replace_all === true,
        }))
        .filter((e) => typeof e.old_string === 'string' && typeof e.new_string === 'string')
    : [];
  const change = content !== undefined ? { content } : edits.length > 0 ? { edits } : null;
  const text = content ?? edits.map((e) => e.new_string).join('\n');
  return {
    path: dests[0] ?? '',
    text,
    // Removing or moving the configuration away is refused like writing it; a copy's source is only read.
    config: [...dests, ...sources],
    // Removing a registry entry only un-trusts a database; writing one is the user's decision.
    registry: removes ? [] : dests,
    // A move or copy onto the settings brings content no hook can read: a known limit, as for the shell.
    settings: change === null || removes ? [] : dests.map((path) => ({ path, change })),
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

/** The directory whose components are walked before reading `abs` (see `readSmallJsonFile`). */
function walkRootFor(abs, cwd, root) {
  for (const base of [root, cwd, homedir()]) {
    const rel = relative(base, abs);
    if (rel && !rel.startsWith('..') && !isAbsolute(rel)) return base;
  }
  return undefined;
}

/**
 * Refuses a write of Claude Code's own settings (`.claude/settings.json` /
 * `settings.local.json`, project or user level) whose RESULT switches
 * dev-guardian's hooks off — `"disableAllHooks": true`, an `env` entry
 * `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0|false` or
 * `GUARDIAN_PKG_VET=0`, or an `enabledPlugins` entry turning dev-guardian off —
 * that the file did not already set (final review M5; `enabledPlugins`:
 * follow-up Part Y). Every other edit of those files (permissions, other env
 * vars, other hooks) passes: agents make them legitimately. The new content is
 * the write's `content`, or its edits applied to the file on disk; when that
 * cannot be reproduced, the edit's own strings are compared instead. A file on
 * the network is not read (review 8, item 13): its edit is judged on its own
 * strings. Emits and exits when it applies; any failure lets the call through
 * (fail-open).
 */
async function claudeSettingsWriteGuard(rawPath, change, cwd, root) {
  if (!rawPath || !change) return;
  // The file the write reaches (review M1: `settings.json::$DATA` IS
  // settings.json on Windows; round 3, item 5: a hard link to it is it too).
  // Then a cheap pre-check, so an ordinary edit never pays for the module import.
  const written = guardedPath(resolve(cwd, rawPath));
  const abs = hardLinkedTo(written, claudeSettingsFiles(root)) ?? written;
  if (!/settings(?:\.local)?\.json$/i.test(abs)) return;
  let added = [];
  try {
    const guard = await import(pathToFileURL(join(DIST_HOOKS, 'settingsGuard.js')).href);
    // With CLAUDE_CONFIG_DIR set, the user's settings live there, not in
    // ~/.claude (review round 2) — resolved the way the written path is.
    const configDir = process.env.CLAUDE_CONFIG_DIR ? guardedPath(resolve(process.env.CLAUDE_CONFIG_DIR)) : undefined;
    if (!guard.isClaudeSettingsPath(abs, configDir)) return;
    const walkRoot = walkRootFor(abs, cwd, root);
    const before = isNetworkPath(abs) && walkRoot === undefined ? undefined : readSmallTextFile(abs, SETTINGS_MAX_BYTES, walkRoot);
    if (typeof change.content === 'string') {
      added = guard.newlyLoosened(before, change.content);
    } else {
      const edits = (change.edits ?? []).filter((e) => e && typeof e.old_string === 'string' && typeof e.new_string === 'string');
      let after = before;
      for (const e of edits) {
        if (after === undefined) break;
        after = guard.applyEdit(after, e.old_string, e.new_string, e.replace_all === true);
      }
      added =
        after !== undefined
          ? guard.newlyLoosened(before, after)
          : guard.newlyLoosened(
              edits.map((e) => e.old_string).join('\n'),
              edits.map((e) => e.new_string).join('\n'),
            );
    }
  } catch (err) {
    debug(`settings guard skipped (fail-open): ${err instanceof Error ? err.message : String(err)}`);
    return;
  }
  if (added.length === 0) return;
  emit('PreToolUse', {
    permissionDecision: 'deny',
    permissionDecisionReason:
      `dev-guardian: this change to Claude Code's settings would switch the guardrail hooks off (${added.join(', ')}). ` +
      'Ask the user to make it themselves — an assistant is not allowed to turn its own guardrails off.',
  });
}

async function handlePreToolUseWrite(write, cwd, root, cfg, allowlist) {
  // Blocking on write is opt-in (secrets.block). Default path does nothing here
  // — PostToolUse already warns.
  if (!cfg.secrets.block) noop();
  const text = write.text;
  if (!text) noop();

  const rawPath = write.path;
  const absPath = rawPath ? resolve(cwd, rawPath) : '';
  // `blockIgnorePaths`, not `ignorePaths`: see `loadConfig`.
  if (absPath && (isPluginOwnFile(absPath) || isIgnoredPath(absPath, root, cfg.blockIgnorePaths))) noop();

  const scanForSecrets = await loadSecretScan();
  // Block only on unambiguous, high-confidence provider tokens. The project
  // allowlist exempts from a block only when the project enabled it (see
  // `loadConfig`'s `userSecretBlock`).
  const hits = scanForSecrets(text, { allowlist: cfg.userSecretBlock ? [] : allowlist, minConfidence: 'high' });
  if (hits.length === 0) noop();

  const list = hits.slice(0, 6).map((h) => `${h.title} (line ${h.line})`).join(', ');
  // Deliberately does not say HOW to turn this off (item 6, fix round 1) —
  // that used to name the exact allowlist file and config key an assistant
  // could write to disable itself, and both are now denied outright by
  // `guardianConfigWriteGuard` anyway, which made the old wording not just a
  // disclosure risk but actively wrong (advice the model cannot act on).
  // Worded like `handlePreToolUseBash`'s own deny reason, for the same
  // reason: the user decides whether this should be allowed.
  emit('PreToolUse', {
    permissionDecision: 'deny',
    permissionDecisionReason:
      `dev-guardian blocked writing a hard-coded secret to ${rawPath ? normalizePath(rawPath) : 'a file'}: ${list}. ` +
      `Use an environment variable or secret manager instead. If this is a false positive, the user ` +
      `can allow it or adjust the guard settings.`,
  });
}

// ─────────────────────────────────── main ──────────────────────────────────

async function main() {
  if (process.env.GUARDIAN_HOOKS === 'off') noop();

  const payload = await readStdin();
  const event = payload.hook_event_name ?? process.argv[2] ?? '';
  const toolName = typeof payload.tool_name === 'string' ? payload.tool_name : '';
  const input = payload.tool_input ?? {};
  const cwd = payload.cwd && existsSync(payload.cwd) ? payload.cwd : process.cwd();

  await loadConfigReader();
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
      for (const p of write.config) guardianConfigWriteGuard(p, cwd, root); // exits via emit() if it applies
      for (const { path, change } of write.settings) await claudeSettingsWriteGuard(path, change, cwd, root); // likewise
      if (write.registry.length > 0) {
        await loadRegistryGuard();
        for (const p of write.registry) guardianRegistryWriteGuard(p, cwd); // likewise
      }
      return handlePreToolUseWrite(write, cwd, root, cfg, allowlist);
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
