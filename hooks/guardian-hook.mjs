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

import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, statSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/hooks
// The plugin root is derived from this file's own location rather than read
// from CLAUDE_PLUGIN_ROOT: hooks.json launches this file AS
// `${CLAUDE_PLUGIN_ROOT}/hooks/guardian-hook.mjs`, so the two agree whenever
// the variable is set, and this form also works when it is not (a manual run,
// `dev-guardian check`, the e2e tests).
const PLUGIN_ROOT = resolve(HERE, '..'); // <plugin>
const DIST_HOOKS = join(PLUGIN_ROOT, 'mcp', 'dist', 'hooks');
const DIST_PKGVET = join(PLUGIN_ROOT, 'mcp', 'dist', 'pkgvet');
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
 */
function respond(eventName, extra) {
  process.exitCode = 0;
  let flushed = !extra;
  if (extra) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: eventName, ...extra } }), () => {
      flushed = true;
    });
  }
  const backstop = () => {
    if (flushed) process.exit(0);
    else setTimeout(backstop, 100).unref();
  };
  setTimeout(backstop, 5000).unref();
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

async function loadConfigReader() {
  try {
    const mod = await import(pathToFileURL(join(DIST_HOOKS, 'configFile.js')).href);
    if (typeof mod.readSmallJsonFile === 'function') readSmallJsonFile = mod.readSmallJsonFile;
    if (typeof mod.walkLinksUnder === 'function') walkLinksUnder = mod.walkLinksUnder;
    if (typeof mod.readSmallTextFile === 'function') readSmallTextFile = mod.readSmallTextFile;
    const paths = await import(pathToFileURL(join(DIST_HOOKS, 'guardedPath.js')).href);
    if (typeof paths.guardedPath === 'function') guardedPath = paths.guardedPath;
    if (typeof paths.hardLinkedTo === 'function') hardLinkedTo = paths.hardLinkedTo;
  } catch (err) {
    debug(`config reader unavailable — protective defaults: ${err instanceof Error ? err.message : String(err)}`);
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

function git(cwd, args) {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
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
 * The path a tool call targets. `NotebookEdit` carries it as `notebook_path`,
 * not `file_path` — reading only `file_path` (as this file used to,
 * uniformly) silently produced no path for every notebook edit, which meant
 * no ignore-path check and no file name in the warning context either.
 */
function extractFilePath(toolName, input) {
  if (!input || typeof input !== 'object') return '';
  return toolName === 'NotebookEdit' ? (input.notebook_path ?? '') : (input.file_path ?? '');
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
  if (/(?:^|\/)\.guardian\/hooks[^/]*\.json$/i.test(normalizePath(abs))) {
    if (isBelow(guardedPath(resolve(root)), abs) || isBelow(guardedPath(resolve(cwd)), abs)) return true;
  }
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

async function loadDetectors() {
  // Dynamic import so a missing/un-built dist fails open rather than throwing
  // at module load. `pathToFileURL`, never `file://${…}` by concatenation: a
  // `#` in the install path read as a URL fragment, the import failed, and the
  // shell guard and the secret scan failed open (review M2).
  const secret = await import(pathToFileURL(join(DIST_HOOKS, 'secretScan.js')).href);
  const bash = await import(pathToFileURL(join(DIST_HOOKS, 'bashGuard.js')).href);
  return { scanForSecrets: secret.scanForSecrets, assessBashCommand: bash.assessBashCommand };
}

/** The guards whose compiled modules the hooks load, and what each one is called in a notice. */
const GUARD_MODULES = [
  { file: join(DIST_HOOKS, 'bashGuard.js'), name: 'the shell guard', export: 'assessBashCommand' },
  { file: join(DIST_HOOKS, 'secretScan.js'), name: 'the secret scan', export: 'scanForSecrets' },
  { file: join(DIST_PKGVET, 'hookDecision.js'), name: 'package vetting', export: 'decideInstallCommand' },
  { file: join(DIST_HOOKS, 'settingsGuard.js'), name: "the Claude Code settings guard", export: 'newlyLoosened' },
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
  const branch = git(root, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const status = git(root, ['status', '--porcelain']);
  const changed = status ? status.split('\n').filter(Boolean).length : 0;

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
  } else {
    lines.push('Not yet guardian-initialized — run /guardian-init to set up security & quality scanning.');
  }
  if (notice) lines.push(notice);

  emit('SessionStart', { additionalContext: lines.join('\n') });
}

async function handlePostToolUse(toolName, input, cwd, root, cfg, allowlist) {
  if (!cfg.secrets.warn) noop();
  const text = extractInsertedText(toolName, input);
  if (!text) noop();

  const rawPath = extractFilePath(toolName, input);
  const absPath = rawPath ? resolve(cwd, rawPath) : '';
  if (absPath && (isPluginOwnFile(absPath) || isIgnoredPath(absPath, root, cfg.ignorePaths))) noop();

  const { scanForSecrets } = await loadDetectors();
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

async function handlePreToolUseBash(input, cfg, cwd, allowlist, toolName) {
  const command = input?.command;
  if (typeof command !== 'string' || !command) noop();

  const { assessBashCommand } = await loadDetectors();
  // The PowerShell tool's commands are also read with PowerShell's quoting:
  // under POSIX quoting alone, `Remove-Item "C:\Users\" -Recurse -Force` hid
  // its path behind an escaped closing quote and read as ok.
  const a = assessBashCommand(command, { shell: toolName === 'PowerShell' ? 'powershell' : 'bash' });

  if (a.level === 'block' && cfg.bash.block) {
    // Deliberately does not say HOW to turn this off (item 6) — that used to
    // name the exact project-file/key an assistant could write to disable
    // itself. It cannot be disabled from a project file at all now (see
    // `projectOverrides`), and the file that CAN change it is
    // one an assistant is refused permission to write — see
    // `guardianConfigWriteGuard`.
    emit('PreToolUse', {
      permissionDecision: 'deny',
      permissionDecisionReason:
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
  return respond('PreToolUse', notes.length > 0 ? { additionalContext: notes.join('\n') } : undefined);
}

/**
 * Refuses to let an assistant Write/Edit/MultiEdit the guard's own
 * configuration (project `.guardian/hooks*.json` or the user-level
 * `~/.config/dev-guardian/hooks.json`) — item 6's other half. Gated by no
 * setting of its own — a downgrade of this exact check is what it exists to
 * prevent — and by nothing a project file can set; only the user-level
 * switches that turn EVERY hook off (`"enabled": false` in the user config,
 * `GUARDIAN_HOOKS=off`) skip it, like everything else in `main()`. It sees
 * the Write/Edit/MultiEdit tools only; a shell write onto the same files is
 * the shell guard's (`guard-config-shell-write` in `bashGuard.ts`). Emits and
 * exits (via `emit`) when it applies; returns normally (so the caller
 * proceeds to the ordinary write handling) when it does not.
 */
function guardianConfigWriteGuard(toolName, input, cwd, root) {
  const rawPath = extractFilePath(toolName, input);
  if (!rawPath || !isGuardianOwnConfigFile(rawPath, cwd, root)) return;
  emit('PreToolUse', {
    permissionDecision: 'deny',
    permissionDecisionReason:
      'dev-guardian: this file controls the guardrail hooks themselves. Ask the user to change it ' +
      'directly — an assistant is not allowed to edit its own guard configuration.',
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
 * Refuses a Write/Edit/MultiEdit of Claude Code's own settings
 * (`.claude/settings.json` / `settings.local.json`, project or user level)
 * whose RESULT switches dev-guardian's hooks off — `"disableAllHooks": true`,
 * an `env` entry `GUARDIAN_HOOKS=off`, `GUARDIAN_HOOKS_BASH_BLOCK=0|false`
 * or `GUARDIAN_PKG_VET=0`, or an `enabledPlugins` entry turning dev-guardian
 * off — that the file did not already set (final review M5; `enabledPlugins`:
 * follow-up Part Y). Every other edit of those files (permissions, other env vars, other
 * hooks) passes: agents make them legitimately. The new content is the Write's
 * `content`, or the Edit/MultiEdit applied to the file on disk; when that
 * cannot be reproduced, the edit's own strings are compared instead. Emits and
 * exits when it applies; any failure lets the call through (fail-open).
 */
async function claudeSettingsWriteGuard(toolName, input, cwd, root) {
  const rawPath = extractFilePath(toolName, input);
  if (!rawPath) return;
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
    const before = readSmallTextFile(abs, SETTINGS_MAX_BYTES, walkRootFor(abs, cwd, root));
    if (toolName === 'Write') {
      if (typeof input.content !== 'string') return;
      added = guard.newlyLoosened(before, input.content);
    } else {
      const edits = (toolName === 'Edit' ? [input] : Array.isArray(input.edits) ? input.edits : []).filter(
        (e) => e && typeof e.old_string === 'string' && typeof e.new_string === 'string',
      );
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

async function handlePreToolUseWrite(toolName, input, cwd, root, cfg, allowlist) {
  // Blocking on write is opt-in (secrets.block). Default path does nothing here
  // — PostToolUse already warns.
  if (!cfg.secrets.block) noop();
  const text = extractInsertedText(toolName, input);
  if (!text) noop();

  const rawPath = extractFilePath(toolName, input);
  const absPath = rawPath ? resolve(cwd, rawPath) : '';
  // `blockIgnorePaths`, not `ignorePaths`: see `loadConfig`.
  if (absPath && (isPluginOwnFile(absPath) || isIgnoredPath(absPath, root, cfg.blockIgnorePaths))) noop();

  const { scanForSecrets } = await loadDetectors();
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
  const toolName = payload.tool_name ?? '';
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
      return handleSessionStart(root, cfg);
    case 'PostToolUse':
      if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(toolName)) {
        return handlePostToolUse(toolName, input, cwd, root, cfg, allowlist);
      }
      return noop();
    case 'PreToolUse':
      if (toolName === 'Bash' || toolName === 'PowerShell') {
        return handlePreToolUseBash(input, cfg, cwd, allowlist, toolName);
      }
      if (toolName === 'Write' || toolName === 'Edit' || toolName === 'MultiEdit') {
        guardianConfigWriteGuard(toolName, input, cwd, root); // exits via emit() if it applies
        await claudeSettingsWriteGuard(toolName, input, cwd, root); // likewise
      }
      if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(toolName)) {
        return handlePreToolUseWrite(toolName, input, cwd, root, cfg, allowlist);
      }
      return noop();
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
