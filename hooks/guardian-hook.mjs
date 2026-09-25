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
 *     by default. All of it is tunable via `.guardian/hooks.config.json` and
 *     killable with `GUARDIAN_HOOKS=off`.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/hooks
const PLUGIN_ROOT = resolve(HERE, '..'); // <plugin>
const DIST_HOOKS = join(PLUGIN_ROOT, 'mcp', 'dist', 'hooks');

const DEBUG = process.env.GUARDIAN_HOOKS_DEBUG === '1';

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

function readJsonFile(path) {
  try {
    if (!existsSync(path)) return undefined;
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return undefined;
  }
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
 * Project config (`.guardian/hooks.config.json`) may only make the guard
 * STRICTER, never weaker: a project file is something the assistant itself
 * can write, so a project that got the assistant to set `"bash":{"block":
 * false}` would be turning the guard off from inside the very thing it is
 * supposed to guard. `"bash":{"block":false}` from a project file is
 * therefore stripped here rather than merged — backward-compatible with
 * anyone who already has it (their project simply stops downgrading, rather
 * than erroring), with one debug-only stderr note explaining why. The real
 * switch for this now lives outside the project: the user-level config
 * (`~/.config/dev-guardian/hooks.json`) or `GUARDIAN_HOOKS_BASH_BLOCK=0`,
 * applied afterwards in `loadConfig`.
 */
function stripProjectBashBlockDowngrade(projectFile) {
  const bash = projectFile.bash;
  if (!bash || bash.block !== false) return projectFile.bash ?? {};
  debug(
    'ignoring "bash":{"block":false} from .guardian/hooks.config.json — a project file may not ' +
      'downgrade this guard. Use the user-level config (~/.config/dev-guardian/hooks.json) or ' +
      'GUARDIAN_HOOKS_BASH_BLOCK=0 instead.',
  );
  const { block, ...rest } = bash;
  return rest;
}

function loadConfig(cwd) {
  const projectFile = readJsonFile(join(cwd, '.guardian', 'hooks.config.json')) ?? {};
  const userFile = readJsonFile(userConfigPath()) ?? {};
  const projectBash = stripProjectBashBlockDowngrade(projectFile);

  const merged = {
    ...DEFAULT_CONFIG,
    ...projectFile,
    ...userFile,
    secrets: { ...DEFAULT_CONFIG.secrets, ...(projectFile.secrets ?? {}), ...(userFile.secrets ?? {}) },
    bash: { ...DEFAULT_CONFIG.bash, ...projectBash, ...(userFile.bash ?? {}) },
    ignorePaths: userFile.ignorePaths ?? projectFile.ignorePaths ?? DEFAULT_CONFIG.ignorePaths,
  };

  // Highest precedence: an explicit env var, checked last so it always wins.
  const envBlock = process.env.GUARDIAN_HOOKS_BASH_BLOCK;
  if (envBlock === '0' || envBlock === 'false') merged.bash.block = false;
  else if (envBlock === '1' || envBlock === 'true') merged.bash.block = true;

  return merged;
}

function loadAllowlist(cwd) {
  const data = readJsonFile(join(cwd, '.guardian', 'hooks-allowlist.json'));
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
function isIgnoredPath(absolutePath, cwd, ignorePaths) {
  if (!absolutePath) return false;
  const rel = normalizePath(relative(cwd, absolutePath));
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
 */
function isGuardianOwnConfigFile(filePath, cwd) {
  if (!filePath) return false;
  const abs = resolve(cwd, filePath);
  const rel = normalizePath(relative(cwd, abs));
  if (!rel.startsWith('..') && /^\.guardian\/hooks[^/]*\.json$/i.test(rel)) return true;
  return samePath(abs, userConfigPath());
}

async function loadDetectors() {
  // Dynamic import so a missing/un-built dist fails open rather than throwing
  // at module load. File URLs keep this correct on Windows.
  const secret = await import(new URL('secretScan.js', `file://${DIST_HOOKS}/`));
  const bash = await import(new URL('bashGuard.js', `file://${DIST_HOOKS}/`));
  return { scanForSecrets: secret.scanForSecrets, assessBashCommand: bash.assessBashCommand };
}

// ─────────────────────────────── handlers ──────────────────────────────────

function handleSessionStart(cwd, cfg) {
  if (!cfg.sessionStart) noop();
  const lines = [];
  const guardianDir = join(cwd, '.guardian');
  const initialized = existsSync(guardianDir);
  const branch = git(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const status = git(cwd, ['status', '--porcelain']);
  const changed = status ? status.split('\n').filter(Boolean).length : 0;

  const head = `🛡️ dev-guardian active (v${pluginVersion()})` + (branch ? ` · branch \`${branch}\`` : '');
  lines.push(head);
  if (changed > 0) lines.push(`${changed} uncommitted change(s) in the working tree.`);

  if (initialized) {
    let scanNote = '';
    try {
      const dbPath = join(guardianDir, 'guardian.db');
      if (existsSync(dbPath)) {
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

  emit('SessionStart', { additionalContext: lines.join('\n') });
}

async function handlePostToolUse(toolName, input, cwd, cfg, allowlist) {
  if (!cfg.secrets.warn) noop();
  const text = extractInsertedText(toolName, input);
  if (!text) noop();

  const rawPath = extractFilePath(toolName, input);
  const absPath = rawPath ? resolve(cwd, rawPath) : '';
  if (absPath && (isPluginOwnFile(absPath) || isIgnoredPath(absPath, cwd, cfg.ignorePaths))) noop();

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
    `Run \`/guardian-leak\` for the rotation checklist, or \`/guardian-scan\` for the authoritative gitleaks pass. ` +
    `False positive? add a substring to \`.guardian/hooks-allowlist.json\`.`;

  emit('PostToolUse', { additionalContext: context });
}

async function handlePreToolUseBash(input, cfg, cwd, allowlist) {
  const command = input?.command;
  if (typeof command !== 'string' || !command) noop();

  const { assessBashCommand } = await loadDetectors();
  const a = assessBashCommand(command);

  if (a.level === 'block' && cfg.bash.block) {
    // Deliberately does not say HOW to turn this off (item 6) — that used to
    // name the exact project-file/key an assistant could write to disable
    // itself. It cannot be disabled from a project file at all now (see
    // `stripProjectBashBlockDowngrade`), and the file that CAN change it is
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

  if ((a.level === 'warn' || (a.level === 'block' && !cfg.bash.block)) && cfg.bash.warn) {
    emit('PreToolUse', {
      additionalContext: `⚠️ dev-guardian: risky shell command — ${a.reasons.join('; ')}. Proceed only if this is intended.`,
    });
  }
  noop();
}

/**
 * Refuses to let an assistant Write/Edit/MultiEdit the guard's own
 * configuration (project `.guardian/hooks*.json` or the user-level
 * `~/.config/dev-guardian/hooks.json`) — item 6's other half. Unconditional:
 * not gated by any config flag, since a downgrade of this exact check is
 * what it exists to prevent. Emits and exits (via `emit`) when it applies;
 * returns normally (so the caller proceeds to the ordinary write handling)
 * when it does not.
 */
function guardianConfigWriteGuard(toolName, input, cwd) {
  const rawPath = extractFilePath(toolName, input);
  if (!rawPath || !isGuardianOwnConfigFile(rawPath, cwd)) return;
  emit('PreToolUse', {
    permissionDecision: 'deny',
    permissionDecisionReason:
      'dev-guardian: this file controls the guardrail hooks themselves. Ask the user to change it ' +
      'directly — an assistant is not allowed to edit its own guard configuration.',
  });
}

async function handlePreToolUseWrite(toolName, input, cwd, cfg, allowlist) {
  // Blocking on write is opt-in (secrets.block). Default path does nothing here
  // — PostToolUse already warns.
  if (!cfg.secrets.block) noop();
  const text = extractInsertedText(toolName, input);
  if (!text) noop();

  const rawPath = extractFilePath(toolName, input);
  const absPath = rawPath ? resolve(cwd, rawPath) : '';
  if (absPath && (isPluginOwnFile(absPath) || isIgnoredPath(absPath, cwd, cfg.ignorePaths))) noop();

  const { scanForSecrets } = await loadDetectors();
  // Block only on unambiguous, high-confidence provider tokens.
  const hits = scanForSecrets(text, { allowlist, minConfidence: 'high' });
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

  const cfg = loadConfig(cwd);
  if (!cfg.enabled) noop();
  const allowlist = loadAllowlist(cwd);

  debug(`event=${event} tool=${toolName} cwd=${cwd}`);

  switch (event) {
    case 'SessionStart':
      return handleSessionStart(cwd, cfg);
    case 'PostToolUse':
      if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(toolName)) {
        return handlePostToolUse(toolName, input, cwd, cfg, allowlist);
      }
      return noop();
    case 'PreToolUse':
      if (toolName === 'Bash' || toolName === 'PowerShell') {
        return handlePreToolUseBash(input, cfg, cwd, allowlist);
      }
      if (toolName === 'Write' || toolName === 'Edit' || toolName === 'MultiEdit') {
        guardianConfigWriteGuard(toolName, input, cwd); // exits via emit() if it applies
      }
      if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(toolName)) {
        return handlePreToolUseWrite(toolName, input, cwd, cfg, allowlist);
      }
      return noop();
    default:
      return noop();
  }
}

main().catch((err) => {
  debug(`fail-open: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  // Never break the host: exit 0 with no output on any error.
  process.exit(0);
});
