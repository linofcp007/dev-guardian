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
 *     where `mcp/node_modules` (better-sqlite3 etc.) is not shipped.
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
import { dirname, join, resolve } from 'node:path';
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
  /** Path substrings whose edits are never secret-scanned. */
  ignorePaths: ['/test/fixtures/', 'eval-vuln-fixture', '/.guardian/', '/hooks/', '__fixtures__'],
};

function loadConfig(cwd) {
  const file = readJsonFile(join(cwd, '.guardian', 'hooks.config.json')) ?? {};
  return {
    ...DEFAULT_CONFIG,
    ...file,
    secrets: { ...DEFAULT_CONFIG.secrets, ...(file.secrets ?? {}) },
    bash: { ...DEFAULT_CONFIG.bash, ...(file.bash ?? {}) },
    ignorePaths: file.ignorePaths ?? DEFAULT_CONFIG.ignorePaths,
  };
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

  const filePath = normalizePath(input?.file_path);
  if (filePath && cfg.ignorePaths.some((frag) => filePath.includes(frag))) noop();

  const { scanForSecrets } = await loadDetectors();
  const hits = scanForSecrets(text, { allowlist, minConfidence: 'medium' });
  if (hits.length === 0) noop();

  const where = filePath ? ` in ${filePath}` : '';
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
    emit('PreToolUse', {
      permissionDecision: 'deny',
      permissionDecisionReason:
        `dev-guardian blocked a catastrophic command: ${a.reasons.join('; ')}. ` +
        `If this is genuinely intended, run it yourself in a terminal, or set "bash":{"block":false} in .guardian/hooks.config.json.`,
    });
  }

  if ((a.level === 'warn' || (a.level === 'block' && !cfg.bash.block)) && cfg.bash.warn) {
    emit('PreToolUse', {
      additionalContext: `⚠️ dev-guardian: risky shell command — ${a.reasons.join('; ')}. Proceed only if this is intended.`,
    });
  }
  noop();
}

async function handlePreToolUseWrite(toolName, input, cwd, cfg, allowlist) {
  // Blocking on write is opt-in (secrets.block). Default path does nothing here
  // — PostToolUse already warns.
  if (!cfg.secrets.block) noop();
  const text = extractInsertedText(toolName, input);
  if (!text) noop();

  const filePath = normalizePath(input?.file_path);
  if (filePath && cfg.ignorePaths.some((frag) => filePath.includes(frag))) noop();

  const { scanForSecrets } = await loadDetectors();
  // Block only on unambiguous, high-confidence provider tokens.
  const hits = scanForSecrets(text, { allowlist, minConfidence: 'high' });
  if (hits.length === 0) noop();

  const list = hits.slice(0, 6).map((h) => `${h.title} (line ${h.line})`).join(', ');
  emit('PreToolUse', {
    permissionDecision: 'deny',
    permissionDecisionReason:
      `dev-guardian blocked writing a hard-coded secret to ${filePath || 'a file'}: ${list}. ` +
      `Use an environment variable or secret manager instead. ` +
      `False positive? add it to .guardian/hooks-allowlist.json or set "secrets":{"block":false}.`,
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
      if (toolName === 'Bash') return handlePreToolUseBash(input, cfg, cwd, allowlist);
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
