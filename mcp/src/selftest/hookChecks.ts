/**
 * The five checks of the guardrail hooks: what each one hands the installed
 * dispatcher, what a working guard answers, and which of the user's own
 * settings explains a softer answer.
 *
 * A check's command is TEXT inside a hook payload, written to the
 * dispatcher's standard input — the dispatcher assesses what it is handed and
 * runs none of it (`docs/hooks.md`, "Only what just happened"). Nothing here
 * is executed, and nothing is given to a shell. The commands are put together
 * from pieces so that this file, and the bundle, hold no line a scanner or a
 * guard would read as the command itself.
 *
 * A guard that answers more softly because THE USER switched it off is their
 * decision, not a defect: it is named and the control is `disabled_by_user`.
 * Only what the dispatcher itself honours counts — the environment and the
 * user-level file; a project file cannot switch a protective hook off, and the
 * temporary project has none.
 */

import { join } from 'node:path';
import { readSmallJsonFile } from '../hooks/configFile.js';
import { COULD_NOT_VET, NOT_VERIFIED } from '../pkgvet/hookDecision.js';
import type { Workspace } from './canaries.js';

type HookCheckId = 'hooks:bash-block' | 'hooks:powershell-block' | 'hooks:settings-guard' | 'hooks:secret-warning' | 'hooks:install-vet';

interface HookCheck {
  id: HookCheckId;
  /** The event the dispatcher is started for (its one argument). */
  event: 'PreToolUse' | 'PostToolUse';
  /** What a working guard answers. */
  expect: 'deny' | 'secret-warning';
  /** The payload, for this workspace. `secretText` is the seeded secret file's content. */
  payload(ws: Workspace, secretText: string): Record<string, unknown>;
}

// A catastrophic command for each shell, in pieces: only ever text in a payload.
const BASH_COMMAND = ['rm', '-rf', '/'].join(' ');
const POWERSHELL_COMMAND = ['Remove-Item', '-Recurse', '-Force', 'C:\\'].join(' ');
// An install, by name, of a package npm replaced by its security placeholder (OSV: a `MAL-` advisory): text in a payload, never run.
const INSTALL_COMMAND = ['npm', 'install', 'crossenv'].join(' ');
/** The seeded file the secret check "writes": the one gitleaks is pointed at. */
export const SECRET_CANARY = 'secrets/app.properties';

const preToolUse = (ws: Workspace, tool: string, input: Record<string, unknown>): Record<string, unknown> => ({
  hook_event_name: 'PreToolUse',
  tool_name: tool,
  tool_input: input,
  cwd: ws.project,
});

export const HOOK_CHECKS: readonly HookCheck[] = [
  {
    id: 'hooks:bash-block',
    event: 'PreToolUse',
    expect: 'deny',
    payload: (ws) => preToolUse(ws, 'Bash', { command: BASH_COMMAND }),
  },
  {
    id: 'hooks:powershell-block',
    event: 'PreToolUse',
    expect: 'deny',
    payload: (ws) => preToolUse(ws, 'PowerShell', { command: POWERSHELL_COMMAND }),
  },
  {
    id: 'hooks:settings-guard',
    event: 'PreToolUse',
    expect: 'deny',
    payload: (ws) =>
      preToolUse(ws, 'Write', {
        file_path: join(ws.project, '.claude', 'settings.json'),
        content: JSON.stringify({ disableAllHooks: true }),
      }),
  },
  {
    id: 'hooks:install-vet',
    event: 'PreToolUse',
    expect: 'deny',
    payload: (ws) => preToolUse(ws, 'Bash', { command: INSTALL_COMMAND }),
  },
  {
    id: 'hooks:secret-warning',
    event: 'PostToolUse',
    expect: 'secret-warning',
    payload: (ws, secretText) => ({
      hook_event_name: 'PostToolUse',
      tool_name: 'Write',
      tool_input: { file_path: join(ws.project, ...SECRET_CANARY.split('/')), content: secretText },
      cwd: ws.project,
    }),
  },
];

/** Whether the dispatcher's standard output is the answer a working guard gives. */
export function answersAsExpected(check: Pick<HookCheck, 'expect'>, stdout: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    return false;
  }
  if (typeof parsed !== 'object' || parsed === null) return false;
  const out = (parsed as { hookSpecificOutput?: unknown }).hookSpecificOutput;
  if (typeof out !== 'object' || out === null) return false;
  const answer = out as { permissionDecision?: unknown; additionalContext?: unknown };
  if (check.expect === 'deny') return answer.permissionDecision === 'deny';
  return typeof answer.additionalContext === 'string' && /secret/i.test(answer.additionalContext);
}

/**
 * The line of the dispatcher's answer that says a package could not be vetted
 * (`pkgvet/hookDecision.ts`'s own words), and nothing else of the answer;
 * `undefined` when there is none. Bounded: this is what a saved result keeps.
 */
export function notVerifiedLine(stdout: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    return undefined;
  }
  const out = isObject(parsed) ? parsed['hookSpecificOutput'] : undefined;
  const context = isObject(out) ? out['additionalContext'] : undefined;
  if (typeof context !== 'string') return undefined;
  const line = context.split(/\r?\n/).find((l) => l.startsWith(COULD_NOT_VET) && l.endsWith(NOT_VERIFIED));
  return line === undefined ? undefined : line.slice(0, MAX_LINE);
}

/** The longest line kept of the dispatcher's answer: the stored reason's own bound. */
const MAX_LINE = 600;

/** The user-level hooks configuration: the one file besides the environment that may switch a guard off. */
const userHooksConfigPath = (home: string): string => join(home, '.config', 'dev-guardian', 'hooks.json');

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** How the file is named to the user: never with the home directory spelled out, which is nobody's business in a saved result. */
const USER_CONFIG_LABEL = '~/.config/dev-guardian/hooks.json';

/**
 * The user's own setting that makes `check` answer more softly, named as the
 * user wrote it — or `undefined` when nothing of theirs explains a softer
 * answer. Read as the dispatcher reads it: `GUARDIAN_HOOKS=off` and the
 * user-level `"enabled": false` switch every hook off; the shell block also
 * by `GUARDIAN_HOOKS_BASH_BLOCK=0` or `"bash": {"block": false}` (the
 * environment wins); package vetting by `GUARDIAN_PKG_VET=0`; the secret warning by `"secrets": {"warn": false}`.
 */
export function softenedBy(check: Pick<HookCheck, 'id'>, env: NodeJS.ProcessEnv, home: string): string | undefined {
  if (env['GUARDIAN_HOOKS'] === 'off') return 'GUARDIAN_HOOKS=off';
  const file = USER_CONFIG_LABEL;
  const read = readSmallJsonFile(userHooksConfigPath(home));
  const user = read.status === 'ok' && isObject(read.value) ? read.value : {};
  if (user['enabled'] === false) return `"enabled": false in ${file}`;
  if (check.id === 'hooks:bash-block' || check.id === 'hooks:powershell-block') {
    const envBlock = env['GUARDIAN_HOOKS_BASH_BLOCK'];
    if (envBlock === '0' || envBlock === 'false') return `GUARDIAN_HOOKS_BASH_BLOCK=${envBlock}`;
    if (envBlock === '1' || envBlock === 'true') return undefined;
    const bash = user['bash'];
    if (isObject(bash) && bash['block'] === false) return `"bash": {"block": false} in ${file}`;
  }
  // The dispatcher reads exactly this value (`GUARDIAN_PKG_VET === '0'`) — and it switches no other guard off.
  if (check.id === 'hooks:install-vet' && env['GUARDIAN_PKG_VET'] === '0') return 'GUARDIAN_PKG_VET=0';
  if (check.id === 'hooks:secret-warning') {
    const secrets = user['secrets'];
    if (isObject(secrets) && secrets['warn'] === false) return `"secrets": {"warn": false} in ${file}`;
  }
  return undefined;
}
