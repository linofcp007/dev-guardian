// @ts-nocheck -- Phase 4 scaffold (dev-spec-driven): the failing tests come first; the implementation replaces these bodies.
/**
 * The four checks of the guardrail hooks: what each one hands the installed
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
import type { Workspace } from './canaries.js';

export type HookCheckId = 'hooks:bash-block' | 'hooks:powershell-block' | 'hooks:settings-guard' | 'hooks:secret-warning';

export interface HookCheck {
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
  throw new Error('selftest: not implemented');
}

/** The user-level hooks configuration: the one file besides the environment that may switch a guard off. */
export const userHooksConfigPath = (home: string): string => join(home, '.config', 'dev-guardian', 'hooks.json');

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** How the file is named to the user: never with the home directory spelled out, which is nobody's business in a saved result. */
const USER_CONFIG_LABEL = '~/.config/dev-guardian/hooks.json';

/**
 * The user's own setting that makes `check` answer more softly, named as the
 * user wrote it — or `undefined` when nothing of theirs explains a softer
 * answer. Read as the dispatcher reads it: `GUARDIAN_HOOKS=off` and the
 * user-level `"enabled": false` switch every hook off; the shell block also
 * by `GUARDIAN_HOOKS_BASH_BLOCK=0` or `"bash": {"block": false}` (the
 * environment wins); the secret warning by `"secrets": {"warn": false}`.
 */
export function softenedBy(check: Pick<HookCheck, 'id'>, env: NodeJS.ProcessEnv, home: string): string | undefined {
  throw new Error('selftest: not implemented');
}
