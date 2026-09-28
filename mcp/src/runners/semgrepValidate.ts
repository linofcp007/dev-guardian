/**
 * Does Semgrep itself accept a rule file? — `semgrep --validate`.
 *
 * `register_custom_rules` checks a file's shape (`platform/customRules.ts`:
 * a non-empty `rules:` list, each rule with an id, message, languages,
 * severity and a pattern). That misses what only Semgrep knows: a rule with
 * `languages: [klingon]` passes the shape check, and one such file makes
 * Semgrep refuse the WHOLE configuration — exit 8, `UnknownLanguageError`,
 * nothing scanned (measured on 1.176.1) — on every later scan_sast and
 * bug_hunt. `--validate` compiles the rules without scanning:
 *
 *   a good file                → exit 0, "Configuration is valid …"
 *   a broken pattern           → exit 2, "[ERROR] Pattern parse error in rule …"
 *   an unknown language        → exit 8, "semgrep error: invalid language: klingon"
 *
 * All the files are validated in one run; only when that run refuses them
 * is each file validated on its own, to say which. A run that could not
 * give an answer (it did not start, timed out, or was cancelled) validates
 * nothing — the caller keeps the shape check and says Semgrep did not look.
 * `--metrics=off`: nothing is sent anywhere.
 */

import { pythonUtf8Env } from './semgrepReport.js';
import { runProcess } from './processRunner.js';

/** Bound on one `semgrep --validate` run. */
export const SEMGREP_VALIDATE_TIMEOUT_MS = 60_000;

export type SemgrepValidation =
  | { validated: true; invalid: Map<string, string> }
  | { validated: false; reason: string };

const ANSI = /\u001b\[[0-9;]*m/g;
const MAX_MESSAGE = 400;

/** Semgrep's own words for why it refused a config: its error lines, else its first lines. */
export function validateMessage(stderr: string, stdout: string): string {
  const lines = `${stderr}\n${stdout}`
    .replace(ANSI, '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !/^(A new version of Semgrep|If Semgrep missed|See https:|Configuration is invalid)/.test(l));
  const start = lines.findIndex((l) => /^(semgrep error:|\[ERROR\])/i.test(l));
  const picked = (start >= 0 ? lines.slice(start, start + 3) : lines.slice(0, 3)).join(' ');
  const text = picked.length > 0 ? picked : 'semgrep refused the configuration';
  return text.length > MAX_MESSAGE ? `${text.slice(0, MAX_MESSAGE - 1)}…` : text;
}

async function validateOnce(
  files: readonly string[],
  cwd: string,
): Promise<{ answered: true; ok: boolean; message: string } | { answered: false; reason: string }> {
  const run = await runProcess({
    command: 'semgrep',
    args: ['--validate', '--metrics=off', '--disable-version-check', ...files.flatMap((f) => ['--config', f])],
    cwd,
    env: pythonUtf8Env(process.env),
    timeoutMs: SEMGREP_VALIDATE_TIMEOUT_MS,
  });
  if (run.outcome === 'timed_out' || run.outcome === 'cancelled' || run.outcome === 'output_too_large' || run.exitCode === null) {
    return { answered: false, reason: `semgrep --validate did not finish (${run.outcome})` };
  }
  if (run.exitCode === 0) return { answered: true, ok: true, message: '' };
  return { answered: true, ok: false, message: validateMessage(run.stderr, run.stdout) };
}

/** `semgrep --validate` over `files` (Semgrep must be on PATH): which it refuses, and why. */
export async function validateRuleFiles(files: readonly string[], cwd: string): Promise<SemgrepValidation> {
  const invalid = new Map<string, string>();
  if (files.length === 0) return { validated: true, invalid };
  const all = await validateOnce(files, cwd);
  if (!all.answered) return { validated: false, reason: all.reason };
  if (all.ok) return { validated: true, invalid };
  if (files.length === 1) {
    const only = files[0];
    if (only !== undefined) invalid.set(only, all.message);
    return { validated: true, invalid };
  }
  for (const file of files) {
    const one = await validateOnce([file], cwd);
    if (!one.answered) return { validated: false, reason: one.reason };
    if (!one.ok) invalid.set(file, one.message);
  }
  return { validated: true, invalid };
}
