/**
 * What the `scan --baseline-ref / --rules-ref / --reset-exclusions-from` e2e
 * files share: the CLI run as a real subprocess, real repositories, and the
 * rules and sources their pull requests change (`test/e2e/ciRefGate*.test.ts`,
 * one file per attack since review 8, finding 6: as one file it was the
 * suite's longest, 244 s, its three real-scan blocks one after another).
 */

import { execa } from 'execa';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { makeTempDir } from './tempDir.js';
import { isInstalled } from './toolchain.js';

const here = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(here, '..', '..', '..');
export const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');

/** A hang-breaker for one real pipeline run on a loaded machine — see ciCliFixture.test.ts. */
export const SCAN_TIMEOUT_MS = 600_000;
export const FAST_TIMEOUT_MS = 45_000;
export const SEMGREP_INSTALLED = await isInstalled('semgrep');
export const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
export const RUN_REAL = SEMGREP_INSTALLED || REQUIRE_SEMGREP;

export const RULES = `rules:
  - id: guardian-test-no-eval
    languages: [javascript]
    severity: ERROR
    message: eval of input
    pattern: eval($X)
`;
export const WEAKENED = `rules:
  - id: guardian-test-no-eval
    languages: [javascript]
    severity: ERROR
    message: eval of input
    pattern: guardian_nothing_matches_this($X)
`;
export const CLEAN_JS = "'use strict';\nmodule.exports = (a, b) => a + b;\n";
export const EVAL_JS = "'use strict';\nmodule.exports = (input) => eval(input);\n";

/** The environment of a run: this process's, with every CI marker removed (a developer's shell), plus `extra`. */
export function envWith(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BITBUCKET_BUILD_NUMBER']) delete env[key];
  return { ...env, ...extra };
}
export const IN_CI = envWith({ CI: 'true' });

export function runCli(args: string[], timeout = SCAN_TIMEOUT_MS, env: NodeJS.ProcessEnv = envWith()): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout, env });
}

export async function git(cwd: string, ...args: string[]): Promise<string> {
  return (await execa('git', args, { cwd })).stdout;
}

export function write(root: string, rel: string, text: string): void {
  const path = join(root, ...rel.split('/'));
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

export async function newRepo(prefix: string): Promise<string> {
  const dir = makeTempDir(prefix);
  await git(dir, 'init', '-q');
  await git(dir, 'config', 'user.email', 'guardian-ci-ref@example.com');
  await git(dir, 'config', 'user.name', 'Guardian CI Ref');
  await git(dir, 'config', 'commit.gpgsign', 'false');
  await git(dir, 'config', 'core.autocrlf', 'false');
  write(dir, 'package.json', '{"name":"guardian-ci-ref","version":"1.0.0","private":true}\n');
  write(dir, '.gitignore', '**/.guardian/*\n!**/.guardian/baseline.json\n');
  return dir;
}

export async function commitAll(dir: string, message: string): Promise<string> {
  await git(dir, 'add', '-A');
  await git(dir, 'commit', '-q', '-m', message);
  return (await git(dir, 'rev-parse', 'HEAD')).trim();
}

export interface JsonReport {
  exit_code: number;
  blocking_findings: Array<{ title: string; file_path?: string; rule_id?: string }>;
  new_findings: unknown[];
  baseline_absent: boolean;
  baseline_source: Record<string, unknown>;
  rules_source: Record<string, unknown> & { tree_differences?: Array<Record<string, unknown>> };
}

export function scanJson(project: string, ...extra: string[]): { status: number | null; report: JsonReport; stderr: string } {
  // In CI: --reset-exclusions-from runs only there, and the other flags do not care.
  const r = runCli(['scan', '--project', project, '--local-only', '--format', 'json', ...extra], SCAN_TIMEOUT_MS, IN_CI);
  let report: JsonReport;
  try {
    report = JSON.parse(r.stdout) as JsonReport;
  } catch {
    throw new Error(`no JSON report (exit ${String(r.status)}):\n${r.stdout}\n${r.stderr}`);
  }
  return { status: r.status, report, stderr: r.stderr };
}

export const blockingFiles = (report: JsonReport): string[] =>
  report.blocking_findings.map((f) => (f.file_path ?? '').replace(/\\/g, '/')).sort();

export const GITLEAKS_INSTALLED = await isInstalled('gitleaks');
