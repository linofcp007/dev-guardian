/**
 * End-to-end tests of `cli/dev-guardian.mjs mcp-config`, invoked as a REAL
 * SUBPROCESS — Task 5 of the 2026-09-25 full review, item 4 (and friends).
 *
 * `mcp-config`'s own arg parser (`parseArgs`, separate from the
 * `takeOperand`-based parsers `scan`/`baseline`/`status`/`dashboard` use) did
 * not check whether `--project`/`--scope` had a value at all: `--project`
 * as the LAST token left `args.project === undefined`, and the very next
 * line, `resolve(args.project)`, threw an UNCAUGHT
 * `TypeError [ERR_INVALID_ARG_TYPE]` — a raw Node stack trace and exit code
 * 1 (Node's default for an uncaught exception), not a clean, flag-naming
 * usage error. Reproduced directly before this fix.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const TIMEOUT_MS = 15_000;

function runCli(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: TIMEOUT_MS,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('mcp-config — --project with no value', () => {
  it('exits 2 with a clean usage error, never an uncaught TypeError stack trace', () => {
    const r = runCli(['mcp-config', 'cursor', '--project']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--project requires a value/);
    expect(r.stderr).not.toMatch(/TypeError|ERR_INVALID_ARG_TYPE|at Object|at async/);
  });

  it('--scope with no value also exits 2 cleanly', () => {
    const r = runCli(['mcp-config', 'cursor', '--scope']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--scope requires a value/);
    expect(r.stderr).not.toMatch(/TypeError|at Object|at async/);
  });

  it('a well-formed preview call is unaffected', () => {
    const r = runCli(['mcp-config', 'cursor']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/dev-guardian/);
  });
});

describe('mcp-config --write — CLI path substitution + delimited rules block (items 6a/6b)', () => {
  let project: string;

  beforeEach(() => {
    project = mkdtempSync(join(tmpdir(), 'guardian-mcpconfig-'));
  });
  afterEach(() => {
    rmSync(project, { recursive: true, force: true });
  });

  it('the installed codex rules file names an absolute CLI path, never the repo-relative one', () => {
    const r = spawnSync(
      process.execPath,
      [CLI, 'mcp-config', 'codex', '--write', '--project', project],
      { encoding: 'utf8', timeout: TIMEOUT_MS },
    );
    expect(r.status).toBe(0);
    const agentsMd = join(project, 'AGENTS.md');
    expect(existsSync(agentsMd)).toBe(true);
    const content = readFileSync(agentsMd, 'utf8');
    expect(content).not.toContain('{{DEV_GUARDIAN_CLI}}');
    // Never the literal repo-relative form a template shipped with — that
    // path does not exist inside `project`.
    expect(content).not.toMatch(/node cli\/dev-guardian\.mjs/);
    expect(content).toContain(resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs'));
  });

  it('installing over an existing AGENTS.md never destroys the user\'s own content', () => {
    writeFileSync(join(project, 'AGENTS.md'), '# My project\n\nNever touch prod.\n', 'utf8');
    const r = spawnSync(
      process.execPath,
      [CLI, 'mcp-config', 'codex', '--write', '--project', project],
      { encoding: 'utf8', timeout: TIMEOUT_MS },
    );
    expect(r.status).toBe(0);
    const content = readFileSync(join(project, 'AGENTS.md'), 'utf8');
    expect(content).toContain('Never touch prod.');
    expect(content).toContain('<!-- dev-guardian:begin -->');
  });
});

describe('mcp-config all --write — global-only hosts require explicit --global (item 6d)', () => {
  it('windsurf/claude-desktop report skipped at the default project scope', () => {
    const project = mkdtempSync(join(tmpdir(), 'guardian-mcpconfig-all-'));
    try {
      const r = spawnSync(
        process.execPath,
        [CLI, 'mcp-config', 'all', '--write', '--project', project],
        { encoding: 'utf8', timeout: TIMEOUT_MS },
      );
      expect(r.status).toBe(0);
      expect(r.stdout).toMatch(/## windsurf[\s\S]*?skipped/);
      expect(r.stdout).toMatch(/## claude-desktop[\s\S]*?skipped/);
    } finally {
      rmSync(project, { recursive: true, force: true });
    }
  });
});

describe('check --help documents exit code 2', () => {
  it('the usage screen names exit code 2 in the check section', () => {
    const r = runCli(['check', '--help']);
    expect(r.status).toBe(0);
    // The check section documents its own exit codes, including 2 (usage
    // error / file not found) alongside the existing 0/1 documentation.
    const checkSection = r.stdout.slice(r.stdout.indexOf('check — run the guardrail detectors'));
    expect(checkSection).toMatch(/2 = /);
  });
});
