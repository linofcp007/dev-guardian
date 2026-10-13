/**
 * `dev-guardian scan --help` tells the user what to put in `.gitignore`,
 * because the CLI never starts the MCP server that would do it for them.
 *
 * It used to say "add `.guardian/`" — a bare directory entry, after which
 * git cannot re-include anything below it: `!.guardian/baseline.json` is
 * powerless, and the baseline the CI gate reads can never be committed.
 * The server itself writes the two lines in `gitignoreGuard.ts` (every
 * `.guardian`'s contents, its `baseline.json` re-included); the help — and the host rules, which said the
 * same — must name the same two lines.
 */

import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { ensureGuardianIgnored } from '../../src/gitignoreGuard.js';
import { RULES_BODY } from '../../src/hostsetup/rulesTemplate.js';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, '..', '..', '..', 'cli', 'dev-guardian.mjs');
/** Hang-breaker for one CLI run; nothing asserts by reaching it. */
const TIMEOUT_MS = 60_000;
// Above the cap, so a hung CLI is reported by the cap — naming it — and not
// by vitest's 10 s default failing the test after the fact (R7-I1).
vi.setConfig({ testTimeout: timeoutAbove(TIMEOUT_MS) });

function help(): string {
  const r = spawnSyncCapped(process.execPath, [CLI, '--help'], { encoding: 'utf8', timeout: TIMEOUT_MS });
  expect(r.status).toBe(0);
  return r.stdout;
}

/** The lines `gitignoreGuard.ts` writes, as git reads them (3.3.0: the shared files re-included too — review 8, C6). */
function writtenLines(): string[] {
  const project = makeTempDir('cli-help-gitignore-');
  mkdirSync(join(project, '.git')); // the guard only writes inside a repository
  ensureGuardianIgnored(project);
  return readFileSync(join(project, '.gitignore'), 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.includes('.guardian') && !l.startsWith('#'));
}

describe('scan --help: the .gitignore advice matches what the server writes', () => {
  it('names the exact lines gitignoreGuard writes, and never a bare `.guardian/`', () => {
    const written = writtenLines();
    expect(written).toEqual([
      '**/.guardian/*',
      '!**/.guardian/baseline.json',
      '!**/.guardian/budgets.yml',
      '!**/.guardian/hooks.config.json',
      '!**/.guardian/hooks-allowlist.json',
      '!**/.guardian/scan.yml',
    ]);

    const text = help();
    for (const line of written) expect(text).toContain(`\`${line}\``);
    expect(text).not.toMatch(/add `\.guardian\/`/);
  });

  it('the host rules every AI host is given name the same lines (host-rules/*, generated from this one body)', () => {
    for (const line of writtenLines()) expect(RULES_BODY).toContain(`\`${line}\``);
    expect(RULES_BODY).not.toMatch(/add `\.guardian\/`/);
  });
});
