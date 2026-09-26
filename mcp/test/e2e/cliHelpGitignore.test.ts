/**
 * `dev-guardian scan --help` tells the user what to put in `.gitignore`,
 * because the CLI never starts the MCP server that would do it for them.
 *
 * It used to say "add `.guardian/`" — a bare directory entry, after which
 * git cannot re-include anything below it: `!.guardian/baseline.json` is
 * powerless, and the baseline the CI gate reads can never be committed.
 * The server itself writes `.guardian/*` plus `!.guardian/baseline.json`
 * (`gitignoreGuard.ts`); the help — and the host rules, which said the
 * same — must name the same two lines.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { ensureGuardianIgnored } from '../../src/gitignoreGuard.js';
import { RULES_BODY } from '../../src/hostsetup/rulesTemplate.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, '..', '..', '..', 'cli', 'dev-guardian.mjs');

function help(): string {
  const r = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8', timeout: 60_000 });
  expect(r.status).toBe(0);
  return r.stdout;
}

describe('scan --help: the .gitignore advice matches what the server writes', () => {
  it('names the exact lines gitignoreGuard writes, and never a bare `.guardian/`', () => {
    const project = makeTempDir('cli-help-gitignore-');
    mkdirSync(join(project, '.git')); // the guard only writes inside a repository
    ensureGuardianIgnored(project);
    const written = readFileSync(join(project, '.gitignore'), 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.startsWith('.guardian') || l.startsWith('!.guardian'));
    expect(written).toEqual(['.guardian/*', '!.guardian/baseline.json']);

    const text = help();
    for (const line of written) expect(text).toContain(`\`${line}\``);
    expect(text).not.toMatch(/add `\.guardian\/`/);

    // The same advice in the host rules every AI host is given
    // (host-rules/*, generated from this one body).
    for (const line of written) expect(RULES_BODY).toContain(`\`${line}\``);
    expect(RULES_BODY).not.toMatch(/add `\.guardian\/`/);
  });
});
