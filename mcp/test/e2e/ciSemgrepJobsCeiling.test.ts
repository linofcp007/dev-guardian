/**
 * 3.18.0 review 1 (R1-XPLUG-01): `semgrep.jobs` in `.guardian/scan.yml` can only LOWER Semgrep's analysis domains.
 * The file is the working tree's in every gate run without `--rules-ref` — dev-spec-driven's finish gate — and every
 * domain more shares Semgrep's one taint budget: one agent-written `jobs: 24` on a 24-core machine passed a feature's
 * command injection (request query → exec) that the default blocked. The reviewer's jobs-gate shape through the real
 * CLI, real git and the real Semgrep (`--local-only`): legacy handlers of the same shape baselined, a feature adding
 * four, and the change's own scan.yml asking for 256 domains — every one of the feature's findings still blocks.
 *
 * Measured on a 24-core machine (Semgrep 1.182.0, 24 files of 20 links): `--jobs 4` 24/24 results twice, `--jobs 24`
 * 0, `--jobs 256` 2 — so 3.18.0 before the fix let this change through. A machine of 4 cores or fewer runs the same
 * count either way (one domain per core at most runs at once), which is what the row asserts: the default's count.
 */

import { execa } from 'execa';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, '..', '..', '..', 'cli', 'dev-guardian.mjs');
/** A hang-breaker for one CLI run; nothing asserts by reaching it. */
const RUN_TIMEOUT_MS = 600_000;
vi.setConfig({ testTimeout: timeoutAbove(RUN_TIMEOUT_MS), hookTimeout: timeoutAbove(2 * RUN_TIMEOUT_MS) });
afterAll(cleanupTempDirs);

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const RULES = `rules:
  - id: exec-taint
    mode: taint
    languages: [javascript]
    severity: ERROR
    message: request data reaches exec
    pattern-sources:
      - pattern: $REQ.query.$X
    pattern-sinks:
      - pattern: exec(...)
`;
const LEGACY = 20;
const FEATURE = 4;
const LINKS = 20;

/** A request handler whose query value reaches exec through `links` assignments (the reviewer's shape). */
function handler(name: string, links: number): string {
  const lines = ["const { exec } = require('child_process');", `function ${name}(req, n) {`, '  let a0 = req.query.cmd;'];
  for (let k = 1; k <= links; k++) lines.push(`  let a${k} = '';`);
  lines.push('  while (n-- > 0) {');
  for (let k = links; k >= 1; k--) lines.push(`    a${k} = a${k - 1} + '';`);
  lines.push('  }', `  exec(a${links});`, '}', `module.exports = { ${name} };`);
  return `${lines.join('\n')}\n`;
}

interface Verdict {
  exit_code?: number;
  blocking_findings?: Array<{ file_path?: string; rule_id?: string }>;
  coverage_notes?: string[];
}

function cli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  return spawnSyncCapped(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: RUN_TIMEOUT_MS, env: process.env });
}

describe('semgrep.jobs above the default never costs the gate a finding (real Semgrep)', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    expect(SEMGREP_INSTALLED, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH').toBe(true);
  });

  let scan = { status: null as number | null, stdout: '', stderr: '' };

  beforeAll(async () => {
    if (!SEMGREP_INSTALLED) return;
    const dir = makeTempDir('ci-semgrep-jobs-');
    const git = async (...args: string[]): Promise<void> => {
      await execa('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'core.autocrlf=false', ...args], { cwd: dir });
    };
    await git('init', '-q');
    await git('config', 'core.autocrlf', 'false');
    mkdirSync(join(dir, 'src', 'legacy'), { recursive: true });
    for (let i = 0; i < LEGACY; i++) writeFileSync(join(dir, 'src', 'legacy', `h${i}.js`), handler(`legacy${i}`, LINKS));
    writeFileSync(join(dir, '.semgrep.yml'), RULES);
    await git('add', '-A');
    await git('commit', '-qm', 'base');
    cli(['baseline', 'update', '--project', dir, '--local-only']);
    // The feature, and the change's own scan.yml asking for more domains than the default.
    mkdirSync(join(dir, 'src', 'api'), { recursive: true });
    for (let i = 0; i < FEATURE; i++) writeFileSync(join(dir, 'src', 'api', `v${i}.js`), handler(`api${i}`, LINKS));
    writeFileSync(join(dir, '.guardian', 'scan.yml'), 'semgrep:\n  jobs: 256\n');
    scan = cli(['scan', '--project', dir, '--local-only', '--fail-on', 'high', '--format', 'json']);
  });

  it.skipIf(!SEMGREP_INSTALLED)("every one of the feature's request-to-exec findings blocks, at jobs: 256 as at the default", () => {
    const v = JSON.parse(scan.stdout) as Verdict;
    const feature = (v.blocking_findings ?? []).filter((f) => /^src[\\/]api[\\/]/.test(f.file_path ?? '')).map((f) => f.file_path?.replace(/\\/g, '/'));
    expect(feature.sort()).toEqual(Array.from({ length: FEATURE }, (_x, i) => `src/api/v${i}.js`));
    expect(scan.status).toBe(1);
    // And the gate says the setting was not applied: one note, never gating.
    expect((v.coverage_notes ?? []).filter((n) => /^semgrep: \.guardian\/scan\.yml semgrep\.jobs 256 is above dev-guardian's default/.test(n))).toHaveLength(1);
  });
});
