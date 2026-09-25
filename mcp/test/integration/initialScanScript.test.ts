/**
 * `scripts/scan/initial-scan.sh` — the first-pass status `init_project` shows.
 *
 * It printed "Secrets: 0 findings" whatever gitleaks found: gitleaks exits 1
 * when it finds a leak, and the count ran only after `gitleaks … &&`. It also
 * read fixed `/tmp/_*.json` paths, so a scanner that failed was reported with
 * the PREVIOUS run's count.
 *
 * Run with the real bash `init_project` would use, against stand-in scanners
 * placed first on PATH: the script's arithmetic is what is under test, not
 * the scanners.
 */

import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { probeShell } from '../../src/platform/shellProbe.js';
import { runShellScript } from '../../src/runners/shellRunner.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const here = dirname(fileURLToPath(import.meta.url));
const SCRIPT = resolve(here, '..', '..', '..', 'scripts', 'scan', 'initial-scan.sh');

const db = new Database(':memory:');
runMigrations(db);
const SHELL = await probeShell(new Storage(db).runtimeMeta);

/** A stand-in scanner: writes `report` to the path after `flag`, exits `code`. */
function fakeTool(bin: string, name: string, flag: string, report: string, code: number): void {
  const path = join(bin, name);
  writeFileSync(
    path,
    [
      '#!/usr/bin/env bash',
      'out=""',
      'prev=""',
      'for a in "$@"; do',
      `  case "$a" in ${flag}=*) out="\${a#${flag}=}";; esac`,
      `  if [ "$prev" = "${flag}" ]; then out="$a"; fi`,
      '  prev="$a"',
      'done',
      `if [ -n "$out" ]; then printf '%s' '${report}' > "$out"; fi`,
      `exit ${code}`,
      '',
    ].join('\n'),
  );
  chmodSync(path, 0o755);
}

describe.skipIf(SHELL === null)('initial-scan.sh', () => {
  it('counts the secrets gitleaks found, although gitleaks exits 1 when it finds any', async () => {
    const bin = makeTempDir('initial-scan-bin-');
    const project = makeTempDir('initial-scan-proj-');
    mkdirSync(join(project, 'src'));
    fakeTool(bin, 'gitleaks', '--report-path', '[{"RuleID":"a"},{"RuleID":"b"}]', 1);
    fakeTool(bin, 'trivy', '--output', '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]}]}', 0);
    fakeTool(bin, 'semgrep', '--output', '{"results":[{"check_id":"x"},{"check_id":"y"},{"check_id":"z"}]}', 1);
    if (SHELL === null) return;
    const r = await runShellScript({
      shell: SHELL,
      scriptPath: SCRIPT,
      args: [project],
      cwd: project,
      env: { ...process.env, PATH: `${bin}${delimiter}${process.env['PATH'] ?? ''}` },
    });
    expect(r.stdout).toMatch(/Secrets: 2 findings/);
    expect(r.stdout).toMatch(/1 HIGH\/CRITICAL/);
    expect(r.stdout).toMatch(/SAST \(Semgrep\): 3 findings/);
  }, 60_000);

  it('says a scanner failed instead of reporting a count it does not have', async () => {
    const bin = makeTempDir('initial-scan-bin-');
    const project = makeTempDir('initial-scan-proj-');
    // Crashes without writing a report.
    fakeTool(bin, 'gitleaks', '--no-such-flag', '[]', 2);
    fakeTool(bin, 'trivy', '--no-such-flag', '{}', 2);
    fakeTool(bin, 'semgrep', '--no-such-flag', '{}', 7);
    if (SHELL === null) return;
    const r = await runShellScript({
      shell: SHELL,
      scriptPath: SCRIPT,
      args: [project],
      cwd: project,
      env: { ...process.env, PATH: `${bin}${delimiter}${process.env['PATH'] ?? ''}` },
    });
    expect(r.stdout).not.toMatch(/Secrets: 0 findings/);
    expect(r.stdout).toMatch(/Secrets: .*(failed|falhou)/i);
    expect(r.stdout).toMatch(/SAST \(Semgrep\): .*(failed|falhou)/i);
  }, 60_000);
});
