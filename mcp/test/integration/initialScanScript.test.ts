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

  /**
   * The status report runs Trivy and Semgrep in the project too: the same
   * rules as the MCP tools (runners/trivyRun.ts, runners/semgrepRun.ts) —
   * never the project's trivy.yaml, never check.trivy.dev, Semgrep in UTF-8
   * mode, and the project's .trivyignore named when it is honoured.
   */
  it("never reads the project's trivy.yaml, never phones home, runs Semgrep in UTF-8 mode", async () => {
    const bin = makeTempDir('initial-scan-bin-');
    const project = makeTempDir('initial-scan-proj-');
    writeFileSync(join(project, 'trivy.yaml'), 'severity:\n  - UNKNOWN\n');
    writeFileSync(join(project, '.trivyignore'), 'CVE-1\n');
    const log = join(bin, 'calls.log');
    for (const name of ['trivy', 'semgrep']) {
      const path = join(bin, name);
      writeFileSync(
        path,
        [
          '#!/usr/bin/env bash',
          `printf '%s|%s|%s|%s|%s|%s\\n' "${name}" "$*" "\${TRIVY_SKIP_VERSION_CHECK:-}" "\${TRIVY_DISABLE_TELEMETRY:-}" "\${PYTHONUTF8:-}" "\${SEMGREP_ENABLE_VERSION_CHECK:-}" >> '${log.replace(/\\/g, '/')}'`,
          'exit 3',
          '',
        ].join('\n'),
      );
      chmodSync(path, 0o755);
    }
    if (SHELL === null) return;
    // Explicitly off (the runner merges the server's own environment, which may set it):
    // only the script itself can turn them on.
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PATH: `${bin}${delimiter}${process.env['PATH'] ?? ''}`,
      PYTHONUTF8: '0',
      TRIVY_SKIP_VERSION_CHECK: 'false',
      TRIVY_DISABLE_TELEMETRY: 'false',
      SEMGREP_ENABLE_VERSION_CHECK: '1',
    };
    const r = await runShellScript({ shell: SHELL, scriptPath: SCRIPT, args: [project], cwd: project, env });
    const { readFileSync } = await import('node:fs');
    const calls = readFileSync(log, 'utf8').trim().split('\n');
    const fields = (tool: string): string[] => (calls.find((c) => c.startsWith(`${tool}|`)) ?? '').split('|');
    const trivy = fields('trivy');
    expect(trivy[1]).toMatch(/--config \S*trivy-config\.yaml/);
    expect([trivy[2], trivy[3]]).toEqual(['true', 'true']);
    expect(fields('semgrep')[4]).toBe('1');
    // Review 3.0, wave 2 (d): Semgrep's version check is off here too.
    expect(fields('semgrep')[5]).toBe('0');
    expect(r.stdout).toMatch(/honra o \.trivyignore/);
    // Round 5, item 3: what it suppressed is not counted here; the line says where it is.
    expect(r.stdout).toMatch(/honra o \.trivyignore do projeto.*o scan_deps diz quantos achados suprimiu, e quais/);
  }, 60_000);
});
