/**
 * `node cli/dev-guardian.mjs import-sarif <file> [--project <dir>]
 * [--allow-outside-project]` as a REAL SUBPROCESS — the `sarif-import`
 * feature's test plan T-19 (US-2.AC-1, US-2.AC-2).
 *
 * The same import as the `import_sarif` tool, for a log that arrives as a
 * pipeline artefact: it prints each scan's id and the counts, and exits with
 * the CLI's conventions — 0 imported, 1 an invalid or refused log, 2 a partial
 * import (`skipped`, or the results limit), 3 a usage error. Exit codes and
 * stdout flushing cannot be observed in process, hence the subprocess (as in
 * `dashboardCli.test.ts`). The CLI runs `mcp/dist/`, so this file goes green
 * only once the implementation is built.
 */

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { sarifLog, sarifResult, sarifRun, writeSarif, type JsonObject } from '../helpers/sarif.js';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const CLI = resolve(REPO_ROOT, 'cli', 'dev-guardian.mjs');
const TIMEOUT_MS = 30_000;
vi.setConfig({ testTimeout: timeoutAbove(TIMEOUT_MS) });

afterAll(cleanupTempDirs);

/** Node can always spawn itself; the guard is the plan's "skip only if Node cannot spawn". */
const CAN_SPAWN = existsSync(process.execPath) && existsSync(CLI);

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSyncCapped(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: TIMEOUT_MS,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const project = (): string => resolveProjectPath(makeTempDir('sarif-cli-')).path;

const ok = (message: string, line: number): JsonObject =>
  sarifResult({ ruleId: 'r1', level: 'warning', message, uri: 'src/a.js', startLine: line, partialFingerprints: { h: message } });

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

/** `name` printed with the count `n`, in either order ("imported: 2", "2 imported"). */
function countLine(name: string, n: number): RegExp {
  return new RegExp(`(${name}\\W{0,4}${String(n)}\\b)|(\\b${String(n)}\\W{0,4}${name})`, 'i');
}

describe('T-19 the import-sarif CLI subcommand (US-2.AC-1, US-2.AC-2)', () => {
  it.skipIf(!CAN_SPAWN)('T-19 imports a log, prints the scan id and every count, and exits 0', () => {
    const dir = project();
    const file = writeSarif(
      dir,
      'ci/results.sarif',
      sarifLog([
        sarifRun({
          tool: 'CodeQL',
          results: [
            ok('one', 1),
            ok('two', 2),
            sarifResult({ ruleId: 'r1', kind: 'pass', message: 'fine', uri: 'src/a.js', startLine: 3 }),
            sarifResult({ ruleId: 'r1', message: 'nowhere', locations: [] }),
            sarifResult({ ruleId: 'r1', message: 'waived', uri: 'src/a.js', startLine: 4, suppressions: [{ kind: 'inSource', status: 'accepted' }] }),
          ],
        }),
      ]),
    );
    const r = runCli(['import-sarif', file, '--project', dir]);
    expect(r.stderr).not.toMatch(/Unknown command/);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(UUID);
    expect(r.stdout).toMatch(countLine('without_location', 1));
    expect(r.stdout).toMatch(countLine('skipped', 0));
    expect(r.stdout).toMatch(countLine('suppressed_at_source', 1));
    expect(r.stdout).toMatch(countLine('not_findings', 1));
    expect(r.stdout).toMatch(/imported/i);
  });

  it.skipIf(!CAN_SPAWN)('T-19 a partial import (a skipped result) exits 2 and says so', () => {
    const dir = project();
    const file = writeSarif(dir, 'partial.sarif', sarifLog([sarifRun({ results: [ok('one', 1), sarifResult({ message: null, uri: 'src/b.js', startLine: 1 })] })]));
    const r = runCli(['import-sarif', file, '--project', dir]);
    expect(r.stderr).not.toMatch(/Unknown command/);
    expect(r.status, r.stderr).toBe(2);
    expect(r.stdout).toMatch(UUID);
    expect(r.stdout).toMatch(countLine('skipped', 1));
  });

  it.skipIf(!CAN_SPAWN)('T-19 an invalid log exits 1 naming the problem', () => {
    const dir = project();
    const file = writeSarif(dir, 'old.sarif', { version: '2.0.0', runs: [] });
    const r = runCli(['import-sarif', file, '--project', dir]);
    expect(r.stderr).not.toMatch(/Unknown command/);
    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toMatch(/invalid_sarif|version/i);
  });

  it.skipIf(!CAN_SPAWN)('T-19 a log outside the project exits 1 without --allow-outside-project, and 0 with it', () => {
    const dir = project();
    const outside = writeSarif(makeTempDir('sarif-cli-outside-'), 'artifact.sarif', sarifLog([sarifRun({ results: [ok('one', 1)] })]));
    const refused = runCli(['import-sarif', outside, '--project', dir]);
    expect(refused.stderr).not.toMatch(/Unknown command/);
    expect(refused.status).toBe(1);
    expect(`${refused.stdout}${refused.stderr}`).toMatch(/outside/i);
    const allowed = runCli(['import-sarif', outside, '--project', dir, '--allow-outside-project']);
    expect(allowed.status, allowed.stderr).toBe(0);
    expect(allowed.stdout).toMatch(UUID);
  });

  it.skipIf(!CAN_SPAWN)('T-19 usage errors exit 3: no file, and an unknown flag', () => {
    const dir = project();
    const noFile = runCli(['import-sarif', '--project', dir]);
    expect(noFile.stderr).not.toMatch(/Unknown command/);
    expect(noFile.status).toBe(3);
    const file = writeSarif(dir, 'a.sarif', sarifLog([sarifRun({ results: [ok('one', 1)] })]));
    const badFlag = runCli(['import-sarif', file, '--project', dir, '--no-such-flag']);
    expect(badFlag.stderr).not.toMatch(/Unknown command/);
    expect(badFlag.status).toBe(3);
  });
});
