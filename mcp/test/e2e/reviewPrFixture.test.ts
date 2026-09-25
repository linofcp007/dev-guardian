/**
 * `review_pr` end to end with REAL Semgrep and gitleaks, on a real git branch
 * whose changes are exactly the paths `review-scan.sh` lost: a deleted file,
 * a path with a space, a Latin-1 accent, a CJK name, and a name starting with
 * `-`. With the script, the deleted file alone made Semgrep scan nothing and
 * the review report 0 findings, `ok`.
 *
 * `local_only` with a one-rule `.semgrep.yml`, so the run is offline and the
 * expected findings are exact. SKIPPED without Semgrep on PATH;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that into a failure.
 */

import { execa } from 'execa';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/reviewPr.js');
  resetScannerCache();
});

const SLOW = 300_000;
const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const RULES = `rules:
  - id: no-eval
    languages: [python]
    severity: ERROR
    message: eval on dynamic input
    pattern: eval(...)
`;

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execa('git', args, { cwd });
}

function write(dir: string, rel: string, content: string): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

describe('review_pr with real Semgrep', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — semgrep must be on PATH', () => {
    expect(SEMGREP_INSTALLED).toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)(
    'finds the issue in every awkwardly named changed file, and a deleted file costs nothing',
    async () => {
      const dir = makeTempDir('review-pr-e2e-');
      await git(dir, 'init', '-q');
      await git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
      await git(dir, 'config', 'user.email', 'guardian-test@example.com');
      await git(dir, 'config', 'user.name', 'Guardian Test');
      await git(dir, 'config', 'commit.gpgsign', 'false');
      write(dir, '.semgrep.yml', RULES);
      write(dir, 'gone.py', 'x = 1\n');
      await git(dir, 'add', '-A');
      await git(dir, 'commit', '-q', '-m', 'base');
      await git(dir, 'checkout', '-q', '-b', 'feature');

      rmSync(join(dir, 'gone.py'));
      const changed = ['-dash.py', 'sub dir/my file.py', 'héllo.py', '日本.py'];
      for (const f of changed) write(dir, f, 'eval(user_input)\n');
      await git(dir, 'add', '-A');
      await git(dir, 'commit', '-q', '-m', 'feature');

      const db = new Database(':memory:');
      runMigrations(db);
      const plugin: PluginContext = {
        storage: new Storage(db),
        shell: null,
        scriptsDir: dir,
        progressNotifier: { send: () => {} },
      };
      const tool = TOOLS.find((t) => t.name === 'review_pr');
      if (!tool) throw new Error('review_pr not registered');
      const r = await tool.handler({ project_path: dir, base_ref: 'main', local_only: true }, plugin);
      expect(r.ok, JSON.stringify(r)).toBe(true);
      const res = r as unknown as { scan_id: string; tools_run: ToolRun[] };

      const semgrep = res.tools_run.find((t) => t.name === 'semgrep');
      expect(semgrep?.status, semgrep?.reason).toBe('ok');
      const paths = plugin.storage.findings
        .listByScan(res.scan_id)
        .filter((f) => f.tool === 'semgrep')
        .map((f) => f.file_path)
        .sort();
      expect(paths).toEqual([...changed].sort());
    },
    SLOW,
  );
});
