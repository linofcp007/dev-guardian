/**
 * scan_sast over a project where one file per scanner can be read only in
 * part — against the REAL Semgrep and Bandit (bugfix
 * sast-partial-parse-as-failed).
 *
 * Measured on OWASP Juice Shop (1618a61): a GitHub Actions workflow whose
 * `run:` block a bash sub-pattern cannot read made Semgrep `failed` (the
 * judge refused any `.yml` path as a per-file error), two Python fixtures
 * with syntax errors made Bandit `failed`, and scan_sast reported coverage
 * `none` — "no scanner ran" — over 969 files read and 68 real results. The
 * workflow and the rule below reproduce the Semgrep half locally (no
 * registry): 10 lines, exit 0, one result, one warn-level PartialParsing on
 * the workflow.
 *
 * Gated on Semgrep and Bandit being on PATH.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  resetScannerCache();
});

const TOOLCHAIN = (await isInstalled('semgrep')) && (await isInstalled('bandit'));

const WORKFLOW =
  'name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: tools\n        run: |\n' +
  '          npm install -g typescript@${{ env.TYPESCRIPT_VERSION }}\n          npm install -g archiver\n';
const RULES =
  'rules:\n  - id: run-npm-global\n    languages: [yaml]\n    severity: INFO\n    message: global npm install in a workflow\n' +
  '    patterns:\n      - pattern: "run: $SHELL"\n      - metavariable-pattern:\n          metavariable: $SHELL\n' +
  '          language: bash\n          pattern: npm install -g $PKG\n';

function project(): string {
  const dir = resolveProjectPath(makeTempDir('sast-partial-parse-')).path;
  const files: Record<string, string> = {
    '.github/workflows/ci.yml': WORKFLOW,
    '.semgrep.yml': RULES,
    'app/a.py': 'import subprocess\n\n\ndef f(x):\n    subprocess.call(x, shell=True)\n',
    'test/files/broken.py': 'def f(:\n    pass\n',
  };
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

describe('scan_sast: a file per scanner read only in part is a partial gap, not a failed scanner', () => {
  it.skipIf(!TOOLCHAIN)('T-04 coverage partial, both scanners ok and missing with their file named, findings kept', async () => {
    const dir = project();
    const tool = TOOLS.find((t) => t.name === 'scan_sast');
    if (!tool) throw new Error('scan_sast not registered');
    const db = new Database(':memory:');
    runMigrations(db);
    const p: PluginContext = { storage: new Storage(db), shell: null, scriptsDir: dir, progressNotifier: { send: () => {} } };
    const r = await tool.handler({ project_path: dir, force: true, local_only: true }, p);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const out = r as unknown as { scan_id: string; coverage: string; tools_run: ToolRun[]; missing_tools: string[] };

    expect(out.coverage).toBe('partial');
    const semgrep = out.tools_run.find((t) => t.name === 'semgrep');
    const bandit = out.tools_run.find((t) => t.name === 'bandit');
    expect(semgrep?.status).toBe('ok');
    expect(bandit?.status).toBe('ok');
    expect(out.missing_tools).toEqual(expect.arrayContaining(['semgrep', 'bandit']));
    expect(semgrep?.partially_parsed?.map((x) => x.file)).toContain('.github/workflows/ci.yml');
    expect(bandit?.partially_parsed?.map((x) => x.file)).toEqual(['test/files/broken.py']);

    const findings = p.storage.findings.listByScan(out.scan_id);
    expect(findings.some((f) => f.tool === 'semgrep' && (f.rule_id ?? '').endsWith('run-npm-global'))).toBe(true);
    expect(findings.some((f) => f.tool === 'bandit' && f.rule_id === 'B602')).toBe(true);
  });
});
