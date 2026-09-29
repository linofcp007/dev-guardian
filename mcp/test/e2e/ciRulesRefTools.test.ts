/**
 * The CI gate's `--rules-ref`, at the tool level, against the REAL scanners:
 * a `PluginContext.repoConfigFromRef` makes `scan_sast` read the project's
 * Semgrep rules, `.bandit` and `.guardianignore` from the ref's copy
 * (`ci/refConfig.ts`), and never the scanned tree's — which, on a pull
 * request, is the pull request's. `ciRefGate.test.ts` runs the whole gate
 * through the CLI; this file pins each file's wiring on its own.
 *
 * Gated on Bandit and Semgrep being on PATH, each test on the one it needs.
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
import type { Finding, ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  resetScannerCache();
});

const BANDIT_INSTALLED = await isInstalled('bandit');
const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const PY = 'import subprocess\n\n\ndef f(x):\n    assert x\n    subprocess.call(x, shell=True)\n';
const SKIP_ALL = '[bandit]\nskips: B101,B602,B404\n';
const NO_EVAL = `rules:
  - id: guardian-test-no-eval
    languages: [javascript]
    severity: ERROR
    message: eval of input
    pattern: eval($X)
`;
const HARMLESS = `rules:
  - id: guardian-test-harmless
    languages: [javascript]
    severity: INFO
    message: never matches
    pattern: guardian_nothing_matches_this($X)
`;

function tree(prefix: string, files: Record<string, string>): string {
  const dir = resolveProjectPath(makeTempDir(prefix)).path;
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, ...rel.split('/'))), { recursive: true });
    writeFileSync(join(dir, ...rel.split('/')), body);
  }
  return dir;
}

async function sast(
  project: string,
  fromRef: string | null,
): Promise<{ findings: Finding[]; toolsRun: ToolRun[] }> {
  const tool = TOOLS.find((t) => t.name === 'scan_sast');
  if (!tool) throw new Error('scan_sast not registered');
  const db = new Database(':memory:');
  runMigrations(db);
  const p: PluginContext = {
    storage: new Storage(db),
    shell: null,
    scriptsDir: project,
    progressNotifier: { send: () => {} },
    ...(fromRef !== null ? { repoConfigFromRef: { root: fromRef, ref: 'origin/main', commit: 'a'.repeat(40) } } : {}),
  };
  const r = await tool.handler({ project_path: project, force: true, local_only: true }, p);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const out = r as unknown as { scan_id: string; tools_run: ToolRun[] };
  return { findings: p.storage.findings.listByScan(out.scan_id), toolsRun: out.tools_run };
}

const banditIds = (findings: Finding[], file?: string): string[] =>
  findings
    .filter((f) => f.tool === 'bandit' && (file === undefined || (f.file_path ?? '').replace(/\\/g, '/').endsWith(file)))
    .map((f) => f.rule_id ?? '')
    .sort();

describe("--rules-ref: scan_sast reads the ref's copy of the project's configuration (real scanners)", () => {
  it.skipIf(!BANDIT_INSTALLED)("Bandit's --ini is the ref's .bandit — the tree's own, which silences everything, is never read", async () => {
    const project = tree('rulesref-bandit-', { 'a.py': PY, '.bandit': SKIP_ALL });
    // Control: read from the tree, the pull request's .bandit hides all three.
    expect(banditIds((await sast(project, null)).findings)).toEqual([]);

    const ref = tree('rulesref-bandit-ref-', { '.bandit': '[bandit]\nskips: B101\n' });
    const fromRef = await sast(project, ref);
    expect(banditIds(fromRef.findings)).toEqual(['B404', 'B602']);
    expect(fromRef.toolsRun.find((t) => t.name === 'bandit')?.honoured_config).toEqual(['.bandit']);

    // The ref has none: the neutral --ini, never the tree's in its place.
    const none = await sast(project, tree('rulesref-bandit-none-', {}));
    expect(banditIds(none.findings)).toEqual(['B101', 'B404', 'B602']);
    expect(none.toolsRun.find((t) => t.name === 'bandit')?.honoured_config).toBeUndefined();
  });

  it.skipIf(!BANDIT_INSTALLED)(".guardianignore is the ref's: the tree's cannot hide a file, and the ref's still does", async () => {
    const project = tree('rulesref-ignore-', { 'a.py': PY, 'hidden/b.py': PY, '.guardianignore': 'hidden/\n' });
    expect(banditIds((await sast(project, null)).findings, 'hidden/b.py')).toEqual([]);

    const noIgnore = await sast(project, tree('rulesref-ignore-ref-', {}));
    expect(banditIds(noIgnore.findings, 'hidden/b.py')).toEqual(['B101', 'B404', 'B602']);

    const refIgnore = await sast(project, tree('rulesref-ignore-ref2-', { '.guardianignore': 'a.py\n' }));
    expect(banditIds(refIgnore.findings, 'a.py').filter(Boolean)).toEqual([]);
    expect(banditIds(refIgnore.findings, 'hidden/b.py')).toEqual(['B101', 'B404', 'B602']);
  });

  it.skipIf(!SEMGREP_INSTALLED && !REQUIRE_SEMGREP)(
    "Semgrep runs the ref's .semgrep.yml, and its findings carry the rule id a tree scan stores — baselines keep matching",
    async () => {
      const project = tree('rulesref-semgrep-', {
        'index.js': 'module.exports = (input) => eval(input);\n',
        '.semgrep.yml': HARMLESS,
      });
      const fromTree = await sast(project, null);
      expect(fromTree.findings.filter((f) => f.tool === 'semgrep')).toEqual([]);

      const ref = tree('rulesref-semgrep-ref-', { '.semgrep.yml': NO_EVAL });
      const fromRef = await sast(project, ref);
      const semgrep = fromRef.findings.filter((f) => f.tool === 'semgrep');
      expect(semgrep.map((f) => f.rule_id)).toEqual(['guardian-test-no-eval']);
      expect((semgrep[0]?.file_path ?? '').replace(/\\/g, '/')).toMatch(/(^|\/)index\.js$/);

      // The same rule read from the tree is stored under the same id.
      const same = tree('rulesref-semgrep-same-', {
        'index.js': 'module.exports = (input) => eval(input);\n',
        '.semgrep.yml': NO_EVAL,
      });
      const treeRun = (await sast(same, null)).findings.filter((f) => f.tool === 'semgrep');
      expect(treeRun.map((f) => f.rule_id)).toEqual(['guardian-test-no-eval']);
      expect(treeRun[0]?.identity).toBe(semgrep[0]?.identity);
    },
  );
});
