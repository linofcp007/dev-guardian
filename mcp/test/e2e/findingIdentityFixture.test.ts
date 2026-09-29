/**
 * Line-independent identity against the REAL Semgrep binary.
 *
 * `test/integration/findingIdentity.test.ts` proves the reproductions through
 * the real scan pipeline with Semgrep's JSON synthesised. This file proves the
 * one thing that cannot be synthesised: what the installed Semgrep actually
 * reports. Semgrep >= ~1.120 without `semgrep login` returns
 * `extra.lines: "requires login"`, so every finding on a line has the SAME
 * snippet and the identity has to come from the file on disk. A version that
 * still returns the text works too — the identity is computed the same way
 * either way (see `fingerprint/findingIdentity.ts`), which is exactly what
 * the first assertion below pins.
 *
 * `local_only: true` with a one-rule `.semgrep.yml`: no registry, no
 * telemetry, seconds rather than a minute.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { judgeScan } from '../../src/fixpr/verify.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';
import { isInstalled } from '../helpers/toolchain.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/suppressFinding.js');
  await import('../../src/tools/diffScans.js');
});

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const SLOW = 180_000;

const RULES = `rules:
  - id: identity-e2e-eval
    languages: [javascript]
    severity: ERROR
    message: eval on a value from outside
    pattern: eval($X)
`;
const APP = 'const q = process.argv[2];\neval(q);\nmodule.exports = {};\n';
const APP_SHIFTED = "'use strict';\nconst q = process.argv[2];\neval(q);\nmodule.exports = {};\n";

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: '.',
    progressNotifier: { send: () => {} },
  };
}

async function scan(plugin: PluginContext, dir: string): Promise<{ scan_id: string; findings: Finding[] }> {
  const r = okResult<{ scan_id: string; tools_run: Array<{ name: string; status: string }> }>(
    await getTool('scan_sast').handler({ project_path: dir, local_only: true, force: true }, plugin),
  );
  expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
  const findings = plugin.storage.findings
    .listByScan(r.scan_id)
    .filter((f) => (f.rule_id ?? '').endsWith('identity-e2e-eval'));
  return { scan_id: r.scan_id, findings };
}

function onlyFinding(findings: readonly Finding[]): Finding {
  const [first, ...rest] = findings;
  if (first === undefined || rest.length > 0) throw new Error(`expected one finding, got ${findings.length}`);
  return first;
}

describe('E2E — a finding keeps its identity when a line is inserted above it (real Semgrep)', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    expect(SEMGREP_INSTALLED, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH').toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)(
    'suppression, diff_scans and create_fix_pr\'s verification all follow it',
    async () => {
      const dir = makeTempDir('finding-identity-e2e-');
      writeFileSync(join(dir, '.semgrep.yml'), RULES);
      writeFileSync(join(dir, 'app.js'), APP);
      const plugin = makePlugin();

      const s1 = await scan(plugin, dir);
      const before = onlyFinding(s1.findings);
      expect(before.line_start).toBe(2);
      expect(before.identity).toMatch(/^[0-9a-f]{64}$/);
      okResult(
        await getTool('suppress_finding').handler(
          { project_path: dir, finding_fingerprint: before.fingerprint, reason: 'e2e' },
          plugin,
        ),
      );

      writeFileSync(join(dir, 'app.js'), APP_SHIFTED);
      const s2 = await scan(plugin, dir);
      const after = onlyFinding(s2.findings);
      expect(after.line_start).toBe(3);
      expect(after.fingerprint).not.toBe(before.fingerprint);
      expect(after.identity).toBe(before.identity);

      // The suppression still holds.
      expect(
        plugin.storage.findings
          .listOpenForProject(dir)
          .filter((f) => (f.rule_id ?? '').endsWith('identity-e2e-eval')),
      ).toEqual([]);

      // diff_scans: not new + resolved. The finding is suppressed, so it is
      // listed apart (Unreleased: diff_scans honours suppressions) — once:
      // both scans' copies are one finding by identity.
      const diff = okResult<{ summary: { new: number; resolved: number; unchanged: number } }>(
        await getTool('diff_scans').handler({ from_scan_id: s1.scan_id, to_scan_id: s2.scan_id }, plugin),
      );
      expect(diff.summary).toEqual({
        new: 0,
        resolved: 0,
        unchanged: 0,
        not_remeasured: 0,
        not_previously_measured: 0,
        suppressed: 1,
      });

      // The unfixed target is still present to the fix verification.
      expect(judgeScan([before.fingerprint], s1, s2)).toMatchObject({
        passed: false,
        still_present: [before.fingerprint],
      });
    },
    SLOW,
  );
});
