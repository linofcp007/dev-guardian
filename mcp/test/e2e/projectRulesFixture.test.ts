/**
 * The assertion whose absence let two dead-rule defects stack up in one file.
 *
 * `configs/semgrep/base.yml` is the rule pack `init_project` installs into a
 * user's project as `.semgrep.yml`. Its `wp-unescaped-output` rule was dead
 * twice over, for independent reasons:
 *
 *   1. `pattern: echo $_GET[$X]` is not valid PHP, so Semgrep could not
 *      compile the rule. Fixed in b51a2dc.
 *   2. Nothing ever loaded the file. `scan_sast` ran `--config=auto`, which
 *      does not pick up a project's `.semgrep.yml`; measured on semgrep
 *      1.164.0 against a project containing both the pack and
 *      `<?php echo $_GET['name'];`, `--config=auto` reports 0 findings while
 *      `--config=<the file>` reports 1.
 *
 * The second one survived a whole round of work on the first, because every
 * test of the pack invoked Semgrep on the rule file directly. Nothing asserted
 * the path a user actually travels: run `init_project`, write vulnerable code,
 * run `scan_sast`, see the finding. That is what this file does, with the real
 * binary and the real `configs/` directory, and it is the only test here that
 * would have caught defect 2.
 */

import { execa } from 'execa';
import { writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { detectOs } from '../../src/platform/osDetect.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  await import('../../src/tools/initProject.js');
  await import('../../src/tools/scanSast.js');
});

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const SCRIPTS_DIR = resolve(ROOT, 'scripts');

/** A registry-backed `--config=auto` pass takes tens of seconds. */
const SLOW = 300_000;

async function isInstalled(bin: string): Promise<boolean> {
  try {
    const r = await execa(detectOs() === 'win32' ? 'where' : 'which', [bin], {
      reject: false,
      timeout: 2_000,
    });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

/**
 * `shell: null` while `init_project` runs, so it does not fire the real
 * `scripts/scan/initial-scan.sh`; a placeholder shell for the scan, which the
 * factory only checks for presence — `scan_sast` shells out through
 * `runProcess`, never through the shell.
 */
function makePlugin(withShell: boolean): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: withShell
      ? { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' }
      : null,
    scriptsDir: SCRIPTS_DIR,
    progressNotifier: { send: () => {} },
  };
}

/** A project as `init_project` leaves it, plus one line of vulnerable PHP. */
async function initialisedProject(): Promise<{ path: string; plugin: PluginContext }> {
  const path = makeTempDir('project-rules-e2e-');
  const initPlugin = makePlugin(false);
  const init = okResult<{ files_written: Array<{ target: string }> }>(
    await getTool('init_project').handler(
      { project_path: path, profile: 'standard' },
      initPlugin,
    ),
  );
  expect(init.files_written.map((f) => f.target)).toContain('.semgrep.yml');
  writeFileSync(join(path, 'vuln.php'), "<?php\necho $_GET['name'];\n", 'utf8');
  // Same storage, now with the placeholder shell the scan factory gates on.
  const plugin: PluginContext = {
    ...initPlugin,
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
  };
  return { path, plugin };
}

interface SastPayload {
  status: string;
  tools_run: Array<{ name: string; status: string; reason?: string }>;
  top_findings: Finding[];
  findings_count_by_severity: Record<string, number>;
  warnings: string[];
}

async function scan(
  project: string,
  plugin: PluginContext,
  extra: Record<string, unknown> = {},
): Promise<{ ok: true } & SastPayload> {
  return okResult<SastPayload>(
    await getTool('scan_sast').handler(
      { project_path: project, force: true, severity_min: 'info', ...extra },
      plugin,
    ),
  );
}

describe('E2E — the rules init_project installs are the rules scan_sast runs', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    expect(
      SEMGREP_INSTALLED,
      'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH, so the only test that proves ' +
        'the shipped rule pack has a consumer would have been skipped. On Windows it is ' +
        'usually in %APPDATA%\\Roaming\\Python\\Python3xx\\Scripts.',
    ).toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)(
    'reports wp-unescaped-output from a project init_project set up',
    async () => {
      const { path, plugin } = await initialisedProject();
      const r = await scan(path, plugin);

      expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
      const ids = r.top_findings.map((f) => f.rule_id ?? '');
      expect(
        ids.some((id) => id.endsWith('wp-unescaped-output')),
        `no wp-unescaped-output in ${JSON.stringify(ids)} — the pack init_project installed ` +
          'was not loaded by the scan',
      ).toBe(true);
    },
    SLOW,
  );

  it.skipIf(!SEMGREP_INSTALLED)(
    'finds it in local_only mode too, with no registry and no telemetry',
    async () => {
      const { path, plugin } = await initialisedProject();
      const r = await scan(path, plugin, { local_only: true });

      expect(r.tools_run.find((t) => t.name === 'semgrep')?.status).toBe('ok');
      expect(r.top_findings.some((f) => (f.rule_id ?? '').endsWith('wp-unescaped-output'))).toBe(true);
    },
    SLOW,
  );

  // The mirror-image guard — "a project with no rules of its own must still
  // scan" — deliberately does NOT live here. It needs no real binary, and this
  // file's cost is not free: a `--config=auto` pass fetches the Semgrep
  // registry, and running two of them was measured tipping
  // `createFixPr.test.ts` (already ~3.5 minutes of real scanning) past its 45s
  // per-test timeouts under full-suite contention. Exactly one registry-backed
  // pass earns its place, because it is the only thing that proves the real
  // default path end to end. The absence case is asserted against a mocked
  // runner in `test/integration/scanSastProjectRules.test.ts` instead, where
  // it costs nothing and checks the same thing.
});
