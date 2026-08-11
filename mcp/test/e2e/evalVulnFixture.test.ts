/**
 * End-to-end test against the eval-vuln fixture (test/e2e/eval-vuln-fixture/):
 *   - app.js with `eval(parsed.query.expr)`.
 *
 * SKIPPED — not passed — when Semgrep is not installed, so a bare runner stays
 * green without ever claiming to have verified anything. This file previously
 * used `console.warn` plus a bare `return`, which vitest reports as a PASSING
 * test; combined with Semgrep living off PATH on Windows
 * (%APPDATA%\Roaming\Python\Python3xx\Scripts), that is how route-fabrication
 * defects reached a green suite through its sibling, rulePackFixture.test.ts.
 * Set `GUARDIAN_REQUIRE_SEMGREP=1` to turn absence into a hard failure.
 *
 * We scan with a **self-contained, offline rule**
 * (no registry/token, no dependency on the bundled config's per-version quirks)
 * so the result is deterministic: real Semgrep must flag the eval().
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { execa } from 'execa';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { detectOs } from '../../src/platform/osDetect.js';
import { probeShell } from '../../src/platform/shellProbe.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');
const FIXTURE = resolve(here, 'eval-vuln-fixture');
const SCRIPTS_DIR = resolve(ROOT, 'scripts');

const EVAL_RULE = [
  'rules:',
  '  - id: e2e-eval-detect',
  '    languages: [javascript]',
  '    severity: ERROR',
  '    message: eval of user input',
  '    pattern: eval(...)',
  '',
].join('\n');

beforeAll(async () => {
  await import('../../src/tools/securityScanFull.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/scanDeps.js');
});

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

/** Resolved once at collection time so `it.skipIf` can report a skip as a skip. */
const FIXTURE_PRESENT = existsSync(FIXTURE);
const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

describe('E2E — eval-vuln fixture', () => {
  it.runIf(REQUIRE_SEMGREP)('GUARDIAN_REQUIRE_SEMGREP=1 — this suite must be runnable', () => {
    expect(
      SEMGREP_INSTALLED,
      'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not on PATH. On Windows it is usually in ' +
        '%APPDATA%\\Roaming\\Python\\Python3xx\\Scripts.',
    ).toBe(true);
    expect(
      FIXTURE_PRESENT,
      `GUARDIAN_REQUIRE_SEMGREP=1 but the fixture tree is missing at ${FIXTURE}.`,
    ).toBe(true);
  });

  it.skipIf(!SEMGREP_INSTALLED)(
    'real Semgrep flags eval() in the fixture (self-contained offline rule)',
    async () => {

    // Write rule AND target into a temp dir OUTSIDE any `test/` path. Semgrep's
    // built-in default ignore skips `test/` directories, so scanning the in-repo
    // fixture (mcp/test/e2e/...) returned zero targets (paths.scanned: []).
    const work = mkdtempSync(join(tmpdir(), 'sg-e2e-'));
    const ruleFile = join(work, 'eval.yml');
    const targetFile = join(work, 'vuln.js');
    writeFileSync(ruleFile, EVAL_RULE, 'utf8');
    writeFileSync(
      targetFile,
      'const http = require("http");\n' +
        'http.createServer((req) => eval(req.url)).listen(3000);\n',
      'utf8',
    );

    const r = await execa(
      'semgrep',
      ['--config', ruleFile, '--json', '--quiet', '--disable-version-check', targetFile],
      { reject: false, timeout: 5 * 60_000, env: { SEMGREP_SEND_METRICS: 'off' } },
    );
    let parsed: { results?: Array<{ check_id?: string }>; errors?: unknown[] } = {};
    try {
      parsed = JSON.parse(r.stdout || '{}');
    } catch {
      /* diagnostic below surfaces the raw failure */
    }
    const ruleIds = (parsed.results ?? []).map((x) => String(x.check_id ?? ''));
    if (ruleIds.length === 0) {
      console.error(
        `[e2e] semgrep exit=${r.exitCode} errors=${JSON.stringify((parsed.errors ?? []).slice(0, 3))} ` +
          `stdout=${(r.stdout || '').slice(0, 500)} stderr=${(r.stderr || '').slice(0, 300)}`,
      );
    }

    expect(ruleIds.length).toBeGreaterThan(0);
    expect(ruleIds.some((id) => /eval/i.test(id))).toBe(true);
  }, 6 * 60_000);

  it.skipIf(!SEMGREP_INSTALLED || !FIXTURE_PRESENT)(
    'security_scan_full runs end-to-end without crashing (orchestration smoke)',
    async () => {

    const db = new Database(':memory:');
    runMigrations(db);
    const storage = new Storage(db);
    const shell = await probeShell(storage.runtimeMeta);
    if (!shell) {
      console.warn('[e2e] no usable shell, skipping');
      return;
    }
    const plugin: PluginContext = {
      storage,
      shell,
      scriptsDir: SCRIPTS_DIR,
      progressNotifier: { send: () => {} },
    };

    const tool = TOOLS.find((t) => t.name === 'security_scan_full');
    expect(tool).toBeDefined();
    const result = (await tool!.handler({ project_path: FIXTURE, force: true }, plugin)) as {
      ok: boolean;
    };
    expect(result.ok).toBe(true);
  }, 6 * 60_000);
});
