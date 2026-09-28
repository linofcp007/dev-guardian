/**
 * Follow-up X, fix round 4 (pre-existing): register_custom_rules accepted a
 * rule file whose shape was right but which Semgrep cannot compile —
 * `languages: [klingon]` — and one such file makes Semgrep refuse the whole
 * configuration on every later scan (exit 8, nothing scanned). With Semgrep
 * installed, registration now runs `semgrep --validate` and refuses the file
 * with Semgrep's own message. Real Semgrep, no mocks.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveCustomSemgrepConfigs } from '../../src/platform/customRules.js';
import { GuardianDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { semgrepAvailable } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/registerCustomRules.js');
});

const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const AVAILABLE = semgrepAvailable();
const TIMEOUT_MS = 180_000;

function plugin(): PluginContext {
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
}

const rule = (id: string, language: string, pattern: string): string =>
  `rules:\n  - id: ${id}\n    message: m\n    languages: [${language}]\n    severity: ERROR\n    pattern: ${pattern}\n`;

describe('register_custom_rules: Semgrep compiles the rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not usable').toBe(true);
  });

  it.skipIf(!AVAILABLE)(
    'an unknown language and a broken pattern are refused with Semgrep\'s message; a good file is registered',
    async () => {
      const project = makeTempDir('reg-semgrep-');
      writeFileSync(join(project, 'good.yml'), rule('good', 'javascript', 'eval($X)'));
      writeFileSync(join(project, 'klingon.yml'), rule('weird', 'klingon', 'foo()'));
      writeFileSync(join(project, 'broken.yml'), rule('broken', 'javascript', '"foo(((("'));
      const p = plugin();
      const tool = TOOLS.find((t) => t.name === 'register_custom_rules');
      if (tool === undefined) throw new Error('register_custom_rules not registered');
      const r = (await tool.handler({ project_path: project, paths: ['good.yml', 'klingon.yml', 'broken.yml'] }, p)) as {
        ok: true;
        registered: string[];
        rejected: Array<{ path: string; reason: string }>;
        semgrep_validated: boolean;
      };
      expect(r.semgrep_validated).toBe(true);
      expect(r.registered).toEqual([join(project, 'good.yml')]);
      const reasons = Object.fromEntries(r.rejected.map((x) => [x.path, x.reason]));
      expect(reasons[join(project, 'klingon.yml')]).toMatch(/^Semgrep refused it: .*invalid language: klingon/);
      expect(reasons[join(project, 'broken.yml')]).toMatch(/^Semgrep refused it: .*Pattern parse error in rule broken/);
      expect(resolveCustomSemgrepConfigs(p, project)).toEqual([join(project, 'good.yml')]);
    },
    TIMEOUT_MS,
  );
});
