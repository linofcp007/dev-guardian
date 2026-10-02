/**
 * T-10 (js-sink-rules): the plan scan_sast hands to Semgrep runs the plugin's
 * Node/Express sink pack, `configs/semgrep/web-js.yml`, beside its
 * LLM-application pack -- in both modes, `local_only` included (NFR-1).
 *
 * `planSemgrepConfigs` is the one definition behind scan_sast's argv, its
 * cache key, review_pr's run and the Docker fallback's read-only pack mount
 * (`runners/semgrepConfigs.ts`, `tools/scanSast.ts`); that the argv IS the
 * plan is held by `integration/scanSastProjectRules.test.ts`. So the plan is
 * the narrowest surface that says what Semgrep is given.
 *
 * The project has rules of its own in both modes: with `local_only` and none,
 * there is no scan at all (`nothingToRun` -- the plugin's packs alone are not
 * a SAST ruleset), and "the pack runs too" would have nothing to run in.
 */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../../src/context.js';
import { planSemgrepConfigs } from '../../../src/runners/semgrepConfigs.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

/** The plugin's pack directory, located from this file -- not through the code under test. */
const PACK_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'configs', 'semgrep');
const LLM_PACK = join(PACK_DIR, 'llm.yml');
const WEBJS_PACK = join(PACK_DIR, 'web-js.yml');

const RULES =
  'rules:\n  - id: x\n    pattern: foo(...)\n    message: m\n    languages: [python]\n    severity: WARNING\n';

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

/** A project with a `.semgrep.yml` of its own, so a `local_only` plan has something to run. */
function projectWithRules(): string {
  const project = makeTempDir('sast-webjs-plan-');
  writeFileSync(join(project, '.semgrep.yml'), RULES, 'utf8');
  return project;
}

describe("scan_sast's Semgrep plan runs the web-js pack", () => {
  for (const localOnly of [false, true]) {
    it(`T-10 passes web-js.yml to Semgrep beside llm.yml, once (local_only: ${String(localOnly)})`, () => {
      const project = projectWithRules();
      const plan = planSemgrepConfigs(project, makePlugin(project), localOnly);
      expect(plan.nothingToRun).toBe(false);
      expect(plan.pluginPacks).toContain(LLM_PACK);
      expect(plan.pluginPacks).toContain(WEBJS_PACK);
      expect(plan.pluginPacks.filter((p) => p === WEBJS_PACK)).toHaveLength(1);
      // The argv and the cache key are built from the same plan.
      expect(plan.args).toContain(`--config=${WEBJS_PACK}`);
      expect(plan.args).toContain(`--config=${LLM_PACK}`);
      expect(plan.rulePacks).toContain(WEBJS_PACK);
      expect(plan.packMissing).toBe(false);
    });
  }
});
