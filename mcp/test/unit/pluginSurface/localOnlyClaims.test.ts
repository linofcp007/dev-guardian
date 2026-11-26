/**
 * What `local_only` is said to do, held to what it does (review 3.0 M4).
 *
 * `local_only` keeps SEMGREP on the machine: rules on disk only — the
 * project's config, registered custom rules AND the plugin's LLM-application
 * pack, which every scan_sast / review_pr run carries — with --metrics=off.
 * It does not stop Trivy downloading its database, nor a .NET project's
 * restore contacting its NuGet feeds (SECURITY.md says so). The two tool
 * descriptions left the LLM pack out of the rules that run, and
 * /guardian-scan offered `local_only: true` "when nothing may leave the
 * machine".
 *
 * Registered rules are a row of the MCP server's database
 * (`platform/customRules.ts`), and the CLI's `scan` runs on a throwaway one
 * (`ci/runScans.ts`): the CLI never runs them. docs/ci.md and scan_sast's
 * skipped reason — which the CLI prints — offered a registration as the way
 * to give `--local-only` rules (3.17.0, G2; CRIT_G2 #8).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../../src/context.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { TOOLS } from '../../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { REPO_ROOT } from './pluginDocs.js';
import '../../../src/registerAll.js';

afterAll(cleanupTempDirs);

function tool(name: string): (typeof TOOLS)[number] {
  const t = TOOLS.find((x) => x.name === name);
  if (t === undefined) throw new Error(`Tool '${name}' not registered`);
  return t;
}

describe.each(['security_scan_full', 'review_pr'])('%s local_only', (name) => {
  it('names the LLM pack among the rules on disk it still runs', () => {
    expect(tool(name).inputSchema['local_only']?.description ?? '').toMatch(/LLM/);
  });

  it('says it does not stop Trivy', () => {
    const t = tool(name);
    expect(`${t.description}\n${t.inputSchema['local_only']?.description ?? ''}`).toMatch(/Trivy[^.]*(still|not)|not[^.]*Trivy/);
  });
});

describe('/guardian-scan', () => {
  const text = readFileSync(resolve(REPO_ROOT, 'commands/guardian-scan.md'), 'utf8');

  it('does not offer local_only as "nothing leaves the machine"', () => {
    expect(text).not.toMatch(/nothing may leave the machine/);
  });

  it('says what still goes out under it', () => {
    const line = text.split('\n').find((l) => l.includes('local_only: true')) ?? '';
    expect(line).toMatch(/Trivy/);
    expect(line).toMatch(/NuGet/);
  });
});

describe('the CLI never runs rules registered with register_custom_rules', () => {
  it("docs/ci.md's --local-only row offers no registration, and says the CLI does not run one", () => {
    const text = readFileSync(resolve(REPO_ROOT, 'docs/ci.md'), 'utf8');
    const row = text.split('\n').find((l) => l.startsWith('| `--local-only` |')) ?? '';
    expect(row).toMatch(/a committed `\.semgrep\.yml`/);
    expect(row).not.toMatch(/or rules registered with/);
    expect(row).toMatch(/the CLI never runs rules registered with `register_custom_rules`: they live in the MCP server's database, and each CLI run uses a fresh one/);
  });

  function makePlugin(): PluginContext {
    const db = new Database(':memory:');
    runMigrations(db);
    return {
      storage: new Storage(db),
      shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
      scriptsDir: makeTempDir('local-only-reason-scripts-'),
      progressNotifier: { send: () => {} },
    };
  }

  interface Run {
    tools_run: Array<{ name: string; status: string; reason?: string }>;
  }

  // Both of scan_sast's paths: the whole project, and a scope (runSemgrepOnScope).
  it.each([
    ['the whole project', {}],
    ['a scope', { scope: { paths: ['a.js'] } }],
  ])("scan_sast's skipped reason (%s) says where a registration lives and that the CLI never reads one", async (_label, extra) => {
    const project = makeTempDir('local-only-reason-');
    writeFileSync(join(project, 'a.js'), 'console.log(1);\n', 'utf8');
    const r = (await tool('scan_sast').handler({ project_path: project, local_only: true, force: true, ...extra }, makePlugin())) as unknown as Run;
    const semgrep = r.tools_run.find((t) => t.name === 'semgrep');
    expect(semgrep?.status).toBe('skipped');
    const reason = semgrep?.reason ?? '';
    // The MCP user's way out stays named.
    expect(reason).toMatch(/no \.semgrep\.yml, nothing registered with register_custom_rules in this database/);
    expect(reason).toMatch(/the CLI's runs never read a registration: each uses a fresh database/);
  });

  it('the whole-project reason still names init_project and the registry', async () => {
    const project = makeTempDir('local-only-reason-');
    writeFileSync(join(project, 'a.js'), 'console.log(1);\n', 'utf8');
    const r = (await tool('scan_sast').handler({ project_path: project, local_only: true, force: true }, makePlugin())) as unknown as Run;
    const reason = r.tools_run.find((t) => t.name === 'semgrep')?.reason ?? '';
    expect(reason).toMatch(/Run init_project, or drop local_only to use the Semgrep registry/);
  });
});
