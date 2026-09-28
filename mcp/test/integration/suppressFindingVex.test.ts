/**
 * `suppress_finding` with a VEX status: a suppression that also says, in
 * OpenVEX's own terms, why the product is `not_affected` by a CVE — which
 * `export_vex` then publishes as a `not_affected` statement.
 *
 * The refusals matter as much as the success: a `not_affected` statement
 * without a justification is not valid VEX (CISA's minimum requirements,
 * OpenVEX's schema), and one on a finding that names no CVE is a statement
 * about nothing a VEX consumer could ever match.
 */
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { join } from 'node:path';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import '../../src/tools/suppressFinding.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

afterAll(cleanupTempDirs);

let ctx: PluginContext;
let projectPath = '';

const CVE_FP = 'a'.repeat(64);
const SAST_FP = 'b'.repeat(64);

beforeEach(() => {
  const db = new Database(':memory:');
  runMigrations(db);
  ctx = {
    storage: new Storage(db),
    shell: null,
    scriptsDir: join(process.cwd(), '..', 'scripts'),
    progressNotifier: { notify: async () => {} } as unknown as PluginContext['progressNotifier'],
  };
  projectPath = resolveProjectPath(makeTempDir('guardian-vex-suppress-')).path;
  const findings: Finding[] = [
    {
      fingerprint: CVE_FP, tool: 'trivy', rule_id: 'CVE-2021-23337', severity: 'high', category: 'security',
      subcategory: 'cve', title: 'lodash: command injection', file_path: 'package-lock.json',
      snippet: 'lodash@4.17.20->4.17.21', fix_available: true,
    },
    {
      fingerprint: SAST_FP, tool: 'semgrep', rule_id: 'no-eval', severity: 'high', category: 'security',
      title: 'eval', file_path: 'src/a.ts', line_start: 3, fix_available: false,
    },
  ];
  ctx.storage.scans.insert({ scan_id: 's1', scan_type: 'deps', project_path: projectPath, tree_hash: 'h' });
  ctx.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: 's1' })));
  ctx.storage.scans.finalize({ scan_id: 's1', status: 'completed', tools_run: [], missing_tools: [] });
});

afterEach(() => ctx.storage.close());

function suppress(input: Record<string, unknown>) {
  const tool = TOOLS.find((t) => t.name === 'suppress_finding');
  if (tool === undefined) throw new Error('suppress_finding is not registered');
  return tool.handler({ project_path: projectPath, reason: 'reviewed', ...input }, ctx);
}

describe('suppress_finding — VEX not_affected', () => {
  it('stores the VEX status, justification and impact statement, and echoes them', async () => {
    const r = okResult<{ vex: unknown }>(
      await suppress({
        finding_fingerprint: CVE_FP,
        vex_status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        impact_statement: 'only lodash.get is used; the template function is never called',
      }),
    );

    expect(r.vex).toEqual({
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      impact_statement: 'only lodash.get is used; the template function is never called',
      cve_ids: ['CVE-2021-23337'],
    });
    expect(ctx.storage.suppressions.listAll()[0]).toMatchObject({
      finding_fingerprint: CVE_FP,
      vex_status: 'not_affected',
      vex_justification: 'vulnerable_code_not_in_execute_path',
    });
  });

  it('a plain suppression carries no VEX status and says so', async () => {
    const r = okResult<{ vex: unknown }>(await suppress({ finding_fingerprint: CVE_FP }));
    expect(r.vex).toBeNull();
    expect(ctx.storage.suppressions.listAll()[0]?.vex_status).toBeUndefined();
  });

  it('refuses not_affected without a justification, and writes nothing', async () => {
    const r = await suppress({ finding_fingerprint: CVE_FP, vex_status: 'not_affected' });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected a refusal');
    expect(r.error.code).toBe('unsupported_target');
    expect(r.error.message).toMatch(/justification/);
    expect(ctx.storage.suppressions.listAll()).toEqual([]);
  });

  it('refuses a justification or impact statement without vex_status', async () => {
    for (const extra of [
      { justification: 'component_not_present' },
      { impact_statement: 'not shipped' },
    ]) {
      const r = await suppress({ finding_fingerprint: CVE_FP, ...extra });
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error('expected a refusal');
      expect(r.error.message).toMatch(/vex_status/);
    }
    expect(ctx.storage.suppressions.listAll()).toEqual([]);
  });

  it('refuses a VEX status on a finding that names no CVE', async () => {
    const r = await suppress({
      finding_fingerprint: SAST_FP,
      vex_status: 'not_affected',
      justification: 'inline_mitigations_already_exist',
    });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected a refusal');
    expect(r.error.message).toMatch(/CVE/);
    expect(ctx.storage.suppressions.listAll()).toEqual([]);
  });
});
