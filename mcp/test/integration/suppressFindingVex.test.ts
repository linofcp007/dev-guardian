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
/** pip-audit PYSEC advisory = CVE-2020-14343; its text MENTIONS CVE-2020-1747. */
const PYSEC_FP = 'c'.repeat(64);
/** A GHSA-only Trivy finding (no CVE assigned) whose description mentions a CVE. */
const GHSA_FP = 'd'.repeat(64);
/** A nuclei template named by its CVE: a vulnerability id, but no package coordinates. */
const NUCLEI_FP = 'e'.repeat(64);
/** A second copy of the lodash CVE, in another lockfile. */
const COPY_FP = 'f'.repeat(64);

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
    {
      fingerprint: PYSEC_FP, tool: 'pip-audit', rule_id: 'PYSEC-2021-142', severity: 'medium', category: 'security',
      subcategory: 'dependency', title: 'PYSEC-2021-142 in pyyaml 5.3', file_path: 'requirements.txt',
      message: 'This flaw is due to an incomplete fix for CVE-2020-1747.', snippet: 'pyyaml@5.3',
      vuln_aliases: ['CVE-2020-14343', 'GHSA-8q59-q68h-6hv4'], fix_available: true,
    },
    {
      fingerprint: GHSA_FP, tool: 'trivy', rule_id: 'GHSA-xvch-5gv4-984h', severity: 'high', category: 'security',
      subcategory: 'cve', title: 'handlebars: prototype pollution', file_path: 'package-lock.json',
      message: 'Related to CVE-2021-23383.', snippet: 'handlebars@4.7.6->4.7.7', fix_available: true,
    },
    {
      fingerprint: NUCLEI_FP, tool: 'nuclei', rule_id: 'CVE-2021-44228', severity: 'critical', category: 'security',
      subcategory: 'dast', title: 'Apache Log4j RCE', file_path: 'https://app.test/login', fix_available: false,
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
      vulnerability_ids: ['CVE-2021-23337'],
      exportable: true,
      other_open_findings: [],
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

  it('refuses a VEX status on a finding that is not about a vulnerability', async () => {
    const r = await suppress({
      finding_fingerprint: SAST_FP,
      vex_status: 'not_affected',
      justification: 'inline_mitigations_already_exist',
    });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected a refusal');
    expect(r.error.message).toMatch(/vulnerability id/);
    expect(ctx.storage.suppressions.listAll()).toEqual([]);
  });

  it('accepts a PYSEC advisory, naming its own ids — never the CVE its text mentions', async () => {
    const r = okResult<{ vex: { vulnerability_ids: string[] } }>(
      await suppress({
        finding_fingerprint: PYSEC_FP,
        vex_status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
      }),
    );
    expect(r.vex.vulnerability_ids).toEqual(['PYSEC-2021-142', 'CVE-2020-14343', 'GHSA-8q59-q68h-6hv4']);
    expect(r.vex.vulnerability_ids).not.toContain('CVE-2020-1747');
  });

  it('accepts a GHSA-only finding under its own id, not the CVE its description mentions', async () => {
    const r = okResult<{ vex: { vulnerability_ids: string[] } }>(
      await suppress({
        finding_fingerprint: GHSA_FP,
        vex_status: 'not_affected',
        justification: 'component_not_present',
      }),
    );
    expect(r.vex.vulnerability_ids).toEqual(['GHSA-xvch-5gv4-984h']);
  });

  it('says a vulnerability finding without package coordinates is not exportable to VEX (final review, M-b)', async () => {
    const r = okResult<{ vex: { exportable: boolean; note?: string } }>(
      await suppress({
        finding_fingerprint: NUCLEI_FP,
        vex_status: 'not_affected',
        justification: 'inline_mitigations_already_exist',
      }),
    );
    expect(r.vex.exportable).toBe(false);
    expect(r.vex.note).toContain('not exportable to VEX (no package coordinates)');
    // The suppression itself is recorded: it still hides the finding.
    expect(ctx.storage.suppressions.listAll()[0]?.finding_fingerprint).toBe(NUCLEI_FP);
  });

  it('warns about, and names, the other open findings of the same vulnerability (final review, M-d)', async () => {
    ctx.storage.findings.bulkInsert([{
      scan_id: 's1', fingerprint: COPY_FP, tool: 'trivy', rule_id: 'CVE-2021-23337', severity: 'high',
      category: 'security', subcategory: 'cve', title: 'lodash: command injection',
      file_path: 'nested/package-lock.json', snippet: 'lodash@4.17.20->4.17.21', fix_available: true,
    }]);

    const r = okResult<{
      vex: { other_open_findings: Array<{ fingerprint: string; file_path: string | null }> };
      warning?: string;
    }>(
      await suppress({
        finding_fingerprint: CVE_FP,
        vex_status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
      }),
    );

    expect(r.vex.other_open_findings.map((f) => [f.fingerprint, f.file_path])).toEqual([
      [COPY_FP, 'nested/package-lock.json'],
    ]);
    expect(r.warning).toMatch(/nested\/package-lock\.json/);
    expect(r.warning).toMatch(/export_vex/);
  });
});

describe('suppress_finding — the copies it names are export_vex’s copies', () => {
  const TRIVY_A = '1'.repeat(64);
  const TRIVY_B = '2'.repeat(64);
  const PIP_AUDIT = '3'.repeat(64);
  /** The same CVE in another pillow version: another statement, not a copy. */
  const OTHER_VERSION = '4'.repeat(64);

  /** Real OSV data: PYSEC-2026-1794 names CVE-2023-4863 and CVE-2023-5129 (pillow). */
  beforeEach(() => {
    const trivy = (fingerprint: string, id: string, version: string): Finding => ({
      fingerprint, tool: 'trivy', rule_id: id, severity: 'high', category: 'security', subcategory: 'cve',
      title: `${id} in pillow`, file_path: 'requirements.txt', snippet: `pillow@${version}->10.0.1`, fix_available: true,
    });
    ctx.storage.scans.insert({ scan_id: 's2', scan_type: 'deps', project_path: projectPath, tree_hash: 'h2' });
    const findings: Finding[] = [
      trivy(TRIVY_A, 'CVE-2023-4863', '10.0.0'),
      trivy(TRIVY_B, 'CVE-2023-5129', '10.0.0'),
      trivy(OTHER_VERSION, 'CVE-2023-5129', '9.5.0'),
      {
        fingerprint: PIP_AUDIT, tool: 'pip-audit', rule_id: 'PYSEC-2026-1794', severity: 'high', category: 'security',
        subcategory: 'dependency', title: 'PYSEC-2026-1794 in pillow 10.0.0', file_path: 'requirements.txt',
        snippet: 'pillow@10.0.0', vuln_aliases: ['CVE-2023-4863', 'CVE-2023-5129'], fix_available: true,
      },
    ];
    ctx.storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: 's2' })));
    ctx.storage.cves.bulkUpsert([
      { scan_id: 's2', cve_id: 'CVE-2023-4863', package_name: 'pillow', installed_version: '10.0.0', fixed_version: '10.0.1', severity: 'high' },
      { scan_id: 's2', cve_id: 'CVE-2023-5129', package_name: 'pillow', installed_version: '10.0.0', fixed_version: '10.0.1', severity: 'high' },
      { scan_id: 's2', cve_id: 'CVE-2023-5129', package_name: 'pillow', installed_version: '9.5.0', fixed_version: '10.0.1', severity: 'high' },
    ]);
    ctx.storage.scans.finalize({ scan_id: 's2', status: 'completed', tools_run: [], missing_tools: [] });
  });

  async function copiesNamedFor(fingerprint: string): Promise<string[]> {
    const r = okResult<{ vex: { other_open_findings: Array<{ fingerprint: string }> } }>(
      await suppress({ finding_fingerprint: fingerprint, vex_status: 'not_affected', justification: 'component_not_present' }),
    );
    return r.vex.other_open_findings.map((f) => f.fingerprint).sort();
  }

  it('names pip-audit’s advisory for Trivy’s CVE-2023-5129 — and not the same CVE in another version', async () => {
    expect(await copiesNamedFor(TRIVY_B)).toEqual([PIP_AUDIT]);
  });

  it('names both Trivy findings for the pip-audit advisory that is both CVEs', async () => {
    expect(await copiesNamedFor(PIP_AUDIT)).toEqual([TRIVY_A, TRIVY_B].sort());
  });
});
