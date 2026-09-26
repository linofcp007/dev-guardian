/**
 * Task 24 (2026-09-25 full review): the history readers Task 8 left on the
 * old unscoped reads — `scans.getLatest()`, `scans.listHistory(n)`,
 * `findings.listOpen()`, `baselines.getActive()`, `suppressions.listActive()`
 * — each answered with whichever project had scanned last. One database
 * holds every project's scans, so every test here seeds TWO projects (and,
 * where it matters, a `create_fix_pr` verification worktree and a scoped
 * scan) and asks for the first one: the answer must be about it alone.
 *
 * Project B's rows are always the NEWER ones, so an unscoped "latest" read
 * picks them and the test fails; a project-scoped read never sees them.
 */

import { relative, sep } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import type { StackSnapshot, ToolResult } from '../../src/types.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';
import { freshPlugin, projectDir, seedScan, type Seeded } from '../helpers/historySeed.js';

afterAll(cleanupTempDirs);

beforeAll(async () => {
  // Every tool: audit_executive looks its sub-tools up in the registry.
  await import('../../src/registerAll.js');
});

function tool(name: string): ToolModule {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool ${name} not registered`);
  return t;
}

/** A `create_fix_pr` verification worktree's path — never a project of its own. */
function worktreePath(): string {
  return projectDir('guardian-fixpr-wt-');
}

/** A timestamp later than anything the handlers under test stamp with `now`. */
function inAnHour(): string {
  return new Date(Date.now() + 60 * 60 * 1000).toISOString();
}

function twoProjects(): { s: Seeded; a: string; b: string } {
  return { s: freshPlugin(), a: projectDir('sweep-a-'), b: projectDir('sweep-b-') };
}

describe('health_status answers for one project', () => {
  function seeded(): { s: Seeded; a: string; b: string } {
    const { s, a, b } = twoProjects();
    seedScan(s, { id: 'a-sast', type: 'sast', project: a });
    seedScan(s, { id: 'b-sast', type: 'sast', project: b });
    seedScan(s, { id: 'b-deps', type: 'deps', project: b, tools_run: [{ name: 'trivy', status: 'ok' }] });
    seedScan(s, { id: 'wt-sast', type: 'sast', project: worktreePath() });
    return { s, a, b };
  }

  it("last_scan and total_scans are the given project's, not the newest project's", async () => {
    const { s, a } = seeded();
    const r = okResult<{
      project_path: string;
      last_scan: { scan_id: string } | null;
      storage: { total_scans: number };
    }>(await tool('health_status').handler({ project_path: a }, s.plugin));
    expect(r.last_scan?.scan_id).toBe('a-sast');
    expect(r.storage.total_scans).toBe(1);
    expect(r.project_path).toBe(a);
  });

  it("defaults to the server's working directory", async () => {
    const { s, a } = seeded();
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(a);
    try {
      const r = okResult<{ project_path: string; last_scan: { scan_id: string } | null }>(
        await tool('health_status').handler({}, s.plugin),
      );
      expect(r.last_scan?.scan_id).toBe('a-sast');
      expect(r.project_path).toBe(a);
    } finally {
      cwd.mockRestore();
    }
  });

  it('a project with no scans reports none, whatever other projects hold', async () => {
    const { s } = seeded();
    const empty = projectDir('sweep-empty-');
    const r = okResult<{ last_scan: unknown; storage: { total_scans: number } }>(
      await tool('health_status').handler({ project_path: empty }, s.plugin),
    );
    expect(r.last_scan).toBeNull();
    expect(r.storage.total_scans).toBe(0);
  });
});

describe('dotnet_describe_setup answers for one project', () => {
  it("reads the project's own audits and open findings — never another project's, a worktree's or a scoped scan's", async () => {
    const { s, a, b } = twoProjects();
    seedScan(s, {
      id: 'a-tfm', type: 'dotnet_target_framework', project: a,
      tools_run: [{ name: 'dotnet_target_framework_check', status: 'ok' }],
      meta: { project_count: 1, eol_count: 0, legacy_count: 0 },
    });
    seedScan(s, {
      id: 'a-sast', type: 'sast', project: a,
      tools_run: [{ name: 'security-code-scan', status: 'ok' }],
      findings: [{ tool: 'security-code-scan', rule_id: 'SCS0005', severity: 'high' }],
    });
    // Newer, all of them: another project's audit and findings, the same
    // project's scoped re-scan, and a create_fix_pr verification re-scan.
    seedScan(s, {
      id: 'b-tfm', type: 'dotnet_target_framework', project: b,
      tools_run: [{ name: 'dotnet_target_framework_check', status: 'ok' }],
      meta: { project_count: 9, eol_count: 5, legacy_count: 2 },
    });
    seedScan(s, {
      id: 'b-sast', type: 'sast', project: b,
      tools_run: [{ name: 'security-code-scan', status: 'ok' }],
      findings: [
        { tool: 'security-code-scan', rule_id: 'SCS0001', severity: 'critical' },
        { tool: 'security-code-scan', rule_id: 'SCS0002', severity: 'critical' },
      ],
    });
    seedScan(s, {
      id: 'a-scoped', type: 'sast', project: a, meta: { scope: { kind: 'paths', paths: ['src'] } },
      tools_run: [{ name: 'security-code-scan', status: 'ok' }],
      findings: [{ tool: 'security-code-scan', rule_id: 'SCS0009', severity: 'critical' }],
    });
    seedScan(s, {
      id: 'wt-sast', type: 'sast', project: worktreePath(),
      tools_run: [{ name: 'security-code-scan', status: 'ok' }],
    });

    const r = okResult<{
      project_path: string;
      audits: { target_framework_check: { scan_id: string; eol_count: number } | null; sast_latest: { scan_id: string } | null };
      open_dotnet_findings_count: number;
      open_critical: number;
      open_high: number;
    }>(await tool('dotnet_describe_setup').handler({ project_path: a }, s.plugin));
    expect(r.audits.target_framework_check).toMatchObject({ scan_id: 'a-tfm', eol_count: 0 });
    expect(r.audits.sast_latest?.scan_id).toBe('a-sast');
    expect(r.open_dotnet_findings_count).toBe(1);
    expect(r.open_high).toBe(1);
    expect(r.open_critical).toBe(0);
    expect(r.project_path).toBe(a);
  });
});

describe('wp_describe_setup answers for one WordPress project', () => {
  it("reads the project's own audits, not a newer one of another install, nor wp_plugin_check's lookup rows", async () => {
    const { s, a, b } = twoProjects();
    seedScan(s, { id: 'a-audit', type: 'wp_audit', project: a, tools_run: [{ name: 'wp-cli', status: 'ok' }], meta: { wp_version: '6.4.1', admins: [] } });
    seedScan(s, { id: 'a-vuln', type: 'wp_vuln_check', project: a, tools_run: [{ name: 'wpscan', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: 'CVE-A', package_name: 'akismet', severity: 'high', scan_id: 'a-vuln' });
    seedScan(s, { id: 'a-rest', type: 'wp_rest_audit', project: 'https://a.example', tools_run: [{ name: 'http-probe', status: 'ok' }], meta: { exposed_count: 1 } });
    // Newer: another install's audit, another site's REST probe, and
    // wp_plugin_check's single-plugin lookup filed as wp_vuln_check.
    seedScan(s, { id: 'b-audit', type: 'wp_audit', project: b, tools_run: [{ name: 'wp-cli', status: 'ok' }], meta: { wp_version: '6.5.0', admins: [] } });
    seedScan(s, { id: 'b-vuln', type: 'wp_vuln_check', project: b, tools_run: [{ name: 'wpscan', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: 'CVE-B', package_name: 'jetpack', severity: 'critical', scan_id: 'b-vuln' });
    seedScan(s, { id: 'b-rest', type: 'wp_rest_audit', project: 'https://b.example', tools_run: [{ name: 'http-probe', status: 'ok' }], meta: { exposed_count: 4 } });
    seedScan(s, {
      id: 'a-lookup', type: 'wp_vuln_check', project: a,
      tools_run: [{ name: 'wp_plugin_check', status: 'ok' }], meta: { slug: 'akismet', known_cves: [] },
    });

    const r = okResult<{
      project_path: string;
      audits: {
        wp_audit: { scan_id: string; wp_version: string | null } | null;
        wp_vuln_check: { scan_id: string; cves_count: number } | null;
        wp_rest_audit: { scan_id: string; exposed_count: number } | null;
      };
      active_cves: Array<{ cve_id: string }>;
    }>(await tool('wp_describe_setup').handler({ project_path: a, target_url: 'https://a.example/' }, s.plugin));
    expect(r.audits.wp_audit).toMatchObject({ scan_id: 'a-audit', wp_version: '6.4.1' });
    expect(r.audits.wp_vuln_check).toMatchObject({ scan_id: 'a-vuln', cves_count: 1 });
    expect(r.audits.wp_rest_audit).toMatchObject({ scan_id: 'a-rest', exposed_count: 1 });
    expect(r.active_cves.map((c) => c.cve_id)).toEqual(['CVE-A']);
    expect(r.project_path).toBe(a);
  });

  it("a site's REST probe is keyed by its URL: without target_url no other site's probe answers", async () => {
    const { s, a } = twoProjects();
    seedScan(s, { id: 'b-rest', type: 'wp_rest_audit', project: 'https://b.example', tools_run: [{ name: 'http-probe', status: 'ok' }], meta: { exposed_count: 4 } });
    const r = okResult<{ audits: { wp_rest_audit: unknown } }>(
      await tool('wp_describe_setup').handler({ project_path: a }, s.plugin),
    );
    expect(r.audits.wp_rest_audit).toBeNull();
  });
});

/**
 * Fix round 1, I3 (constraint 10: stored data keeps working). Builds up to
 * 2.0.x filed `wp_vuln_check` under the RAW `wp_install_path ?? url`: a
 * relative path, forward slashes, a trailing separator, a URL's trailing
 * slash. No migration rewrites them; the readers look them up under every
 * spelling (`wordpress/siteKeys.ts`).
 */
describe('WordPress rows an earlier build filed under a raw spelling are still found', () => {
  const legacyVuln = (s: Seeded, id: string, key: string, cve: string, slug = 'akismet'): void => {
    seedScan(s, { id, type: 'wp_vuln_check', project: key, tools_run: [{ name: 'wpscan', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: cve, package_name: slug, severity: 'high', scan_id: id });
  };

  it.each([
    ['a relative install path', (dir: string): string => relative(process.cwd(), dir)],
    ['forward slashes', (dir: string): string => dir.replace(/\\/g, '/')],
    ['a trailing separator', (dir: string): string => `${dir}${sep}`],
  ])('wp_describe_setup and wp_plugin_check find a wp_vuln_check filed under %s', async (_label, spell) => {
    const s = freshPlugin();
    const dir = projectDir('sweep-legacy-');
    const raw = spell(dir);
    legacyVuln(s, 'legacy', raw, 'CVE-LEGACY');

    const d = okResult<{ audits: { wp_vuln_check: { scan_id: string; cves_count: number } | null } }>(
      await tool('wp_describe_setup').handler({ project_path: raw }, s.plugin),
    );
    expect(d.audits.wp_vuln_check).toMatchObject({ scan_id: 'legacy', cves_count: 1 });

    const p = okResult<{ known_cves: Array<{ cve_id: string }> }>(
      await tool('wp_plugin_check').handler({ slug: 'akismet', project_path: raw }, s.plugin),
    );
    expect(p.known_cves.map((c) => c.cve_id)).toEqual(['CVE-LEGACY']);
  });

  it("finds rows filed under a site URL's trailing-slash spelling, and keeps the newest across every key", async () => {
    const { s, a } = twoProjects();
    legacyVuln(s, 'old-canonical', a, 'CVE-OLD');
    legacyVuln(s, 'legacy-url', 'https://legacy.example/', 'CVE-URL');
    seedScan(s, {
      id: 'legacy-rest', type: 'wp_rest_audit', project: 'https://legacy.example/',
      tools_run: [{ name: 'http-probe', status: 'ok' }], meta: { exposed_count: 2 },
    });

    const d = okResult<{
      audits: { wp_vuln_check: { scan_id: string } | null; wp_rest_audit: { scan_id: string } | null };
    }>(await tool('wp_describe_setup').handler({ project_path: a, target_url: 'https://legacy.example' }, s.plugin));
    // The URL row is newer than the one under the install root: it answers.
    expect(d.audits.wp_vuln_check?.scan_id).toBe('legacy-url');
    expect(d.audits.wp_rest_audit?.scan_id).toBe('legacy-rest');
  });
});

/**
 * Fix round 1, M3: only the audits that report through `meta` are read
 * whatever their scanner coverage. `wp_vuln_check`, `wp_vuln_check_source` and
 * `scan_wordpress` are finding scans — one that measured nothing is passed
 * over and the one before it answers, the way `wp_plugin_check` already reads
 * them.
 */
describe('wp_describe_setup passes over a finding scan that measured nothing', () => {
  it.each([
    ['wp_vuln_check', 'wpscan', 'wp_vuln_check'],
    ['wp_vuln_check_source', 'wordfence-feed', 'wp_vuln_check_source'],
    ['wordpress', 'semgrep-wp', 'scan_wordpress'],
  ] as const)('%s', async (type, scanner, field) => {
    const { s, a } = twoProjects();
    seedScan(s, { id: 'measured', type, project: a, tools_run: [{ name: scanner, status: 'ok' }] });
    seedScan(s, { id: 'blind', type, project: a, tools_run: [{ name: scanner, status: 'failed' }], missing_tools: [scanner] });
    const d = okResult<{ audits: Record<string, { scan_id: string } | null> }>(
      await tool('wp_describe_setup').handler({ project_path: a }, s.plugin),
    );
    expect(d.audits[field]?.scan_id).toBe('measured');
  });
});

describe('wp_recommend_hardening answers for one WordPress project', () => {
  it("builds the checklist from the project's own wp_audit, not a newer one of another install", async () => {
    const { s, a, b } = twoProjects();
    const meta = (risky: boolean): Record<string, unknown> => ({
      config_flags: { DISALLOW_FILE_EDIT: true, WP_DEBUG: false, FORCE_SSL_ADMIN: true },
      admins: [{ user_login: risky ? 'admin' : 'jane', user_email: 'x@x', risky }],
      checksum_mismatches: { core: [], plugins: {}, themes: {} },
      plugins_with_auto_update: ['akismet'],
      warnings: [],
    });
    seedScan(s, { id: 'a-audit', type: 'wp_audit', project: a, tools_run: [{ name: 'wp-cli', status: 'ok' }], meta: meta(true) });
    seedScan(s, { id: 'b-audit', type: 'wp_audit', project: b, tools_run: [{ name: 'wp-cli', status: 'ok' }], meta: meta(false) });

    const r = okResult<{ project_path: string; audit_scan_id: string; summary: { critical: number } }>(
      await tool('wp_recommend_hardening').handler({ project_path: a }, s.plugin),
    );
    expect(r.audit_scan_id).toBe('a-audit');
    expect(r.summary.critical).toBe(1);
    expect(r.project_path).toBe(a);
  });

  it('reports no audit for a project that has none, whatever other installs hold', async () => {
    const { s, a, b } = twoProjects();
    seedScan(s, { id: 'b-audit', type: 'wp_audit', project: b, tools_run: [{ name: 'wp-cli', status: 'ok' }], meta: {} });
    const r = okResult<{ audit_found: boolean }>(
      await tool('wp_recommend_hardening').handler({ project_path: a }, s.plugin),
    );
    expect(r.audit_found).toBe(false);
  });
});

describe('wp_plugin_check answers for one WordPress project', () => {
  it("reads the slug's CVEs from the project's own newest CVE sources only", async () => {
    const { s, a, b } = twoProjects();
    seedScan(s, { id: 'a-deps', type: 'deps_audit', project: a, tools_run: [{ name: 'trivy', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: 'CVE-A', package_name: 'contact-form-7', severity: 'high', scan_id: 'a-deps' });
    seedScan(s, { id: 'b-deps', type: 'deps_audit', project: b, tools_run: [{ name: 'trivy', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: 'CVE-B', package_name: 'contact-form-7', severity: 'critical', scan_id: 'b-deps' });
    seedScan(s, { id: 'b-src', type: 'wp_vuln_check_source', project: b, tools_run: [{ name: 'wordfence-feed', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: 'CVE-B2', package_name: 'contact-form-7', severity: 'high', scan_id: 'b-src' });

    const r = okResult<{ project_path: string; known_cves: Array<{ cve_id: string }> }>(
      await tool('wp_plugin_check').handler({ slug: 'contact-form-7', project_path: a }, s.plugin),
    );
    expect(r.known_cves.map((c) => c.cve_id)).toEqual(['CVE-A']);
    expect(r.project_path).toBe(a);
  });

  it('files its lookup as a SCOPED scan of the project (meta.scope), which never enters the open set', async () => {
    const { s, a } = twoProjects();
    seedScan(s, {
      id: 'a-vuln', type: 'wp_vuln_check', project: a, tools_run: [{ name: 'wpscan', status: 'ok' }],
      findings: [{ tool: 'wpscan', rule_id: 'CVE-A', severity: 'high' }],
    });
    const r = okResult<{ scan_id: string }>(
      await tool('wp_plugin_check').handler({ slug: 'akismet', project_path: a }, s.plugin),
    );
    const row = s.storage.scans.getById(r.scan_id);
    expect(row?.project_path).toBe(a);
    expect(row?.meta?.['scope']).toMatchObject({ kind: 'plugin', slug: 'akismet' });
    const { openSetForProject } = await import('../../src/history/openSet.js');
    const set = openSetForProject(s.storage, a);
    expect(set.sources.map((x) => x.scan_id)).toEqual(['a-vuln']);
    expect(set.findings).toHaveLength(1);
  });
});

describe('compliance_evidence answers for one project', () => {
  it("documents the project's own scans, baseline and suppressions — never the newest project's", async () => {
    const { s, a, b } = twoProjects();
    seedScan(s, {
      id: 'a-comp', type: 'compliance', project: a, tools_run: [{ name: 'policy-docs', status: 'ok' }],
      meta: { policy_documents_found: { privacy_policy: true, terms_of_service: true, security_policy: true } },
    });
    seedScan(s, { id: 'a-deps', type: 'deps_audit', project: a, tools_run: [{ name: 'trivy', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: 'CVE-A', package_name: 'lodash', severity: 'high', scan_id: 'a-deps' });
    s.storage.baselines.set({ scan_id: 'a-deps' });
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-a', reason: 'a', project_path: a });
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-any', reason: 'legacy, every project' });
    // Newer: project B's own everything.
    seedScan(s, { id: 'b-comp', type: 'compliance', project: b, tools_run: [{ name: 'policy-docs', status: 'ok' }], meta: {} });
    seedScan(s, { id: 'b-deps', type: 'deps_audit', project: b, tools_run: [{ name: 'trivy', status: 'ok' }] });
    s.storage.cves.upsert({ cve_id: 'CVE-B1', package_name: 'x', severity: 'critical', scan_id: 'b-deps' });
    s.storage.cves.upsert({ cve_id: 'CVE-B2', package_name: 'y', severity: 'critical', scan_id: 'b-deps' });
    s.storage.baselines.set({ scan_id: 'b-deps' });
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-b1', reason: 'b', project_path: b });
    s.storage.suppressions.insert({ finding_fingerprint: 'fp-b2', reason: 'b', project_path: b });

    const r = okResult<{ project_path: string; markdown: string }>(
      await tool('compliance_evidence').handler({ project_path: a }, s.plugin),
    );
    expect(r.markdown).toContain(`Project path: \`${a}\``);
    expect(r.markdown).toContain('`a-comp`');
    expect(r.markdown).toContain('`a-deps`');
    expect(r.markdown).toContain('- Active CVEs: 1');
    expect(r.markdown).toContain('Active baseline: `a-deps`');
    expect(r.markdown).toContain('Suppressions active: 2');
    expect(r.markdown).not.toContain('b-comp');
    expect(r.markdown).not.toContain('b-deps');
    expect(r.project_path).toBe(a);
  });
});

describe('audit_executive answers for one project', () => {
  const SUB_TOOLS = [
    'security_scan_full', 'quality_check', 'deps_audit', 'compliance_check',
    'scan_wordpress', 'scan_dotnet_secrets', 'dotnet_target_framework_check',
  ];

  async function withMockedSubTools<T>(calls: string[], body: () => Promise<T>): Promise<T> {
    const originals = new Map<string, ToolModule['handler']>();
    for (const name of SUB_TOOLS) {
      const t = tool(name);
      originals.set(name, t.handler);
      t.handler = async (): Promise<ToolResult<Record<string, unknown>>> => {
        calls.push(name);
        return { ok: true, coverage: 'full' };
      };
    }
    try {
      return await body();
    } finally {
      for (const [name, handler] of originals) tool(name).handler = handler;
    }
  }

  it("picks its sub-tools from the project's own stack snapshot and compares with the project's own previous audit", async () => {
    const { s, a, b } = twoProjects();
    const snapshot = (languages: string[], frameworks: string[]): StackSnapshot => ({
      os: 'linux', arch: 'x64', languages, package_managers: [], frameworks, existing_tools: [],
      has_docker: false, has_compose: false, has_terraform: false, has_kubernetes: false,
      has_ansible: false, has_github_actions: false, has_gitlab_ci: false, has_iac: false, projects: [],
    });
    s.storage.stack.insert({ project_path: a, snapshot: snapshot(['javascript'], []) });
    s.storage.stack.insert({ project_path: b, snapshot: snapshot(['php', 'csharp'], ['wordpress']) });
    // B's detection is the newer one (two inserts can share a millisecond).
    s.db.prepare('UPDATE stack_snapshots SET captured_at = ? WHERE project_path = ?').run(inAnHour(), b);
    seedScan(s, {
      id: 'b-audit', type: 'audit', project: b, tools_run: [{ name: 'security_scan_full', status: 'ok' }],
      findings: [{ tool: 'semgrep', severity: 'high' }],
    });

    const calls: string[] = [];
    const r = await withMockedSubTools(calls, async () =>
      okResult<{ project_path: string; sub_scans: Record<string, unknown>; deltas?: unknown }>(
        await tool('audit_executive').handler({ project_path: a }, s.plugin),
      ),
    );
    expect(r.project_path).toBe(a);
    expect(calls.sort()).toEqual(['compliance_check', 'deps_audit', 'quality_check', 'security_scan_full']);
    expect(Object.keys(r.sub_scans).sort()).toEqual(['compliance_check', 'deps_audit', 'quality_check', 'security_scan_full']);
    expect(r.deltas).toBeUndefined();
  });

  it("a second audit of the same project is compared with the first, not with another project's newer one", async () => {
    const { s, a, b } = twoProjects();
    const calls: string[] = [];
    const first = await withMockedSubTools(calls, async () =>
      okResult<{ scan_id: string }>(await tool('audit_executive').handler({ project_path: a }, s.plugin)),
    );
    seedScan(s, { id: 'b-audit', type: 'audit', project: b, tools_run: [{ name: 'security_scan_full', status: 'ok' }] });
    // Project B's audit completed after A's first one.
    s.db.prepare('UPDATE scans SET started_at = ? WHERE id = ?').run(inAnHour(), 'b-audit');
    const second = await withMockedSubTools(calls, async () =>
      okResult<{ deltas?: { since_audit_scan_id: string } }>(
        await tool('audit_executive').handler({ project_path: a }, s.plugin),
      ),
    );
    expect(second.deltas?.since_audit_scan_id).toBe(first.scan_id);
  });
});
