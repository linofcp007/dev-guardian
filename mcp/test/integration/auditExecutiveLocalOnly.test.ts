/**
 * `audit_executive` and what leaves the machine.
 *
 * Review 3.0 I3. It runs security_scan_full (Semgrep registry, with usage
 * metrics), deps_audit (npm audit; pip-audit installs requirements from PyPI
 * and builds sdists; `dotnet restore` executes MSBuild), and scan_wordpress
 * or the .NET tools by detected stack — concurrently, while its description
 * said "in sequence". It had no `local_only`, and SECURITY.md's per-tool
 * egress table did not name it. The router's full checkup and both release
 * gates route to it.
 *
 * These tests replace the children's handlers with recorders of the input
 * each was handed.
 */

import { afterAll, afterEach, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { TOOLS, type ToolModule } from '../../src/tools/index.js';
import type { StackSnapshot, ToolRun } from '../../src/types.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';
import { freshPlugin, projectDir } from '../helpers/historySeed.js';
// Static: the children must be registered when this file is collected.
import '../../src/registerAll.js';

afterAll(cleanupTempDirs);

const restore: Array<() => void> = [];
afterEach(() => {
  for (const undo of restore.splice(0)) undo();
});

function tool(name: string): ToolModule {
  const t = TOOLS.find((x) => x.name === name);
  if (t === undefined) throw new Error(`Tool '${name}' not registered`);
  return t;
}

const ALL_CHILDREN = [
  'security_scan_full',
  'quality_check',
  'deps_audit',
  'compliance_check',
  'scan_wordpress',
  'scan_dotnet_secrets',
  'dotnet_target_framework_check',
];

/** Every child's handler replaced by a recorder of the input it was handed. */
function recordInputs(): Map<string, Record<string, unknown>> {
  const seen = new Map<string, Record<string, unknown>>();
  for (const name of ALL_CHILDREN) {
    const t = tool(name);
    const original = t.handler;
    t.handler = async (input) => {
      seen.set(name, input);
      return { ok: true, coverage: 'full' };
    };
    restore.push(() => {
      t.handler = original;
    });
  }
  return seen;
}

/** A project whose latest detect_stack says WordPress and .NET, so every child applies. */
function wordpressAndDotnet(): { plugin: PluginContext; project: string } {
  const { plugin } = freshPlugin();
  const project = projectDir('audit-local-');
  const snapshot: StackSnapshot = {
    os: 'linux', arch: 'x64', languages: ['php', 'csharp'], package_managers: [], frameworks: ['wordpress'],
    existing_tools: [], has_docker: false, has_compose: false, has_terraform: false, has_kubernetes: false,
    has_ansible: false, has_github_actions: false, has_gitlab_ci: false, has_iac: false, projects: [],
  };
  plugin.storage.stack.insert({ project_path: project, snapshot });
  return { plugin, project };
}

interface AuditOk {
  ok: true;
  scan_id: string;
  coverage: string;
  coverage_warnings?: string[];
  sub_scans: Record<string, { ok: boolean; skipped?: string }>;
  local_only_gaps?: string[];
}

async function audit(input: Record<string, unknown>, plugin: PluginContext): Promise<AuditOk> {
  const r = await tool('audit_executive').handler(input, plugin);
  if (!r.ok) throw new Error(r.error.message);
  return r as unknown as AuditOk;
}

describe('audit_executive local_only', () => {
  it('is a parameter', () => {
    expect(Object.keys(tool('audit_executive').inputSchema)).toContain('local_only');
  });

  it('is passed to every child that takes it, and to no other', async () => {
    const { plugin, project } = wordpressAndDotnet();
    const seen = recordInputs();
    await audit({ project_path: project, local_only: true }, plugin);
    const takers = ALL_CHILDREN.filter((n) => 'local_only' in tool(n).inputSchema);
    expect(takers).toContain('security_scan_full');
    for (const [name, input] of seen) {
      expect(input['local_only'], name).toBe(takers.includes(name) ? true : undefined);
    }
  });

  it('skips scan_wordpress, which has no local-only mode, with the reason — and coverage says partial', async () => {
    const { plugin, project } = wordpressAndDotnet();
    const seen = recordInputs();
    const r = await audit({ project_path: project, local_only: true }, plugin);
    expect(seen.has('scan_wordpress')).toBe(false);
    expect(r.sub_scans['scan_wordpress']).toMatchObject({ ok: false, skipped: expect.stringMatching(/local-only/) });
    expect(r.coverage).toBe('partial');
    expect(r.coverage_warnings).toContainEqual(expect.stringMatching(/scan_wordpress.*skipped/));
    const run = plugin.storage.scans.getById(r.scan_id)?.tools_run.find((t: ToolRun) => t.name === 'scan_wordpress');
    expect(run).toMatchObject({ status: 'skipped', reason: expect.stringMatching(/local-only/) });
  });

  it('names in the result what it does not stop: Trivy, the package registries, a .NET restore', async () => {
    const { plugin, project } = wordpressAndDotnet();
    recordInputs();
    const r = await audit({ project_path: project, local_only: true }, plugin);
    const gaps = (r.local_only_gaps ?? []).join('\n');
    expect(gaps).toMatch(/Trivy/);
    expect(gaps).toMatch(/deps_audit/);
    expect(gaps).toMatch(/PyPI/);
    expect(gaps).toMatch(/dotnet restore/);
    expect(plugin.storage.scans.getById(r.scan_id)?.meta?.['local_only']).toBe(true);
  });

  // Round 2: measured, not assumed. Trivy 0.69.3, `fs --scanners license
  // --quiet` (compliance_check's exact arguments), an empty cache, every
  // proxy variable on a logging proxy: no vulnerability-DB download, but
  // CONNECT check.trivy.dev:443 (the version check, on every run; only
  // TRIVY_SKIP_VERSION_CHECK=true AND TRIVY_DISABLE_TELEMETRY=true together
  // stop it) and CONNECT repo.maven.apache.org:443 for a pom.xml. Every
  // Trivy run now sets both (runners/trivyRun.ts), so check.trivy.dev is no
  // longer a gap: only Maven Central remains.
  it('lists compliance_check, whose license scan still reaches Maven Central — and no longer check.trivy.dev', async () => {
    const { plugin, project } = wordpressAndDotnet();
    recordInputs();
    const r = await audit({ project_path: project, local_only: true }, plugin);
    const gaps = r.local_only_gaps ?? [];
    const compliance = gaps.find((g) => g.startsWith('compliance_check'));
    expect(compliance).toMatch(/Maven Central/);
    expect(gaps.join('\n')).not.toMatch(/check\.trivy\.dev/);
  });

  it('without it nothing changes: no child is handed local_only, scan_wordpress runs, no gaps listed', async () => {
    const { plugin, project } = wordpressAndDotnet();
    const seen = recordInputs();
    const r = await audit({ project_path: project }, plugin);
    expect([...seen.keys()].sort()).toEqual([...ALL_CHILDREN].sort());
    for (const [name, input] of seen) expect(input['local_only'], name).toBeUndefined();
    expect(r.coverage).toBe('full');
    expect(r.local_only_gaps).toBeUndefined();
  });
});

describe('audit_executive says what it runs', () => {
  const d = (): string => tool('audit_executive').description;

  it('says concurrently, not in sequence', () => {
    expect(d()).not.toMatch(/in sequence/i);
    expect(d()).toMatch(/concurrently/i);
  });

  it('states its egress and the code it executes', () => {
    expect(d()).toMatch(/Semgrep registry/);
    expect(d()).toMatch(/metrics/);
    expect(d()).toMatch(/Trivy/);
    expect(d()).toMatch(/PyPI/);
    expect(d()).toMatch(/MSBuild/);
    expect(d()).toMatch(/local_only/);
  });
});
