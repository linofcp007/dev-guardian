/**
 * The scan factory's half of scoped scans and `.guardianignore`: what a
 * scoped call hands the scanner, what it keeps, what it records, how it is
 * cached, and how history treats the row afterwards.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { PluginContext } from '../../../src/context.js';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { ScanScopeInput } from '../../../src/platform/scope.js';
import { makeFinding, type ScannerParser } from '../../../src/runners/scannerParsers/index.js';
import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { TOOLS } from '../../../src/tools/index.js';
import { makeScanTool, type InvokeContext, type ScannerInvocation } from '../../../src/tools/scanToolFactory.js';
import type { Finding } from '../../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { okResult } from '../../helpers/toolResult.js';

beforeAll(async () => {
  await import('../../../src/tools/setBaseline.js');
  await import('../../../src/tools/diffScans.js');
});
afterAll(cleanupTempDirs);

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function buildPlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

function write(dir: string, rel: string, content = 'x\n'): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, content);
}

function finding(file: string, severity: Finding['severity'] = 'high'): Finding {
  return makeFinding({ tool: 'mock', severity, category: 'security', title: file, file_path: file, line_start: 1 });
}

function constantParser(findings: Finding[]): ScannerParser {
  return { name: 'mock', parse: () => ({ findings, cves: [] }) };
}

const schema = {
  project_path: z.string().optional(),
  severity_min: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  force: z.boolean().optional(),
  scope: ScanScopeInput,
};

interface Payload {
  scan_id: string;
  cached?: boolean;
  cached_from?: string;
  warnings: string[];
  findings_count_by_severity: Record<string, number>;
  top_findings: Finding[];
  scope?: { kind: string; files: number; findings_outside_scope: number; files_excluded_by_guardianignore?: number };
  exclusions?: { file: string; patterns: number; excluded_files: number; findings_excluded: number };
}

/** A scope-aware tool reporting `findings`; records every context it was invoked with. */
function scopedTool(name: string, findings: Finding[], seen: InvokeContext[] = []) {
  return makeScanTool({
    name,
    scan_type: 'sast',
    category: 'security',
    description: '',
    inputSchema: schema,
    supportsScope: true,
    invoke: async (_input, ctx): Promise<ScannerInvocation> => {
      seen.push(ctx);
      return {
        outcome: 'completed',
        tools_run: [{ name: 'mock', status: 'ok' }],
        missing_tools: [],
        parser_inputs: [{ parser: constantParser(findings), input: {} }],
        report_paths: [],
      };
    },
  });
}

describe('scoped scans in the factory', () => {
  let project: string;
  let plugin: PluginContext;

  beforeEach(() => {
    project = resolveProjectPath(makeTempDir('scope-factory-')).path;
    plugin = buildPlugin(project);
    write(project, 'src/a.ts');
    write(project, 'src/b.ts');
    write(project, 'lib/c.ts');
  });

  it('refuses a project_path that is a file, and says how to scope to it', async () => {
    const tool = scopedTool('scope_file_path', []);
    const r = await tool.handler({ project_path: join(project, 'src', 'a.ts') }, plugin);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.code).toBe('unsupported_target');
    expect(r.error.message).toContain('scope');
    expect(r.error.retry_with).toEqual({ project_path: join(project, 'src'), scope: { paths: ['a.ts'] } });
  });

  it('hands the scanner the resolved files, keeps only in-scope findings, and records meta.scope', async () => {
    const seen: InvokeContext[] = [];
    const tool = scopedTool('scope_basic', [finding('src/a.ts'), finding('lib/c.ts'), finding('src/b.ts', 'low')], seen);
    const r = okResult<Payload>(await tool.handler({ project_path: project, scope: { paths: ['src'] } }, plugin));
    expect(seen[0]?.scope?.files).toEqual(['src/a.ts', 'src/b.ts']);
    expect(r.findings_count_by_severity).toMatchObject({ high: 1, low: 1 });
    expect(r.scope).toMatchObject({ kind: 'paths', files: 2, findings_outside_scope: 1 });
    expect(r.warnings.some((w) => w.includes('Scoped scan'))).toBe(true);
    // Out-of-scope findings are not stored either: the row is the scope.
    expect(plugin.storage.findings.listByScan(r.scan_id).map((f) => f.file_path).sort()).toEqual(['src/a.ts', 'src/b.ts']);
    expect(plugin.storage.scans.getById(r.scan_id)?.meta?.['scope']).toMatchObject({ kind: 'paths', files: 2 });
  });

  it('an unscoped call passes a null scope and records no meta.scope', async () => {
    const seen: InvokeContext[] = [];
    const tool = scopedTool('scope_none', [finding('src/a.ts')], seen);
    const r = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    expect(seen[0]?.scope).toBeNull();
    expect(r.scope).toBeUndefined();
    expect(plugin.storage.scans.getById(r.scan_id)?.meta?.['scope']).toBeUndefined();
  });

  it('reports a scope that cannot be resolved as a domain error, before any scan row exists', async () => {
    const tool = scopedTool('scope_missing', []);
    const r = await tool.handler({ project_path: project, scope: { paths: ['nope.ts'] } }, plugin);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected failure');
    expect(r.error.code).toBe('target_not_found');
    const bad = await tool.handler({ project_path: project, scope: { paths: 'src' } }, plugin);
    expect(bad.ok).toBe(false);
    if (bad.ok) throw new Error('expected failure');
    expect(bad.error.code).toBe('unsupported_target');
  });

  it('never shares a cache entry between a scoped and an unscoped call, and a hit re-emits the scope', async () => {
    let calls = 0;
    const tool = makeScanTool({
      name: 'scope_cache',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: schema,
      supportsScope: true,
      invoke: async () => {
        calls += 1;
        return { outcome: 'completed', tools_run: [], missing_tools: [], parser_inputs: [], report_paths: [] };
      },
    });
    const whole = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    const scoped = okResult<Payload>(await tool.handler({ project_path: project, scope: { paths: ['src'] } }, plugin));
    expect(scoped.cached).toBeUndefined();
    const scopedAgain = okResult<Payload>(await tool.handler({ project_path: project, scope: { paths: ['src'] } }, plugin));
    expect(scopedAgain.cached_from).toBe(scoped.scan_id);
    expect(scopedAgain.scope).toMatchObject({ kind: 'paths', files: 2 });
    const wholeAgain = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    expect(wholeAgain.cached_from).toBe(whole.scan_id);
    expect(wholeAgain.scope).toBeUndefined();
    const otherScope = okResult<Payload>(await tool.handler({ project_path: project, scope: { paths: ['lib'] } }, plugin));
    expect(otherScope.cached).toBeUndefined();
    expect(calls).toBe(3);
  });

  it('a scoped scan never becomes a baseline, the previous scan, or the latest scan of a comparison', async () => {
    const tool = scopedTool('scope_hist', [finding('src/a.ts'), finding('lib/c.ts')]);
    const first = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    const whole = okResult<Payload>(await tool.handler({ project_path: project, force: true }, plugin));
    const scoped = okResult<Payload>(await tool.handler({ project_path: project, scope: { paths: ['src'] } }, plugin));
    expect(scoped.findings_count_by_severity.high).toBe(1);

    const refused = await getTool('set_baseline').handler({ scan_id: scoped.scan_id }, plugin);
    expect(refused.ok).toBe(false);
    if (refused.ok) throw new Error('expected failure');
    expect(refused.error.code).toBe('unsupported_target');
    expect(refused.error.message).toContain('scoped');

    const latest = okResult<{ scan_id: string }>(await getTool('set_baseline').handler({ project_path: project }, plugin));
    expect(latest.scan_id).toBe(whole.scan_id);

    // The newer scoped row is neither "latest" nor anyone's "previous": a
    // diff against it would report lib/c.ts as resolved.
    const diff = okResult<{ from_scan_id: string; to_scan_id: string; summary: { resolved: number } }>(
      await getTool('diff_scans').handler({ project_path: project }, plugin),
    );
    expect(diff.to_scan_id).toBe(whole.scan_id);
    expect(diff.from_scan_id).toBe(first.scan_id);
    expect(diff.summary.resolved).toBe(0);
  });
});

describe('.guardianignore in the factory', () => {
  let project: string;
  let plugin: PluginContext;

  beforeEach(() => {
    project = resolveProjectPath(makeTempDir('ignore-factory-')).path;
    plugin = buildPlugin(project);
    write(project, 'src/app.ts');
    write(project, 'mcp/test/fixtures/vuln.py');
    write(project, 'mcp/test/fixtures/deep/vuln2.py');
  });

  it('drops excluded findings before they are stored, and says how many files and findings it excluded', async () => {
    write(project, '.guardianignore', '# vulnerable on purpose\nmcp/test/fixtures/\n');
    const seen: InvokeContext[] = [];
    const tool = scopedTool('ignore_basic', [finding('src/app.ts'), finding('mcp/test/fixtures/vuln.py', 'critical')], seen);
    const r = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    expect(seen[0]?.exclusions?.excludedDirs).toEqual(['mcp/test/fixtures']);
    expect(r.findings_count_by_severity.critical).toBe(0);
    expect(r.exclusions).toEqual({ file: '.guardianignore', patterns: 1, excluded_files: 2, findings_excluded: 1 });
    expect(r.warnings.some((w) => w.includes('.guardianignore'))).toBe(true);
    expect(plugin.storage.findings.listByScan(r.scan_id).map((f) => f.file_path)).toEqual(['src/app.ts']);

    // A cache hit says the same.
    const again = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    expect(again.cached).toBe(true);
    expect(again.exclusions).toEqual(r.exclusions);
    expect(again.warnings.some((w) => w.includes('.guardianignore'))).toBe(true);
  });

  it('reports the file even when it excluded nothing, so exclusion is never silent', async () => {
    write(project, '.guardianignore', 'nothing-here/\n');
    const r = okResult<Payload>(await scopedTool('ignore_nothing', [finding('src/app.ts')]).handler({ project_path: project }, plugin));
    expect(r.exclusions).toEqual({ file: '.guardianignore', patterns: 1, excluded_files: 0, findings_excluded: 0 });
  });

  it('is absent from a project without the file', async () => {
    const seen: InvokeContext[] = [];
    const r = okResult<Payload>(await scopedTool('ignore_absent', [finding('mcp/test/fixtures/vuln.py')], seen).handler({ project_path: project }, plugin));
    expect(seen[0]?.exclusions).toBeNull();
    expect(r.exclusions).toBeUndefined();
    expect(r.findings_count_by_severity.high).toBe(1);
  });

  it('changing the ignore file is a new scan, not a cache hit', async () => {
    write(project, '.guardianignore', 'mcp/test/fixtures/\n');
    const tool = scopedTool('ignore_cache', [finding('src/app.ts')]);
    const first = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    write(project, '.guardianignore', 'mcp/\n');
    const second = okResult<Payload>(await tool.handler({ project_path: project }, plugin));
    expect(second.cached).toBeUndefined();
    expect(second.scan_id).not.toBe(first.scan_id);
  });

  it("an orchestrator reports what its children excluded — its own findings are theirs, already filtered", async () => {
    write(project, '.guardianignore', 'mcp/test/fixtures/\n');
    const child = scopedTool('ignore_child', [finding('src/app.ts'), finding('mcp/test/fixtures/vuln.py', 'critical')]);
    const parent = makeScanTool({
      name: 'ignore_parent',
      scan_type: 'security_full',
      category: 'security',
      description: '',
      inputSchema: schema,
      orchestrator: true,
      invoke: async (_input, ctx): Promise<ScannerInvocation> => {
        const r = okResult<Payload>(await child.handler({ project_path: ctx.projectPath }, plugin, ctx.childCallMeta));
        const stored = plugin.storage.findings.listByScan(r.scan_id);
        return {
          outcome: 'completed',
          tools_run: [{ name: 'mock', status: 'ok' }],
          missing_tools: [],
          parser_inputs: [{ parser: constantParser(stored), input: {} }],
          report_paths: [],
          extras: { child_scans: [{ tool: 'ignore_child', scan_id: r.scan_id, status: 'completed' }] },
        };
      },
    });
    const r = okResult<Payload>(await parent.handler({ project_path: project }, plugin));
    expect(r.exclusions).toMatchObject({ findings_excluded: 1 });
  });

  it('applies to a scoped scan too: an excluded file is not a target, and is counted', async () => {
    write(project, '.guardianignore', 'mcp/test/fixtures/\n');
    const seen: InvokeContext[] = [];
    const r = okResult<Payload>(
      await scopedTool('ignore_scoped', [], seen).handler({ project_path: project, scope: { paths: ['mcp', 'src'] } }, plugin),
    );
    expect(seen[0]?.scope?.files).toEqual(['src/app.ts']);
    expect(r.scope?.files_excluded_by_guardianignore).toBe(2);
  });
});
