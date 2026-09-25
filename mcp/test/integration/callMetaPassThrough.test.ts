/**
 * `audit_executive` and `create_fix_pr` run other tools' handlers in-process.
 * They used to call them without the host's `callMeta`, so cancelling the
 * outer call aborted nothing underneath: the child scans kept running to the
 * end, and their progress never reached the host. These tests replace the
 * sub-tools' handlers with recorders and check what each one was handed.
 */

import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/fixpr/apply.js', () => ({
  applyGroup: vi.fn(async () => ({ applied: true, commands: ['semgrep --autofix'], failure: null })),
}));

import type { PluginContext } from '../../src/context.js';
import { applyGroup } from '../../src/fixpr/apply.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS, type ToolCallMeta, type ToolModule } from '../../src/tools/index.js';
import type { ToolResult } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/registerAll.js');
});
afterAll(cleanupTempDirs);

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
}

type Handler = ToolModule['handler'];
const restore: Array<() => void> = [];
afterEach(() => {
  for (const undo of restore.splice(0)) undo();
});

/** Replaces a registered tool's handler with a recorder of its `callMeta`. */
function record(name: string, result: ToolResult<Record<string, unknown>>): Array<ToolCallMeta | undefined> {
  const tool = TOOLS.find((t) => t.name === name);
  if (tool === undefined) throw new Error(`Tool '${name}' not registered`);
  const original: Handler = tool.handler;
  const seen: Array<ToolCallMeta | undefined> = [];
  tool.handler = async (_input, _ctx, callMeta) => {
    seen.push(callMeta);
    return result;
  };
  restore.push(() => {
    tool.handler = original;
  });
  return seen;
}

function tool(name: string): ToolModule {
  const t = TOOLS.find((x) => x.name === name);
  if (t === undefined) throw new Error(`Tool '${name}' not registered`);
  return t;
}

const CANCELLED: ToolResult<Record<string, unknown>> = {
  ok: false,
  error: { code: 'cancelled', message: 'Scan was cancelled by the host.' },
};

describe('audit_executive hands the host callMeta to every sub-scan', () => {
  it('passes the same AbortSignal and progress token through', async () => {
    const project = makeTempDir('callmeta-audit-');
    const plugin = makePlugin();
    const subTools = ['security_scan_full', 'quality_check', 'deps_audit', 'compliance_check'];
    const seen = new Map(subTools.map((name) => [name, record(name, CANCELLED)]));

    const controller = new AbortController();
    const callMeta: ToolCallMeta = { signal: controller.signal, progressToken: 'tok-audit' };
    await tool('audit_executive').handler({ project_path: project }, plugin, callMeta);

    for (const name of subTools) {
      const calls = seen.get(name) ?? [];
      expect(calls, name).toHaveLength(1);
      expect(calls[0]?.signal, name).toBe(controller.signal);
      expect(calls[0]?.progressToken, name).toBe('tok-audit');
    }
  });
});

const AUDIT_SUB_TOOLS = ['security_scan_full', 'quality_check', 'deps_audit', 'compliance_check'];

describe('a cancelled audit_executive is recorded as cancelled, not as a clean audit', () => {
  function cancelAll(controller: AbortController): void {
    for (const name of AUDIT_SUB_TOOLS) {
      const t = tool(name);
      const original: Handler = t.handler;
      t.handler = async () => {
        controller.abort();
        return CANCELLED;
      };
      restore.push(() => {
        t.handler = original;
      });
    }
  }

  it('finalises the audit row as cancelled and returns the cancelled failure', async () => {
    const project = makeTempDir('callmeta-audit-cancel-');
    const plugin = makePlugin();
    const controller = new AbortController();
    cancelAll(controller);

    const result = await tool('audit_executive').handler({ project_path: project }, plugin, {
      signal: controller.signal,
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('expected the cancelled failure');
    expect(result.error.code).toBe('cancelled');
    const audit = plugin.storage.scans.listHistory(10).find((s) => s.scan_type === 'audit');
    expect(audit?.status).toBe('cancelled');
    expect(audit === undefined ? [] : plugin.storage.findings.listByScan(audit.scan_id)).toEqual([]);
  });

  it('never becomes the baseline of the next audit\'s delta', async () => {
    // It used to be finalised `completed` with zero findings, so the next real
    // audit reported every finding as new and nothing as resolved.
    const project = makeTempDir('callmeta-audit-delta-');
    const plugin = makePlugin();
    const controller = new AbortController();
    cancelAll(controller);
    await tool('audit_executive').handler({ project_path: project }, plugin, { signal: controller.signal });
    for (const undo of restore.splice(0)) undo();

    // A real sub-scan with two findings, reported by the next audit.
    plugin.storage.scans.insert({ scan_id: 'sub', scan_type: 'security_full', project_path: project, tree_hash: 'h' });
    plugin.storage.findings.bulkInsert(
      ['a', 'b'].map((fp) => ({
        scan_id: 'sub',
        fingerprint: `fp-${fp}`,
        tool: 'semgrep',
        severity: 'high' as const,
        category: 'security' as const,
        title: fp,
        fix_available: false,
      })),
    );
    plugin.storage.scans.finalize({ scan_id: 'sub', status: 'completed', tools_run: [], missing_tools: [] });
    record('security_scan_full', { ok: true, scan_id: 'sub', coverage: 'full', missing_tools: [] });
    for (const name of AUDIT_SUB_TOOLS.slice(1)) record(name, { ok: true, coverage: 'full', missing_tools: [] });

    const next = await tool('audit_executive').handler({ project_path: project }, plugin);
    expect(next.ok).toBe(true);
    // No COMPLETED audit precedes it, so there is nothing to diff against.
    expect((next as unknown as { deltas?: unknown }).deltas).toBeUndefined();
  });
});

describe('create_fix_pr stops between groups once the host cancels', () => {
  it('creates no further worktree, applies nothing more, and reports the rest as cancelled', async () => {
    const repo = makeTempDir('callmeta-fixpr-cancel-');
    const git = (...args: string[]): string =>
      execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    git('init', '-q', '-b', 'main');
    git('config', 'user.email', 't@example.com');
    git('config', 'user.name', 'T');
    git('config', 'core.autocrlf', 'false');
    writeFileSync(join(repo, 'index.js'), 'console.log(1);\n');
    git('add', '.');
    git('commit', '-q', '-m', 'first');

    // Two groups: deps/npm (critical, processed first) and semgrep (high).
    const plugin = makePlugin();
    const projectPath = resolveProjectPath(repo).path;
    // Each finding in the kind of scan that produces it — create_fix_pr
    // re-verifies a target with the tool that found it (Task 11), and pairs a
    // dependency finding by its structured package (Trivy's snippet).
    plugin.storage.scans.insert({ scan_id: 'deps-before', scan_type: 'deps_audit', project_path: projectPath, tree_hash: 'h' });
    plugin.storage.findings.bulkInsert([
      {
        scan_id: 'deps-before', fingerprint: 'fp-dep', tool: 'trivy', rule_id: 'CVE-2021-23337', severity: 'critical',
        category: 'security', subcategory: 'cve', title: 'lodash: prototype pollution', fix_available: true,
        file_path: 'package-lock.json', snippet: 'lodash@4.17.20->4.17.21',
      },
    ]);
    plugin.storage.scans.finalize({ scan_id: 'deps-before', status: 'completed', tools_run: [], missing_tools: [] });
    plugin.storage.scans.insert({ scan_id: 'before', scan_type: 'sast', project_path: projectPath, tree_hash: 'h' });
    plugin.storage.findings.bulkInsert([
      {
        scan_id: 'before', fingerprint: 'fp-sg', tool: 'semgrep', rule_id: 'js.rule', severity: 'high',
        category: 'security', title: 'x', file_path: 'index.js', line_start: 1, fix_available: true,
      },
    ]);
    plugin.storage.scans.finalize({ scan_id: 'before', status: 'completed', tools_run: [], missing_tools: [] });

    const controller = new AbortController();
    record('deps_update_plan', {
      ok: true,
      plan: [
        {
          package_name: 'lodash', installed_version: '4.17.20', latest_version: '4.17.21',
          classification: 'security', ecosystem: 'npm', upgrade_command: 'npm install lodash@4.17.21',
        },
      ],
    });
    // The host cancels while the first group's verification re-scan runs.
    const depsAudit = tool('deps_audit');
    const originalDepsAudit: Handler = depsAudit.handler;
    depsAudit.handler = async () => {
      controller.abort();
      return CANCELLED;
    };
    restore.push(() => {
      depsAudit.handler = originalDepsAudit;
    });
    const sastCalls = record('scan_sast', CANCELLED);
    vi.mocked(applyGroup).mockClear();

    const result = await tool('create_fix_pr').handler({ project_path: repo }, plugin, {
      signal: controller.signal,
    });

    expect(result.ok).toBe(true);
    const r = result as unknown as {
      cancelled?: boolean;
      groups: Array<{ key: string; outcome: string }>;
    };
    expect(r.cancelled).toBe(true);
    expect(r.groups.map((g) => g.key)).toEqual(['npm', 'semgrep']);
    expect(r.groups[1]?.outcome).toBe('cancelled');
    expect(vi.mocked(applyGroup)).toHaveBeenCalledTimes(1);
    expect(sastCalls).toHaveLength(0);
    expect(git('worktree', 'list').trim().split('\n')).toHaveLength(1);
  }, 60_000);
});

describe('create_fix_pr hands the host callMeta to its sub-tools', () => {
  it('passes it to deps_update_plan and to the verification re-scan', async () => {
    const repo = makeTempDir('callmeta-fixpr-');
    const git = (...args: string[]): void => {
      execFileSync('git', ['-C', repo, ...args], { stdio: 'ignore' });
    };
    git('init', '-q', '-b', 'main');
    git('config', 'user.email', 't@example.com');
    git('config', 'user.name', 'T');
    git('config', 'core.autocrlf', 'false');
    writeFileSync(join(repo, 'index.js'), 'console.log(1);\n');
    git('add', '.');
    git('commit', '-q', '-m', 'first');

    // One open, fixable semgrep finding, so one group is selected and driven
    // through the worktree, the (mocked) fix, and the re-scan.
    const plugin = makePlugin();
    const projectPath = resolveProjectPath(repo).path;
    plugin.storage.scans.insert({ scan_id: 'before', scan_type: 'sast', project_path: projectPath, tree_hash: 'h' });
    plugin.storage.findings.bulkInsert([
      {
        scan_id: 'before',
        fingerprint: 'fp-1',
        tool: 'semgrep',
        rule_id: 'javascript.some-rule',
        severity: 'high',
        category: 'security',
        title: 'x',
        file_path: 'index.js',
        line_start: 1,
        fix_available: true,
      },
    ]);
    plugin.storage.scans.finalize({ scan_id: 'before', status: 'completed', tools_run: [], missing_tools: [] });

    const planCalls = record('deps_update_plan', { ok: true, plan: [] });
    const rescanCalls = record('scan_sast', CANCELLED);

    const controller = new AbortController();
    const callMeta: ToolCallMeta = { signal: controller.signal, progressToken: 'tok-fix' };
    const result = await tool('create_fix_pr').handler({ project_path: repo }, plugin, callMeta);
    expect(result.ok).toBe(true);

    expect(planCalls).toHaveLength(1);
    expect(planCalls[0]?.signal).toBe(controller.signal);
    expect(rescanCalls).toHaveLength(1);
    expect(rescanCalls[0]?.signal).toBe(controller.signal);
    expect(rescanCalls[0]?.progressToken).toBe('tok-fix');
  }, 60_000);
});
