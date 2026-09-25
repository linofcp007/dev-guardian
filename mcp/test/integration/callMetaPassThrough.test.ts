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
