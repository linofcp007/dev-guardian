import Database from 'better-sqlite3';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { PluginContext } from '../../../src/context.js';
import {
  makeScanTool,
  type ScannerInvocation,
} from '../../../src/tools/scanToolFactory.js';
import type { ShellChoice } from '../../../src/platform/shellProbe.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { Storage } from '../../../src/storage/index.js';
import {
  makeFinding,
  type ScannerParser,
} from '../../../src/runners/scannerParsers/index.js';

function tempProject(): string {
  return mkdtempSync(join(tmpdir(), 'factory-test-'));
}

function buildPlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const shell: ShellChoice = {
    command: 'bash',
    args_prefix: [],
    needs_wsl_path_translate: false,
    label: 'fake',
  };
  return {
    storage,
    shell,
    scriptsDir: projectPath,
    progressNotifier: { send: () => {} },
  };
}

function constantParser(findings: ReturnType<typeof makeFinding>[]): ScannerParser {
  return {
    name: 'mock',
    parse: () => ({ findings, cves: [] }),
  };
}

const tinySchema = {
  project_path: z.string().optional(),
  severity_min: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  force: z.boolean().optional(),
};

interface ToolOkPayload {
  scan_id: string;
  cached?: boolean;
  cached_from?: string;
  status: string;
  findings_count_by_severity: Record<string, number>;
  top_findings: Array<{ fingerprint: string }>;
}

describe('makeScanTool', () => {
  let projectPath: string;
  let plugin: PluginContext;

  beforeEach(() => {
    projectPath = tempProject();
    plugin = buildPlugin(projectPath);
  });

  it('runs invoke + parser, persists findings, returns ok=true', async () => {
    const finding = makeFinding({
      tool: 'mock',
      severity: 'high',
      category: 'security',
      title: 'boom',
      file_path: 'src/app.ts',
      line_start: 1,
      line_end: 1,
    });
    let invokeCalls = 0;

    const tool = makeScanTool({
      name: 'mock_scan',
      scan_type: 'sast',
      category: 'security',
      description: 'mock',
      inputSchema: tinySchema,
      invoke: async () => {
        invokeCalls += 1;
        const inv: ScannerInvocation = {
          outcome: 'completed',
          tools_run: [{ name: 'mock', status: 'ok' }],
          missing_tools: [],
          parser_inputs: [{ parser: constantParser([finding]), input: {} }],
          report_paths: [],
        };
        return inv;
      },
    });

    const r = (await tool.handler({ project_path: projectPath }, plugin)) as {
      ok: true;
    } & ToolOkPayload;
    expect(r.ok).toBe(true);
    expect(r.findings_count_by_severity.high).toBe(1);
    expect(r.top_findings[0]?.fingerprint).toBe(finding.fingerprint);
    expect(invokeCalls).toBe(1);
  });

  it('returns a cached result on the second call within the TTL window', async () => {
    const finding = makeFinding({
      tool: 'mock',
      severity: 'low',
      category: 'quality',
      title: 'cached-me',
      file_path: 'src/util.ts',
    });
    let invokeCalls = 0;
    const tool = makeScanTool({
      name: 'cache_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => {
        invokeCalls += 1;
        return {
          outcome: 'completed',
          tools_run: [{ name: 'mock', status: 'ok' }],
          missing_tools: [],
          parser_inputs: [{ parser: constantParser([finding]), input: {} }],
          report_paths: [],
        };
      },
    });

    const first = (await tool.handler({ project_path: projectPath }, plugin)) as {
      ok: true;
    } & ToolOkPayload;
    const second = (await tool.handler({ project_path: projectPath }, plugin)) as {
      ok: true;
    } & ToolOkPayload;

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(second.cached).toBe(true);
    expect(second.cached_from).toBe(first.scan_id);
    expect(invokeCalls).toBe(1);
  });

  it('honours force=true to bypass the cache', async () => {
    let invokeCalls = 0;
    const tool = makeScanTool({
      name: 'force_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => {
        invokeCalls += 1;
        return {
          outcome: 'completed',
          tools_run: [],
          missing_tools: [],
          parser_inputs: [],
          report_paths: [],
        };
      },
    });
    await tool.handler({ project_path: projectPath }, plugin);
    await tool.handler({ project_path: projectPath, force: true }, plugin);
    expect(invokeCalls).toBe(2);
  });

  it('finalizes the scan and returns scanner_failed when invoke throws', async () => {
    const tool = makeScanTool({
      name: 'boom_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => {
        throw new Error('semgrep blew up');
      },
    });
    const r = (await tool.handler({ project_path: projectPath }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string; message: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('scanner_failed');
      expect(r.error.message).toContain('semgrep');
    }
    const history = plugin.storage.scans.listHistory(10);
    expect(history[0]?.status).toBe('failed');
  });

  it('finalizes with status=cancelled and returns cancelled domain error', async () => {
    const tool = makeScanTool({
      name: 'cancel_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => ({
        outcome: 'cancelled',
        tools_run: [],
        missing_tools: [],
        parser_inputs: [],
        report_paths: [],
      }),
    });
    const r = (await tool.handler({ project_path: projectPath }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('cancelled');
    const history = plugin.storage.scans.listHistory(10);
    expect(history[0]?.status).toBe('cancelled');
  });

  it('returns no_bash_shell when no shell is available', async () => {
    plugin.shell = null;
    const tool = makeScanTool({
      name: 'no_shell_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => ({
        outcome: 'completed',
        tools_run: [],
        missing_tools: [],
        parser_inputs: [],
        report_paths: [],
      }),
    });
    const r = (await tool.handler({ project_path: projectPath }, plugin)) as
      | { ok: true }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.code).toBe('no_bash_shell');
  });

  it('applies severity_min before persistence', async () => {
    const tool = makeScanTool({
      name: 'sev_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => ({
        outcome: 'completed',
        tools_run: [],
        missing_tools: [],
        parser_inputs: [
          {
            parser: constantParser([
              makeFinding({
                tool: 't',
                severity: 'low',
                category: 'quality',
                title: 'low',
                file_path: 'a.ts',
              }),
              makeFinding({
                tool: 't',
                severity: 'high',
                category: 'security',
                title: 'high',
                file_path: 'b.ts',
              }),
            ]),
            input: {},
          },
        ],
        report_paths: [],
      }),
    });
    const r = (await tool.handler(
      { project_path: projectPath, severity_min: 'medium' },
      plugin,
    )) as { ok: true } & ToolOkPayload;
    expect(r.ok).toBe(true);
    expect(r.findings_count_by_severity.low).toBe(0);
    expect(r.findings_count_by_severity.high).toBe(1);
  });
});
