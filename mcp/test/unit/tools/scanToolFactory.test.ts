import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
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
import { okResult } from '../../helpers/toolResult.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';
import { TOOLS } from '../../../src/tools/index.js';
import type { Finding, Severity } from '../../../src/types.js';

// `set_baseline` and `diff_scans` register themselves on import. The
// baseline sequel below needs the real ones: the whole point of that test is
// that a filtered scan feeds them the same history an unfiltered one would.
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

function tempProject(): string {
  return makeTempDir('factory-test-');
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
  warnings: string[];
  findings_count_by_severity: Record<string, number>;
  top_findings: Array<{ fingerprint: string }>;
  severity_filter?: {
    severity_min: Severity;
    withheld: number;
    withheld_by_severity: Record<string, number>;
    suggested_severity_min: Severity | null;
    recovered_by_suggestion: number;
  };
}

/** One finding per severity, each with its own file so the fingerprints differ. */
function oneOfEach(severities: readonly Severity[]): Finding[] {
  return severities.map((severity, i) =>
    makeFinding({
      tool: 't',
      severity,
      category: 'security',
      title: severity,
      file_path: `src/${severity}-${i}.ts`,
      line_start: i + 1,
    }),
  );
}

/** A scan tool that always reports exactly `findings`. */
function toolReporting(name: string, findings: Finding[]) {
  return makeScanTool({
    name,
    scan_type: 'sast',
    category: 'security',
    description: '',
    inputSchema: tinySchema,
    invoke: async () => ({
      outcome: 'completed' as const,
      tools_run: [{ name: 'mock', status: 'ok' as const }],
      missing_tools: [],
      parser_inputs: [{ parser: constantParser(findings), input: {} }],
      report_paths: [],
    }),
  });
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

    const r = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath }, plugin),
    );
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

    const first = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath }, plugin),
    );
    const second = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath }, plugin),
    );

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

  it('applies severity_min to the response', async () => {
    const tool = toolReporting('sev_scan', oneOfEach(['low', 'high']));
    const r = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath, severity_min: 'medium' }, plugin),
    );
    expect(r.ok).toBe(true);
    expect(r.findings_count_by_severity.low).toBe(0);
    expect(r.findings_count_by_severity.high).toBe(1);
  });
});

/**
 * `severity_min` used to filter BEFORE `bulkInsert`, so the findings below
 * the floor were never written at all. The response looked identical either
 * way — these tests look at the database.
 */
describe('makeScanTool: severity_min filters the response, not the history', () => {
  let projectPath: string;
  let plugin: PluginContext;

  beforeEach(() => {
    projectPath = tempProject();
    plugin = buildPlugin(projectPath);
  });

  it('persists every finding the scan produced, above the floor and below it', async () => {
    const findings = oneOfEach(['info', 'low', 'medium', 'high', 'critical']);
    const tool = toolReporting('persist_all_scan', findings);

    const r = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath, severity_min: 'high' }, plugin),
    );

    // The response is the filtered VIEW: high + critical only.
    expect(r.findings_count_by_severity).toEqual({
      info: 0, low: 0, medium: 0, high: 1, critical: 1,
    });
    expect(r.top_findings).toHaveLength(2);

    // The database holds the whole scan.
    const stored = plugin.storage.findings.listByScan(r.scan_id);
    expect(stored).toHaveLength(5);
    expect(new Set(stored.map((f) => f.severity))).toEqual(
      new Set(['info', 'low', 'medium', 'high', 'critical']),
    );
    for (const f of findings) {
      expect(stored.some((s) => s.fingerprint === f.fingerprint)).toBe(true);
    }
  });

  it('records the floor on the scan row, so a later reader can tell filtered from clean', async () => {
    const filtered = toolReporting('meta_scan', oneOfEach(['low']));
    const rf = okResult<ToolOkPayload>(
      await filtered.handler({ project_path: projectPath, severity_min: 'high' }, plugin),
    );
    expect(plugin.storage.scans.getById(rf.scan_id)?.meta).toEqual({ severity_min: 'high' });

    // No floor passed ⇒ nothing recorded: absence means "unfiltered".
    // `force` because both scans share a tree_hash and would otherwise be
    // one cache hit.
    const unfiltered = toolReporting('meta_scan_2', oneOfEach(['low']));
    const ru = okResult<ToolOkPayload>(
      await unfiltered.handler({ project_path: projectPath, force: true }, plugin),
    );
    expect(plugin.storage.scans.getById(ru.scan_id)?.meta?.['severity_min']).toBeUndefined();
  });

  it('tells the caller what the floor withheld, and what to pass to see it', async () => {
    const tool = toolReporting('disclose_scan', oneOfEach(['low', 'medium', 'medium', 'critical']));
    const r = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath, severity_min: 'high' }, plugin),
    );

    expect(r.severity_filter).toEqual({
      severity_min: 'high',
      withheld: 3,
      withheld_by_severity: { info: 0, low: 1, medium: 2, high: 0, critical: 0 },
      suggested_severity_min: 'medium',
      recovered_by_suggestion: 2,
    });
    expect(r.warnings.join('\n')).toContain('1 low');
    expect(r.warnings.join('\n')).toContain('are recorded in scan');
  });

  it('says nothing when the floor withheld nothing', async () => {
    const tool = toolReporting('quiet_scan', oneOfEach(['critical']));
    const r = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath, severity_min: 'high' }, plugin),
    );
    expect(r.severity_filter?.withheld).toBe(0);
    expect(r.warnings.join('\n')).not.toContain('severity_min');
  });

  it('applies the CALLER\'s floor on a cache hit, not the cached scan\'s', async () => {
    const tool = toolReporting('cache_floor_scan', oneOfEach(['low', 'critical']));

    const first = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath }, plugin),
    );
    expect(first.findings_count_by_severity.low).toBe(1);

    const second = okResult<ToolOkPayload>(
      await tool.handler({ project_path: projectPath, severity_min: 'high' }, plugin),
    );
    expect(second.cached).toBe(true);
    expect(second.cached_from).toBe(first.scan_id);
    expect(second.findings_count_by_severity.low).toBe(0);
    expect(second.findings_count_by_severity.critical).toBe(1);
    expect(second.severity_filter?.withheld).toBe(1);
  });

  /**
   * The sequel this defect was found through: filter, baseline, re-scan
   * unfiltered. With the floor applied before persistence the baseline never
   * held the below-floor findings, so the unfiltered re-scan reported them as
   * `new` — the opposite of true. They had been there all along.
   */
  it('does not report previously-filtered findings as new after a baseline', async () => {
    const findings = oneOfEach(['low', 'medium', 'high']);
    const belowFloor = findings.filter((f) => f.severity !== 'high');

    const filteredScan = toolReporting('seq_scan_1', findings);
    const first = okResult<ToolOkPayload>(
      await filteredScan.handler({ project_path: projectPath, severity_min: 'high' }, plugin),
    );
    expect(first.findings_count_by_severity.medium).toBe(0);

    const baseline = okResult<{ scan_id: string }>(
      await getTool('set_baseline').handler({ scan_id: first.scan_id }, plugin),
    );
    expect(baseline.scan_id).toBe(first.scan_id);

    // Same tree, same findings — but nobody asks for a floor this time.
    const unfilteredScan = toolReporting('seq_scan_2', findings);
    const second = okResult<ToolOkPayload>(
      await unfilteredScan.handler({ project_path: projectPath, force: true }, plugin),
    );
    expect(second.findings_count_by_severity.medium).toBe(1);
    expect(second.scan_id).not.toBe(first.scan_id);

    const diff = okResult<{
      new_findings: Finding[];
      unchanged_findings: Finding[];
      summary: { new: number; resolved: number; unchanged: number };
    }>(
      await getTool('diff_scans').handler(
        { from: 'baseline', to_scan_id: second.scan_id },
        plugin,
      ),
    );

    expect(diff.summary.new).toBe(0);
    expect(diff.summary.resolved).toBe(0);
    expect(diff.summary.unchanged).toBe(3);
    for (const f of belowFloor) {
      expect(diff.new_findings.some((n) => n.fingerprint === f.fingerprint)).toBe(false);
      expect(diff.unchanged_findings.some((u) => u.fingerprint === f.fingerprint)).toBe(true);
    }
  });
});
