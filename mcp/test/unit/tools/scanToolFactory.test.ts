import { GuardianDatabase as Database } from '../../../src/storage/db.js';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import type { PluginContext } from '../../../src/context.js';
import type { ProgressPayload } from '../../../src/progress/progressEmitter.js';
import {
  makeScanTool,
  type InvokeContext,
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

  it('redacts a credential finding\'s snippet before it is persisted or returned', async () => {
    const secretFinding = makeFinding({
      tool: 'bandit',
      rule_id: 'B105',
      subcategory: 'hardcoded_password_string',
      severity: 'low',
      category: 'security',
      title: 'hardcoded password',
      file_path: 'app.py',
      line_start: 1,
      line_end: 1,
      snippet: '1 password = "hunter2"',
    });

    const tool = makeScanTool({
      name: 'secret_mock_scan',
      scan_type: 'secrets',
      category: 'security',
      description: 'mock',
      inputSchema: tinySchema,
      invoke: async () => ({
        outcome: 'completed' as const,
        tools_run: [{ name: 'mock', status: 'ok' as const }],
        missing_tools: [],
        parser_inputs: [{ parser: constantParser([secretFinding]), input: {} }],
        report_paths: [],
      }),
    });

    const r = okResult<ToolOkPayload & { scan_id: string }>(
      await tool.handler({ project_path: projectPath }, plugin),
    );
    expect(r.ok).toBe(true);
    const topSnippet = (r.top_findings[0] as unknown as { snippet?: string }).snippet;
    expect(topSnippet).toBeDefined();
    expect(topSnippet).not.toContain('hunter2');

    const stored = plugin.storage.findings.listByScan(r.scan_id);
    expect(stored).toHaveLength(1);
    expect(stored[0]?.snippet).toBeDefined();
    expect(stored[0]?.snippet).not.toContain('hunter2');
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

  it('scans on a host with no bash shell — no factory tool runs a shell script any more', async () => {
    plugin.shell = null;
    const tool = makeScanTool({
      name: 'no_shell_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => ({
        outcome: 'completed',
        tools_run: [{ name: 'mock', status: 'ok' }],
        missing_tools: [],
        parser_inputs: [],
        report_paths: [],
      }),
    });
    const r = (await tool.handler({ project_path: projectPath }, plugin)) as
      | { ok: true; status: string }
      | { ok: false; error: { code: string } };
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.status).toBe('completed');
  });

  it('refuses auto_fix when git cannot confirm the tree is clean (not a git repo), and never invokes the scanner', async () => {
    // `projectPath` is a plain temp dir — no `.git` anywhere above it that
    // git would accept. auto_fix would rewrite unversioned files there.
    let invokeCalls = 0;
    const tool = makeScanTool({
      name: 'autofix_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: { ...tinySchema, auto_fix: z.boolean().optional(), allow_dirty: z.boolean().optional() },
      invoke: async () => {
        invokeCalls += 1;
        return { outcome: 'completed', tools_run: [{ name: 'mock', status: 'ok' }], missing_tools: [], parser_inputs: [], report_paths: [] };
      },
    });
    const r = await tool.handler({ project_path: projectPath, auto_fix: true }, plugin);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('not_a_git_repo');
      expect(r.error.retry_with).toEqual({ allow_dirty: true });
    }
    expect(invokeCalls).toBe(0);

    // The caller may still opt in, knowingly.
    const optedIn = await tool.handler({ project_path: projectPath, auto_fix: true, allow_dirty: true }, plugin);
    expect(optedIn.ok).toBe(true);
    expect(invokeCalls).toBe(1);
  });

  it('records the orchestrator that ran it in meta.parent_scan_id, and hands its children its own id', async () => {
    let seen: InvokeContext['childCallMeta'] | undefined;
    const child = makeScanTool({
      name: 'child_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async (_input, ctx) => {
        seen = ctx.childCallMeta;
        return { outcome: 'completed', tools_run: [{ name: 'mock', status: 'ok' }], missing_tools: [], parser_inputs: [], report_paths: [] };
      },
    });
    const controller = new AbortController();
    const r = okResult<ToolOkPayload>(
      await child.handler({ project_path: projectPath }, plugin, {
        parentScanId: 'parent-1',
        progressToken: 'tok',
        signal: controller.signal,
      }),
    );
    const row = plugin.storage.scans.getById(r.scan_id);
    expect(row?.meta?.['parent_scan_id']).toBe('parent-1');
    // Not an extra of the response: it is the factory's own bookkeeping.
    expect((r as unknown as Record<string, unknown>)['parent_scan_id']).toBeUndefined();
    expect(seen?.parentScanId).toBe(r.scan_id);
    expect(seen?.progressToken).toBe('tok');
    controller.abort();
    expect(seen?.signal?.aborted).toBe(true);
  });

  // M-b: OWASP coverage judges a scan against the languages the project
  // had WHEN it ran, recorded on the row — for every scan type a detector
  // reads, and only those.
  it.each([
    ['sast', true],
    ['quality', false],
  ] as const)('a %s scan records the project languages on its row: %s', async (scanType, recorded) => {
    writeFileSync(join(projectPath, 'main.go'), 'package main\n');
    const tool = makeScanTool({
      name: `lang_${scanType}`,
      scan_type: scanType,
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => ({ outcome: 'completed', tools_run: [{ name: 'mock', status: 'ok' }], missing_tools: [], parser_inputs: [], report_paths: [] }),
    });
    const r = okResult<ToolOkPayload>(await tool.handler({ project_path: projectPath }, plugin));
    const meta = plugin.storage.scans.getById(r.scan_id)?.meta;
    if (recorded) {
      expect(meta?.['project_languages']).toMatchObject({ languages: ['go'] });
      // Bookkeeping, not an extra of the response.
      expect((r as unknown as Record<string, unknown>)['project_languages']).toBeUndefined();
    } else {
      expect(meta?.['project_languages']).toBeUndefined();
    }
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

/** A completed, finding-free invocation. */
function emptyRun(extras?: Record<string, unknown>): ScannerInvocation {
  const run: ScannerInvocation = {
    outcome: 'completed',
    tools_run: [{ name: 'mock', status: 'ok' }],
    missing_tools: [],
    parser_inputs: [],
    report_paths: [],
  };
  if (extras !== undefined) run.extras = extras;
  return run;
}

interface CachePayload {
  scan_id: string;
  scan_type: string;
  cached?: boolean;
  cached_from?: string;
  started_at: string;
  finished_at: string | null;
  duration_ms?: number | null;
  [key: string]: unknown;
}

/**
 * The cache key used to be (tree_hash, scan_type) and nothing else. Every
 * test here is a reproduction of a call that was answered from somebody
 * else's scan.
 */
describe('makeScanTool: the cache key covers everything that shapes a scan', () => {
  let projectPath: string;
  let plugin: PluginContext;

  beforeEach(() => {
    projectPath = tempProject();
    plugin = buildPlugin(projectPath);
  });

  function countingTool(name: string, extraSchema: Record<string, z.ZodTypeAny> = {}) {
    const calls: Array<Record<string, unknown>> = [];
    const tool = makeScanTool<{ project_path?: string; [k: string]: unknown }>({
      name,
      scan_type: 'containers',
      category: 'security',
      description: '',
      inputSchema: { ...tinySchema, ...extraSchema },
      invoke: async (input) => {
        calls.push({ ...input });
        return emptyRun();
      },
    });
    return { tool, calls };
  }

  it('does not answer a call for another input from the cache (scan_containers image vs Dockerfile)', async () => {
    const { tool, calls } = countingTool('key_input_scan', {
      image: z.string().optional(),
      dockerfile_path: z.string().optional(),
    });
    const first = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    const second = okResult<CachePayload>(
      await tool.handler({ project_path: projectPath, image: 'nginx:1.19' }, plugin),
    );
    expect(calls).toHaveLength(2);
    expect(second.cached).toBeUndefined();
    expect(second.scan_id).not.toBe(first.scan_id);

    // The same input again IS a hit — the key is precise, not disabled.
    const third = okResult<CachePayload>(
      await tool.handler({ project_path: projectPath, image: 'nginx:1.19' }, plugin),
    );
    expect(third.cached).toBe(true);
    expect(third.cached_from).toBe(second.scan_id);
    expect(calls).toHaveLength(2);
  });

  it('ignores response-only inputs (severity_min, force) and input key order when keying', async () => {
    const { tool, calls } = countingTool('key_order_scan', {
      base_ref: z.string().optional(),
      head_ref: z.string().optional(),
    });
    await tool.handler({ project_path: projectPath, base_ref: 'main', head_ref: 'HEAD' }, plugin);
    const hit = okResult<CachePayload>(
      await tool.handler(
        { head_ref: 'HEAD', severity_min: 'high', base_ref: 'main', project_path: projectPath },
        plugin,
      ),
    );
    expect(hit.cached).toBe(true);
    expect(calls).toHaveLength(1);

    const otherRef = okResult<CachePayload>(
      await tool.handler({ project_path: projectPath, base_ref: 'develop', head_ref: 'HEAD' }, plugin),
    );
    expect(otherRef.cached).toBeUndefined();
    expect(calls).toHaveLength(2);
  });

  it('treats an omitted input with a schema default the same as the default passed explicitly', async () => {
    const { tool, calls } = countingTool('key_default_scan', {
      include_language_packs: z.boolean().optional().default(false),
    });
    await tool.handler({ project_path: projectPath }, plugin);
    const hit = okResult<CachePayload>(
      await tool.handler({ project_path: projectPath, include_language_packs: false }, plugin),
    );
    expect(hit.cached).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it('never shares a cache entry between two projects whose trees hash the same', async () => {
    // Two empty directories have the same tree hash. The second project used
    // to be handed the first one's scan — findings, report paths and all.
    const { tool, calls } = countingTool('key_project_scan');
    const otherProject = tempProject();
    const first = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    const second = okResult<CachePayload>(await tool.handler({ project_path: otherProject }, plugin));
    expect(calls).toHaveLength(2);
    expect(second.cached).toBeUndefined();
    expect(first.scan_id).not.toBe(second.scan_id);
  });

  it('never shares a cache entry between two tools, even with the same scan_type', async () => {
    const a = countingTool('key_tool_a');
    const b = countingTool('key_tool_b');
    await a.tool.handler({ project_path: projectPath }, plugin);
    const other = okResult<CachePayload>(await b.tool.handler({ project_path: projectPath }, plugin));
    expect(other.cached).toBeUndefined();
    expect(b.calls).toHaveLength(1);
  });

  it('misses when a rule pack the tool loads changes on disk', async () => {
    const pack = join(tempProject(), 'rules.yml');
    writeFileSync(pack, 'rules: []\n');
    let invokes = 0;
    const tool = makeScanTool({
      name: 'key_pack_scan',
      scan_type: 'bugs',
      category: 'bug',
      description: '',
      inputSchema: tinySchema,
      rulePacks: () => [pack, 'p/r2c-bug-scan'],
      invoke: async () => {
        invokes += 1;
        return emptyRun();
      },
    });
    await tool.handler({ project_path: projectPath }, plugin);
    const hit = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(hit.cached).toBe(true);

    writeFileSync(pack, 'rules:\n  - id: new-rule\n');
    const miss = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(miss.cached).toBeUndefined();
    expect(invokes).toBe(2);
  });

  it('never serves a run whose scanner was missing or failed — install, re-run, and the re-run scans', async () => {
    // A run with the scanner not installed is `completed` with coverage
    // `none`, and its own warning says "install … and re-run". The re-run,
    // inside the cache window, used to get that very result back.
    let scannerInstalled = false;
    let invokes = 0;
    const tool = makeScanTool({
      name: 'key_coverage_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => {
        invokes += 1;
        return scannerInstalled
          ? emptyRun()
          : {
              outcome: 'completed' as const,
              tools_run: [{ name: 'semgrep', status: 'skipped' as const, reason: 'not_installed' }],
              missing_tools: ['semgrep'],
              parser_inputs: [],
              report_paths: [],
            };
      },
    });

    const missing = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(missing['coverage']).toBe('none');

    scannerInstalled = true;
    const rerun = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(rerun.cached).toBeUndefined();
    expect(rerun['coverage']).toBe('full');
    expect(invokes).toBe(2);

    // A full-coverage run is still cached.
    const hit = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(hit.cached).toBe(true);
    expect(hit.cached_from).toBe(rerun.scan_id);
    expect(invokes).toBe(2);
  });

  it('never serves a partial run (one scanner failed) either', async () => {
    let invokes = 0;
    const tool = makeScanTool({
      name: 'key_partial_scan',
      scan_type: 'deps',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => {
        invokes += 1;
        return {
          outcome: 'completed' as const,
          tools_run: [
            { name: 'trivy', status: 'ok' as const },
            { name: 'npm', status: 'failed' as const, reason: 'failed to run' },
          ],
          missing_tools: ['npm'],
          parser_inputs: [],
          report_paths: [],
        };
      },
    });
    await tool.handler({ project_path: projectPath }, plugin);
    const again = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(again.cached).toBeUndefined();
    expect(again['coverage']).toBe('partial');
    expect(invokes).toBe(2);
  });

  it('never serves a row written before the cache key existed', async () => {
    // A 2.0.0 database: a completed scan of this very tree, same type, no
    // cache key. Nothing records which inputs or rule packs produced it.
    const { tool, calls } = countingTool('key_legacy_scan');
    const probe = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    plugin.storage
      .rawHandle()
      .prepare('UPDATE scans SET cache_key = NULL WHERE id = ?')
      .run(probe.scan_id);
    const again = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(again.cached).toBeUndefined();
    expect(calls).toHaveLength(2);
  });
});

describe('makeScanTool: a cache hit is shaped like the run it came from', () => {
  let projectPath: string;
  let plugin: PluginContext;

  beforeEach(() => {
    projectPath = tempProject();
    plugin = buildPlugin(projectPath);
  });

  it('re-emits the extras the original run returned', async () => {
    const extras = {
      bot_configured: { renovate: true, dependabot: false },
      licenses_summary: { MIT: 2 },
      wordpress_layout_detected: false,
    };
    const tool = makeScanTool({
      name: 'extras_scan',
      scan_type: 'deps_audit',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => emptyRun(extras),
    });
    const fresh = okResult<CachePayload>(
      await tool.handler({ project_path: projectPath, severity_min: 'low' }, plugin),
    );
    const cached = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));

    expect(cached.cached).toBe(true);
    expect(cached['bot_configured']).toEqual(extras.bot_configured);
    expect(cached['licenses_summary']).toEqual(extras.licenses_summary);
    expect(cached['wordpress_layout_detected']).toBe(false);
    // The first call's floor is not an extra and must not leak into the
    // second call's payload; nor is the raw `meta` blob part of a result.
    expect(cached['severity_min']).toBeUndefined();
    expect(cached['meta']).toBeUndefined();
    for (const key of Object.keys(fresh)) {
      if (key === 'severity_filter' || key === 'warnings') continue;
      expect(Object.keys(cached)).toContain(key);
    }
  });

  it('returns the scan row\'s real start and finish times and the duration between them', async () => {
    const tool = makeScanTool({
      name: 'timing_scan',
      scan_type: 'sast',
      category: 'security',
      description: '',
      inputSchema: tinySchema,
      invoke: async () => {
        await new Promise((resolve) => setTimeout(resolve, 40));
        return emptyRun();
      },
    });
    const fresh = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    const row = plugin.storage.scans.getById(fresh.scan_id);
    expect(row).not.toBeNull();
    if (row === null || row.finished_at === null) throw new Error('scan row not finalized');

    expect(fresh.started_at).toBe(row.started_at);
    expect(fresh.finished_at).toBe(row.finished_at);
    expect(fresh.started_at).not.toBe(fresh.finished_at);
    expect(fresh.duration_ms).toBe(Date.parse(row.finished_at) - Date.parse(row.started_at));
    expect(fresh.duration_ms).toBeGreaterThanOrEqual(30);

    const cached = okResult<CachePayload>(await tool.handler({ project_path: projectPath }, plugin));
    expect(cached.cached).toBe(true);
    expect(cached.started_at).toBe(row.started_at);
    expect(cached.finished_at).toBe(row.finished_at);
    expect(cached.duration_ms).toBe(fresh.duration_ms);
  });
});

describe('makeScanTool: progress while a scan runs', () => {
  let projectPath: string;
  let plugin: PluginContext;

  beforeEach(() => {
    projectPath = tempProject();
    plugin = buildPlugin(projectPath);
  });

  it('emits a boundary event, heartbeats during the scanner, and forwards scanner stderr', async () => {
    // Only the heartbeat's interval is faked: the tree hash spawns `git`,
    // whose own timers must stay real.
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    try {
      const sent: ProgressPayload[] = [];
      plugin.progressNotifier = { send: (p) => sent.push(p) };
      let sentBeforeScanner = -1;
      let sentDuringScanner = -1;
      const tool = makeScanTool({
        name: 'progress_scan',
        scan_type: 'sast',
        category: 'security',
        description: '',
        inputSchema: tinySchema,
        invoke: async (_input, ctx: InvokeContext) => {
          sentBeforeScanner = sent.length;
          expect(typeof ctx.onLog).toBe('function');
          ctx.onLog?.('semgrep: scanning 12 files');
          vi.advanceTimersByTime(35_000);
          sentDuringScanner = sent.length - sentBeforeScanner;
          return emptyRun();
        },
      });

      await tool.handler({ project_path: projectPath }, plugin, { progressToken: 'tok-scan' });

      expect(sentBeforeScanner).toBeGreaterThan(0);
      expect(sentDuringScanner).toBeGreaterThanOrEqual(3);
      expect(sent.some((p) => p.message?.includes('semgrep: scanning 12 files'))).toBe(true);
      for (const p of sent) expect(p.progressToken).toBe('tok-scan');
      for (let i = 1; i < sent.length; i++) {
        const prev = sent[i - 1];
        const cur = sent[i];
        if (prev === undefined || cur === undefined) continue;
        expect(cur.progress).toBeGreaterThan(prev.progress);
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('stops sending once the scan has returned', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    try {
      const sent: ProgressPayload[] = [];
      plugin.progressNotifier = { send: (p) => sent.push(p) };
      const tool = makeScanTool({
        name: 'progress_stop_scan',
        scan_type: 'sast',
        category: 'security',
        description: '',
        inputSchema: tinySchema,
        invoke: async () => emptyRun(),
      });
      await tool.handler({ project_path: projectPath }, plugin, { progressToken: 7 });
      const after = sent.length;
      vi.advanceTimersByTime(60_000);
      expect(sent.length).toBe(after);
    } finally {
      vi.useRealTimers();
    }
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
    // (A sast row also records the project's languages — see the
    // project_languages test above; this one is about the floor.)
    expect(plugin.storage.scans.getById(rf.scan_id)?.meta).toMatchObject({ severity_min: 'high' });

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
