/**
 * The plugin as Claude Code installs it runs: a checkout of the files git
 * tracks, with NO `node_modules` anywhere in reach — the CLI's every
 * subcommand, the hooks and the MCP server, each started with a plain `node`.
 *
 * ---- The regression (3.2.0 -> 3.2.1) ----------------------------------------
 *
 * 3.2.0's `cli/dev-guardian.mjs scan` and `status` failed in every install —
 * `dev-guardian: unexpected error: Cannot find package 'yaml' imported from
 * …/mcp/dist/platform/boundedParse.js`, exit 3. The CLI imported tsc's
 * per-file output, `mcp/dist/<area>/*.js`, and since the llm-scan /
 * import_sarif work that graph reached the npm packages, which tsc's output
 * imports by name: they resolve in this checkout (`mcp/node_modules`) and in
 * no install. Every test was green, because every test ran the CLI from here.
 * dev-spec-driven 1.29's `/spec-finish` runs `scan --project . --fail-on high
 * --format json` from the installed plugin as its gate — with 3.2.0 it could
 * only fail. The CLI then ran on its own self-contained bundle; since 3.3.0
 * the CLI and the server share one, `mcp/dist/engine.js` (`mcp/src/engine.ts`;
 * `mcp/dist/server.js` starts it), the hooks load theirs, `mcp/dist/hooks.js`,
 * and the build ships no per-file output at all (review 8, findings 2 and 3).
 *
 * ---- How the install is made --------------------------------------------------
 *
 * A real `git archive` (review 11, finding 16: it was a copy of what `git
 * ls-files` names), extracted into a temp directory whose path holds a SPACE,
 * as `C:\Users\Jane Doe\.claude\plugins\…` does: the tree of the next commit
 * — the index, with every tracked file's working-tree content (`git add -u`
 * into a copy of the index, so the real one is never touched) — and nothing
 * git does not track: no `node_modules`, and whatever `export-ignore` would
 * leave out. A file the install needs must therefore be TRACKED for this
 * file to pass — a new source, a new build output (`npm run build`, then
 * `git add` what it made) — exactly as it must be committed to ship. The
 * first positive control proves the archive is an install: none of
 * `mcp/package.json`'s dependencies resolves from it. Outside a git checkout
 * (an exported tree) there is nothing to archive, and the suite is skipped,
 * visibly.
 *
 * Every command is checked for what the defect looked like — exit 3 and a
 * `Cannot find package` — on top of its own exit code. The one real scan is
 * the gate's exact command, so it takes as long as the scanners installed
 * here take (none: a few seconds, with exit 2 for the missing coverage). The
 * hooks run exactly as `hooks/hooks.json` declares them — exec form, its
 * `command` and `args`, `${CLAUDE_PLUGIN_ROOT}` replaced by the install's
 * root — one run per declared entry. A damaged `mcp/dist` beside it is the
 * negative control: what these checks would see if the build were broken.
 */

import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, cpSync, existsSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { sarifLog, sarifResult, sarifRun, writeSarif } from '../helpers/sarif.js';
import { spawnSyncCapped, timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));

/** `git` in the repository, plainly (this repository is trusted): stdout as bytes. */
function gitIn(args: readonly string[], env: Record<string, string> = {}): { status: number | null; stdout: Buffer; stderr: string } {
  const r = spawnSync('git', ['-C', REPO_ROOT, ...args], {
    env: { ...process.env, ...env },
    maxBuffer: 1024 * 1024 * 1024,
    windowsHide: true,
  });
  return { status: r.status, stdout: r.stdout ?? Buffer.alloc(0), stderr: (r.stderr ?? Buffer.alloc(0)).toString('utf8') };
}

/** Whether REPO_ROOT is the root of a git work tree (not an exported copy of one). */
const IN_CHECKOUT = ((): boolean => {
  const top = gitIn(['rev-parse', '--show-toplevel']);
  if (top.status !== 0) return false;
  try {
    return realpathSync.native(top.stdout.toString('utf8').trim()).toLowerCase() === realpathSync.native(REPO_ROOT).toLowerCase();
  } catch {
    return false;
  }
})();

/** A CLI run that reaches no scanner, a hook, the server's handshake: a hang-breaker, generous for a loaded machine. */
const FAST_TIMEOUT_MS = 45_000;
/** The real scan (whatever scanners are installed here): a hang-breaker, as in ciCliFixture.test.ts. */
const SCAN_TIMEOUT_MS = 600_000;
/** Copying ~2,200 tracked files. */
const COPY_TIMEOUT_MS = 180_000;
vi.setConfig({ testTimeout: timeoutAbove(FAST_TIMEOUT_MS) });

afterAll(cleanupTempDirs);

/** What the 3.2.0 defect printed, in any of its spellings. */
const UNRESOLVED = /Cannot find (?:package|module)|ERR_MODULE_NOT_FOUND|unexpected error/;

/**
 * `git archive` of the next commit's tree — the index, every tracked file at
 * its working-tree content — extracted into `into`; returns how many files
 * the tree holds. A copy of the index is updated (`git add -u`), never the
 * index itself.
 */
function installArchive(into: string): number {
  const indexPath = gitIn(['rev-parse', '--git-path', 'index']).stdout.toString('utf8').trim();
  const tempIndex = join(makeTempDir('guardian-install-index-'), 'index');
  copyFileSync(resolve(REPO_ROOT, indexPath), tempIndex);
  const env = { GIT_INDEX_FILE: tempIndex };
  const added = gitIn(['add', '-u'], env);
  if (added.status !== 0) throw new Error(`git add -u failed: ${added.stderr}`);
  const tree = gitIn(['write-tree'], env).stdout.toString('utf8').trim();
  if (!/^[0-9a-f]{40,64}$/.test(tree)) throw new Error(`git write-tree gave ${JSON.stringify(tree)}`);
  const archive = gitIn(['archive', '--format=tar', tree]);
  if (archive.status !== 0) throw new Error(`git archive failed: ${archive.stderr}`);
  // System32's bsdtar on Windows: GNU tar (Git Bash's) reads `C:` as a host.
  const tar = process.platform === 'win32' ? join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  const x = spawnSync(tar, ['-x', '-f', '-', '-C', into], { input: archive.stdout, maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  if (x.status !== 0) throw new Error(`tar -x failed: ${(x.stderr ?? Buffer.alloc(0)).toString('utf8')}`);
  return gitIn(['ls-tree', '-r', '--name-only', '-z', tree]).stdout.toString('utf8').split('\0').filter((f) => f !== '').length;
}

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

describe.skipIf(!IN_CHECKOUT)('a plugin install — a git archive, at a path with a space, no node_modules', () => {
  let install: string;
  let cli: string;
  let project: string;

  beforeAll(() => {
    install = makeTempDir('guardian install ');
    expect(install).toMatch(/ /);
    expect(installArchive(install)).toBeGreaterThan(1000);
    expect(existsSync(join(install, 'mcp', 'node_modules'))).toBe(false);
    cli = join(install, 'cli', 'dev-guardian.mjs');
    project = makeTempDir('guardian-install-project-');
    writeFileSync(join(project, 'index.js'), 'console.log("hello");\n');
  }, COPY_TIMEOUT_MS);

  function node(args: string[], opts: { cwd?: string; input?: string; timeout?: number; env?: Record<string, string> } = {}): Run {
    const r = spawnSyncCapped(process.execPath, args, {
      cwd: opts.cwd ?? project,
      encoding: 'utf8',
      timeout: opts.timeout ?? FAST_TIMEOUT_MS,
      env: { ...process.env, NO_COLOR: '1', ...opts.env },
      ...(opts.input === undefined ? {} : { input: opts.input }),
    });
    return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  }

  const run = (args: string[], opts: Parameters<typeof node>[1] = {}): Run => node([cli, ...args], opts);

  /** Ran, and none of it failed to load. */
  function loaded(r: Run, ...statuses: number[]): void {
    expect(`${r.stdout}${r.stderr}`).not.toMatch(UNRESOLVED);
    expect(statuses, `exit ${String(r.status)}\n${r.stderr}`).toContain(r.status);
  }

  it('what ships in mcp/dist: the two bundles (the hooks one in parts), the server’s entry, the bundles’ declarations and the assets — no per-file output, no source map', () => {
    const dist = join(install, 'mcp', 'dist');
    const shipped = gitIn(['ls-files', '-z', '--', 'mcp/dist'])
      .stdout.toString('utf8')
      .split('\0')
      .filter((f) => f !== '')
      .map((f) => f.slice('mcp/dist/'.length));
    const bundles = ['engine.js', 'hooks.js', 'hooksBash.js', 'hooksSession.js', 'hooksVet.js', 'hooksWrite.js', 'server.js'];
    // One `export *` line each, for the type check of the CLI and the hook (3.4.0).
    const declarations = ['engine.d.ts', 'hooks.d.ts'];
    expect(shipped.filter((f) => f.endsWith('.js')).sort()).toEqual(bundles);
    expect(shipped.filter((f) => f.endsWith('.d.ts')).sort()).toEqual(declarations);
    expect(shipped.filter((f) => f.endsWith('.map'))).toEqual([]);
    expect(
      shipped.filter((f) => !bundles.includes(f) && !declarations.includes(f) && !/^storage\/migrations\/\d{3}_\w+\.sql$|^hostsetup\/legacyRulesTemplates\//.test(f)),
    ).toEqual([]);
    expect(bundles.every((b) => existsSync(join(dist, b)))).toBe(true);
  });

  it('positive control: the copy is an install — none of mcp/package.json’s dependencies resolves from it', () => {
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'mcp', 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
    const deps = Object.keys(pkg.dependencies);
    expect(deps).toContain('yaml');
    // Resolved from inside the copy's mcp/dist, where the bundles are.
    const probe = join(install, 'mcp', 'dist', 'resolve-probe.mjs');
    writeFileSync(
      probe,
      'const out = {};\n' +
        'for (const p of JSON.parse(process.argv[2])) {\n' +
        "  try { await import(p); out[p] = 'resolved'; } catch (e) { out[p] = e.code ?? String(e); }\n" +
        '}\n' +
        'process.stdout.write(JSON.stringify(out));\n',
    );
    const r = node([probe, JSON.stringify(deps)]);
    expect(r.status, r.stderr).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual(Object.fromEntries(deps.map((d) => [d, 'ERR_MODULE_NOT_FOUND'])));
  });

  describe('the CLI', () => {
    it('--help, and scan --help', () => {
      for (const args of [['--help'], ['scan', '--help']]) {
        const r = run(args);
        loaded(r, 0);
        expect(r.stdout).toMatch(/dev-guardian — CLI/);
      }
    });

    it('check --bash "ls" is OK, and check --bash "rm -rf /" is not', () => {
      const ok = run(['check', '--bash', 'ls']);
      loaded(ok, 0);
      expect(ok.stdout).toMatch(/OK/);
      const bad = run(['check', '--bash', 'rm -rf /']);
      expect(`${bad.stdout}${bad.stderr}`).not.toMatch(UNRESOLVED);
      expect(bad.status).not.toBe(0);
    });

    it('mcp-config cursor previews the entry for the server', () => {
      const r = run(['mcp-config', 'cursor', '--project', project]);
      loaded(r, 0);
      expect(r.stdout).toMatch(/"mcpServers"/);
      expect(r.stdout).toMatch(/mcp[\\/]+dist[\\/]+server\.js/);
    });

    it('mcp-config codex --write recognises a 2.0.0 rules file — the legacy templates resolve from the bundle', () => {
      const dir = makeTempDir('guardian-install-legacy-');
      writeFileSync(
        join(dir, 'AGENTS.md'),
        readFileSync(join(install, 'mcp', 'dist', 'hostsetup', 'legacyRulesTemplates', 'agents-2.0.0.md.txt'), 'utf8'),
      );
      const first = run(['mcp-config', 'codex', '--write', '--project', dir]);
      loaded(first, 0);
      // Without them: manual_merge_required.
      expect(first.stdout).toMatch(/rules: needs_update/);
      const update = run(['mcp-config', 'codex', '--write', '--update-mcp', '--project', dir]);
      loaded(update, 0);
      expect(update.stdout).toMatch(/rules: merged/);
    });

    it('ci-init github previews a workflow', () => {
      const r = run(['ci-init', 'github', '--project', project], { env: { GUARDIAN_CI_INIT_PIN_SHA: 'a'.repeat(40) } });
      loaded(r, 0);
      expect(r.stdout).toMatch(/dev-guardian/);
    });

    it('scan and baseline update load the scan pipeline: their usage errors come after it', () => {
      const scan = run(['scan', '--fail-on', 'bogus']);
      loaded(scan, 3);
      expect(scan.stderr).toMatch(/--fail-on must be one of info\|low\|medium\|high\|critical/);
      const baseline = run(['baseline', 'update', '--project', join(project, 'missing')]);
      loaded(baseline, 3);
      expect(baseline.stderr).toMatch(/--project does not exist/);
    });

    it(
      'the gate dev-spec-driven runs — scan --project . --fail-on high --format json — exits 0, 1 or 2 with a JSON verdict',
      () => {
        const r = run(['scan', '--project', '.', '--fail-on', 'high', '--format', 'json'], { timeout: SCAN_TIMEOUT_MS });
        loaded(r, 0, 1, 2);
        const verdict = JSON.parse(r.stdout) as { exit_code: number; coverage: string };
        expect(verdict.exit_code).toBe(r.status);
        // `none` where no scanner is installed at all (the first Linux container run): exit 2, never a pass.
        expect(['full', 'partial', 'none']).toContain(verdict.coverage);
        if (verdict.coverage === 'none') expect(r.status).toBe(2);
      },
      timeoutAbove(SCAN_TIMEOUT_MS),
    );

    it('status on a project never scanned', () => {
      const r = run(['status', '--project', project]);
      loaded(r, 0);
      expect(r.stdout).toMatch(/No scan yet/);
    });

    it('import-sarif writes the project’s database; status, dashboard and db adopt read it', () => {
      const dir = makeTempDir('guardian-install-db-');
      const log = writeSarif(
        dir,
        'results.sarif',
        sarifLog([sarifRun({ results: [sarifResult({ ruleId: 'r1', level: 'warning', message: 'one', uri: 'a.js', startLine: 1 })] })]),
      );
      const imported = run(['import-sarif', log, '--project', dir], { cwd: dir });
      loaded(imported, 0);
      expect(imported.stdout).toMatch(/imported: 1/);

      const status = run(['status', '--project', dir]);
      loaded(status, 0);
      expect(status.stdout).not.toMatch(/No scan yet/);

      const out = join(dir, 'dashboard.html');
      const dashboard = run(['dashboard', '--project', dir, '--out', out, '--no-open']);
      loaded(dashboard, 0);
      expect(readFileSync(out, 'utf8')).toMatch(/<html/i);

      const adopt = run(['db', 'adopt', '--project', dir]);
      loaded(adopt, 0);
      expect(adopt.stdout).toMatch(/Already registered/);
    });
  });

  describe('the hooks, as hooks/hooks.json declares them', () => {
    interface Declared {
      event: string;
      matcher?: string;
      command: string;
      args: string[];
    }
    /** Every hook entry of the install's hooks.json, flattened. */
    const declared = (): Declared[] => {
      const doc = JSON.parse(readFileSync(join(install, 'hooks', 'hooks.json'), 'utf8')) as {
        hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ type: string; command: string; args?: string[] }> }>>;
      };
      return Object.entries(doc.hooks).flatMap(([event, groups]) =>
        groups.flatMap((g) =>
          g.hooks.map((h) => ({ event, ...(g.matcher !== undefined ? { matcher: g.matcher } : {}), command: h.command, args: h.args ?? [] })),
        ),
      );
    };

    /**
     * One declared entry run as Claude Code runs it: exec form (no shell),
     * its `command` — `node`, run here as this Node — and its `args`, with
     * `${CLAUDE_PLUGIN_ROOT}` the install's root (a path with a space).
     */
    const runDeclared = (entry: Declared, payload: Record<string, unknown>): { output: unknown; run: Run } => {
      expect(entry.command).toBe('node');
      const args = entry.args.map((a) => a.split('${CLAUDE_PLUGIN_ROOT}').join(install));
      const home = makeTempDir('guardian-install-home-');
      const r = node(args, {
        input: JSON.stringify({ cwd: project, hook_event_name: entry.event, ...payload }),
        // The user-level hook configuration is this test's, not the machine's (as in hooksDispatcher.test.ts).
        env: { HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: '', GUARDIAN_HOOKS: '', GUARDIAN_HOOKS_BASH_BLOCK: '', CLAUDE_PROJECT_DIR: project },
      });
      const text = r.stdout.trim();
      return { output: text === '' ? undefined : (JSON.parse(text) as unknown), run: r };
    };

    const entry = (event: string, tool?: string): Declared => {
      const found = declared().find((d) => d.event === event && (tool === undefined || d.matcher === undefined || new RegExp(d.matcher).test(tool)));
      if (found === undefined) throw new Error(`hooks.json declares no ${event} hook${tool !== undefined ? ` for ${tool}` : ''}`);
      return found;
    };

    it('every entry is exec form — node, and the dispatcher under ${CLAUDE_PLUGIN_ROOT} with its event — and runs from the install', () => {
      const all = declared();
      expect(all.length).toBeGreaterThanOrEqual(4);
      for (const d of all) {
        expect(d.command, d.event).toBe('node');
        expect(d.args, d.event).toEqual(['${CLAUDE_PLUGIN_ROOT}/hooks/guardian-hook.mjs', d.event]);
        // A tool no matcher names: the dispatcher answers nothing, exit 0 — it loaded.
        const { run: r } = runDeclared(d, { tool_name: 'Read', tool_input: { file_path: join(project, 'index.js') } });
        expect(r.status, `${d.event} ${d.matcher ?? ''}\n${r.stderr}`).toBe(0);
        expect(r.stderr).not.toMatch(UNRESOLVED);
      }
    });

    it('SessionStart loads every guard module', () => {
      const { output, run: r } = runDeclared(entry('SessionStart'), {});
      expect(r.status, r.stderr).toBe(0);
      const context = (output as { hookSpecificOutput?: { additionalContext?: string } } | undefined)?.hookSpecificOutput?.additionalContext;
      expect(context).toBeTypeOf('string');
      expect(context).not.toMatch(/could not be loaded/);
    });

    it('PreToolUse (the Bash entry) denies rm -rf /', () => {
      const { output } = runDeclared(entry('PreToolUse', 'Bash'), { tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
      expect(output).toMatchObject({ hookSpecificOutput: { permissionDecision: 'deny' } });
    });

    // Each from its own loader in mcp/dist/hooks.js: the install gate and package vetting, the secret scan.
    it('PreToolUse vets an npx download — offline, it says so: the vetting loaded', () => {
      const { output, run: r } = runDeclared(entry('PreToolUse', 'Bash'), {
        tool_name: 'Bash',
        tool_input: { command: 'npx -y zz-no-such-pkg-install-test' },
      });
      expect(r.status, r.stderr).toBe(0);
      expect(JSON.stringify(output)).toMatch(/could not vet zz-no-such-pkg-install-test/);
    });

    it('PreToolUse (the Write entry) denies a write to the hooks configuration', () => {
      const { output, run: r } = runDeclared(entry('PreToolUse', 'Write'), {
        tool_name: 'Write',
        tool_input: { file_path: join(project, '.guardian', 'hooks.config.json'), content: '{"enabled":false}' },
      });
      expect(r.status, r.stderr).toBe(0);
      expect(output, JSON.stringify(output)).toMatchObject({ hookSpecificOutput: { permissionDecision: expect.stringMatching(/deny|ask/) } });
    });

    it('PostToolUse warns about a secret just written', () => {
      const key = ['AKIA', 'Z7Q4', 'XR2M', 'P9LK', 'W3TB'].join('');
      const { output } = runDeclared(entry('PostToolUse', 'Write'), {
        tool_name: 'Write',
        tool_input: { file_path: join(project, 'aws.js'), content: `const k = "${key}";\n` },
      });
      expect(JSON.stringify(output)).toMatch(/AWS access key/);
    });
  });

  // The negative control (review 11, finding 16): the same install with its
  // bundles cut short. Each check above must tell that apart from a working
  // build — or it proves nothing about one.
  describe('negative control: the same install, its bundles damaged', () => {
    let damaged: string;
    beforeAll(() => {
      damaged = makeTempDir('guardian install damaged ');
      for (const part of ['cli', 'hooks', '.claude-plugin', join('mcp', 'dist'), join('mcp', 'package.json')]) {
        cpSync(join(install, part), join(damaged, part), { recursive: true });
      }
      for (const bundle of ['engine.js', 'hooks.js', 'hooksBash.js', 'hooksVet.js', 'hooksWrite.js', 'hooksSession.js']) {
        const path = join(damaged, 'mcp', 'dist', bundle);
        const text = readFileSync(path, 'utf8');
        writeFileSync(path, text.slice(0, Math.min(200_000, Math.floor(text.length / 2))));
      }
    }, COPY_TIMEOUT_MS);

    it('the CLI exits 3 and says the engine could not be loaded — what `loaded` refuses', () => {
      const r = node([join(damaged, 'cli', 'dev-guardian.mjs'), '--help']);
      expect(r.status).toBe(3);
      expect(r.stderr).toMatch(/its engine, mcp\/dist\/engine\.js, could not be loaded/);
      expect(() => loaded(r, 0)).toThrow();
    });

    it('the server does not answer: it exits', () => {
      const r = spawnSyncCapped(process.execPath, [join(damaged, 'mcp', 'dist', 'server.js')], {
        cwd: project,
        encoding: 'utf8',
        timeout: FAST_TIMEOUT_MS,
        input: '',
        env: { ...process.env, NO_COLOR: '1' },
      });
      expect(r.status).not.toBe(0);
      expect(r.stdout ?? '').not.toMatch(/"serverInfo"/);
    });

    it('the hooks fail open — exit 0 — and the guard the deny check looks for is gone', () => {
      const doc = JSON.parse(readFileSync(join(damaged, 'hooks', 'hooks.json'), 'utf8')) as {
        hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ args?: string[] }> }>>;
      };
      const bash = (doc.hooks['PreToolUse'] ?? []).find((g) => g.matcher !== undefined && new RegExp(g.matcher).test('Bash'));
      const args = (bash?.hooks[0]?.args ?? []).map((a) => a.split('${CLAUDE_PLUGIN_ROOT}').join(damaged));
      expect(args.length).toBe(2);
      const home = makeTempDir('guardian-install-home-');
      const r = node(args, {
        input: JSON.stringify({ cwd: project, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /' } }),
        env: { HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: '', GUARDIAN_HOOKS: '', GUARDIAN_HOOKS_BASH_BLOCK: '', CLAUDE_PROJECT_DIR: project },
      });
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).not.toMatch(/"permissionDecision":\s*"deny"/);
    });
  });

  describe('the MCP server', () => {
    it(
      'dist/server.js answers initialize with its instructions, lists the folded tools, and a hidden alias answers',
      async () => {
        const child = spawn(process.execPath, [join(install, 'mcp', 'dist', 'server.js')], {
          cwd: project,
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...process.env, NO_COLOR: '1' },
        });
        let stderr = '';
        child.stderr.setEncoding('utf8').on('data', (c: string) => (stderr += c));
        interface Reply {
          id?: number;
          result?: {
            serverInfo?: { name?: string };
            instructions?: string;
            tools?: Array<{ name: string }>;
            content?: Array<{ type: string; text?: string }>;
            isError?: boolean;
          };
          error?: { message?: string };
        }
        const replies = new Map<number, Reply>();
        let buffered = '';
        const answered = new Promise<void>((done, fail) => {
          const timer = setTimeout(() => fail(new Error(`no answer from the server within ${FAST_TIMEOUT_MS} ms\n${stderr}`)), FAST_TIMEOUT_MS);
          child.on('exit', (code) => fail(new Error(`the server exited (${String(code)}) before answering\n${stderr}`)));
          child.stdout.setEncoding('utf8').on('data', (chunk: string) => {
            buffered += chunk;
            for (let nl = buffered.indexOf('\n'); nl !== -1; nl = buffered.indexOf('\n')) {
              const line = buffered.slice(0, nl).trim();
              buffered = buffered.slice(nl + 1);
              if (line === '') continue;
              const message = JSON.parse(line) as Reply;
              if (typeof message.id === 'number') replies.set(message.id, message);
              if (message.id === 1) {
                child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
                child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`);
              }
              if (message.id === 2) {
                // A hidden alias (the triage view of prioritize_findings), called by its own name.
                child.stdin.write(
                  `${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'triage_findings', arguments: { project_path: project } } })}\n`,
                );
              }
              if (message.id === 3) {
                clearTimeout(timer);
                done();
              }
            }
          });
        });
        child.stdin.write(
          `${JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'install-test', version: '0.0.0' } },
          })}\n`,
        );
        try {
          await answered;
        } finally {
          child.removeAllListeners('exit');
          child.stdin.end();
          child.kill();
        }
        expect(stderr).not.toMatch(UNRESOLVED);
        expect(replies.get(1)?.result?.serverInfo?.name).toBe('dev-guardian');
        expect(replies.get(1)?.result?.instructions).toMatch(/dev-guardian/i);
        const listed = (replies.get(2)?.result?.tools ?? []).map((t) => t.name);
        expect(listed.length).toBeGreaterThan(40);
        // The folds' custom tools/list: the fold is listed, its member alias is not.
        expect(listed).toContain('prioritize_findings');
        expect(listed).not.toContain('triage_findings');
        // …and the alias still answers from the bundle: a tool result, never "unknown tool".
        const alias = replies.get(3);
        expect(alias?.error, JSON.stringify(alias)).toBeUndefined();
        expect(alias?.result?.content?.length).toBeGreaterThan(0);
      },
      timeoutAbove(FAST_TIMEOUT_MS),
    );
  });
});
