/**
 * Review 3.0, W2E-git, against a REAL git: a repository delivered with its
 * own `.git/` names commands — `core.fsmonitor`, hooks, a filter driver, two
 * textconv drivers (one from an `include.path`, mapped by
 * `$GIT_DIR/info/attributes`), `gpg.program` with `log.showSignature` — and
 * nothing dev-guardian runs on it may execute any of them.
 *
 * Every command is `mark.sh <name>` (`test/helpers/hostileRepo.ts`): a file
 * written in the test's temp directory, nothing else, no network. The first
 * block is the CONTROL — plain git, on the same repository, writes those
 * markers — so the second block cannot pass by testing a repository that
 * runs nothing. Then each dev-guardian path runs on it and must write none.
 *
 * gitleaks and Semgrep are real when installed; a path that needs one and
 * finds it missing is SKIPPED, which vitest reports — never passed by
 * running something else. `GUARDIAN_REQUIRE_GITLEAKS=1` /
 * `GUARDIAN_REQUIRE_SEMGREP=1` turn a missing scanner into a failure.
 */
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { configDifferences, copyConfigFromRef, readBaselineAtRef, resolveCiRef } from '../../src/ci/refConfig.js';
import { createWorktree } from '../../src/fixpr/worktree.js';
import { openPr } from '../../src/fixpr/pr.js';
import { projectTreeState } from '../../src/fixpr/treeState.js';
import { languagesFromFiles, languagesFromFilesAsync } from '../../src/frameworks/projectLanguages.js';
import { applyGitSafety, execGit, forgetGitConfigReads, GIT_COMMAND, gitSafetyFor } from '../../src/platform/gitSafety.js';
import { resolveScope } from '../../src/platform/scope.js';
import {
  changedFiles,
  historyState,
  initialisedSubmodules,
  materialiseCommit,
  repoState,
  uncommittedFiles,
} from '../../src/runners/git.js';
import { runProcess, type ProcessRunOptions, type ProcessRunResult } from '../../src/runners/processRunner.js';
import { gitIndexAt } from '../../src/storage/dbProvenance.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { computeTreeHash } from '../../src/treeHash/computeTreeHash.js';
import { isGitRepo, workingTreeState } from '../../src/tools/gitState.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { buildHostileRepo, buildHostileSuperproject, shPath, type HostileRepo, type HostileSuperproject } from '../helpers/hostileRepo.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 300_000, hookTimeout: 120_000 });

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const HOOK = join(REPO_ROOT, 'hooks', 'guardian-hook.mjs');
const GITLEAKS = await isInstalled('gitleaks');
const SEMGREP = await isInstalled('semgrep');
const PRECOMMIT = await isInstalled('pre-commit');

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/tools/scanSecrets.js');
  await import('../../src/tools/scanSast.js');
  await import('../../src/tools/reviewPr.js');
  await import('../../src/tools/precommitInstall.js');
  resetScannerCache();
});

/** The process environment with the fixture's isolation, and no git variable of this machine's. */
function isolate(repo: { env: Record<string, string>; base: string }): void {
  for (const k of Object.keys(process.env)) if (/^GIT_/i.test(k)) vi.stubEnv(k, undefined);
  for (const [k, v] of Object.entries(repo.env)) vi.stubEnv(k, v);
  vi.stubEnv('GUARDIAN_DATA_DIR', join(repo.base, 'guardian-data'));
  // Tests below rewrite a repository's configuration between runs: no reading reused across that.
  forgetGitConfigReads();
}
afterEach(() => {
  vi.unstubAllEnvs();
});

function context(scriptsDir: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir, progressNotifier: { send: () => {} } };
}

async function runTool(name: string, input: Record<string, unknown>): Promise<{ tools_run: ToolRun[]; warnings?: string[] }> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`${name} not registered`);
  const r = await tool.handler(input, context(join(REPO_ROOT, 'scripts')));
  if (!r.ok) throw new Error(`${name}: ${JSON.stringify(r.error)}`);
  return r as unknown as { tools_run: ToolRun[]; warnings?: string[] };
}

// ---------------------------------------------------------------- the control

describe('control: plain git on this repository runs every command it names', () => {
  let repo: HostileRepo;
  beforeAll(() => {
    repo = buildHostileRepo();
  });
  beforeEach(() => {
    isolate(repo);
    repo.clearMarkers();
    repo.touchMapped();
  });

  it('status: core.fsmonitor, both clean filters (one from include.path, mapped by info/attributes), post-index-change', () => {
    expect(repo.plainGit(['status', '--porcelain']).status).toBe(0);
    expect(repo.markersWritten()).toEqual(['clean', 'fsmonitor', 'hook-post-index-change', 'infclean']);
  });

  it('ls-files --others: core.fsmonitor', () => {
    repo.plainGit(['ls-files', '-z', '--others', '--exclude-standard']);
    expect(repo.markersWritten()).toContain('fsmonitor');
  });

  it('log -p (gitleaks\' own arguments): both textconv drivers, and gpg.program for the signed commit', () => {
    expect(repo.plainGit(['log', '-p', '-U0', '--full-history', '--all', '--diff-filter=tuxdb']).status).toBe(0);
    expect(repo.markersWritten()).toEqual(expect.arrayContaining(['gpg', 'inctextconv', 'textconv']));
  });

  it('worktree add: both smudge filters, post-checkout, reference-transaction', () => {
    const wt = join(makeTempDir('guardian-ctl-wt-'), 'wt');
    expect(repo.plainGit(['worktree', 'add', '--detach', '-q', wt, repo.featureSha]).status).toBe(0);
    expect(repo.markersWritten()).toEqual(
      expect.arrayContaining(['hook-post-checkout', 'hook-reference-transaction', 'infsmudge', 'smudge']),
    );
    repo.plainGit(['worktree', 'remove', '--force', wt]);
  });

  it('commit --no-verify still runs prepare-commit-msg, post-commit and reference-transaction', () => {
    const wt = join(makeTempDir('guardian-ctl-wt2-'), 'wt');
    repo.plainGit(['worktree', 'add', '--detach', '-q', wt, 'HEAD']);
    repo.clearMarkers();
    writeFileSync(join(wt, 'a.js'), 'console.log(3);\n');
    expect(repo.plainGit(['commit', '--no-verify', '-qam', 'x'], wt).status).toBe(0);
    expect(repo.markersWritten()).toEqual(
      expect.arrayContaining(['hook-post-commit', 'hook-prepare-commit-msg', 'hook-reference-transaction']),
    );
    repo.plainGit(['worktree', 'remove', '--force', wt]);
  });

  it('a child process started with dev-guardian\'s environment runs none of it (the fake scanner below, unhardened)', () => {
    const r = spawnSync(process.execPath, ['-e', FAKE_SCANNER], {
      cwd: repo.root,
      env: { ...process.env },
      encoding: 'utf8',
    });
    expect(r.status).toBe(0);
    expect(repo.markersWritten()).toEqual(expect.arrayContaining(['fsmonitor', 'gpg', 'textconv']));
  });
});

/** A "scanner" that runs git itself — as Semgrep and gitleaks do — inheriting its environment. */
const FAKE_SCANNER = [
  "const { spawnSync } = require('node:child_process');",
  "for (const a of [['status', '--porcelain'], ['ls-files', '-z'], ['log', '-p', '--all']]) {",
  "  const r = spawnSync('git', a, { stdio: ['ignore', 'pipe', 'pipe'] });",
  "  if (r.status !== 0) { process.stderr.write(String(r.stderr)); process.exit(1); }",
  '}',
].join('\n');

// ---------------------------------------------------------------- dev-guardian

describe('dev-guardian on the same repository runs none of them', () => {
  let repo: HostileRepo;
  beforeAll(() => {
    repo = buildHostileRepo();
  });
  beforeEach(() => {
    isolate(repo);
    repo.clearMarkers();
    repo.touchMapped();
  });
  afterEach(() => {
    expect(repo.markersWritten()).toEqual([]);
  });

  it("runners/git.ts: every query scan_sast, scan_secrets and security_scan_full ask (status, diff, ls-files, log)", async () => {
    expect((await repoState(repo.root)).kind).toBe('has_commits');
    expect(await uncommittedFiles(repo.root, true, [])).toEqual(expect.any(Array));
    expect(Object.keys(await historyState(repo.root))).toEqual(['head', 'refs']);
    expect(await initialisedSubmodules(repo.root)).toEqual([]);
    expect(await changedFiles(repo.root, 'main', 'feature')).toEqual(expect.arrayContaining(['a.js', 'b.dat', 'e.inf']));
  });

  it('a child process runProcess starts — a scanner running git itself — inherits the hardening', async () => {
    const r = await runProcess({ command: process.execPath, args: ['-e', FAKE_SCANNER], cwd: repo.root });
    expect(r.stderr).toBe('');
    expect(r.outcome).toBe('completed');
    expect(r.gitNotApplied).toEqual(expect.arrayContaining(['core.fsmonitor', 'diff.tv.textconv', 'filter.evil.clean', 'gpg.program']));
  });

  it('gitState (the auto_fix guard) and detect_stack\'s listing, sync and async', async () => {
    expect((await workingTreeState(repo.root)).state).not.toBe('unknown');
    expect(await isGitRepo(repo.root)).toBe(true);
    expect(languagesFromFiles(repo.root).listing).toBe('git');
    expect((await languagesFromFilesAsync(repo.root)).listing).toBe('git');
  });

  it('the tree hash and the database provenance check', async () => {
    expect(await computeTreeHash(repo.root)).toMatch(/^[0-9a-f]{64}$/);
    expect(gitIndexAt(repo.root).state).toBe('ok');
  });

  it('the CI gate: --baseline-ref and --rules-ref reads', async () => {
    const at = await resolveCiRef(repo.root, 'main', '--baseline-ref');
    expect(at.commit).toBe(repo.mainSha);
    await readBaselineAtRef(repo.root, at);
    const copy = await copyConfigFromRef(repo.root, at, makeTempDir('guardian-rules-ref-'));
    await configDifferences(repo.root, at, copy);
  });

  it("review_pr's head checkout: no smudge filter, no hook — and it says which of the repository's settings it did not apply", async () => {
    const tree = await materialiseCommit(repo.root, repo.featureSha);
    try {
      expect(readFileSync(join(tree.root, 'b.dat'), 'utf8')).toBe('data2\n');
      expect(tree.notApplied).toEqual(expect.arrayContaining(['filter.evil.smudge', 'filter.evil2.smudge', 'core.fsmonitor']));
    } finally {
      expect(await tree.remove()).toBeNull();
    }
  });

  it('create_fix_pr: tree state, worktree, commit and push — to a local origin whose own hooks and receivepack are armed', async () => {
    expect((await projectTreeState(repo.root)).ok).toBe(true);
    const dest = join(repo.base, 'dest.git');
    expect(repo.plainGit(['init', '-q', '--bare', dest], repo.base).status).toBe(0);
    for (const h of ['pre-receive', 'update', 'post-receive', 'post-update', 'reference-transaction']) {
      const f = join(dest, 'hooks', h);
      writeFileSync(f, `#!/bin/sh\necho ${h} >> '${shPath(repo.markers)}/dest-${h}'\n`, { mode: 0o755 });
    }
    repo.plainGit(['remote', 'add', 'origin', dest]);
    repo.plainGit(['config', 'remote.origin.receivepack', repo.mark('receivepack')]);

    // Control, first: plain git runs the repository's receivepack, and — with
    // the standard one — the destination's own hooks.
    repo.plainGit(['push', 'origin', 'HEAD:refs/heads/control-a']);
    repo.plainGit(['push', '--receive-pack=git-receive-pack', 'origin', 'HEAD:refs/heads/control-b']);
    expect(repo.markersWritten()).toEqual(expect.arrayContaining(['dest-post-receive', 'dest-pre-receive', 'hook-pre-push', 'receivepack']));
    repo.clearMarkers();
    forgetGitConfigReads();

    const branch = 'dev-guardian/fix-w2e';
    const created = await createWorktree({ projectPath: repo.root, branch });
    if (!created.ok) throw new Error(created.reason);
    const { worktree } = created;
    try {
      expect(readFileSync(join(worktree.path, 'b.dat'), 'utf8')).toBe('data\n');
      expect(worktree.notApplied).toEqual(expect.arrayContaining(['filter.evil.smudge', 'core.fsmonitor']));
      writeFileSync(join(worktree.path, 'a.js'), 'console.log("fixed");\n');
      const pr = await openPr({ projectPath: repo.root, worktreePath: worktree.path, branch, title: 'fix', body: 'b', run: fakeGh });
      expect(pr.status).toBe('created');
      expect(pr.git_config_not_applied).toEqual(expect.arrayContaining(['remote.origin.receivepack', 'filter.evil.clean']));
      expect(repo.plainGit(['--git-dir', dest, 'rev-parse', '--verify', '-q', `refs/heads/${branch}`], repo.base).status).toBe(0);
    } finally {
      await worktree.remove();
    }
  });

  it("create_fix_pr: a push over ssh uses ssh, never the repository's core.sshCommand — and a failed push names it", async () => {
    const ssh = buildHostileRepo();
    isolate(ssh);
    ssh.plainGit(['remote', 'add', 'origin', 'ssh://git@127.0.0.1:1/nothing.git']);
    ssh.plainGit(['config', 'core.sshCommand', ssh.mark('sshcommand')]);
    ssh.plainGit(['ls-remote', 'origin']);
    expect(ssh.markersWritten()).toEqual(['sshcommand']);
    ssh.clearMarkers();
    forgetGitConfigReads();

    const branch = 'dev-guardian/fix-w2e-ssh';
    const created = await createWorktree({ projectPath: ssh.root, branch });
    if (!created.ok) throw new Error(created.reason);
    try {
      writeFileSync(join(created.worktree.path, 'a.js'), 'console.log("fixed");\n');
      const pr = await openPr({ projectPath: ssh.root, worktreePath: created.worktree.path, branch, title: 'fix', body: 'b', run: fakeGh });
      expect(pr.status).toBe('push_failed');
      expect(pr.detail).toMatch(/not applied for .*core\.sshcommand/);
      expect(ssh.markersWritten()).toEqual([]);
    } finally {
      await created.worktree.remove();
    }
  });

  it.runIf(process.env['GUARDIAN_REQUIRE_GITLEAKS'] === '1')('GUARDIAN_REQUIRE_GITLEAKS=1 — gitleaks must be on PATH', () => {
    expect(GITLEAKS).toBe(true);
  });

  it.skipIf(!GITLEAKS)("scan_secrets: gitleaks' git log -p runs neither textconv driver nor gpg.program, and says so", async () => {
    const out = await runTool('scan_secrets', { project_path: repo.root, force: true });
    const history = out.tools_run.find((t) => t.name === 'gitleaks');
    expect(history?.status).toBe('ok');
    expect(history?.reason).toMatch(/history: \d+ commit\(s\) scanned/);
    expect(history?.reason).toMatch(/not applied for [^—]*diff\.tv\.textconv/);
  });

  it.runIf(process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1')('GUARDIAN_REQUIRE_SEMGREP=1 — semgrep must be on PATH', () => {
    expect(SEMGREP).toBe(true);
  });

  it.skipIf(!SEMGREP)("scan_sast (local_only): Semgrep's own git ls-files runs no core.fsmonitor", async () => {
    // A project rule, so local_only has something to run — untracked, which
    // Semgrep finds through its own `git ls-files --others`.
    const rules = join(repo.root, '.semgrep.yml');
    writeFileSync(rules, 'rules:\n  - id: w2e-console\n    languages: [javascript]\n    severity: INFO\n    message: m\n    pattern: console.log(...)\n');
    try {
      const out = await runTool('scan_sast', { project_path: repo.root, local_only: true, force: true });
      expect(out.tools_run.find((t) => t.name === 'semgrep')?.status, JSON.stringify(out.tools_run)).toBe('ok');
    } finally {
      rmSync(rules, { force: true });
    }
  });

  it('review_pr (local_only) of a head that is not checked out', async () => {
    const out = await runTool('review_pr', { project_path: repo.root, base_ref: 'main', head_ref: 'feature', local_only: true, force: true });
    expect(out.warnings?.join('\n') ?? '').toMatch(/Head checkout: the repository's own git configuration was not applied/);
  });

  it.skipIf(!PRECOMMIT)(
    "precommit_install: pre-commit installs its hooks where git says — and runs none of the repository's commands",
    async () => {
      const cfg = join(repo.root, '.pre-commit-config.yaml');
      writeFileSync(cfg, 'repos: []\n');
      try {
        const tool = TOOLS.find((t) => t.name === 'precommit_install');
        if (!tool) throw new Error('precommit_install not registered');
        const r = await tool.handler({ project_path: repo.root }, context(join(REPO_ROOT, 'scripts')));
        expect(r.ok, JSON.stringify(r)).toBe(true);
        expect((r as unknown as { stages_installed: string[] }).stages_installed).toContain('pre-commit');
        expect(readFileSync(join(repo.root, '.git', 'hooks', 'pre-commit'), 'utf8')).toMatch(/pre-commit/);
      } finally {
        rmSync(cfg, { force: true });
      }
    },
  );

  it("the hook's SessionStart briefing (git status in the project a session opens)", () => {
    const r = sessionStart(repo.root, repo.base);
    expect(r.status).toBe(0);
    // git DID run — the briefing names the branch — and ran nothing of the repository's.
    expect(r.stdout).toContain('branch `main`');
  });
});

/** The real SessionStart dispatcher (from `dist/`), in `root`, with a fake home. */
function sessionStart(root: string, base: string): { status: number | null; stdout: string } {
  expect(existsSync(join(REPO_ROOT, 'mcp', 'dist', 'platform', 'gitSafety.js'))).toBe(true);
  const home = join(base, 'hook-home');
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: root };
  delete env['CLAUDE_CONFIG_DIR'];
  const r = spawnSync(process.execPath, [HOOK], {
    cwd: root,
    input: JSON.stringify({ hook_event_name: 'SessionStart', cwd: root }),
    encoding: 'utf8',
    env,
    timeout: 60_000,
  });
  return { status: r.status, stdout: r.stdout };
}

/** `gh` answered locally: no pull request yet, and one created. Everything else is the real runner. */
async function fakeGh(o: ProcessRunOptions): Promise<ProcessRunResult> {
  if (o.command === 'gh') {
    const stdout = o.args?.[1] === 'list' ? '[]' : 'https://example.invalid/pull/1\n';
    return { outcome: 'completed', exitCode: 0, stdout, stderr: '', truncated: false };
  }
  return runProcess(o);
}

// ---------------------------------------------------------------- submodules (round 2)

describe("submodules: each one's OWN drivers — absorbed, nested and in-tree — run nowhere dev-guardian goes", () => {
  let s: HostileSuperproject;
  beforeAll(() => {
    s = buildHostileSuperproject();
  });
  beforeEach(() => {
    isolate(s);
    s.clearMarkers();
    s.touchMapped();
  });

  it('control: a plain superproject status runs all three filters; a plain log -p the submodule textconv', () => {
    expect(s.plainGit(['status', '--porcelain'], s.root).status).toBe(0);
    expect(s.markersWritten()).toEqual(['DEEPCLEAN', 'OLDCLEAN', 'SUBCLEAN']);
    s.clearMarkers();
    s.touchMapped();
    expect(s.plainGit(['log', '-p', '-1'], s.root).status).toBe(0);
    expect(s.markersWritten()).toEqual(['SUBTEXTCONV']);
  });

  it('control: --ignore-submodules=dirty alone keeps a plain status out of every submodule', () => {
    expect(s.plainGit(['status', '--porcelain', '--ignore-submodules=dirty'], s.root).status).toBe(0);
    expect(s.markersWritten()).toEqual([]);
  });

  describe('dev-guardian', () => {
    afterEach(() => {
      expect(s.markersWritten()).toEqual([]);
    });

    it('a full, recursing status runs none of them: every submodule configuration is neutralised', async () => {
      const r = await execGit(s.root, ['status', '--porcelain']);
      expect(r.status).toBe(0);
      expect(r.notApplied).toEqual(expect.arrayContaining(['filter.sm.clean (submodule sub)', 'filter.dp.clean (submodule sub/deep)']));
    });

    it("the auto_fix guard: clean when clean, and still dirty for a submodule's uncommitted work or moved commit", async () => {
      expect(await workingTreeState(s.root)).toEqual({ state: 'clean' });
      expect(s.markersWritten()).toEqual([]);
      const x = join(s.root, 'sub', 'x.dat');
      writeFileSync(x, 'changed\n');
      expect((await workingTreeState(s.root)).state).toBe('dirty');
      writeFileSync(x, 'data\n');
      s.touchMapped();
      expect(await workingTreeState(s.root)).toEqual({ state: 'clean' });
      expect(s.markersWritten()).toEqual([]);
      s.plainGit(['checkout', '-q', 'HEAD~1'], join(s.root, 'sub'));
      s.clearMarkers(); // the plain checkout above, not dev-guardian
      s.touchMapped();
      expect((await workingTreeState(s.root)).state).toBe('dirty');
      expect(s.markersWritten()).toEqual([]);
      s.plainGit(['checkout', '-q', '-'], join(s.root, 'sub'));
      s.clearMarkers();
    });

    it("the hook's SessionStart briefing", () => {
      const r = sessionStart(s.root, s.base);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('branch `main`');
    });

    it('the working-tree listings: uncommitted files, a diff scope, create_fix_pr tree state, the CI gate', async () => {
      expect(await uncommittedFiles(s.root, true, [])).toEqual(expect.any(Array));
      expect((await resolveScope(s.root, { diff: {} }, { exclusions: null })).kind).toBe('diff');
      expect((await projectTreeState(s.root)).ok).toBe(true);
      const at = await resolveCiRef(s.root, 'HEAD', '--rules-ref');
      await configDifferences(s.root, at, await copyConfigFromRef(s.root, at, makeTempDir('guardian-rules-ref-sub-')));
    });

    it('a scanner running status and log -p itself (and the repository asks for diffs inside submodules)', async () => {
      const r = await runProcess({ command: process.execPath, args: ['-e', FAKE_SCANNER], cwd: s.root });
      expect(r.stderr).toBe('');
      expect(r.outcome).toBe('completed');
    });

    it.skipIf(!GITLEAKS)("scan_secrets: gitleaks' git log -p stays out of the submodule", async () => {
      const out = await runTool('scan_secrets', { project_path: s.root, force: true });
      expect(out.tools_run.find((t) => t.name === 'gitleaks')?.status).toBe('ok');
    });

    it("with the user's own submodule.recurse=true, review_pr's head checkout and create_fix_pr's worktree still work", async () => {
      appendFileSync(s.globalConfig, '[submodule]\n\trecurse = true\n');
      try {
        const tree = await materialiseCommit(s.root, s.headSha);
        expect(existsSync(join(tree.root, 'a.txt'))).toBe(true);
        expect(await tree.remove()).toBeNull();
        const created = await createWorktree({ projectPath: s.root, branch: null });
        if (!created.ok) throw new Error(created.reason);
        expect(existsSync(join(created.worktree.path, 'a.txt'))).toBe(true);
        await created.worktree.remove();
      } finally {
        writeFileSync(s.globalConfig, readFileSync(s.globalConfig, 'utf8').replace('[submodule]\n\trecurse = true\n', ''));
      }
    });
  });
});

// ---------------------------------------------------------------- credentials over HTTP (round 2)

interface Seen {
  server: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
}

/** A local HTTP server that records every request; `info/refs` answers as an empty (dumb) repository. */
async function recorder(name: string, seen: Seen[]): Promise<{ url: string; close: () => void }> {
  const server = createServer((req, res) => {
    seen.push({ server: name, url: req.url ?? '', headers: req.headers });
    res.setHeader('Set-Cookie', 'sess=abc; Path=/');
    if (req.url?.includes('/info/refs')) {
      res.setHeader('Content-Type', 'text/plain');
      res.end('');
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  return { url: `http://127.0.0.1:${port}`, close: () => server.close() };
}

describe('the repository cannot route, inspect or redirect the credentials a git sends over HTTP (local servers only)', () => {
  let repo: HostileRepo;
  let origin: { url: string; close: () => void };
  let other: { url: string; close: () => void };
  const seen: Seen[] = [];
  beforeAll(async () => {
    repo = buildHostileRepo();
    origin = await recorder('origin', seen);
    other = await recorder('other', seen);
    repo.plainGit(['remote', 'add', 'origin', `${origin.url}/r.git`]);
  });
  afterAll(() => {
    origin.close();
    other.close();
  });
  beforeEach(() => {
    isolate(repo);
    seen.length = 0;
  });

  const lsRemote = (): Promise<ProcessRunResult> =>
    runProcess({ command: GIT_COMMAND, args: ['ls-remote', 'origin'], cwd: repo.root, timeoutMs: 30_000 });
  const reached = (): string[] => [...new Set(seen.map((s) => s.server))].sort();
  const headerValues = (h: string): string[] => seen.flatMap((s) => (typeof s.headers[h] === 'string' ? [s.headers[h] as string] : []));

  it("extra headers: the repository's, generic and URL-specific, are not sent; the user's own still are", async () => {
    repo.plainGit(['config', 'http.extraHeader', 'X-Evil: 1']);
    repo.plainGit(['config', `http.${origin.url}/.extraHeader`, 'X-Evil: 2']);
    appendFileSync(repo.env['GIT_CONFIG_GLOBAL'] ?? '', '[http]\n\textraHeader = X-Mine: 1\n');
    try {
      await repo.plainGitAsync(['ls-remote', 'origin']);
      expect(headerValues('x-evil')).toEqual(expect.arrayContaining(['1, 2']));
      seen.length = 0;
      expect((await lsRemote()).outcome).toBe('completed');
      expect(headerValues('x-evil')).toEqual([]);
      expect(headerValues('x-mine').length).toBeGreaterThan(0);
    } finally {
      repo.plainGit(['config', '--unset-all', 'http.extraHeader']);
      repo.plainGit(['config', '--unset-all', `http.${origin.url}/.extraHeader`]);
      const global = repo.env['GIT_CONFIG_GLOBAL'] ?? '';
      writeFileSync(global, readFileSync(global, 'utf8').replace('[http]\n\textraHeader = X-Mine: 1\n', ''));
    }
  });

  const proxyKeys: ReadonlyArray<readonly [string, () => string]> = [
    ['http.proxy', (): string => 'http.proxy'],
    ['http.<url>.proxy', (): string => `http.${origin.url}/.proxy`],
    ['remote.origin.proxy', (): string => 'remote.origin.proxy'],
  ];
  it.each(proxyKeys)("%s: the repository's proxy is not used — the user's own proxy variable is", async (_label, key) => {
    repo.plainGit(['config', key(), other.url]);
    try {
      await repo.plainGitAsync(['ls-remote', 'origin']);
      expect(reached()).toEqual(['other']);
      seen.length = 0;
      await lsRemote();
      expect(reached()).toEqual(['origin']);
      seen.length = 0;
      vi.stubEnv('http_proxy', other.url);
      await lsRemote();
      expect(reached()).toEqual(['other']);
    } finally {
      repo.plainGit(['config', '--unset', key()]);
    }
  });

  it('cookies: none sent from a file of the repository\'s choosing, and none written to one', async () => {
    const jar = join(repo.base, 'jar.txt');
    writeFileSync(jar, '127.0.0.1\tFALSE\t/\tFALSE\t0\tstolen\tyes\n');
    repo.plainGit(['config', 'http.cookieFile', jar]);
    repo.plainGit(['config', 'http.saveCookies', 'true']);
    try {
      await repo.plainGitAsync(['ls-remote', 'origin']);
      expect(headerValues('cookie').join(';')).toContain('stolen=yes');
      expect(readFileSync(jar, 'utf8')).toContain('sess');
      writeFileSync(jar, '127.0.0.1\tFALSE\t/\tFALSE\t0\tstolen\tyes\n');
      seen.length = 0;
      expect((await lsRemote()).outcome).toBe('completed');
      expect(headerValues('cookie').join(';')).not.toContain('stolen');
      expect(readFileSync(jar, 'utf8')).not.toContain('sess');
    } finally {
      repo.plainGit(['config', '--unset', 'http.cookieFile']);
      repo.plainGit(['config', '--unset', 'http.saveCookies']);
    }
  });

  it('followRedirects: git reads its own default, not the repository\'s', async () => {
    repo.plainGit(['config', 'http.followRedirects', 'true']);
    try {
      expect((await execGit(repo.root, ['config', '--get', 'http.followRedirects'])).stdout.trim()).toBe('initial');
    } finally {
      repo.plainGit(['config', '--unset', 'http.followRedirects']);
    }
  });

  const OPENSSL = spawnSync('openssl', ['version'], { encoding: 'utf8' }).status === 0;
  it.skipIf(!OPENSSL)('TLS: neither sslVerify=false nor a certificate authority of the repository\'s choosing lets a self-signed server through', async () => {
    const dir = makeTempDir('guardian-tls-');
    const key = join(dir, 'k.pem');
    const cert = join(dir, 'c.pem');
    const made = spawnSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
      { encoding: 'utf8' },
    );
    expect(made.status, made.stderr).toBe(0);
    const tls = createHttpsServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
      seen.push({ server: 'tls', url: req.url ?? '', headers: req.headers });
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((r) => tls.listen(0, '127.0.0.1', r));
    const address = tls.address();
    const tlsUrl = `https://127.0.0.1:${typeof address === 'object' && address !== null ? address.port : 0}/r.git`;
    repo.plainGit(['remote', 'set-url', 'origin', tlsUrl]);
    try {
      for (const [k, v] of [['http.sslVerify', 'false'], ['http.sslCAInfo', cert]] as const) {
        repo.plainGit(['config', k, v]);
        forgetGitConfigReads(); // the configuration changed inside the 2 s a reading is reused
        seen.length = 0;
        await repo.plainGitAsync(['ls-remote', 'origin']);
        expect(reached(), `plain git with ${k}`).toEqual(['tls']);
        seen.length = 0;
        await lsRemote();
        expect(reached(), `dev-guardian with ${k}`).toEqual([]);
        repo.plainGit(['config', '--unset', k]);
      }
    } finally {
      repo.plainGit(['remote', 'set-url', 'origin', `${origin.url}/r.git`]);
      tls.close();
    }
  });

  it("create_fix_pr refuses a push the repository's own url.<base>.insteadOf sends to another host, and names it", async () => {
    repo.plainGit(['config', `url.${other.url}/.insteadOf`, `${origin.url}/`]);
    try {
      await repo.plainGitAsync(['push', '--no-verify', 'origin', 'HEAD:refs/heads/control']);
      expect(reached()).toEqual(['other']);
      seen.length = 0;
      forgetGitConfigReads();
      const branch = 'dev-guardian/fix-w2e-rewrite';
      const created = await createWorktree({ projectPath: repo.root, branch });
      if (!created.ok) throw new Error(created.reason);
      try {
        writeFileSync(join(created.worktree.path, 'a.js'), 'console.log("fixed");\n');
        const pr = await openPr({ projectPath: repo.root, worktreePath: created.worktree.path, branch, title: 'fix', body: 'b', run: fakeGh });
        expect(pr.status).toBe('push_failed');
        expect(pr.detail).toMatch(/url\.http:\/\/127\.0\.0\.1:\d+\/\.insteadof = http:\/\/127\.0\.0\.1:\d+\/ turns/);
        expect(reached()).toEqual([]);
      } finally {
        await created.worktree.remove();
        repo.plainGit(['branch', '-D', branch]);
      }
    } finally {
      repo.plainGit(['config', '--unset', `url.${other.url}/.insteadOf`]);
    }
  });
});

// ---------------------------------------------------------------- measured overrides

describe('what each neutral value does to a real git (the helper\'s environment, applied by hand)', () => {
  let repo: HostileRepo;
  beforeAll(() => {
    repo = buildHostileRepo();
  });
  beforeEach(() => {
    isolate(repo);
    repo.clearMarkers();
  });

  async function hardenedEnv(): Promise<NodeJS.ProcessEnv> {
    const s = await gitSafetyFor([repo.root]);
    expect(s.refused).toBeNull();
    return applyGitSafety(s, process.env);
  }

  it('textconv `cat` is identity: the diff shows the stored bytes', async () => {
    const r = spawnSync('git', ['log', '-p', '-1', 'main~1', '--', 'c.bin'], { cwd: repo.root, env: await hardenedEnv(), encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('+bin2');
    expect(repo.markersWritten()).toEqual([]);
  });

  it('an empty clean filter with required forced false passes the content through (status stays clean)', async () => {
    repo.touchMapped();
    const r = spawnSync('git', ['status', '--porcelain'], { cwd: repo.root, env: await hardenedEnv(), encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe('');
    expect(repo.markersWritten()).toEqual([]);
  });

  it("credential helpers: the repository's never runs; the user's own still does", async () => {
    const helperMarks = join(repo.base, 'bin', 'helper.sh');
    writeFileSync(helperMarks, `#!/bin/sh\necho "$1" >> '${shPath(repo.markers)}/'"$1"\n`, { mode: 0o755 });
    repo.plainGit(['config', 'credential.helper', `!sh '${shPath(helperMarks)}' repohelper`]);
    const globalFile = repo.env['GIT_CONFIG_GLOBAL'] ?? '';
    spawnSync('git', ['config', '--file', globalFile, 'credential.helper', `!sh '${shPath(helperMarks)}' userhelper`]);
    const input = 'protocol=https\nhost=example.invalid\n\n';
    spawnSync('git', ['credential', 'fill'], { cwd: repo.root, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, input, encoding: 'utf8' });
    expect(repo.markersWritten()).toEqual(['repohelper', 'userhelper']);
    repo.clearMarkers();
    forgetGitConfigReads();
    spawnSync('git', ['credential', 'fill'], { cwd: repo.root, env: { ...(await hardenedEnv()), GIT_TERMINAL_PROMPT: '0' }, input, encoding: 'utf8' });
    expect(repo.markersWritten()).toEqual(['userhelper']);
    repo.plainGit(['config', '--unset', 'credential.helper']);
    spawnSync('git', ['config', '--file', globalFile, '--unset', 'credential.helper']);
  });
});
