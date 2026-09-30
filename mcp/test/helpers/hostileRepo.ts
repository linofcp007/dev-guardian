/**
 * A repository whose own `.git/` names commands — built at test time in a
 * temp directory, never committed with a live `.git` (review 3.0, W2E-git).
 *
 * Every command it names is `mark.sh <name>`, which appends `<name>` to a file
 * of that name in `markers/` and nothing else: harmless, local, no network.
 * Armed with:
 *
 *   - `core.fsmonitor`                                  → marker `fsmonitor`
 *   - hooks in `.git/hooks` (post-index-change, post-checkout,
 *     reference-transaction, pre-commit, prepare-commit-msg, commit-msg,
 *     post-commit, pre-push, pre-auto-gc, post-rewrite)  → `hook-<name>`
 *   - filter `evil` (`*.dat`, by `.gitattributes`), `required = true`
 *                                                       → `clean`, `smudge`
 *   - textconv `tv` (`*.bin`)                            → `textconv`
 *   - `include.path` → a file defining textconv `inctv` (`*.itv`, by
 *     `.gitattributes`) and filter `evil2` (`*.inf`, mapped only by
 *     `$GIT_DIR/info/attributes`)                       → `inctextconv`,
 *                                                         `infclean`, `infsmudge`
 *   - `log.showSignature` + `gpg.program`, and a commit carrying a
 *     signature                                         → `gpg`
 *
 * `main` is checked out at a signed commit; `feature` (NOT checked out)
 * changes a `.dat`, an `.inf` and a `.js` file — what a review of a head that
 * is not checked out materialises.
 *
 * Git here runs with an isolated configuration: `HOME` / `USERPROFILE` a fake
 * home, `GIT_CONFIG_GLOBAL` its `.gitconfig`, `GIT_CONFIG_NOSYSTEM=1`.
 */
import { spawn, spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { makeTempDir } from './tempDir.js';

export interface HostileRepo {
  /** The temp directory holding everything below. */
  base: string;
  /** The work tree. */
  root: string;
  markers: string;
  /** The isolation environment: fake home, its global config, no system config. */
  env: Record<string, string>;
  baseSha: string;
  /** `main`, checked out: the signed commit. */
  mainSha: string;
  /** `feature`, not checked out. */
  featureSha: string;
  /** Names of the marker files written since the last {@link clearMarkers}. */
  markersWritten(): string[];
  clearMarkers(): void;
  /** Makes every filter-mapped file stat-dirty, so the next status / diff runs its clean filter. */
  touchMapped(): void;
  /** git with the isolation environment and NOTHING of dev-guardian's: the control. */
  plainGit(args: readonly string[], cwd?: string, input?: string): SpawnSyncReturns<string>;
  /**
   * {@link plainGit}, without blocking the test's event loop — for a control
   * that talks to a server running in the test process itself (a synchronous
   * spawn there waits for an answer the blocked server can never give).
   */
  plainGitAsync(args: readonly string[], cwd?: string): Promise<{ status: number | null; stderr: string }>;
  /** `mark.sh <name>` as a config value (quoted for git's shell). */
  mark(name: string, passThrough?: boolean): string;
}

/** A path as git's shell reads it (forward slashes; Git for Windows' sh takes `C:/…`). */
export function shPath(p: string): string {
  return p.replace(/\\/g, '/');
}

export const HOOKS = [
  'post-index-change',
  'post-checkout',
  'reference-transaction',
  'pre-commit',
  'prepare-commit-msg',
  'commit-msg',
  'post-commit',
  'pre-push',
  'pre-auto-gc',
  'post-rewrite',
] as const;

export function buildHostileRepo(): HostileRepo {
  const base = makeTempDir('guardian-hostile-');
  const markers = join(base, 'markers');
  const home = join(base, 'home');
  const bin = join(base, 'bin');
  const root = join(base, 'repo');
  for (const d of [markers, home, bin, root]) mkdirSync(d, { recursive: true });

  const globalConfig = join(home, '.gitconfig');
  writeFileSync(
    globalConfig,
    '[user]\n\tname = Hostile Fixture\n\temail = fixture@example.invalid\n' +
      '[init]\n\tdefaultBranch = main\n[core]\n\tautocrlf = false\n\tsafecrlf = false\n',
  );
  const env: Record<string, string> = {
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    GIT_CONFIG_GLOBAL: globalConfig,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
  };

  const markScript = join(bin, 'mark.sh');
  writeFileSync(markScript, `#!/bin/sh\necho "$1" >> '${shPath(markers)}/'"$1"\n`);
  chmodSync(markScript, 0o755);
  const gpgMark = join(bin, 'gpg-mark');
  writeFileSync(gpgMark, `#!/bin/sh\necho gpg >> '${shPath(markers)}/gpg'\nexit 1\n`);
  chmodSync(gpgMark, 0o755);

  const mark = (name: string, passThrough = false): string =>
    `sh '${shPath(markScript)}' ${name}${passThrough ? '; cat' : ' #'}`;

  const plainGit = (args: readonly string[], cwd: string = root, input?: string): SpawnSyncReturns<string> => {
    const clean: NodeJS.ProcessEnv = { ...process.env };
    for (const k of Object.keys(clean)) if (/^GIT_/i.test(k)) delete clean[k];
    return spawnSync('git', [...args], {
      cwd,
      env: { ...clean, ...env },
      encoding: 'utf8',
      windowsHide: true,
      ...(input !== undefined ? { input } : { stdio: ['ignore', 'pipe', 'pipe'] }),
    });
  };
  const plainGitAsync = (args: readonly string[], cwd: string = root): Promise<{ status: number | null; stderr: string }> =>
    new Promise((resolveRun) => {
      const clean: NodeJS.ProcessEnv = { ...process.env };
      for (const k of Object.keys(clean)) if (/^GIT_/i.test(k)) delete clean[k];
      const child = spawn('git', [...args], { cwd, env: { ...clean, ...env }, windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
      let stderr = '';
      child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
      child.on('error', (e) => resolveRun({ status: null, stderr: e.message }));
      child.on('close', (status) => resolveRun({ status, stderr }));
    });
  const must = (args: readonly string[], input?: string): string => {
    const r = plainGit(args, root, input);
    if (r.status !== 0) throw new Error(`fixture: git ${args.join(' ')} failed: ${r.stderr}`);
    return r.stdout.trim();
  };

  // The history, built before anything is armed.
  must(['init', '-q']);
  writeFileSync(join(root, 'a.js'), 'console.log(1);\n');
  writeFileSync(join(root, 'b.dat'), 'data\n');
  writeFileSync(join(root, 'c.bin'), 'bin1\n');
  writeFileSync(join(root, 'd.itv'), 'inc1\n');
  writeFileSync(join(root, 'e.inf'), 'inf1\n');
  writeFileSync(join(root, '.gitattributes'), '*.dat filter=evil\n*.bin diff=tv\n*.itv diff=inctv\n');
  must(['add', '-A']);
  must(['commit', '-qm', 'base']);
  const baseSha = must(['rev-parse', 'HEAD']);
  writeFileSync(join(root, 'c.bin'), 'bin2\n');
  writeFileSync(join(root, 'd.itv'), 'inc2\n');
  must(['commit', '-qam', 'two']);
  // A commit that carries a (fake) signature: `log.showSignature` hands it to
  // gpg.program. It changes a file — gitleaks' `--diff-filter=tuxdb` drops a
  // commit with an empty diff, and gpg with it.
  writeFileSync(join(root, 'sig.txt'), 'signed\n');
  must(['add', 'sig.txt']);
  const tree = must(['write-tree']);
  const parent = must(['rev-parse', 'HEAD']);
  const signed = must(
    ['hash-object', '-t', 'commit', '-w', '--stdin'],
    `tree ${tree}\nparent ${parent}\nauthor F <f@example.invalid> 1700000000 +0000\ncommitter F <f@example.invalid> 1700000000 +0000\n` +
      'gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQ==\n -----END PGP SIGNATURE-----\n\nsigned\n',
  );
  must(['update-ref', 'refs/heads/main', signed]);
  must(['reset', '-q', '--hard', 'main']);
  must(['checkout', '-q', '-b', 'feature']);
  writeFileSync(join(root, 'a.js'), 'console.log(2);\n');
  writeFileSync(join(root, 'b.dat'), 'data2\n');
  writeFileSync(join(root, 'e.inf'), 'inf2\n');
  must(['commit', '-qam', 'feature']);
  const featureSha = must(['rev-parse', 'HEAD']);
  must(['checkout', '-q', 'main']);
  const mainSha = must(['rev-parse', 'HEAD']);

  // Armed.
  const included = join(base, 'included.gitconfig');
  writeFileSync(
    included,
    `[diff "inctv"]\n\ttextconv = ${mark('inctextconv', true)}\n` +
      `[filter "evil2"]\n\tclean = ${mark('infclean', true)}\n\tsmudge = ${mark('infsmudge', true)}\n`,
  );
  must(['config', 'core.fsmonitor', mark('fsmonitor')]);
  must(['config', 'filter.evil.clean', mark('clean', true)]);
  must(['config', 'filter.evil.smudge', mark('smudge', true)]);
  must(['config', 'filter.evil.required', 'true']);
  must(['config', 'diff.tv.textconv', mark('textconv', true)]);
  must(['config', 'include.path', shPath(included)]);
  must(['config', 'log.showSignature', 'true']);
  must(['config', 'gpg.program', shPath(gpgMark)]);
  mkdirSync(join(root, '.git', 'info'), { recursive: true });
  writeFileSync(join(root, '.git', 'info', 'attributes'), '*.inf filter=evil2\n');
  const hooks = join(root, '.git', 'hooks');
  mkdirSync(hooks, { recursive: true });
  for (const h of HOOKS) {
    const f = join(hooks, h);
    writeFileSync(f, `#!/bin/sh\necho ${h} >> '${shPath(markers)}/hook-${h}'\n`);
    chmodSync(f, 0o755);
  }

  const touchMapped = (): void => {
    const later = new Date(Date.now() + 2000);
    for (const f of ['b.dat', 'e.inf']) {
      const p = join(root, f);
      if (existsSync(p)) utimesSync(p, later, later);
    }
  };
  touchMapped();

  return {
    base,
    root,
    markers,
    env,
    baseSha,
    mainSha,
    featureSha,
    markersWritten: () => (existsSync(markers) ? readdirSync(markers).sort() : []),
    clearMarkers: () => {
      rmSync(markers, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
      mkdirSync(markers, { recursive: true });
    },
    touchMapped,
    plainGit,
    plainGitAsync,
    mark,
  };
}

export interface HostileSuperproject {
  base: string;
  /** The superproject's work tree. */
  root: string;
  markers: string;
  env: Record<string, string>;
  /** The fake global configuration file (tests add `submodule.recurse` to it). */
  globalConfig: string;
  /** The superproject's HEAD. */
  headSha: string;
  markersWritten(): string[];
  clearMarkers(): void;
  /** Makes every filter-mapped file of every submodule stat-dirty. */
  touchMapped(): void;
  plainGit(args: readonly string[], cwd?: string): SpawnSyncReturns<string>;
}

/**
 * A superproject whose SUBMODULES name commands (review of W2E-git, round 2):
 * each defines drivers under names the superproject never uses, in its own
 * configuration, which a superproject `git status` goes into.
 *
 *   - `sub`, an absorbed submodule (`.git/modules/sub/config`): filter `sm`
 *     (`*.dat`) → `SUBCLEAN`, textconv `smtv` (`*.bin`) → `SUBTEXTCONV`;
 *   - `sub/deep`, a submodule OF that submodule
 *     (`.git/modules/sub/modules/deep/config`): filter `dp` → `DEEPCLEAN`;
 *   - `old`, an old-style gitlink whose repository lives in the work tree
 *     (`old/.git/`): filter `ol` → `OLDCLEAN`.
 *
 * The superproject itself sets `diff.submodule = diff`, which makes
 * `git log -p` — gitleaks' — diff inside `sub` (its last commit moves `sub`).
 */
export function buildHostileSuperproject(): HostileSuperproject {
  const base = makeTempDir('guardian-hostile-super-');
  const markers = join(base, 'markers');
  const home = join(base, 'home');
  const bin = join(base, 'bin');
  for (const d of [markers, home, bin]) mkdirSync(d, { recursive: true });
  const globalConfig = join(home, '.gitconfig');
  writeFileSync(
    globalConfig,
    '[user]\n\tname = Hostile Fixture\n\temail = fixture@example.invalid\n' +
      '[init]\n\tdefaultBranch = main\n[core]\n\tautocrlf = false\n\tsafecrlf = false\n' +
      // Local submodules: git 2.38.1+ refuses the file transport for them by default.
      '[protocol "file"]\n\tallow = always\n',
  );
  const env: Record<string, string> = {
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    GIT_CONFIG_GLOBAL: globalConfig,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
  };
  const markScript = join(bin, 'mark.sh');
  writeFileSync(markScript, `#!/bin/sh\necho "$1" >> '${shPath(markers)}/'"$1"\n`);
  chmodSync(markScript, 0o755);
  const mark = (name: string): string => `sh '${shPath(markScript)}' ${name}; cat`;

  const plainGit = (args: readonly string[], cwd: string = base): SpawnSyncReturns<string> => {
    const clean: NodeJS.ProcessEnv = { ...process.env };
    for (const k of Object.keys(clean)) if (/^GIT_/i.test(k)) delete clean[k];
    return spawnSync('git', [...args], { cwd, env: { ...clean, ...env }, encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  };
  const must = (cwd: string, args: readonly string[]): string => {
    const r = plainGit(args, cwd);
    if (r.status !== 0) throw new Error(`fixture: git ${args.join(' ')} in ${cwd} failed: ${r.stderr}`);
    return r.stdout.trim();
  };
  const repo = (name: string, files: Record<string, string>): string => {
    const dir = join(base, name);
    mkdirSync(dir, { recursive: true });
    must(dir, ['init', '-q']);
    for (const [f, text] of Object.entries(files)) writeFileSync(join(dir, f), text);
    must(dir, ['add', '-A']);
    must(dir, ['commit', '-qm', `${name} 1`]);
    return dir;
  };

  const deepsrc = repo('deepsrc', { 'z.dat': 'deep\n', '.gitattributes': '*.dat filter=dp\n' });
  const subsrc = repo('subsrc', { 'x.dat': 'data\n', 'y.bin': 'bin1\n', '.gitattributes': '*.dat filter=sm\n*.bin diff=smtv\n' });
  must(subsrc, ['submodule', 'add', '-q', shPath(deepsrc), 'deep']);
  must(subsrc, ['commit', '-qm', 'subsrc deep']);
  writeFileSync(join(subsrc, 'y.bin'), 'bin2\n');
  must(subsrc, ['commit', '-qam', 'subsrc 3']);
  const oldsrc = repo('oldsrc', { 'w.dat': 'old\n', '.gitattributes': '*.dat filter=ol\n' });

  const root = repo('super', { 'a.txt': 'a\n' });
  must(root, ['submodule', 'add', '-q', shPath(subsrc), 'sub']);
  must(root, ['submodule', 'update', '--init', '--recursive', '-q']);
  must(root, ['commit', '-qm', 'super sub']);
  must(root, ['clone', '-q', shPath(oldsrc), 'old']);
  must(root, ['add', 'old']);
  must(root, ['commit', '-qm', 'super old']);
  // The last commit MOVES sub (subsrc's HEAD~1, then its HEAD), so `git log -p`
  // has a submodule diff to show.
  const subDir = join(root, 'sub');
  must(subDir, ['checkout', '-q', 'HEAD~1']);
  must(root, ['commit', '-qam', 'super pin sub']);
  must(subDir, ['checkout', '-q', '-']);
  must(root, ['commit', '-qam', 'super move sub']);
  const headSha = must(root, ['rev-parse', 'HEAD']);

  // Armed: each submodule's OWN configuration, and the superproject's diff.submodule.
  must(subDir, ['config', 'filter.sm.clean', mark('SUBCLEAN')]);
  must(subDir, ['config', 'diff.smtv.textconv', mark('SUBTEXTCONV')]);
  must(join(subDir, 'deep'), ['config', 'filter.dp.clean', mark('DEEPCLEAN')]);
  must(join(root, 'old'), ['config', 'filter.ol.clean', mark('OLDCLEAN')]);
  must(root, ['config', 'diff.submodule', 'diff']);

  const touchMapped = (): void => {
    const later = new Date(Date.now() + 2000);
    for (const f of [join(subDir, 'x.dat'), join(subDir, 'deep', 'z.dat'), join(root, 'old', 'w.dat')]) {
      if (existsSync(f)) utimesSync(f, later, later);
    }
  };
  touchMapped();
  return {
    base,
    root,
    markers,
    env,
    globalConfig,
    headSha,
    markersWritten: () => (existsSync(markers) ? readdirSync(markers).sort() : []),
    clearMarkers: () => {
      rmSync(markers, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
      mkdirSync(markers, { recursive: true });
    },
    touchMapped,
    plainGit,
  };
}
