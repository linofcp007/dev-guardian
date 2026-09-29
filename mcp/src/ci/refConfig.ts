/**
 * The CI gate's `--baseline-ref` and `--rules-ref`: what a pull request
 * cannot change about its own gate.
 *
 * ---- The threat ------------------------------------------------------------
 *
 * A pull request's checkout holds the pull request's own
 * `.guardian/baseline.json` and its own scanner configuration. A gate that
 * reads them from the tree it scans lets the change under review decide how
 * it is judged: a fork adds its new findings to the baseline, deletes the
 * rule that would catch them from `.semgrep.yml`, or lists the file in
 * `.guardianignore` — and passes.
 *
 * ---- `--baseline-ref <ref>` ------------------------------------------------
 *
 * `.guardian/baseline.json` is read with git from the commit `<ref>` names
 * (`git ls-tree` for the entry, `git cat-file` for its bytes, the size checked
 * first), never from the working tree. None at that commit is no baseline —
 * every finding is new; a ref that names no commit is a usage error, never "no
 * baseline" (`resolveCiRef`).
 *
 * ---- `--rules-ref <ref>` ---------------------------------------------------
 *
 * Every file of {@link FROM_REF_FILES}, and each Semgrep rule file the ref's
 * own `.dev-guardian/configs.json` records, is copied from that commit into a
 * temporary directory ({@link copyConfigFromRef}); the scanners are handed
 * that copy explicitly and never read the tree's:
 *
 *   | file                                        | read by                 | the copy reaches it as                              |
 *   | ------------------------------------------- | ----------------------- | --------------------------------------------------- |
 *   | `.semgrep.yml`, `.semgrep.yaml`, manifest's | Semgrep (`scan_sast`)   | `--config=<copy>` (`InvokeContext.rulesProjectPath`: |
 *   | `semgrep/` targets                          |                         | rule ids as from the project root, baselines match) |
 *   | `.guardianignore`                           | every scan              | `loadProjectExclusions(project, <copy dir>)`; the   |
 *   |                                             |                         | submodule and size gaps and the language report     |
 *   |                                             |                         | read it too (`guardianIgnoreFrom`)                  |
 *   | `.trivyignore`                              | Trivy (deps, IaC)       | `--ignorefile <copy>`                               |
 *   | `.bandit`                                   | Bandit (`scan_sast`)    | `--ini <copy>` (the neutral one when the ref has none) |
 *
 * A file the ref does not have is not read from the tree either: the scan runs
 * as the project would with none. One the ref has but that cannot be copied —
 * over {@link CONFIG_MAX_BYTES}, not a file, a link leaving the repository —
 * stops the run (`CiRefError`): leaving it out would run fewer rules, or
 * exclude less, than the ref says, without a word.
 *
 * ---- What stays the tree's, named ------------------------------------------
 *
 * The rest of what the gate's scanners read from the repository
 * ({@link GATE_CONFIG}'s `tree` runners) is not taken from the ref:
 *
 *   - `.semgrepignore` — Semgrep reads every one in the tree it scans; the
 *     only flags that would change that (`--x-ignore-semgrepignore-files`,
 *     `--x-semgrepignore-filename`) are marked INTERNAL in 1.176.1's help, "may
 *     change or disappear without notice", and the second reads a file placed
 *     IN the scanned tree.
 *   - `.gitleaks.toml`, `.gitleaksignore` — measured on gitleaks 8.30.1:
 *     `--config` does replace the tree's `.gitleaks.toml`, but
 *     `<source>/.gitleaksignore` is read whatever `--gitleaks-ignore-path`
 *     names, and from any working directory. A fingerprint there hides a
 *     secret as surely as an allowlist, so taking the one from the ref and not
 *     the other would protect nothing.
 *   - actionlint's and zizmor's configuration — the workflows they audit are
 *     the pull request's own anyway.
 *   - the .NET build's `.editorconfig`, `.globalconfig`, `Directory.Build.*`
 *     and NuGet configuration — the build reads them from the tree it
 *     compiles.
 *
 * Each of those the pull request adds, changes or deletes against the ref is
 * named in the gate's output ({@link configDifferences}) — neither counted nor
 * a coverage gap: a pull request may legitimately edit its `.editorconfig`,
 * and a reviewer decides. So is each {@link FROM_REF_FILES} file it changes,
 * as not applied.
 */

import { execa } from 'execa';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, posix } from 'node:path';
import { MANIFEST_RELATIVE_PATH, readManifest } from '../configdrift/manifest.js';
import { CONVENTIONAL_TARGETS, SEMGREP_SOURCE_PREFIX } from '../platform/projectSemgrepConfig.js';
import { git, repoState, resolveCommit, showPrefix, splitNul } from '../runners/git.js';
import { REPO_CONFIG, type RepoConfigRunner } from '../runners/repoConfig.js';
import { PROJECT_TRIVYIGNORE } from '../runners/trivyRun.js';
import { GUARDIAN_IGNORE_FILE } from '../platform/guardianIgnore.js';
import { BASELINE_RELATIVE_PATH } from './baseline.js';
import type { ConfigDifference } from './types.js';

export type { ConfigDifference } from './types.js';

/** A ref that cannot be used, said as the CLI prints it (exit 3). */
export class CiRefError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CiRefError';
  }
}

/** A `--baseline-ref` / `--rules-ref` resolved against the scanned project. */
export interface ResolvedRef {
  /** As the caller spelled it. */
  ref: string;
  /** The commit it names. */
  commit: string;
  /** The project's path inside its repository: `''` at the root, else `sub/`. */
  prefix: string;
}

/** The largest baseline read from a ref. */
export const BASELINE_MAX_BYTES = 32 * 1024 * 1024;
/** The largest configuration or rule file copied from a ref. */
export const CONFIG_MAX_BYTES = 8 * 1024 * 1024;

/**
 * The repository files `--rules-ref` takes from the ref (the module comment's
 * table), project-relative. The Semgrep rule files a manifest records are
 * added per ref ({@link copyConfigFromRef}).
 */
export const FROM_REF_FILES: readonly string[] = [
  ...CONVENTIONAL_TARGETS,
  MANIFEST_RELATIVE_PATH,
  GUARDIAN_IGNORE_FILE,
  PROJECT_TRIVYIGNORE,
  '.bandit',
];

/**
 * Every runner of `runners/repoConfig.ts#REPO_CONFIG`, by what the gate does
 * with its files — complete by construction (`refConfig.test.ts`):
 *   - `ref`: taken from `--rules-ref` ({@link FROM_REF_FILES});
 *   - `tree`: the gate runs it and it reads the tree's own — named when the
 *     pull request changes one (the module comment says why each);
 *   - `not_in_gate`: no step of the gate's pipeline runs it.
 */
export const GATE_CONFIG: Readonly<Record<RepoConfigRunner, 'ref' | 'tree' | 'not_in_gate'>> = {
  guardian: 'ref',
  trivy: 'ref',
  bandit: 'ref',
  semgrep: 'tree',
  gitleaks: 'tree',
  actionlint: 'tree',
  zizmor: 'tree',
  'dotnet-analyzers': 'tree',
  // deps_audit, scan_containers and quality_check are not gate steps.
  npm: 'not_in_gate',
  dotnet: 'not_in_gate',
  hadolint: 'not_in_gate',
  ruff: 'not_in_gate',
  jscpd: 'not_in_gate',
  radon: 'not_in_gate',
  staticcheck: 'not_in_gate',
  eslint: 'not_in_gate',
};

/** What `--rules-ref` copied, for the gate's output. */
export interface RefConfigCopy {
  /** The directory holding the copies at their project-relative paths — what the scanners read. */
  root: string;
  /** Project-relative paths copied from the ref. */
  copied: string[];
  /** Looked for at the ref, and not there (so read from nowhere). */
  absent: string[];
}

/**
 * `ref` resolved against the project: the commit it names, and the project's
 * place in its repository. Throws {@link CiRefError} — never an empty answer
 * — when the project is not in a git work tree or `ref` names no commit
 * there (a shallow clone, a base branch that was never fetched).
 */
export async function resolveCiRef(projectPath: string, ref: string, flag: string): Promise<ResolvedRef> {
  if (ref.length === 0) throw new CiRefError(`${flag} requires a value`);
  if (ref.startsWith('-')) throw new CiRefError(`${flag} takes a git ref, not an option (got '${ref}')`);
  const state = await repoState(projectPath);
  if (state.kind === 'not_git') {
    throw new CiRefError(`${flag} ${ref}: ${projectPath} is not inside a git work tree`);
  }
  if (state.kind === 'error') throw new CiRefError(`${flag} ${ref}: git cannot read the repository (${state.message})`);
  const commit = await resolveCommit(projectPath, ref);
  if (commit === null) {
    throw new CiRefError(
      `${flag} ${ref}: names no commit in this repository — fetch it first (a shallow clone, or a base ` +
        'branch the checkout never fetched, does not have it)',
    );
  }
  let prefix: string;
  try {
    prefix = await showPrefix(projectPath);
  } catch (e) {
    throw new CiRefError(`${flag} ${ref}: ${e instanceof Error ? e.message : String(e)}`);
  }
  return { ref, commit, prefix };
}

/** An entry of the ref's tree: `git ls-tree` of one path. */
interface TreeEntry {
  mode: string;
  type: string;
  object: string;
}

/** The ref's tree entry at `fullPath` (repository-relative), or null when there is none. */
async function treeEntry(cwd: string, commit: string, fullPath: string): Promise<TreeEntry | null> {
  const r = await git(cwd, ['ls-tree', '-z', '--full-tree', commit, '--', fullPath]);
  if (r.exitCode !== 0) throw new CiRefError(`git ls-tree ${commit.slice(0, 12)} -- ${fullPath} failed: ${firstLine(r.stderr)}`);
  for (const line of splitNul(r.stdout)) {
    const tab = line.indexOf('\t');
    if (tab < 0 || line.slice(tab + 1) !== fullPath) continue;
    const [mode, type, object] = line.slice(0, tab).split(' ');
    if (mode === undefined || type === undefined || object === undefined) continue;
    return { mode, type, object };
  }
  return null;
}

/** The bytes of blob `object`, refused over `maxBytes` (checked before reading). */
async function blobBytes(cwd: string, object: string, maxBytes: number, label: string): Promise<Buffer> {
  const size = await git(cwd, ['cat-file', '-s', object]);
  const n = Number(size.stdout.trim());
  if (size.exitCode !== 0 || !Number.isInteger(n)) throw new CiRefError(`${label}: git cat-file -s failed: ${firstLine(size.stderr)}`);
  if (n > maxBytes) throw new CiRefError(`${label} is ${n} bytes, over the ${maxBytes}-byte limit — not read`);
  try {
    const r = await execa('git', ['-C', cwd, 'cat-file', 'blob', object], {
      encoding: 'buffer',
      // The bytes as git stored them: execa would drop a final newline.
      stripFinalNewline: false,
      reject: false,
      timeout: 60_000,
      maxBuffer: maxBytes + 1,
    });
    if (r.exitCode !== 0 || !(r.stdout instanceof Uint8Array)) {
      throw new CiRefError(`${label}: git cat-file blob failed`);
    }
    return Buffer.from(r.stdout);
  } catch (e) {
    if (e instanceof CiRefError) throw e;
    throw new CiRefError(`${label}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * The bytes of the regular file at `rel` (project-relative) in the ref's
 * commit, or null when the ref has no entry there. A symbolic link is followed
 * once, inside the repository — what a checkout of the ref would give a
 * scanner; a link to a link, one leaving the repository, a directory or a
 * submodule are refused ({@link CiRefError}).
 */
export async function readAtRef(projectPath: string, at: ResolvedRef, rel: string, maxBytes: number): Promise<Buffer | null> {
  const fullPath = `${at.prefix}${rel}`;
  const label = `${rel} at ${at.ref}`;
  const entry = await treeEntry(projectPath, at.commit, fullPath);
  if (entry === null) return null;
  if (entry.mode === '120000') {
    const target = (await blobBytes(projectPath, entry.object, 4096, label)).toString('utf8');
    const resolved = posix.normalize(posix.join(posix.dirname(fullPath), target));
    if (target.startsWith('/') || resolved === '..' || resolved.startsWith('../')) {
      throw new CiRefError(`${label} is a symbolic link out of the repository (${target}) — not read`);
    }
    const followed = await treeEntry(projectPath, at.commit, resolved);
    if (followed === null) throw new CiRefError(`${label} is a symbolic link to ${target}, which the ref does not have`);
    if (followed.type !== 'blob' || followed.mode === '120000') {
      throw new CiRefError(`${label} is a symbolic link to ${target}, which is not a regular file — not read`);
    }
    return blobBytes(projectPath, followed.object, maxBytes, label);
  }
  if (entry.type !== 'blob') throw new CiRefError(`${label} is not a file (a ${entry.type === 'commit' ? 'submodule' : 'directory'}) — not read`);
  return blobBytes(projectPath, entry.object, maxBytes, label);
}

/** What `--baseline-ref` read. */
export interface BaselineAtRef {
  /** The baseline's text, or null when the ref has none (no baseline: every finding is new). */
  text: string | null;
  /** The scanned tree's `.guardian/baseline.json` differs from the ref's (added, changed or deleted): not read. */
  treeDiffers: boolean;
}

/** `.guardian/baseline.json` at the ref — see the module comment. */
export async function readBaselineAtRef(projectPath: string, at: ResolvedRef): Promise<BaselineAtRef> {
  const bytes = await readAtRef(projectPath, at, BASELINE_RELATIVE_PATH, BASELINE_MAX_BYTES);
  const changed = await changedAgainst(projectPath, at, [literal(BASELINE_RELATIVE_PATH)]);
  return { text: bytes === null ? null : bytes.toString('utf8'), treeDiffers: changed.size > 0 };
}

/** A path with nothing a scanner could be pointed out of the copy with: relative, no `..`, no drive. */
function safeRelative(path: string): boolean {
  if (path.length === 0 || path.includes('\0') || path.includes('\\')) return false;
  if (path.startsWith('/') || /^[A-Za-z]:/.test(path)) return false;
  return !path.split('/').some((segment) => segment === '..' || segment === '');
}

/**
 * Copies {@link FROM_REF_FILES} — and the Semgrep rule files the ref's own
 * manifest records — from the ref into `into` at their project-relative
 * paths. A manifest entry whose target is not a plain relative path is
 * dropped from the copy of the manifest (so nothing reads outside `into`),
 * and the run stops (`CiRefError`) — the ref names a rule file the gate
 * cannot read.
 */
export async function copyConfigFromRef(projectPath: string, at: ResolvedRef, into: string): Promise<RefConfigCopy> {
  mkdirSync(into, { recursive: true });
  const copied: string[] = [];
  const absent: string[] = [];
  const put = (rel: string, bytes: Buffer): void => {
    const dest = join(into, ...rel.split('/'));
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, bytes);
    copied.push(rel);
  };
  for (const rel of FROM_REF_FILES) {
    const bytes = await readAtRef(projectPath, at, rel, CONFIG_MAX_BYTES);
    if (bytes === null) absent.push(rel);
    else put(rel, bytes);
  }
  const manifest = copied.includes(MANIFEST_RELATIVE_PATH) ? readManifest(into) : null;
  for (const entry of manifest?.entries ?? []) {
    if (!entry.source.startsWith(SEMGREP_SOURCE_PREFIX) || copied.includes(entry.target)) continue;
    if (!safeRelative(entry.target)) {
      throw new CiRefError(
        `${MANIFEST_RELATIVE_PATH} at ${at.ref} records the Semgrep rules '${entry.target}', which is not a path ` +
          'inside the project — not read',
      );
    }
    const bytes = await readAtRef(projectPath, at, entry.target, CONFIG_MAX_BYTES);
    // A recorded target the ref does not have is drift, not breakage — the
    // tree scan skips it the same way (`platform/projectSemgrepConfig.ts`).
    if (bytes === null) absent.push(entry.target);
    else put(entry.target, bytes);
  }
  return { root: into, copied, absent };
}

/** A pathspec for one project-relative file, taken literally. */
function literal(rel: string): string {
  return `:(literal)${rel}`;
}

/** The pathspec(s) of one REPO_CONFIG file: at any depth when it is `nested`. */
function pathspecsOf(file: string, nested: boolean): string[] {
  return nested ? [`:(glob)**/${file}`] : [literal(file)];
}

/**
 * Project-relative paths (among `pathspecs`) where the working tree differs
 * from the ref: tracked changes from `git diff <commit>` (the working tree,
 * against the ref), and untracked files git does not ignore — a local run's
 * new `.gitleaksignore` is read by gitleaks whether or not it is committed.
 */
async function changedAgainst(
  projectPath: string,
  at: ResolvedRef,
  pathspecs: readonly string[],
): Promise<Map<string, ConfigDifference['change']>> {
  const out = new Map<string, ConfigDifference['change']>();
  if (pathspecs.length === 0) return out;
  const diff = await git(projectPath, ['diff', '--name-status', '-z', '--no-renames', '--relative', at.commit, '--', ...pathspecs]);
  if (diff.exitCode !== 0) throw new CiRefError(`git diff ${at.ref} failed: ${firstLine(diff.stderr)}`);
  const fields = splitNul(diff.stdout);
  for (let i = 0; i + 1 < fields.length; i += 2) {
    const status = fields[i];
    const path = fields[i + 1];
    if (status === undefined || path === undefined) continue;
    out.set(path, status.startsWith('A') ? 'added' : status.startsWith('D') ? 'deleted' : 'modified');
  }
  const untracked = await git(projectPath, ['ls-files', '-z', '--others', '--exclude-standard', '--', ...pathspecs]);
  if (untracked.exitCode !== 0) throw new CiRefError(`git ls-files failed: ${firstLine(untracked.stderr)}`);
  for (const path of splitNul(untracked.stdout)) if (!out.has(path)) out.set(path, 'added');
  return out;
}

/**
 * Every repository configuration file the gate reads that the scanned tree
 * holds differently from the ref: added, modified or deleted — each with the
 * copy the scan read (`ConfigDifference.applied`) and the scanners that
 * read it. `fromRef` is the copy `--rules-ref` made: its files, and the rule
 * files the ref's manifest recorded, were read from the ref. Sorted by path.
 */
export async function configDifferences(
  projectPath: string,
  at: ResolvedRef,
  fromRef: RefConfigCopy,
): Promise<ConfigDifference[]> {
  // path spec -> (applied, readers), for the classification afterwards.
  const specs: Array<{ file: string; nested: boolean; applied: 'tree' | 'ref'; reader: string }> = [];
  for (const [runner, where] of Object.entries(GATE_CONFIG) as Array<[RepoConfigRunner, 'ref' | 'tree' | 'not_in_gate']>) {
    if (where === 'not_in_gate') continue;
    for (const spec of REPO_CONFIG[runner]) {
      specs.push({ file: spec.file, nested: spec.nested === true, applied: where, reader: runner });
    }
  }
  // The tree's own manifest is not read, but a rule file it adds is a change
  // the pull request makes to what would run: named, as not applied.
  const treeTargets = (readManifest(projectPath)?.entries ?? [])
    .filter((e) => e.source.startsWith(SEMGREP_SOURCE_PREFIX) && safeRelative(e.target))
    .map((e) => e.target);
  const semgrepRules = [
    ...new Set([...CONVENTIONAL_TARGETS, MANIFEST_RELATIVE_PATH, ...fromRef.copied, ...fromRef.absent, ...treeTargets]),
  ];
  for (const file of semgrepRules) {
    if (specs.some((s) => !s.nested && s.file === file)) continue;
    specs.push({ file, nested: false, applied: 'ref', reader: file === MANIFEST_RELATIVE_PATH ? 'semgrep (rule files it records)' : 'semgrep' });
  }
  const changed = await changedAgainst(projectPath, at, [...new Set(specs.flatMap((s) => pathspecsOf(s.file, s.nested)))]);
  // A file the tree's scanners read by its path whether git ignores it or not
  // — gitleaks reads `<source>/.gitleaksignore` — is named when it is there
  // and gitignored too: neither `git diff` nor the untracked listing shows it.
  const byPath = specs.filter((spec) => spec.applied === 'tree' && !spec.nested).map((spec) => spec.file);
  for (const [path, change] of await ignoredButPresent(projectPath, at, byPath)) changed.set(path, change);
  const out: ConfigDifference[] = [];
  for (const [path, change] of changed) {
    const base = path.split('/').pop() ?? path;
    const matching = specs.filter((s) => (s.nested ? base === s.file : path === s.file));
    if (matching.length === 0) continue;
    // A file read from the ref by one scanner and from the tree by another
    // (none today) would still have been applied: the tree wins the label.
    const applied = matching.some((s) => s.applied === 'tree') ? 'tree' : 'ref';
    out.push({ path, change, applied, read_by: [...new Set(matching.map((s) => s.reader))].sort() });
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * Root files among `files` that git ignores but the working tree holds, and
 * how each differs from the ref: `added` when the ref has none, `modified`
 * when its bytes differ. One the same as the ref's is not named.
 */
async function ignoredButPresent(
  projectPath: string,
  at: ResolvedRef,
  files: readonly string[],
): Promise<Map<string, ConfigDifference['change']>> {
  const out = new Map<string, ConfigDifference['change']>();
  if (files.length === 0) return out;
  const r = await git(projectPath, ['ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--', ...files.map(literal)]);
  if (r.exitCode !== 0) throw new CiRefError(`git ls-files --ignored failed: ${firstLine(r.stderr)}`);
  for (const path of splitNul(r.stdout)) {
    let tree: Buffer;
    try {
      tree = readFileSync(join(projectPath, ...path.split('/')));
    } catch {
      continue;
    }
    const atRef = await readAtRef(projectPath, at, path, CONFIG_MAX_BYTES).catch(() => null);
    if (atRef === null) out.set(path, 'added');
    else if (!atRef.equals(tree)) out.set(path, 'modified');
  }
  return out;
}

function firstLine(text: string): string {
  return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
}
