/**
 * What a fix's commit may hold — `openPr` stages exactly these paths, and
 * refuses, naming the rest, when anything else in the worktree changed.
 *
 * `git add -A` staged whatever was not git-ignored: with a test command the
 * worktree is where the fix was installed (`npm install pkg@ver` is a full
 * install), where the re-scan restored (`dotnet restore` writes `obj/`) and
 * where the project's own tests ran (snapshots, `coverage/`, `__pycache__`)
 * — and every such file not in `.gitignore` became part of the pull request.
 * The scope is the fix and nothing else:
 *
 *   - a Semgrep group: the target findings' files;
 *   - a pip step: the requirements file or pyproject.toml it edits;
 *   - any other step: its ecosystem's manifest and lock files in the
 *     project's directory, and the lock file a workspace root above it keeps
 *     (npm, Cargo; .NET's central `Directory.Packages.props`).
 *
 * Paths are repository-relative POSIX, as `git status --porcelain` prints
 * them; `prefix` is the project's place in the repository (`app/`, or empty).
 */

import type { FixGroup } from './types.js';

export interface CommitScope {
  /** Whether a changed path (repository-relative POSIX) belongs in the commit. */
  allows(path: string): boolean;
}

/** Per ecosystem: names allowed in the project's directory, and names also allowed in each one above it. */
const ECOSYSTEM_FILES: Readonly<Record<string, { here: readonly string[]; above: readonly string[]; pattern?: RegExp }>> = {
  npm: { here: ['package.json', 'package-lock.json', 'npm-shrinkwrap.json'], above: ['package-lock.json', 'npm-shrinkwrap.json'] },
  composer: { here: ['composer.json', 'composer.lock'], above: [] },
  cargo: { here: ['Cargo.toml', 'Cargo.lock'], above: ['Cargo.lock'] },
  go: { here: ['go.mod', 'go.sum'], above: ['go.work.sum'] },
  dotnet: { here: ['packages.lock.json', 'Directory.Packages.props'], above: ['Directory.Packages.props'], pattern: /^[^/]+\.(?:cs|fs|vb)proj$/i },
};

export function commitScopeFor(group: FixGroup, prefix: string): CommitScope {
  const base = prefix.replace(/\/+$/, '');
  const inProject = (rel: string): string => (base === '' ? rel : `${base}/${rel}`).replace(/\\/g, '/').replace(/^\.\//, '');
  const exact = new Set<string>();
  const patterns: RegExp[] = [];
  if (group.source === 'semgrep') {
    for (const c of group.candidates) if (c.file_path !== undefined) exact.add(inProject(c.file_path));
  } else {
    for (const step of group.candidates.flatMap((c) => c.steps ?? [])) {
      if (step.ecosystem === 'pip') {
        if (step.file !== undefined) exact.add(inProject(step.file));
        continue;
      }
      const files = ECOSYSTEM_FILES[step.ecosystem];
      if (files === undefined) continue;
      for (const name of files.here) exact.add(inProject(name));
      for (const dir of ancestors(base)) for (const name of files.above) exact.add(dir === '' ? name : `${dir}/${name}`);
      if (files.pattern !== undefined) patterns.push(files.pattern);
    }
  }
  return {
    allows: (path) => {
      if (exact.has(path)) return true;
      const rel = base === '' ? path : path.startsWith(`${base}/`) ? path.slice(base.length + 1) : null;
      return rel !== null && patterns.some((p) => p.test(rel));
    },
  };
}

/** `a/b` → `a`, `` — the directories above the project's, up to the repository root. */
function ancestors(dir: string): string[] {
  const out: string[] = [];
  for (let d = dir; d !== ''; ) {
    const at = d.lastIndexOf('/');
    d = at === -1 ? '' : d.slice(0, at);
    out.push(d);
  }
  return out;
}
