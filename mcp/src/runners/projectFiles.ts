/**
 * Walking a project directory without a shell.
 *
 * `find . -name "*.py" | head -1 | grep -q .` under `set -o pipefail` is how
 * `full-security-scan.sh` and `quality-scan.sh` decided whether a project had
 * Python: on a large tree `head` exits after the first line, `find` dies of
 * SIGPIPE, the pipeline "fails", and Bandit / ruff were silently skipped —
 * reproduced on a project with 3 000 `.py` files. The walk below stops at the
 * first match instead, and never asks a pipe for its exit status.
 */

import { readdirSync, type Dirent } from 'node:fs';
import { join } from 'node:path';
import { FS_EXCLUDE } from '../treeHash/computeTreeHash.js';

/**
 * Directories no scan of the project's OWN files should descend into: the
 * tree-hash denylist (`.git`, `.guardian`, `node_modules`, build output,
 * virtualenvs, caches) plus `vendor` (Composer / Go vendoring).
 */
export const PROJECT_WALK_EXCLUDE: ReadonlySet<string> = new Set([...FS_EXCLUDE, 'vendor']);

/**
 * {@link PROJECT_WALK_EXCLUDE} without `.guardian`, for the listings that
 * stand for what a SCANNER reads (a scope's files, gitleaks' working tree):
 * there only the root `.guardian/`'s generated output is left out, by its
 * project-relative path (`platform/guardianOutput.ts#isGuardianOutput`) — a
 * `.guardian` folder below the root is the project's code, and leaving it
 * out by name let `lib/.guardian/handler.js` through the CI gate unscanned
 * (review 10, finding 1).
 */
export const SCANNED_WALK_EXCLUDE: ReadonlySet<string> = new Set([...PROJECT_WALK_EXCLUDE].filter((d) => d !== '.guardian'));

/**
 * What the walks that mirror what a SCANNER reads leave out — Trivy's
 * dependency-manifest walk (`scannerParsers/trivy.ts`) and its
 * IaC-looking-files walk (`trivyConfig.ts`), through
 * {@link trivyWalkSkipsDir}; the repository-configuration walk
 * (`repoConfig.ts`) besides {@link PROJECT_WALK_EXCLUDE} — while entering
 * every other hidden directory, since Trivy reads them
 * (`.github/actions/…/package.json`, `.devcontainer/Dockerfile`, measured
 * on 0.69.3): version control, the package managers' and tools' caches, and
 * bower's and jspm's dependency directories. Round 4, items 4 and 5; round
 * 5, item 1.
 */
export const SCANNER_WALK_EXCLUDE: ReadonlySet<string> = new Set([
  '.git',
  '.hg',
  '.svn',
  '.bzr',
  '_darcs',
  'CVS',
  '.yarn',
  '.pnpm-store',
  '.npm',
  '.gradle',
  '.m2',
  '.terraform',
  'bower_components',
  'jspm_packages',
]);

/**
 * What the two walks that mirror what TRIVY reads (above) leave out at any
 * depth: {@link SCANNER_WALK_EXCLUDE}, and the directories that hold
 * installed dependencies or a tool's cache — `node_modules` (Trivy reads no
 * lock file there), `vendor`, virtualenvs (a JupyterLab extension's lockless
 * `package.json` lives in `.venv/share/`), `.tox`, `.cache` and Python's
 * caches. A manifest there is a dependency's, never the project's.
 *
 * Not {@link PROJECT_WALK_EXCLUDE}: it leaves out build output and tools'
 * folders by NAME at any depth, and Trivy reads them all — measured on
 * 0.74.0 (2026-10-25), a `package-lock.json` in each of `build`, `dist`,
 * `target`, `coverage`, `.next`, `.specs`, `.kiro`, `.guardian`,
 * `lib/.guardian` and `vendor/x` got a Result, one under `.git/` or
 * `node_modules/` none, and `trivy config` read a Dockerfile in every one,
 * `node_modules/` included. So a lockless `.github/actions/build/package.json`
 * read full. Build output is left out at the ROOT only
 * ({@link TRIVY_WALK_ROOT_EXCLUDE}).
 */
const TRIVY_WALK_EXCLUDE: ReadonlySet<string> = new Set([
  ...SCANNER_WALK_EXCLUDE,
  'node_modules',
  'vendor',
  'venv',
  '.venv',
  '.tox',
  '.cache',
  '__pycache__',
  '.pytest_cache',
]);

/**
 * Left out by those walks at the project's root alone: generated output — a
 * build's, a test run's coverage report, and dev-guardian's own `.guardian/`
 * (a `.guardian` below the root is the project's, as everywhere).
 */
const TRIVY_WALK_ROOT_EXCLUDE: ReadonlySet<string> = new Set(['.guardian', 'dist', 'build', 'target', 'coverage', '.next', '.nuxt']);

/** Whether a walk that mirrors what Trivy reads leaves out the directory `name` in `parentRel` (`''`: the root). */
export function trivyWalkSkipsDir(parentRel: string, name: string): boolean {
  return TRIVY_WALK_EXCLUDE.has(name) || (parentRel === '' && TRIVY_WALK_ROOT_EXCLUDE.has(name));
}

function readDir(dir: string): Dirent[] {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

/**
 * Whether any regular file under `root` ends with one of `extensions`
 * (lower-case, with the dot). Depth-first, stops at the first match; skips
 * `exclude` directories and hidden directories.
 */
export function hasFileWithExtension(
  root: string,
  extensions: readonly string[],
  exclude: ReadonlySet<string> = PROJECT_WALK_EXCLUDE,
): boolean {
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    if (dir === undefined) break;
    for (const entry of readDir(dir)) {
      if (entry.isDirectory()) {
        if (!exclude.has(entry.name) && !entry.name.startsWith('.')) stack.push(join(dir, entry.name));
      } else if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        if (extensions.some((ext) => lower.endsWith(ext))) return true;
      }
    }
  }
  return false;
}

/**
 * How many regular files under `root` end with one of `extensions` — the
 * same walk as {@link hasFileWithExtension} (skipping `exclude` and hidden
 * directories), counted to the end. `skipFile` (given the lower-cased file
 * name) leaves a matching file out of the count.
 */
export function countFilesWithExtension(
  root: string,
  extensions: readonly string[],
  exclude: ReadonlySet<string> = PROJECT_WALK_EXCLUDE,
  skipFile: (lowerName: string) => boolean = () => false,
): number {
  let count = 0;
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    if (dir === undefined) break;
    for (const entry of readDir(dir)) {
      if (entry.isDirectory()) {
        if (!exclude.has(entry.name) && !entry.name.startsWith('.')) stack.push(join(dir, entry.name));
      } else if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        if (extensions.some((ext) => lower.endsWith(ext)) && !skipFile(lower)) count += 1;
      }
    }
  }
  return count;
}

/**
 * Every regular file under `root`, as a `/`-separated path relative to it,
 * skipping `exclude` directories (at any depth) and anything that is not a
 * regular file (symlinks, sockets, devices).
 */
export function listProjectFiles(
  root: string,
  exclude: ReadonlySet<string> = PROJECT_WALK_EXCLUDE,
): string[] {
  const out: string[] = [];
  const stack: Array<{ abs: string; rel: string }> = [{ abs: root, rel: '' }];
  while (stack.length > 0) {
    const next = stack.pop();
    if (next === undefined) break;
    for (const entry of readDir(next.abs)) {
      const rel = next.rel === '' ? entry.name : `${next.rel}/${entry.name}`;
      if (entry.isDirectory()) {
        if (!exclude.has(entry.name)) stack.push({ abs: join(next.abs, entry.name), rel });
      } else if (entry.isFile()) {
        out.push(rel);
      }
    }
  }
  return out.sort();
}
