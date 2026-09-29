/**
 * Which version of an npm package some code loads — the dependency
 * provider's `NpmResolver`, and its only I/O.
 *
 * Node's own lookup: from the importing file's directory upwards, the first
 * `node_modules/<name>` wins. Read, per manifest directory, from
 * `npm-shrinkwrap.json` or `package-lock.json` (npm's precedence) — v2/v3
 * `packages` keys are exactly those install paths
 * (`node_modules/x/node_modules/lodash`, `packages/api/node_modules/lodash`
 * in a workspace), v1's nested `dependencies` build the same keys — and,
 * with no lockfile, from the installed `node_modules/<name>/package.json`.
 * Only the directories from the importing file up to the manifest's are
 * searched: that is the install the finding is about.
 *
 * `version: null`, WITH THE REASON, whenever it cannot be told: no lockfile
 * and nothing installed, a lockfile that is not JSON or is over
 * {@link MAX_LOCKFILE_BYTES} (then the installed tree is NOT read in its
 * place — it may be of another install), a package the lockfile does not
 * install where the code looks. The provider then claims no more than
 * `imported`, and quotes the reason — never `reachable` on a version it
 * could not read. yarn.lock and pnpm-lock.yaml are not read (neither records
 * where a package is installed); the installed tree answers for them when
 * present.
 */

import { readProjectText } from '../platform/projectFs.js';
import { join } from 'node:path';
import type { NpmResolver, ResolvedPackage } from './dependencyProvider.js';

/** A lockfile larger than this is not read (a large monorepo's is a few MB). */
export const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const LOCKFILES = ['npm-shrinkwrap.json', 'package-lock.json'];

interface LockView {
  kind: 'lock';
  /** Project-relative label of the lockfile read. */
  file: string;
  /** Install path relative to the lockfile's directory → version. */
  versions: ReadonlyMap<string, string>;
}

/**
 * What stands beside a manifest: a lockfile read, none at all (the installed
 * tree then answers), or one present but unreadable — which answers nothing,
 * and is never passed over for the installed tree (review of part C, M-f: it
 * was, against this module's own contract).
 */
type LockState = LockView | { kind: 'none' } | { kind: 'unreadable'; file: string };

export function makeNpmResolver(projectPath: string): NpmResolver {
  const locks = new Map<string, LockState>();
  const lockOf = (rootDir: string): LockState => {
    const cached = locks.get(rootDir);
    if (cached !== undefined) return cached;
    const read = readLock(projectPath, rootDir);
    locks.set(rootDir, read);
    return read;
  };

  return (fromDir, rootDir, name) => {
    const lock = lockOf(rootDir);
    if (lock.kind === 'unreadable') {
      return { version: null, reason: `${lock.file} is not valid JSON (or larger than 64 MiB)` };
    }
    let dir = fromDir;
    for (;;) {
      const rel = relativeTo(rootDir, dir);
      if (rel === null) {
        return { version: null, reason: `'${fromDir || '.'}' is outside '${rootDir || '.'}', the manifest's directory` };
      }
      if (lock.kind === 'lock') {
        const version = lock.versions.get(`${rel === '' ? '' : `${rel}/`}node_modules/${name}`);
        if (version !== undefined) return { version, source: lock.file };
      } else {
        const installed = readInstalled(projectPath, dir, name);
        if (installed !== null) return installed;
      }
      if (dir === rootDir) break;
      dir = parentOf(dir);
    }
    return {
      version: null,
      reason:
        lock.kind === 'lock'
          ? `${lock.file} does not install '${name}' where ${fromDir || '.'} looks for it`
          : `no package-lock.json or npm-shrinkwrap.json in '${rootDir || '.'}', and no installed node_modules/${name}`,
    };
  };
}

function readLock(projectPath: string, rootDir: string): LockState {
  for (const candidate of LOCKFILES) {
    const file = rootDir === '' ? candidate : `${rootDir}/${candidate}`;
    const parsed = readJson(projectPath, join(projectPath, rootDir, candidate), MAX_LOCKFILE_BYTES);
    if (parsed === undefined) continue;
    // Present but unreadable: never fall back to a lesser source.
    if (parsed === null) return { kind: 'unreadable', file };
    const versions = new Map<string, string>();
    const packages = record(parsed['packages']);
    if (packages !== null) {
      for (const [key, value] of Object.entries(packages)) {
        const entry = record(value);
        if (key === '' || entry === null || entry['link'] === true) continue;
        if (typeof entry['version'] === 'string') versions.set(key, entry['version']);
      }
    } else {
      walkV1(record(parsed['dependencies']), '', versions);
    }
    return { kind: 'lock', file, versions };
  }
  return { kind: 'none' };
}

function walkV1(deps: Record<string, unknown> | null, prefix: string, out: Map<string, string>): void {
  if (deps === null) return;
  for (const [name, value] of Object.entries(deps)) {
    const entry = record(value);
    if (entry === null) continue;
    const key = `${prefix}node_modules/${name}`;
    if (typeof entry['version'] === 'string') out.set(key, entry['version']);
    walkV1(record(entry['dependencies']), `${key}/`, out);
  }
}

function readInstalled(projectPath: string, dir: string, name: string): ResolvedPackage | null {
  const parsed = readJson(projectPath, join(projectPath, dir, 'node_modules', ...name.split('/'), 'package.json'), MAX_PACKAGE_JSON_BYTES);
  const version = parsed?.['version'];
  if (typeof version !== 'string') return null;
  return { version, source: `${dir === '' ? '' : `${dir}/`}node_modules/${name}/package.json` };
}

/**
 * `undefined`: no such regular file. `null`: present, but too large, not a
 * JSON object, or refused. Read through `platform/projectFs.ts`: contained in
 * the project (a package name with `..` in it, or a `node_modules` link out
 * of the project, reads nothing), judged on the opened descriptor.
 */
function readJson(projectPath: string, path: string, maxBytes: number): Record<string, unknown> | null | undefined {
  const r = readProjectText(projectPath, path, maxBytes);
  if (r.status === 'absent') return undefined;
  if (r.status === 'refused') return r.reason === 'not-a-regular-file' ? undefined : null;
  try {
    return record(JSON.parse(r.text) as unknown);
  } catch {
    return null;
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** `dir` relative to `rootDir` (both project-relative POSIX), or null when outside it. */
function relativeTo(rootDir: string, dir: string): string | null {
  if (rootDir === '') return dir;
  if (dir === rootDir) return '';
  return dir.startsWith(`${rootDir}/`) ? dir.slice(rootDir.length + 1) : null;
}

function parentOf(dir: string): string {
  const at = dir.lastIndexOf('/');
  return at === -1 ? '' : dir.slice(0, at);
}
