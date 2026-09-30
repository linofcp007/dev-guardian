/**
 * Cache keys for scans and attack-surface snapshots.
 *
 * A cached result may be served only when a fresh run would have produced the
 * same thing. The tree hash alone never guaranteed that: the key used to be
 * `(tree_hash, scan_type)`, and every one of these was reproduced —
 *
 *   - `scan_containers({ image: 'nginx:1.19' })` answered with a cached
 *     Dockerfile scan of the same tree;
 *   - `deps_audit` and `scan_deps` shared the scan type `deps` and returned
 *     each other's results, so `deps_audit` lost its `bot_configured`;
 *   - `review_pr` ignored `base_ref`/`head_ref`, so a diff against `develop`
 *     came back as the diff against `main`;
 *   - two projects whose trees hash the same (two empty directories, two
 *     checkouts of one commit) were handed each other's scans;
 *   - a rule pack edited on disk, or a new plugin version, changed nothing.
 *
 * So a key now names everything that shapes a run: the canonical project
 * path, the tool and its scan type, the tree hash, the normalised input, the
 * plugin version and the content of every rule pack the run loads. Each part
 * is hashed separately and then together, so no two parts can run into each
 * other.
 */

import { createHash } from 'node:crypto';
import { readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { hashRegularFileSync } from '../platform/projectFs.js';

function sha256(text: string | Buffer): string {
  return createHash('sha256').update(text).digest('hex');
}

/**
 * JSON with object keys sorted at every depth, so two inputs that differ only
 * in key order serialise identically. `undefined` members are dropped, the
 * way `JSON.stringify` drops them. Array order is kept: it can be meaningful.
 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    const json = JSON.stringify(value);
    return json === undefined ? 'null' : json;
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`;
}

/** Hash of a normalised tool input — see {@link stableStringify}. */
export function hashInput(input: Record<string, unknown>): string {
  return sha256(stableStringify(input));
}

/** Every file under `dir`, relative, sorted — a Semgrep directory config. */
function listFilesRecursive(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string): void => {
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const abs = join(current, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) out.push(relative(dir, abs).split(sep).join('/'));
    }
  };
  walk(dir);
  return out.sort();
}

function describePack(entry: string): string {
  let isDir = false;
  let isFile = false;
  try {
    const s = statSync(entry);
    isDir = s.isDirectory();
    isFile = s.isFile();
  } catch {
    // Not on disk: a registry name (`p/r2c-bug-scan`, `auto`) — only the
    // name can be keyed. Plugin version and the cache TTL bound its drift.
  }
  // Streamed, and judged on a non-blocking descriptor (`hashRegularFileSync`):
  // a pack may be the project's own Semgrep config, and a path swapped for a
  // FIFO or a device after the `stat` above is never waited on or read.
  // Same digest as hashing the whole buffer: no stored cache key moves.
  if (isFile) {
    return `file:${entry}:${hashRegularFileSync(entry) ?? 'unreadable'}`;
  }
  if (isDir) {
    const parts = listFilesRecursive(entry).map((rel) => `${rel}:${hashRegularFileSync(join(entry, rel)) ?? 'unreadable'}`);
    return `dir:${entry}:${sha256(parts.join('\n'))}`;
  }
  return `ref:${entry}`;
}

/**
 * Hash of the rule packs a run loads, in the order it loads them: a file by
 * its content, a directory by the content of every file in it, anything else
 * (a registry pack name) by its name. Never throws.
 */
export function hashRulePacks(entries: readonly string[]): string {
  return sha256(entries.map(describePack).join('\n'));
}

export interface ScanCacheKeyParts {
  /** Canonical project path (`resolveProjectPath`'s output). */
  projectPath: string;
  tool: string;
  scanType: string;
  treeHash: string;
  /** {@link hashInput} of the normalised input. */
  inputHash: string;
  pluginVersion: string;
  /** {@link hashRulePacks} of the packs the run loads. */
  rulePacksHash: string;
}

/** The `scans.cache_key` a run is stored and looked up under. */
export function scanCacheKey(parts: ScanCacheKeyParts): string {
  return sha256(
    stableStringify({
      v: 1,
      project_path: parts.projectPath,
      tool: parts.tool,
      scan_type: parts.scanType,
      tree_hash: parts.treeHash,
      input: parts.inputHash,
      plugin_version: parts.pluginVersion,
      rule_packs: parts.rulePacksHash,
    }),
  );
}

export interface SurfaceCacheKeyParts {
  projectPath: string;
  treeHash: string;
  /** {@link hashRulePacks} of `configs/semgrep/routes.yml`. */
  routesPackHash: string;
  pluginVersion: string;
  /** Whether env-var names were collected — it changes what is stored. */
  includeEnvVars: boolean;
}

/** The `surface_snapshots.cache_key` a snapshot is stored and looked up under. */
export function surfaceCacheKey(parts: SurfaceCacheKeyParts): string {
  return sha256(
    stableStringify({
      v: 1,
      project_path: parts.projectPath,
      tree_hash: parts.treeHash,
      routes_pack: parts.routesPackHash,
      plugin_version: parts.pluginVersion,
      include_env_vars: parts.includeEnvVars,
    }),
  );
}
