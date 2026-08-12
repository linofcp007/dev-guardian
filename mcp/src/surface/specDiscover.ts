/**
 * Find OpenAPI / Swagger documents in a project and read their contents.
 *
 * This is the only I/O in the spec-import feature; `specImport.ts` (parsing)
 * and `specDiff.ts` (comparison) are both pure. Discovery walks the project
 * tree looking for conventionally-named documents, or — when the caller
 * supplies an explicit list — reads exactly those paths instead.
 *
 * Two caps keep this bounded on large or adversarial trees: at most
 * `MAX_SPEC_FILES` candidate files, and at most `MAX_SPEC_BYTES` per file.
 * Both caps are reported rather than silently applied — a truncated result
 * with no signal reads as "there were only 20 specs", and a vanished
 * oversized file reads as "that spec doesn't exist". `DiscoveryOutcome`
 * carries `truncated` and `oversized` so callers can surface both.
 *
 * Never throws: an unreadable file (permission error, path that doesn't
 * exist, race with a concurrent delete) is simply absent from the result.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { FS_EXCLUDE } from '../treeHash/computeTreeHash.js';

export interface DiscoveredSpec {
  file: string;
  text: string;
}

export interface DiscoveryOutcome {
  specs: DiscoveredSpec[];
  /** Files skipped for exceeding the size cap, with their paths. */
  oversized: string[];
  /** True when the file cap truncated the candidate set. */
  truncated: boolean;
}

export const MAX_SPEC_FILES = 20;
export const MAX_SPEC_BYTES = 5 * 1024 * 1024;

const SPEC_BASENAMES = new Set(['openapi', 'swagger', 'api-docs']);
const SPEC_EXTENSIONS = new Set(['.json', '.yaml', '.yml']);

/**
 * Find OpenAPI/Swagger documents under `projectPath`, or read exactly the
 * `explicit` paths when given. Never throws.
 */
export function discoverSpecs(projectPath: string, explicit?: readonly string[]): DiscoveryOutcome {
  const root = resolve(projectPath);

  const candidates =
    explicit && explicit.length > 0 ? dedupeResolved(explicit) : walk(root, root).sort();

  // The file cap applies on both entry paths: discovery can find more than
  // MAX_SPEC_FILES candidates, and a caller can just as easily hand in an
  // over-cap explicit list. Either way `truncated` must reflect it.
  const truncated = candidates.length > MAX_SPEC_FILES;
  const selected = candidates.slice(0, MAX_SPEC_FILES);

  const outcome = readCandidates(selected);
  outcome.truncated = truncated;
  return outcome;
}

/**
 * Canonicalise and dedupe explicit paths so two spellings of the same file —
 * e.g. `<dir>/openapi.yaml` and `<dir>/./openapi.yaml` — are read once, not
 * twice. Without this, a caller-supplied duplicate silently doubles that
 * document's routes in the diff (`spec_routes_total`, `matched`, `spec_only`
 * all inflate); classification itself stays correct, only the counts lie.
 * `resolve()` collapses `.`/`..` segments and repeated separators the same
 * way the filesystem does — it does not touch case or follow symlinks, so
 * two paths differing only by a symlink hop are still read twice, a
 * narrower gap than the one this closes.
 *
 * Exported because the caller's accounting of which named paths were "not
 * read" has to be built from the SAME list this function returns. Applying
 * the `MAX_SPEC_FILES` cap to the raw (un-deduped) list instead would slide
 * that window: with duplicates present, the caller's window ends earlier
 * than the one discovery actually selected, and a genuinely unreadable path
 * falling in the gap vanishes with no diagnostic — the exact conflation
 * ("that document could not be read" reading as "there is no spec") the rest
 * of this feature exists to prevent. `resolveExplicitSpecPath`
 * (mapAttackSurface.ts) canonicalises with the same `resolve()` before an
 * explicit path reaches either call site, so the two lists agree by string
 * equality.
 */
export function dedupeResolved(paths: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const path of paths) {
    const resolved = resolve(path);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    out.push(resolved);
  }
  return out;
}

function readCandidates(paths: readonly string[]): DiscoveryOutcome {
  const specs: DiscoveredSpec[] = [];
  const oversized: string[] = [];

  for (const path of paths) {
    let size: number;
    try {
      size = statSync(path).size;
    } catch {
      // Path doesn't exist, isn't readable, or a race removed it — absent
      // from the result, not an error.
      continue;
    }

    if (size > MAX_SPEC_BYTES) {
      oversized.push(path);
      continue;
    }

    try {
      const text = readFileSync(path, 'utf8');
      specs.push({ file: path, text });
    } catch {
      // Unreadable (permissions, race between stat and read) — absent.
      continue;
    }
  }

  return { specs, oversized, truncated: false };
}

function walk(root: string, dir: string): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }

  const out: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (FS_EXCLUDE.has(entry.name)) continue;
      out.push(...walk(root, join(dir, entry.name)));
    } else if (entry.isFile()) {
      if (isSpecCandidate(root, dir, entry.name)) {
        out.push(join(dir, entry.name));
      }
    }
  }
  return out;
}

/**
 * `dir` matches the "under an openapi/ directory" rule only when a
 * *project-relative* path segment is named `openapi` — i.e. relative to
 * `root`, not the absolute path. Checking the absolute path would also match
 * any project that merely happens to live beneath a directory named
 * `openapi` (a checkout path, a monorepo namespace), pulling in unrelated
 * files from outside the project entirely.
 */
function isSpecCandidate(root: string, dir: string, name: string): boolean {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return false;
  const base = name.slice(0, dot);
  const ext = name.slice(dot).toLowerCase();
  if (!SPEC_EXTENSIONS.has(ext)) return false;

  if (SPEC_BASENAMES.has(base.toLowerCase())) return true;

  const relDir = relative(root, dir);
  if (relDir === '') return false;
  return relDir.split(sep).some((segment) => segment.toLowerCase() === 'openapi');
}
