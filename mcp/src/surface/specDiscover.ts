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

import { readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { readSmallText } from '../hooks/configFile.js';
import { readProjectText } from '../platform/projectFs.js';
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
 * The widened names (bugfix openapi-discovery-names): a base name that only
 * STARTS with openapi/swagger (`openapi3`, `openapi-v1`, `swagger2`), one that
 * ends `.openapi`/`.swagger` (`petstore.openapi`), and a directory segment
 * that starts with openapi/swagger or is `api-docs`/`apidocs`
 * (`openapi_specs/`, `swagger-docs/`). Measured on VAmPI: its only route
 * table is `openapi_specs/openapi3.yml`, and the exact names alone found
 * nothing. These names are also worn by files that are not documents —
 * `openapi-generator-config.yaml`, `openapitools.json` — so a widened
 * candidate is kept only when its text declares a top-level `openapi` or
 * `swagger` key ({@link DECLARES_SPEC}); the exact names are reported as
 * before, valid or not.
 */
const WIDENED_BASE = /^(?:openapi|swagger)|\.(?:openapi|swagger)$/i;
const WIDENED_DIR = /^(?:openapi|swagger)|^api-?docs$/i;

/**
 * A top-level `openapi`/`swagger` key: a YAML key at column 0, bare or
 * quoted, or a JSON key whose value is a string (the version).
 */
const DECLARES_SPEC = /^["']?(?:openapi|swagger)["']?[ \t]*:|"(?:openapi|swagger)"\s*:\s*"/m;

type CandidateTier = 'exact' | 'widened';

/**
 * Find OpenAPI/Swagger documents under `projectPath`, or read exactly the
 * `explicit` paths when given. Never throws.
 */
export function discoverSpecs(projectPath: string, explicit?: readonly string[]): DiscoveryOutcome {
  const root = resolve(projectPath);

  const isExplicit = explicit !== undefined && explicit.length > 0;
  const found = isExplicit ? null : walk(root, root);
  // Exact names first, so a widened candidate never pushes a conventional
  // document out of the cap.
  const candidates = found === null ? dedupeResolved(explicit ?? []) : [...found.exact.sort(), ...found.widened.sort()];

  // The file cap applies on both entry paths: discovery can find more than
  // MAX_SPEC_FILES candidates, and a caller can just as easily hand in an
  // over-cap explicit list. Either way `truncated` must reflect it.
  const truncated = candidates.length > MAX_SPEC_FILES;
  const selected = candidates.slice(0, MAX_SPEC_FILES);

  const outcome = readCandidates(isExplicit ? null : root, selected, new Set(found?.widened ?? []));
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

/**
 * Reads each candidate bounded and regular-files-only (the size used to be
 * `stat`ed and the file then read whole, so a FIFO — size 0 — blocked the
 * read and a `/dev/zero` link read without end), at most
 * {@link MAX_SPEC_BYTES}. A DISCOVERED candidate (`root` given) is the
 * repository's and is read contained in it (`platform/projectFs.ts`); an
 * explicit `spec_paths` entry is the caller's choice and may lie anywhere
 * (`hooks/configFile.ts`'s reader). Over the cap is `oversized`; absent,
 * unreadable or refused is absent from the result, not an error. A
 * `widened` candidate that reads but declares no `openapi`/`swagger` key is
 * not a document, and is left out.
 */
function readCandidates(root: string | null, paths: readonly string[], widened: ReadonlySet<string>): DiscoveryOutcome {
  const specs: DiscoveredSpec[] = [];
  const oversized: string[] = [];

  for (const path of paths) {
    const read = root === null ? readSmallText(path, MAX_SPEC_BYTES) : readProjectText(root, path, MAX_SPEC_BYTES);
    if (read.status === 'ok') {
      if (widened.has(path) && !DECLARES_SPEC.test(read.text)) continue;
      specs.push({ file: path, text: read.text });
    } else if (read.status === 'refused' && read.reason === 'too-large') oversized.push(path);
  }

  return { specs, oversized, truncated: false };
}

function walk(root: string, dir: string): { exact: string[]; widened: string[] } {
  const out = { exact: [] as string[], widened: [] as string[] };
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (FS_EXCLUDE.has(entry.name)) continue;
      const sub = walk(root, join(dir, entry.name));
      out.exact.push(...sub.exact);
      out.widened.push(...sub.widened);
    } else if (entry.isFile()) {
      const tier = specCandidateTier(root, dir, entry.name);
      if (tier !== null) out[tier].push(join(dir, entry.name));
    }
  }
  return out;
}

/**
 * `exact` for the conventional names (a base name of exactly openapi,
 * swagger or api-docs, or a file under a directory named exactly `openapi`),
 * `widened` for the names {@link WIDENED_BASE} / {@link WIDENED_DIR} admit,
 * null for anything else.
 *
 * `dir` matches a directory rule only on *project-relative* path segments —
 * i.e. relative to `root`, not the absolute path. Checking the absolute path
 * would also match any project that merely happens to live beneath a
 * directory named `openapi` (a checkout path, a monorepo namespace), pulling
 * in unrelated files from outside the project entirely.
 */
function specCandidateTier(root: string, dir: string, name: string): CandidateTier | null {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return null;
  const base = name.slice(0, dot);
  const ext = name.slice(dot).toLowerCase();
  if (!SPEC_EXTENSIONS.has(ext)) return null;

  if (SPEC_BASENAMES.has(base.toLowerCase())) return 'exact';

  const relDir = relative(root, dir);
  const segments = relDir === '' ? [] : relDir.split(sep);
  if (segments.some((segment) => segment.toLowerCase() === 'openapi')) return 'exact';
  if (WIDENED_BASE.test(base) || segments.some((segment) => WIDENED_DIR.test(segment))) return 'widened';
  return null;
}
