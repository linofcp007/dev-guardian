/**
 * File-level import edges, for the `validate_finding` import graph
 * (`mcp/src/validate/importGraph.ts`) — a WIDER, SECOND extraction over the
 * same `guardian_kind: import` Semgrep matches `mapAttackSurface.ts`'s own
 * `extractImports()` already reads for mount resolution.
 *
 * That existing extraction requires both a bound symbol and a module,
 * because `resolveNodeMounts`'s `buildPrefixIndex` matches an imported
 * symbol against a mount's router variable. The import graph never reads a
 * symbol — it only cares "does file A import file B" — so requiring one
 * here would silently drop every import form that does not bind a local
 * name: all Java and Ruby imports, every unaliased Go import, plain C#
 * `using`, and bare Python `import x`. This module intentionally does NOT
 * reuse `extractImports`/`resolveModuleFile`, and does not change them —
 * mount resolution keeps its own, narrower, symbol-requiring path.
 *
 * `extractModuleEdges` is pure text-shuffling: it never decides whether an
 * edge is resolvable. `resolveModuleEdges` does, against a caller-supplied
 * project-file set, and every edge it cannot resolve is reported back in
 * `unresolved` rather than dropped — a thinner-than-reality graph is exactly
 * the failure `validate_finding`'s negative verdict cannot afford (a file
 * that is actually imported would silently read as "nothing imports this").
 */

import { languageFromPath } from './extract.js';

/** An import edge with no symbol requirement — the graph never reads one. */
export interface ModuleEdge {
  /** Project-relative POSIX path of the file containing the import. */
  file: string;
  /** The raw specifier as written: './x', 'os', 'crate::a::b', 'net/http'. */
  specifier: string;
  language: string;
}

export interface ResolvedEdge {
  file: string;
  module_file: string;
}

/**
 * Languages whose import specifier deterministically encodes a filesystem
 * path: JS/TS relative specifiers, Python dotted modules, Go package paths,
 * Rust `crate::`/`self::` paths. Java and C# specifiers name a namespace,
 * not a path; Ruby autoloads by convention; PHP resolves via composer's
 * PSR-4 config — none of those four can be mapped to a file without reading
 * project configuration this module is never given (no go.mod, no
 * Cargo.toml, no composer.json here either — go.mod's `module` prefix and
 * Cargo workspace layout are out of scope too, see resolveGo's comment).
 *
 * This is also exactly the set where design §5.3 already makes the negative
 * (`unreachable`) verdict unavailable, so an edge in one of the other four
 * costs nothing that was ever promised — but it is still extracted and
 * counted in `unresolved`, never silently dropped.
 */
export const RESOLVABLE_LANGUAGES: ReadonlySet<string> = new Set([
  'typescript',
  'javascript',
  'python',
  'go',
  'rust',
]);

/* ---------------------------------------------------------------------- *
 * Extraction
 * ---------------------------------------------------------------------- */

/**
 * `guardian_kind: import` matches → one `ModuleEdge` per match, requiring
 * only a module (never a symbol). Malformed rows are skipped, never thrown
 * on — same contract as `extract.ts`'s `extractSurface`, since both read the
 * same Semgrep output and the rule pack is user-extensible.
 */
export function extractModuleEdges(results: readonly unknown[]): ModuleEdge[] {
  const edges: ModuleEdge[] = [];

  for (const raw of results) {
    const extra = prop(raw, 'extra');
    const metadata = prop(extra, 'metadata');
    if (str(metadata, 'guardian_kind') !== 'import') continue;

    const file = str(raw, 'path');
    if (file === undefined) continue;

    const metavars = prop(extra, 'metavars');
    const module = stripQuotes(metavar(metavars, '$MODULE'));
    if (module === undefined) continue;
    const symbol = stripQuotes(metavar(metavars, '$SYMBOL'));

    const language = languageFromPath(file);
    edges.push({ file, specifier: buildSpecifier(language, module, symbol), language });
  }

  return edges;
}

/**
 * Every language's rule binds `$MODULE` to the complete specifier text
 * EXCEPT Rust's `use $MODULE::$SYMBOL;` / `use $MODULE::{$SYMBOL};`, where
 * `$SYMBOL` is the final path segment, not a bound local name the way JS/Go's
 * import symbol is — so the specifier a resolver needs is the recombined
 * path, not `$MODULE` alone.
 */
function buildSpecifier(language: string, module: string, symbol: string | undefined): string {
  if (language !== 'rust' || symbol === undefined) return module;
  // routes.yml's guardian-import-rust comment: Semgrep joins a multi-segment
  // $MODULE capture with a SPACE instead of `::` (a rendering quirk of
  // abstract_content, not a real token — measured on 1.86.0). Undone here so
  // `crate::models::User` round-trips instead of a multi-segment
  // crate-relative import permanently failing to resolve.
  return `${module.replace(/ /g, '::')}::${symbol}`;
}

/* ---- tiny structural accessors, mirroring extract.ts's own (private
   there, and Finding-shaped helpers elsewhere would not fit either — see
   that file's header comment) ---- */

function prop(value: unknown, key: string): unknown {
  if (value === null || typeof value !== 'object') return undefined;
  return (value as Record<string, unknown>)[key];
}

function str(value: unknown, key: string): string | undefined {
  const v = prop(value, key);
  return typeof v === 'string' ? v : undefined;
}

/** Semgrep nests captures as `metavars.$NAME.abstract_content`. */
function metavar(metavars: unknown, name: string): string | undefined {
  return str(prop(metavars, name), 'abstract_content');
}

/**
 * Semgrep's `abstract_content` keeps the source quoting (`'./x'`, not `./x`)
 * for a captured STRING LITERAL — true for ESM's, Go's and Ruby's `$MODULE`,
 * which sit inside quotes in their patterns. Python, PHP, Rust, Java and C#
 * capture a raw name/path node instead (no quotes in the source syntax), so
 * this is a safe no-op for those. Only a matched quote pair is stripped —
 * same reasoning as extract.ts's own `stripQuotes`: an unbalanced one means
 * the capture is not a whole literal, and stripping it anyway would silently
 * shorten a truncated capture into a clean-looking wrong one.
 */
function stripQuotes(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const quote = value[0];
  if (quote === undefined || !/^['"`]$/.test(quote)) return value;
  if (value.length < 2 || !value.endsWith(quote)) return value;
  return value.slice(1, -1);
}

/* ---------------------------------------------------------------------- *
 * Resolution
 * ---------------------------------------------------------------------- */

/**
 * Resolve every edge against the known project-file set. An edge whose
 * language cannot resolve at all, whose specifier does not match the
 * language's resolvable shape (a bare/third-party specifier, an external
 * crate, …), or whose candidate names no file in `projectFiles`, is
 * returned in `unresolved` — NEVER dropped, and NEVER assigned a
 * `module_file` that is not a member of `projectFiles`: every resolver
 * below only ever returns a string it first found in that set.
 */
export function resolveModuleEdges(
  edges: readonly ModuleEdge[],
  projectFiles: ReadonlySet<string>,
): { resolved: ResolvedEdge[]; unresolved: ModuleEdge[] } {
  const byPosixPath = buildPosixIndex(projectFiles);
  const resolved: ResolvedEdge[] = [];
  const unresolved: ModuleEdge[] = [];

  for (const edge of edges) {
    const moduleFile = RESOLVABLE_LANGUAGES.has(edge.language)
      ? resolveSpecifier(edge, byPosixPath)
      : undefined;
    if (moduleFile !== undefined) {
      resolved.push({ file: edge.file, module_file: moduleFile });
    } else {
      unresolved.push(edge);
    }
  }

  return { resolved, unresolved };
}

function resolveSpecifier(edge: ModuleEdge, byPosixPath: ReadonlyMap<string, string>): string | undefined {
  switch (edge.language) {
    case 'typescript':
    case 'javascript':
      return resolveJsTs(edge.file, edge.specifier, byPosixPath);
    case 'python':
      return resolvePython(edge.specifier, byPosixPath);
    case 'go':
      return resolveGo(edge.specifier, byPosixPath);
    case 'rust':
      return resolveRust(edge.file, edge.specifier, byPosixPath);
    default:
      return undefined;
  }
}

/**
 * Extension-then-index-file candidates for a JS/TS relative specifier, tried
 * in order — first hit wins. `.ts`/`.tsx` before `.js`/`.jsx`: this repo's
 * own NodeNext convention (ESM specifiers end in `.js`, sources are `.ts`,
 * per CLAUDE.md) means a specifier's literal extension is frequently the
 * WRONG one to trust, so when a project happens to carry both `x.ts` and
 * `x.js`, the TypeScript source is the more likely intended target.
 * Plain-file candidates before `/index.*`, because a bare specifier names a
 * file far more often than a directory.
 */
const JS_TS_SUFFIXES = [
  '.ts', '.tsx', '.js', '.jsx',
  '/index.ts', '/index.tsx', '/index.js', '/index.jsx',
];

/**
 * Only a relative specifier (`./x`, `../x`) is project-local; a bare one
 * (`express`) names a package and is left unresolved rather than guessed —
 * same rule `resolveModuleFile` in mapAttackSurface.ts already applies for
 * mount resolution.
 */
function resolveJsTs(
  importingFile: string,
  specifier: string,
  byPosixPath: ReadonlyMap<string, string>,
): string | undefined {
  if (!specifier.startsWith('.')) return undefined;
  // Strip a JS/TS extension the specifier may already carry (NodeNext-style
  // `./users.js`) before appending candidates, so `./users` and `./users.js`
  // both land on the same base and neither doubles an extension.
  const base = stripJsTsExtension(joinAndNormalize(dirOf(importingFile), specifier));
  return lookupCandidates(byPosixPath, JS_TS_SUFFIXES.map((suffix) => `${base}${suffix}`));
}

function stripJsTsExtension(path: string): string {
  return path.replace(/\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/, '');
}

/**
 * `app.models` → `app/models.py` (a plain module) before
 * `app/models/__init__.py` (a package of the same name) — tried in that
 * order because a plain module is the more common shape when a project
 * happens to have both.
 *
 * A leading dot (`from . import x`, `from ..shared import x`) is a RELATIVE
 * import: resolving it correctly needs the importing file's package depth,
 * and guessing wrong would silently point at a same-named file at the wrong
 * directory level — worse than reporting unresolved. Only the absolute
 * dotted form is resolved.
 */
const PYTHON_SUFFIXES = ['.py', '/__init__.py'];

function resolvePython(specifier: string, byPosixPath: ReadonlyMap<string, string>): string | undefined {
  if (specifier.startsWith('.')) return undefined;
  const base = specifier.split('.').join('/');
  if (base.length === 0) return undefined;
  return lookupCandidates(byPosixPath, PYTHON_SUFFIXES.map((suffix) => `${base}${suffix}`));
}

/**
 * Same module-before-package-directory reasoning as Python, for Rust's
 * `mod.rs` convention.
 */
const RUST_SUFFIXES = ['.rs', '/mod.rs'];

/**
 * Cargo's crate root is `src/` by convention (`src/lib.rs` or
 * `src/main.rs`), so a `crate::` path is anchored there; `self::` is
 * anchored at the importing file's own directory — the closest Rust
 * analogue of a relative import. Anything else (an external crate name, e.g.
 * `actix_web::web`) is not a path resolvable without reading Cargo.toml, so
 * it is left unresolved.
 *
 * A `use` path's FINAL segment is very often a specific item — a struct, fn
 * or const — not a module: `use crate::settings::Config;` imports the
 * `Config` type FROM `settings.rs`, there is no `Config.rs`. Tried against
 * the fixture, treating every segment as a path component resolved zero
 * multi-segment crate-relative imports — the dominant real-world shape —
 * even though the module itself was perfectly resolvable one level up. So
 * every segment count from the full chain down to one is tried in turn,
 * longest (most specific) first: a project genuinely nesting modules
 * (`crate::api::v1::handlers`) still resolves at full depth, and a path
 * ending in an item name falls back to its module once the full chain
 * fails every candidate.
 */
function resolveRust(
  importingFile: string,
  specifier: string,
  byPosixPath: ReadonlyMap<string, string>,
): string | undefined {
  let root: string;
  let tail: string;
  if (specifier.startsWith('crate::')) {
    root = 'src';
    tail = specifier.slice('crate::'.length);
  } else if (specifier.startsWith('self::')) {
    root = dirOf(importingFile);
    tail = specifier.slice('self::'.length);
  } else {
    return undefined;
  }

  const segments = tail.split('::').filter((segment) => segment.length > 0);
  for (let depth = segments.length; depth > 0; depth -= 1) {
    const base = joinAndNormalize(root, segments.slice(0, depth).join('/'));
    const hit = lookupCandidates(byPosixPath, RUST_SUFFIXES.map((suffix) => `${base}${suffix}`));
    if (hit !== undefined) return hit;
  }
  return undefined;
}

/**
 * Go names every import by a full package path whose prefix is the module
 * name declared in `go.mod` (e.g. `module myapp` makes `myapp/pkg/handler`
 * the specifier for the directory `pkg/handler`). Reading go.mod is out of
 * scope here (no interface above asks for it), so the module-name prefix is
 * unknown — but Go's own resolution rule still holds structurally:
 * everything AFTER that prefix is the package's exact directory path
 * relative to the module root, which — under the same "module root =
 * scanned tree root" assumption `projectFiles` already makes — is
 * recoverable as a SUFFIX match against a known `.go` file's own path
 * (extension stripped).
 *
 * The longest matching suffix wins: a shorter match consumes less of the
 * specifier and implies an implausibly long module-name prefix (e.g. prefer
 * `pkg/handler` over a coincidental bare `handler` elsewhere in the tree).
 * There is no tie to break — a string has exactly one suffix of any given
 * length, so at most one known file can match at each length — which also
 * makes the result order-independent: which file Semgrep happened to report
 * first never changes the answer.
 */
function resolveGo(specifier: string, byPosixPath: ReadonlyMap<string, string>): string | undefined {
  let best: string | undefined;
  let bestLength = -1;

  for (const [posixPath, original] of byPosixPath) {
    if (!posixPath.endsWith('.go')) continue;
    const stripped = posixPath.slice(0, -'.go'.length);
    if (specifier !== stripped && !specifier.endsWith(`/${stripped}`)) continue;

    if (stripped.length > bestLength) {
      best = original;
      bestLength = stripped.length;
    }
  }

  return best;
}

/* ---- shared path plumbing --------------------------------------------- */

/**
 * Semgrep reports paths in the host's native separator (backslash on an
 * absolute Windows target — see mapAttackSurface.ts's own `toPosixPath` and
 * its header comment). Every resolver above works in POSIX form internally,
 * but a `module_file` that differs from `projectFiles`' own spelling only by
 * separator would never string-equal the same file's appearance elsewhere in
 * the snapshot (a route's `file`, another edge's `file`) — silently breaking
 * the graph on Windows while looking correct on POSIX CI. So comparison
 * happens on a POSIX-normalised key, but the value returned is always the
 * ORIGINAL, verbatim string from `projectFiles`.
 */
function buildPosixIndex(projectFiles: ReadonlySet<string>): Map<string, string> {
  const index = new Map<string, string>();
  for (const file of projectFiles) {
    index.set(toPosix(file), file);
  }
  return index;
}

function lookupCandidates(
  byPosixPath: ReadonlyMap<string, string>,
  candidates: readonly string[],
): string | undefined {
  for (const candidate of candidates) {
    const hit = byPosixPath.get(candidate);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

function toPosix(path: string): string {
  return path.replace(/\\/g, '/');
}

function dirOf(file: string): string {
  const parts = toPosix(file).split('/');
  parts.pop();
  return parts.join('/');
}

/** Join a directory and a `/`-separated tail, resolving `.` and `..`
 *  segments. Mirrors the stack-based normalisation `resolveModuleFile` in
 *  mapAttackSurface.ts already uses for the same purpose. */
function joinAndNormalize(dir: string, tail: string): string {
  const stack: string[] = [];
  for (const part of `${dir}/${tail}`.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  return stack.join('/');
}
