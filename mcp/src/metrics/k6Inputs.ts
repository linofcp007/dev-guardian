/**
 * The local modules a k6 script imports, read before the run: an input of the k6 series (`perfSeries.ts`
 * `k6Series`), as the script and its content are. Grafana's own examples keep a script's load in a module
 * (quickpizza's `lib/load-options.js`: `SmokeOptions`, `AverageStages`, …), so an edit there is another load, and
 * keyed by the entry script alone it read as a regression of the old one.
 *
 * - A module is LOCAL when its specifier starts with `./`, `../`, `/` or `file://`. `k6`, `k6/*` and `k6/x/*` are
 *   built-ins; an `http(s)://` module is keyed by its URL, which is in the importing text already; a bare name
 *   resolves nowhere (k6 has no `node_modules`).
 * - Specifiers are found by four linear patterns, a keyword then a quoted literal: `from '<s>'` (an `import … from`
 *   or `export … from`, over any number of lines), `import '<s>'`, `import('<s>')` and `require('<s>')`. An
 *   `import(` or `require(` whose argument is no such literal alone is `dynamic`: what it loads is not keyed, and
 *   the label says so. Comments and strings are not stripped: a commented-out import of a file that exists is keyed
 *   (it splits a series only when that file changes).
 * - The walk is breadth-first from the entry, each module resolved against the directory of the module that
 *   imports it, every path read at most once (the entry included, so a cycle ends). A module is keyed by the
 *   sha256 of its BYTES (two files that decode alike are still two files), and scanned as UTF-8.
 * - The formula is chosen by the TEXT, never by a read: every local specifier inside the project enters `files`,
 *   readable or not (`missing`, `unreadable`, `too-large`), so a script that imports a local module always gets
 *   the new key — a read that fails can split a series, never join the series of runs from before the upgrade.
 *   A script that names none (or only dynamic or outside ones) has `files` empty: the 3.17.0 key, unchanged.
 *
 * Bounds: at most {@link K6_INPUT_FILES_MAX} modules besides the entry are read, each under the reader's cap (the
 * project file cap, 8 MiB): what lies past either is not keyed (`bound`) — so at most 64 reads of 8 MiB a run, and
 * a module over the cap is keyed by that fact alone, never by its content. A path out of the project is never read
 * (`outside`). Not keyed at all: the files a script `open()`s (its data — a file regenerated before each run would
 * make every run a new series), k6's own config file and the variables k6 is handed (docs/maintainers/
 * architecture.md, The metrics module).
 *
 * Pure: the reader is injected (`tools/perfCheck.ts` builds it over `platform/projectFs.ts`).
 */

import { createHash } from 'node:crypto';

/** How a module read ended. `too-large`: over the reader's cap, so neither hashed nor scanned. */
export type K6ModuleRead =
  | { readonly kind: 'ok'; readonly bytes: Uint8Array }
  | { readonly kind: 'absent' }
  | { readonly kind: 'refused' }
  | { readonly kind: 'too-large' };

export interface K6InputReader {
  /** A module's bytes, by its project-relative POSIX path. */
  read(rel: string): K6ModuleRead;
  /** `spec` (a local specifier) resolved against `fromDir` (project-relative POSIX, `''` the root); null outside the project. */
  resolve(fromDir: string, spec: string): string | null;
}

/** Why the key does not hold every input: a specifier built at run time, one out of the project, a bound, a read refused. */
type K6Partial = 'bound' | 'dynamic' | 'outside' | 'unreadable';

export interface K6LocalInputs {
  /** `[path, sha256 | 'missing' | 'unreadable' | 'too-large']`, sorted by path; the entry is not in it (it is keyed already). */
  readonly files: ReadonlyArray<readonly [string, string]>;
  /** Sorted, each at most once. */
  readonly partial: readonly K6Partial[];
}

/** The modules read besides the entry. */
export const K6_INPUT_FILES_MAX = 64;

/** What a walk that threw keys: never the empty list, which is the key of a script that imports nothing. */
export const K6_WALK_FAILED: K6LocalInputs = { files: [['', 'unreadable']], partial: ['unreadable'] };

/** A specifier: up to 1,024 characters, no quote, no line break, no `$` (so no `${…}` of a template literal). */
const SPEC = String.raw`[^'"\x60\r\n$]{1,1024}`;
const FROM = new RegExp(String.raw`\bfrom\s*(['"])(${SPEC})\1`, 'g');
const IMPORT_BARE = new RegExp(String.raw`\bimport\s*(['"])(${SPEC})\1`, 'g');
/**
 * Every call of `import(` or `require(`; its argument is a literal when {@link CALL_LITERAL} matches there — the
 * literal alone, then `)` or the `,` of an options argument (`require('./a' + b)` is no literal).
 */
const CALL = /\b(?:import|require)\s*\(/g;
const CALL_LITERAL = new RegExp(String.raw`(?:import|require)\s*\(\s*(['"\x60])(${SPEC})\1\s*[,)]`, 'y');

/** The specifiers a module's text names, in the order found, and whether a call's argument is no literal. */
export function k6Specifiers(text: string): { specifiers: string[]; dynamic: boolean } {
  const specifiers: string[] = [];
  for (const re of [FROM, IMPORT_BARE]) {
    re.lastIndex = 0;
    for (let m = re.exec(text); m !== null; m = re.exec(text)) specifiers.push(m[2] ?? '');
  }
  let dynamic = false;
  CALL.lastIndex = 0;
  for (let m = CALL.exec(text); m !== null; m = CALL.exec(text)) {
    CALL_LITERAL.lastIndex = m.index;
    const literal = CALL_LITERAL.exec(text);
    if (literal === null) dynamic = true;
    else specifiers.push(literal[2] ?? '');
  }
  return { specifiers, dynamic };
}

/** A specifier k6 reads from the file system. */
function isLocalSpecifier(spec: string): boolean {
  return spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('/') || spec.startsWith('file://');
}

const dirOf = (rel: string): string => (rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '');
const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const decoder = new TextDecoder('utf-8');

/** The local modules `entry` (project-relative POSIX) imports, transitively. Never throws: a walk that does is {@link K6_WALK_FAILED}. */
export function k6LocalInputs(entry: string, reader: K6InputReader): K6LocalInputs {
  try {
    return walk(entry, reader);
  } catch {
    return K6_WALK_FAILED;
  }
}

function walk(entry: string, reader: K6InputReader): K6LocalInputs {
  const files = new Map<string, string>();
  const partial = new Set<K6Partial>();
  const seen = new Set<string>([entry]);
  const queue: string[] = [entry];
  for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
    const read = reader.read(next);
    if (read.kind !== 'ok') {
      // A missing module fails k6's run, which is then never kept: keyed, and nothing more to say.
      if (read.kind === 'too-large') partial.add('bound');
      else if (read.kind === 'refused' || next === entry) partial.add('unreadable');
      // The entry unread: what it imports is unknown, so its key is never the one of a script that imports nothing.
      files.set(next === entry ? '' : next, read.kind === 'absent' ? 'missing' : read.kind === 'refused' ? 'unreadable' : 'too-large');
      continue;
    }
    if (next !== entry) files.set(next, sha256(read.bytes));
    const { specifiers, dynamic } = k6Specifiers(decoder.decode(read.bytes));
    if (dynamic) partial.add('dynamic');
    for (const spec of specifiers) {
      if (!isLocalSpecifier(spec)) continue;
      const resolved = reader.resolve(dirOf(next), spec);
      if (resolved === null) {
        partial.add('outside');
        continue;
      }
      // The project root named as a module is the path `.`: `''` is the entry's own marker in `files`.
      const rel = resolved === '' ? '.' : resolved;
      if (seen.has(rel)) continue;
      // `seen` holds the entry too: K6_INPUT_FILES_MAX modules besides it.
      if (seen.size - 1 >= K6_INPUT_FILES_MAX) {
        partial.add('bound');
        continue;
      }
      seen.add(rel);
      queue.push(rel);
    }
  }
  return {
    files: [...files].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    partial: [...partial].sort(),
  };
}
