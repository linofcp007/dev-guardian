/**
 * A Python project's own manifest as a source of installs: `pyproject.toml`
 * and `setup.cfg`, judged by the same fail-closed rule as a requirements file
 * (`pipRequirements.ts`, review of 3.0, W2E).
 *
 * Measured with the reviewer's probe: create_fix_pr's `deps_audit` re-scan
 * ran real `pip-audit` on a project with a `pyproject.toml` and no
 * requirements file, and it fetched `GET /evilpkg-1.0.tar.gz` from the host
 * `[project].dependencies` named (`evilpkg @ http://…`). So in these files
 * every dependency string must be a plain PEP 508 requirement with no URL —
 * `[project].dependencies`, `[project.optional-dependencies]`,
 * `[dependency-groups]` and `[build-system].requires` — and a tool's own
 * package source or index refuses the install outright: `[tool.uv.sources]`,
 * `[tool.uv.index]` and uv's index keys, `[[tool.poetry.source]]` and a
 * Poetry dependency with `git`/`url`/`path`/`source`, `[tool.pdm.source]`,
 * Hatch's `allow-direct-references`, `setup.cfg`'s `dependency_links`.
 *
 * A line-by-line reader, not a TOML parser, and it fails closed: a table
 * header or a dependency array it cannot read is `unparsed manifest`, a
 * refusal like any other. When pip-audit would build the project itself (no
 * requirements file to hand it), dependencies the build backend decides —
 * `dynamic`, or no `[project]` table — are refused too: `setup.py` can fetch
 * from anywhere.
 */

import { join } from 'node:path';
import { describeReadRefusal, presentInProject, readProjectText } from '../platform/projectFs.js';
import { textLines } from '../platform/textLines.js';
import { judgeRequirement, type PipRefusal } from './pipRequirements.js';

/** A manifest is read up to this size; a real one is a few KB. */
const MANIFEST_MAX_BYTES = 1024 * 1024;

/** Key paths (table + key, dotted, quotes removed) that choose a package source. */
const SOURCE_PATHS: readonly string[] = [
  'tool.uv.sources',
  'tool.uv.index',
  'tool.uv.index-url',
  'tool.uv.extra-index-url',
  'tool.uv.find-links',
  'tool.uv.no-index',
  'tool.uv.index-strategy',
  'tool.uv.pip',
  'tool.poetry.source',
  'tool.pdm.source',
  'tool.hatch.metadata.allow-direct-references',
];

/** Tables whose every key is a dependency ARRAY of requirement strings. */
const ARRAY_TABLES = /^(project\.optional-dependencies|dependency-groups)$/;
/** Poetry's dependency tables: a key whose value is an inline table with a source is refused. */
const POETRY_DEP_TABLE = /^tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/;
/** An inline-table key in a Poetry dependency that fetches from elsewhere. */
const POETRY_SOURCE_KEY = /(^|[{,\s])(git|url|path|source|develop)\s*=/;

function normalise(key: string): string {
  return key.replace(/["'\s]/g, '');
}

/** The strings of a TOML array's text (`[ … ]`), or null when an item is not a plain string. */
function arrayStrings(text: string): string[] | null {
  const out: string[] = [];
  let i = text.indexOf('[');
  if (i < 0) return null;
  i += 1;
  for (;;) {
    while (i < text.length && /[\s,]/.test(text.charAt(i))) i += 1;
    if (i >= text.length) return null;
    const c = text.charAt(i);
    if (c === ']') return out;
    if (c === '#') {
      const nl = text.indexOf('\n', i);
      if (nl < 0) return null;
      i = nl + 1;
      continue;
    }
    if (c === '"') {
      if (text.startsWith('"""', i)) return null;
      let s = '';
      let j = i + 1;
      for (; j < text.length; j++) {
        const d = text.charAt(j);
        if (d === '"') break;
        if (d === '\\') {
          const e = text.charAt(j + 1);
          const simple: Record<string, string> = { '"': '"', '\\': '\\', n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' };
          if (simple[e] !== undefined) {
            s += simple[e];
            j += 1;
            continue;
          }
          return null; // \u escapes and the rest: not read here
        }
        if (d === '\n') return null;
        s += d;
      }
      if (j >= text.length) return null;
      out.push(s);
      i = j + 1;
      continue;
    }
    if (c === "'") {
      if (text.startsWith("'''", i)) return null;
      const end = text.indexOf("'", i + 1);
      if (end < 0 || text.slice(i + 1, end).includes('\n')) return null;
      out.push(text.slice(i + 1, end));
      i = end + 1;
      continue;
    }
    // PEP 735 lets a group include another: `{ include-group = "name" }`.
    if (c === '{') {
      const end = text.indexOf('}', i);
      if (end < 0 || !/^\{\s*include-group\s*=\s*"[A-Za-z0-9._-]+"\s*\}$/.test(text.slice(i, end + 1))) return null;
      i = end + 1;
      continue;
    }
    return null;
  }
}

/** Whether the brackets of an array's text are balanced (strings and comments skipped). */
function arrayClosed(text: string): boolean {
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (quote !== null) {
      if (c === '\\' && quote === '"') i += 1;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '#') {
      const nl = text.indexOf('\n', i);
      if (nl < 0) return false;
      i = nl;
    } else if (c === '[') depth += 1;
    else if (c === ']') {
      depth -= 1;
      if (depth === 0) return true;
    }
  }
  return false;
}

/**
 * Every refusal `pyproject.toml` in `projectDir` holds (see the module doc).
 * `pipAuditBuildsProject`: no requirements file will be handed to pip-audit,
 * so it builds the project from this manifest.
 */
export function checkPyproject(projectDir: string, checkoutRoot: string, pipAuditBuildsProject: boolean): PipRefusal[] {
  const file = 'pyproject.toml';
  if (!presentInProject(projectDir, file)) return [];
  const read = readProjectText(checkoutRoot, join(projectDir, file), MANIFEST_MAX_BYTES);
  if (read.status === 'absent') return [];
  if (read.status === 'refused') return [{ file, line: 0, kind: 'unreadable', detail: describeReadRefusal(read.reason) }];
  const refusals: PipRefusal[] = [];
  let table = '';
  /** The current table is itself a refused source table: its keys are not named again. */
  let tableRefused = false;
  let sawProject = false;
  let dynamicDeps = false;
  let pending: { key: string; line: number; text: string } | null = null;
  let skipUntil: string | null = null;
  let n = 0;
  const judgeArray = (key: string, line: number, text: string): void => {
    const items = arrayStrings(text);
    if (items === null) {
      refusals.push({ file, line, kind: 'unparsed manifest', detail: key });
      return;
    }
    for (const item of items) {
      const bad = judgeRequirement(item);
      if (bad !== null) refusals.push({ file, line, ...bad, detail: key });
    }
  };
  for (const raw of textLines(read.text)) {
    n += 1;
    if (skipUntil !== null) {
      if (raw.includes(skipUntil)) skipUntil = null;
      continue;
    }
    if (pending !== null) {
      pending.text += `\n${raw}`;
      if (arrayClosed(pending.text)) {
        judgeArray(pending.key, pending.line, pending.text);
        pending = null;
      } else if (pending.text.length > MANIFEST_MAX_BYTES) {
        refusals.push({ file, line: pending.line, kind: 'unparsed manifest', detail: pending.key });
        pending = null;
      }
      continue;
    }
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    if (line.startsWith('[')) {
      const header = /^\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$/.exec(line);
      if (header?.[1] === undefined) {
        refusals.push({ file, line: n, kind: 'unparsed manifest', detail: 'a table header' });
        continue;
      }
      table = normalise(header[1]);
      if (table === 'project') sawProject = true;
      tableRefused = SOURCE_PATHS.some((p) => table === p || table.startsWith(`${p}.`));
      if (tableRefused) {
        refusals.push({ file, line: n, kind: 'source table', detail: `[${table}]` });
      }
      continue;
    }
    const kv = /^((?:"[^"]*"|'[^']*'|[A-Za-z0-9_.-]+)(?:\s*\.\s*(?:"[^"]*"|'[^']*'|[A-Za-z0-9_.-]+))*)\s*=\s*(.*)$/.exec(line);
    if (kv?.[1] === undefined || kv[2] === undefined) continue;
    const key = normalise(kv[1]);
    const value = kv[2];
    const path = table === '' ? key : `${table}.${key}`;
    // A multi-line string outside what is judged: skipped to its end.
    for (const q of ['"""', "'''"]) {
      const at = value.indexOf(q);
      if (at >= 0 && value.indexOf(q, at + 3) < 0) skipUntil = q;
    }
    if (tableRefused) continue;
    if (SOURCE_PATHS.some((p) => path === p || path.startsWith(`${p}.`) || (p.startsWith(`${path}.`) && value.includes('{')))) {
      if (path === 'tool.hatch.metadata.allow-direct-references' && !/^true\b/.test(value)) continue;
      refusals.push({ file, line: n, kind: 'source table', detail: path });
      continue;
    }
    if (POETRY_DEP_TABLE.test(table) && POETRY_SOURCE_KEY.test(value)) {
      refusals.push({ file, line: n, kind: 'source table', detail: `${table}.${key}` });
      continue;
    }
    if (/^tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)\.[^.]+$/.test(table) && /^(git|url|path|source|develop)$/.test(key)) {
      refusals.push({ file, line: n, kind: 'source table', detail: path });
      continue;
    }
    if (path === 'project.dynamic' && /["'](dependencies|optional-dependencies)["']/.test(value)) dynamicDeps = true;
    const judged = path === 'project.dependencies' || path === 'build-system.requires' || ARRAY_TABLES.test(table);
    if (!judged) continue;
    if (!value.startsWith('[')) {
      refusals.push({ file, line: n, kind: 'unparsed manifest', detail: path });
      continue;
    }
    if (arrayClosed(value)) judgeArray(path, n, value);
    else pending = { key: path, line: n, text: value };
  }
  if (pending !== null) refusals.push({ file, line: pending.line, kind: 'unparsed manifest', detail: pending.key });
  if (pipAuditBuildsProject && (!sawProject || dynamicDeps)) {
    refusals.push({ file, line: 0, kind: 'dynamic dependencies', detail: sawProject ? '[project].dynamic' : 'no [project] table' });
  }
  return refusals;
}

/** Every refusal `setup.cfg` in `projectDir` holds: `dependency_links`, and a requirement that is not plain. */
export function checkSetupCfg(projectDir: string, checkoutRoot: string): PipRefusal[] {
  const file = 'setup.cfg';
  if (!presentInProject(projectDir, file)) return [];
  const read = readProjectText(checkoutRoot, join(projectDir, file), MANIFEST_MAX_BYTES);
  if (read.status === 'absent') return [];
  if (read.status === 'refused') return [{ file, line: 0, kind: 'unreadable', detail: describeReadRefusal(read.reason) }];
  const refusals: PipRefusal[] = [];
  let inRequires = false;
  let section = '';
  let n = 0;
  for (const raw of textLines(read.text)) {
    n += 1;
    const line = raw.replace(/(^|\s)[#;].*$/, '');
    if (line.trim() === '') continue;
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header?.[1] !== undefined) {
      section = header[1].trim();
      inRequires = section === 'options.extras_require';
      continue;
    }
    const kv = /^([A-Za-z0-9_.-]+)\s*[=:]\s*(.*)$/.exec(line);
    if (kv?.[1] !== undefined && !/^\s/.test(line)) {
      const key = kv[1].toLowerCase();
      if (key === 'dependency_links') {
        refusals.push({ file, line: n, kind: 'source table', detail: 'dependency_links' });
        inRequires = false;
        continue;
      }
      inRequires = ['install_requires', 'setup_requires', 'tests_require'].includes(key) || section === 'options.extras_require';
      const first = (kv[2] ?? '').trim();
      if (inRequires && first !== '') {
        const bad = judgeRequirement(first);
        if (bad !== null) refusals.push({ file, line: n, ...bad, detail: key });
      }
      continue;
    }
    if (inRequires) {
      const bad = judgeRequirement(line.trim());
      if (bad !== null) refusals.push({ file, line: n, ...bad });
    }
  }
  return refusals;
}
