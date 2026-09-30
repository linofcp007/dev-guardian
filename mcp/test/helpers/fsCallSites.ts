/**
 * Every call in `mcp/src` to a `node:fs` / `node:fs/promises` function that
 * reads or writes a file or a directory listing — found through the
 * TypeScript AST, by the local name each file imported the function under,
 * so a comment, a string or a method of the same name is never counted.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import ts from 'typescript';

/** The `node:fs` functions whose raw use the source scan tracks. */
export const TRACKED_FS_APIS = new Set([
  // reads
  'readFileSync',
  'readFile',
  'readdirSync',
  'readdir',
  'opendirSync',
  'opendir',
  'statSync',
  'stat',
  // Review of 3.0, W2E (round 2): these follow a link on the way too — on Windows
  // a link to \\host\share, and `existsSync` of it blocked for 157 s.
  'existsSync',
  'accessSync',
  'access',
  'realpathSync',
  'realpath',
  'createReadStream',
  // writes
  'writeFileSync',
  'writeFile',
  'appendFileSync',
  'appendFile',
  'copyFileSync',
  'copyFile',
  'cpSync',
  'cp',
  'createWriteStream',
]);

export interface FsCallSite {
  /** POSIX path relative to `mcp/`. */
  file: string;
  /** The `node:fs` function's own name (not the local alias). */
  api: string;
  line: number;
  text: string;
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) walk(abs, out);
    else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) out.push(abs);
  }
}

/** Local name → `node:fs` API name, for the tracked functions this file imports. */
function fsImports(sf: ts.SourceFile): Map<string, string> {
  const names = new Map<string, string>();
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
    const from = stmt.moduleSpecifier.text;
    if (from !== 'node:fs' && from !== 'node:fs/promises' && from !== 'fs' && from !== 'fs/promises') continue;
    const clause = stmt.importClause;
    if (clause === undefined || clause.isTypeOnly) continue;
    const bindings = clause.namedBindings;
    if (bindings === undefined) continue;
    if (ts.isNamespaceImport(bindings)) {
      names.set(`${bindings.name.text}.*`, '*');
      continue;
    }
    for (const el of bindings.elements) {
      if (el.isTypeOnly) continue;
      const api = (el.propertyName ?? el.name).text;
      if (TRACKED_FS_APIS.has(api)) names.set(el.name.text, api);
    }
  }
  return names;
}

/** Every tracked `node:fs` call under `srcDir`, relative to `mcpDir`. */
export function findFsCallSites(mcpDir: string, srcDir: string): FsCallSite[] {
  const files: string[] = [];
  walk(srcDir, files);
  const sites: FsCallSite[] = [];
  for (const abs of files.sort()) {
    const text = readFileSync(abs, 'utf8');
    const sf = ts.createSourceFile(abs, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const imports = fsImports(sf);
    if (imports.size === 0) continue;
    const file = relative(mcpDir, abs).split(sep).join('/');
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        let api: string | undefined;
        if (ts.isIdentifier(callee)) api = imports.get(callee.text);
        // `realpathSync.native(…)`, and `fs.realpathSync.native(…)` through a namespace import.
        else if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'native') {
          const inner = callee.expression;
          if (ts.isIdentifier(inner)) api = imports.get(inner.text);
          else if (
            ts.isPropertyAccessExpression(inner) &&
            ts.isIdentifier(inner.expression) &&
            imports.has(`${inner.expression.text}.*`) &&
            TRACKED_FS_APIS.has(inner.name.text)
          ) {
            api = inner.name.text;
          }
        }
        else if (
          ts.isPropertyAccessExpression(callee) &&
          ts.isIdentifier(callee.expression) &&
          imports.has(`${callee.expression.text}.*`) &&
          TRACKED_FS_APIS.has(callee.name.text)
        ) {
          api = callee.name.text;
        }
        if (api !== undefined) {
          const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
          sites.push({ file, api, line: line + 1, text: node.getText(sf).split('\n')[0] ?? '' });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return sites;
}

/** `{ file: { api: count } }` for the sites. */
export function countSites(sites: readonly FsCallSite[]): Map<string, Map<string, number>> {
  const out = new Map<string, Map<string, number>>();
  for (const s of sites) {
    const perFile = out.get(s.file) ?? new Map<string, number>();
    perFile.set(s.api, (perFile.get(s.api) ?? 0) + 1);
    out.set(s.file, perFile);
  }
  return out;
}
