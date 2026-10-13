#!/usr/bin/env node
/**
 * Exports nothing imports (review 8, finding 15) — part of `npm run lint`.
 *
 * `noUnusedLocals` cannot see an export: a name exported from a module is
 * "used" as far as tsc is concerned, so a function whose last caller went
 * away stays forever, and a helper exported for no one invites a second
 * module to grow a dependency on an internal. This reads every module of
 * `src/` and `test/` with the TypeScript parser (no type check — a second or
 * two), and lists each export of `src/` that no OTHER module imports by
 * name, re-exports, or reaches through `import * as` / `import()` of its
 * module. The bundles' entries (`engine.ts`, `cli.ts`, `hooksEntry.ts`,
 * `server.ts`) export for the CLI and the hooks, which are not TypeScript:
 * all of theirs count as used.
 *
 * A ratchet, not a purge: `scripts/unusedExports.baseline.json` holds the
 * exports that were unimported when the check began (most are types and
 * helpers of the tool modules, kept exported while that surface is being
 * reworked). The check fails on an unimported export NOT in the baseline — a
 * new one — and on a baseline entry that is imported now or gone — remove it.
 * `--write-baseline` rewrites the file (after a deliberate cleanup).
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE = join(root, 'scripts', 'unusedExports.baseline.json');
const ENTRIES = new Set(['src/engine.ts', 'src/cli.ts', 'src/hooksEntry.ts', 'src/server.ts']);

/** Every `.ts` file under `dir`, project-relative with `/`. */
function files(dir) {
  const out = [];
  for (const e of readdirSync(join(root, dir), { withFileTypes: true })) {
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) {
      if (rel === 'test/fixtures') continue;
      out.push(...files(rel));
    } else if (e.name.endsWith('.ts') && !e.name.endsWith('.d.ts')) out.push(rel);
  }
  return out;
}

/** `./x.js` from `src/a/b.ts` → `src/a/x.ts` (or `…/index.ts`); null for a package or an unknown file. */
function resolveSpecifier(from, spec, known) {
  if (!spec.startsWith('.')) return null;
  const base = relative(root, resolve(root, dirname(from), spec)).split('\\').join('/');
  for (const candidate of [base.replace(/\.js$/, '.ts'), `${base}.ts`, `${base}/index.ts`]) {
    if (known.has(candidate)) return candidate;
  }
  return null;
}

const all = [...files('src'), ...files('test')];
const known = new Set(all);
/** module → its exported names. */
const exported = new Map();
/** module → the names other modules import from it; `*` for all of them. */
const imported = new Map();
const use = (mod, name) => {
  if (!imported.has(mod)) imported.set(mod, new Set());
  imported.get(mod).add(name);
};

for (const file of all) {
  const sf = ts.createSourceFile(file, readFileSync(join(root, file), 'utf8'), ts.ScriptTarget.Latest, true);
  const names = new Set();
  const hasExport = (node) => ts.getCombinedModifierFlags(node) & ts.ModifierFlags.Export;
  const visit = (node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const spec = node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier) ? node.moduleSpecifier.text : null;
      const target = spec === null ? null : resolveSpecifier(file, spec, known);
      if (ts.isImportDeclaration(node) && target !== null) {
        const clause = node.importClause;
        if (clause?.name) use(target, 'default');
        const bindings = clause?.namedBindings;
        if (bindings && ts.isNamespaceImport(bindings)) use(target, '*');
        else if (bindings) for (const el of bindings.elements) use(target, (el.propertyName ?? el.name).text);
        if (!clause) use(target, '*'); // a side-effect import
      }
      if (ts.isExportDeclaration(node)) {
        if (target !== null) {
          if (!node.exportClause) use(target, '*');
          else if (ts.isNamedExports(node.exportClause)) for (const el of node.exportClause.elements) use(target, (el.propertyName ?? el.name).text);
          else use(target, '*');
        }
        if (node.exportClause && ts.isNamedExports(node.exportClause)) for (const el of node.exportClause.elements) names.add(el.name.text);
      }
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const arg = node.arguments[0];
      const target = arg && ts.isStringLiteral(arg) ? resolveSpecifier(file, arg.text, known) : null;
      if (target !== null) use(target, '*');
    } else if (ts.isImportTypeNode(node)) {
      const lit = node.argument && ts.isLiteralTypeNode(node.argument) ? node.argument.literal : null;
      const target = lit && ts.isStringLiteral(lit) ? resolveSpecifier(file, lit.text, known) : null;
      if (target !== null) use(target, node.qualifier && ts.isIdentifier(node.qualifier) ? node.qualifier.text : '*');
    }
    if (node.parent === sf && hasExport(node)) {
      if (ts.isVariableStatement(node)) {
        for (const d of node.declarationList.declarations) {
          if (ts.isIdentifier(d.name)) names.add(d.name.text);
        }
      } else if (node.name && ts.isIdentifier(node.name)) {
        names.add(node.name.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  if (file.startsWith('src/')) exported.set(file, names);
}

const unused = [];
for (const [mod, names] of exported) {
  if (ENTRIES.has(mod)) continue;
  const used = imported.get(mod) ?? new Set();
  if (used.has('*')) continue;
  for (const name of names) if (!used.has(name)) unused.push(`${mod}#${name}`);
}
unused.sort();

if (process.argv.includes('--write-baseline')) {
  writeFileSync(BASELINE, `${JSON.stringify(unused, null, 2)}\n`);
  console.log(`unusedExports: baseline written, ${unused.length} entries`);
  process.exit(0);
}

const baseline = new Set(JSON.parse(readFileSync(BASELINE, 'utf8')));
const fresh = unused.filter((e) => !baseline.has(e));
const current = new Set(unused);
const stale = [...baseline].filter((e) => !current.has(e));
if (fresh.length > 0) {
  console.error(`unusedExports: ${fresh.length} export(s) no other module imports — use it, un-export it, or delete it:`);
  for (const e of fresh) console.error(`  ${e}`);
}
if (stale.length > 0) {
  console.error(`unusedExports: ${stale.length} baseline entr(ies) imported now or gone — remove from scripts/unusedExports.baseline.json:`);
  for (const e of stale) console.error(`  ${e}`);
}
if (fresh.length > 0 || stale.length > 0) process.exit(1);
console.log(`unusedExports: ok (${unused.length} known, in the baseline)`);
