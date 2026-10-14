/**
 * The strings `src/` answers with name the tools a model can call (review 10,
 * "hidden alias names in responses").
 *
 * A Claude Code model can call only listed tools; a hidden alias
 * (`scan_dotnet_secrets`, `wp_rest_audit`, `llm_scan_submit`, …) answers
 * `tools/call` but is not in `tools/list`. `docReferences.test.ts` holds the skills, commands and
 * READMEs to that; this file holds the code's own strings: every string or
 * template literal of `src/` that is PROSE — anything more than the bare name
 * — names a fold call (`wp_vuln_check { mode: "rest" }`, `tools/fold.ts#listedCall`),
 * never a hidden alias.
 *
 * A literal that IS the bare name is an identity, not prose: a tool's
 * registered name, a fold's member, a scan type, a `tools_run` name, a
 * finding's `tool`. Those keep the member's name — fingerprints, baselines
 * and the history match on them (`fingerprint/findingIdentity.ts` reads a
 * finding's `tool` into every identity).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';
import { listedCall } from '../../../src/tools/fold.js';
import { TOOLS } from '../../../src/tools/index.js';

const MCP = resolve(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');

/** Prose that names an alias on purpose, each with why it is never read by the model as a tool to call. */
const ALLOWED: Readonly<Record<string, string>> = {
  'dev-guardian/wp_rest_audit': "the User-Agent wp_vuln_check {mode: \"rest\"} sends to the audited site — the site's logs, never a response",
};

beforeAll(async () => {
  await import('../../../src/registerAll.js');
});

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return sources(abs);
    return e.name.endsWith('.ts') && !e.name.endsWith('.d.ts') ? [abs] : [];
  });
}

/** Every string and template literal of a file, with its line — comments are not literals. */
function literals(file: string): Array<{ text: string; line: number }> {
  const sf = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const out: Array<{ text: string; line: number }> = [];
  const at = (node: ts.Node): number => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      out.push({ text: node.text, line: at(node) });
    } else if (ts.isTemplateExpression(node)) {
      // The template's own text, a `${…}` standing for each hole: never the bare name.
      const text = [node.head.text, ...node.templateSpans.map((s) => `\${…}${s.literal.text}`)].join('');
      out.push({ text, line: at(node) });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

describe('response strings in src/', () => {
  it('listedCall names the fold call for a hidden alias, the name itself otherwise', () => {
    expect(listedCall('scan_dotnet_secrets')).toBe('dotnet_check { check: "secrets" }');
    expect(listedCall('wp_rest_audit')).toBe('wp_vuln_check { mode: "rest" }');
    expect(listedCall('wp_vuln_check')).toBe('wp_vuln_check');
    expect(listedCall('security_scan_full')).toBe('security_scan_full');
    // The LLM scan's steps (fold `llm_scan`, 3.4.0): its aliases name no step in prose either.
    expect(listedCall('llm_scan_start')).toBe('llm_scan { step: "start" }');
    expect(listedCall('llm_scan_task')).toBe('llm_scan { step: "task" }');
    expect(listedCall('llm_scan_submit')).toBe('llm_scan { step: "submit" }');
  });

  it('no prose literal names a hidden alias', () => {
    const hidden = TOOLS.filter((t) => t.listed === false).map((t) => t.name);
    expect(hidden).toEqual(expect.arrayContaining(['scan_dotnet_secrets', 'wp_rest_audit', 'llm_scan_start', 'llm_scan_task', 'llm_scan_submit']));
    const word = new RegExp(`(?<![\\w-])(${hidden.join('|')})(?![\\w-])`);
    const offenders: string[] = [];
    for (const file of sources(join(MCP, 'src'))) {
      const rel = relative(MCP, file).split('\\').join('/');
      for (const { text, line } of literals(file)) {
        if (hidden.includes(text) || ALLOWED[text] !== undefined) continue;
        const hit = word.exec(text);
        if (hit !== null) offenders.push(`${rel}:${line}: ${hit[1] ?? ''} in ${JSON.stringify(text.slice(0, 120))}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('the allowlist holds only literals that are still there', () => {
    const all = new Set(sources(join(MCP, 'src')).flatMap((f) => literals(f).map((l) => l.text)));
    expect(Object.keys(ALLOWED).filter((text) => !all.has(text))).toEqual([]);
  });
});
