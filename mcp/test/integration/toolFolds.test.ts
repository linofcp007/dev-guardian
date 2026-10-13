/**
 * The `tools/list` a host is shown, and the folds behind it — read through a
 * real MCP client, as a host reads them.
 *
 *   - `tools/list` names the listed tools only, and carries no `$schema` and
 *     no `execution` (what the SDK adds and no client needs: 6 KB a list);
 *   - without `$schema` a schema is read as JSON Schema 2020-12, so none
 *     may use a keyword whose meaning changed since draft-07;
 *   - a hidden alias still answers `tools/call` with its own parameters, and
 *     its fold runs the same handler for the same answer;
 *   - a fold refuses a parameter its mode does not take, and the member's
 *     required parameters stay required — strict, as every tool is;
 *   - a fold's annotations cover every member's;
 *   - initialize carries the server's `instructions`.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import '../../src/registerAll.js';
import { TOOL_ANNOTATIONS } from '../../src/tools/annotations.js';
import { FOLDS } from '../../src/tools/fold.js';
import { attachAllTools, listedTools, TOOLS } from '../../src/tools/index.js';
import { SERVER_INSTRUCTIONS } from '../../src/tools/instructions.js';
import { freshPlugin, projectDir, seedScan, type Seeded } from '../helpers/historySeed.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

let s: Seeded;
let client: Client;
let project = '';

beforeAll(async () => {
  s = freshPlugin();
  project = projectDir('folds-');
  seedScan(s, { id: 'a', type: 'sast', project, findings: [{ fp: 'kept', severity: 'high' }] });
  seedScan(s, {
    id: 'b',
    type: 'sast',
    project,
    findings: [
      { fp: 'kept', severity: 'high' },
      { fp: 'fresh', severity: 'critical' },
    ],
  });
  const server = new McpServer({ name: 'test', version: '0.0.0' }, { instructions: SERVER_INSTRUCTIONS });
  attachAllTools(server, s.plugin);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-client', version: '0.0.0' });
  await client.connect(clientTransport);
});

interface CallResult {
  isError?: boolean;
  content: Array<{ type: string; text?: string }>;
  structuredContent?: Record<string, unknown>;
}

async function call(name: string, args: Record<string, unknown>): Promise<CallResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as CallResult;
}

const text = (r: CallResult): string => r.content.map((c) => c.text ?? '').join('\n');

describe('tools/list', () => {
  it('names the listed tools, in registry order, and no hidden alias', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(listedTools().map((t) => t.name));
    const hidden = TOOLS.filter((t) => t.listed === false).map((t) => t.name);
    expect(hidden.length).toBeGreaterThan(0);
    expect(tools.filter((t) => hidden.includes(t.name))).toEqual([]);
  });

  it('carries no $schema and no execution', async () => {
    const raw = JSON.stringify((await client.listTools()).tools);
    expect(raw).not.toContain('"$schema"');
    expect(raw).not.toContain('"execution"');
  });

  it('uses no keyword whose meaning differs between JSON Schema draft-07 and 2020-12', async () => {
    const offenders: string[] = [];
    const walk = (node: unknown, path: string): void => {
      if (node === null || typeof node !== 'object') return;
      if (Array.isArray(node)) {
        node.forEach((n, i) => walk(n, `${path}[${i}]`));
        return;
      }
      for (const [key, value] of Object.entries(node)) {
        if (key === 'properties' && value !== null && typeof value === 'object') {
          for (const [prop, schema] of Object.entries(value)) walk(schema, `${path}.${prop}`);
          continue;
        }
        if (['$ref', 'definitions', 'dependencies', 'additionalItems'].includes(key)) offenders.push(`${path}: ${key}`);
        if (key === 'items' && Array.isArray(value)) offenders.push(`${path}: tuple items`);
        walk(value, `${path}.${key}`);
      }
    };
    for (const t of (await client.listTools()).tools) walk(t.inputSchema, t.name);
    expect(offenders).toEqual([]);
  });
});

describe('the folds', () => {
  it('every fold is listed and every non-head member is a hidden alias', () => {
    const listed = new Set(listedTools().map((t) => t.name));
    for (const f of FOLDS) {
      expect(listed.has(f.name), f.name).toBe(true);
      for (const member of Object.values(f.modes)) {
        if (member === f.name) continue;
        expect(TOOLS.find((t) => t.name === member)?.listed, member).toBe(false);
      }
    }
  });

  it('a hidden alias answers tools/call, and its fold returns the same answer', async () => {
    const alias = await call('triage_findings', { project_path: project });
    const folded = await call('prioritize_findings', { view: 'triage', project_path: project });
    expect(alias.isError, text(alias)).toBeFalsy();
    expect(folded.isError, text(folded)).toBeFalsy();
    expect(folded.structuredContent).toEqual(alias.structuredContent);

    const regression = await call('regression_alert', { project_path: project, scan_type: 'sast' });
    const viaDiff = await call('diff_scans', { mode: 'regression', project_path: project, scan_type: 'sast' });
    expect(viaDiff.isError, text(viaDiff)).toBeFalsy();
    expect(viaDiff.structuredContent?.['regressed']).toBe(true);
    expect(viaDiff.structuredContent?.['new_findings_by_severity']).toEqual(
      regression.structuredContent?.['new_findings_by_severity'],
    );
  });

  it('a fold that kept a member name runs that member when the mode is omitted', async () => {
    const r = await call('diff_scans', { project_path: project, scan_type: 'sast' });
    expect(r.isError, text(r)).toBeFalsy();
    expect(r.structuredContent).toHaveProperty('summary');
    expect(r.structuredContent).not.toHaveProperty('regressed');
  });

  it("refuses a parameter of another mode, naming what the mode takes", async () => {
    const r = await call('diff_scans', { mode: 'regression', project_path: project, from: 'baseline' });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/invalid_input/);
    expect(text(r)).toMatch(/does not take from; it takes project_path, scan_type, source_tool, threshold/);
  });

  it('a fold with no default mode requires one (the schema says so; the handler too, when called directly)', async () => {
    const r = await call('dotnet_check', { project_path: project });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/Required at check/);
    const direct = await TOOLS.find((t) => t.name === 'dotnet_check')?.handler({ project_path: project }, s.plugin);
    expect(direct).toMatchObject({ ok: false, error: { code: 'invalid_input' } });
    expect(JSON.stringify(direct)).toMatch(/dotnet_check needs check: one of \\"secrets\\", \\"target_framework\\", \\"efcore\\", \\"setup\\"/);
  });

  it("keeps a member's required parameter required in its mode", async () => {
    const r = await call('wp_report', { kind: 'plugin' });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/invalid_input/);
    expect(text(r)).toMatch(/slug/);
  });

  it('refuses a parameter no member takes, before any handler runs', async () => {
    const r = await call('wp_report', { kind: 'setup', project_path: project, bogus: 1 });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/bogus/);
  });

  it("each fold's annotations cover its members': read-only only when all are, destructive or open-world when any is", () => {
    for (const f of FOLDS) {
      const own = TOOL_ANNOTATIONS[f.name];
      expect(own, f.name).toBeDefined();
      const members = Object.values(f.modes).map((m) => TOOL_ANNOTATIONS[m]);
      expect(members.every((m) => m !== undefined), f.name).toBe(true);
      const hints = members.filter((m) => m !== undefined);
      expect(own?.readOnlyHint, `${f.name} readOnlyHint`).toBe(hints.every((m) => m.readOnlyHint));
      expect(own?.destructiveHint, `${f.name} destructiveHint`).toBe(hints.some((m) => m.destructiveHint));
      expect(own?.idempotentHint, `${f.name} idempotentHint`).toBe(hints.every((m) => m.idempotentHint));
      expect(own?.openWorldHint, `${f.name} openWorldHint`).toBe(hints.some((m) => m.openWorldHint));
    }
  });
});

describe('the server instructions', () => {
  it('initialize carries them', () => {
    expect(client.getInstructions()).toBe(SERVER_INSTRUCTIONS);
  });

  it('say when to use which family, that a scanner that did not run is a gap, the safety rules and the dev-spec-driven routing', () => {
    expect(SERVER_INSTRUCTIONS).toMatch(/security_scan_full/);
    expect(SERVER_INSTRUCTIONS).toMatch(/did not run is a gap, never 0 findings/);
    expect(SERVER_INSTRUCTIONS).toMatch(/Never run db adopt for the user/);
    expect(SERVER_INSTRUCTIONS).toMatch(/Never run baseline update to accept one finding/);
    expect(SERVER_INSTRUCTIONS).toMatch(/\.specs\/[^\n]*spec_next_action[^\n]*\/spec-bugfix/);
  });

  it('name only listed tools', () => {
    const listed = listedTools();
    const names = new Set(listed.map((t) => t.name));
    const params = new Set(listed.flatMap((t) => Object.keys(t.inputSchema)));
    const prefixes = new Set(listed.map((t) => t.name.split('_')[0] ?? ''));
    const strays = [...SERVER_INSTRUCTIONS.matchAll(/\b([a-z]+(?:_[a-z]+)+)\b/g)]
      .map((m) => m[1] ?? '')
      .filter((n) => prefixes.has(n.split('_')[0] ?? '') && !names.has(n) && !params.has(n));
    expect(strays).toEqual([]);
  });
});
