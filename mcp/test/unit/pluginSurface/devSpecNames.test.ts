/**
 * dev-guardian's prose against the dev-spec-driven names it may cite.
 *
 * A dev-spec-driven tool or command named in a skill, a command, a rules
 * template, a README or a server message is an instruction the model follows
 * in another plugin, and nothing in this repo fails when that plugin renames
 * it — `guardian-improve` went on citing `spec_backlog` for three
 * dev-spec-driven releases after it stopped being listed. So:
 *
 *   - every `spec_*` / `ears_*` / `steering_*` / `trace_*` name in the prose is
 *     a tool in DEV_SPEC_TOOLS, or one of dev-guardian's own identifiers
 *     (OWN_NAMES — `map_attack_surface`'s OpenAPI fields);
 *   - every `/spec…` command, and every retired dev-spec-driven command, is
 *     a command in DEV_SPEC_COMMANDS;
 *   - when a dev-spec-driven checkout (`../dev-spec-driven`) or install
 *     (`<claude config>/plugins/cache/<marketplace>/dev-spec-driven/<version>`)
 *     of the fixture's version or newer is on this machine, the fixture is
 *     held to it: each tool is in its `tools/list` (a real handshake, in
 *     Claude Code plugin mode) and each command is one of its command files.
 *     With none, that part is skipped, and its title says why.
 *
 * The lists, and where they come from: `devSpecNames.ts`. CHANGELOG.md is
 * history and names the old spellings on purpose, so it is not read.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import {
  DEV_SPEC_COMMANDS,
  DEV_SPEC_FIXTURE_VERSION,
  DEV_SPEC_HIDDEN_ALIASES,
  DEV_SPEC_RETIRED_COMMANDS,
  DEV_SPEC_TOOLS,
} from './devSpecNames.js';
import { REPO_ROOT } from './pluginDocs.js';

afterAll(cleanupTempDirs);

// ------------------------------------------------------------------ prose

/** What dev-guardian ships as text a model or a user reads: files, or directories walked whole. */
const PROSE_ROOTS = [
  'skills',
  'commands',
  'evals',
  'docs',
  'host-rules',
  'hooks',
  'cli',
  'mcp/src',
  'mcp/README.md',
  '.cursor/rules',
  '.windsurf/rules',
  '.github/copilot-instructions.md',
  'README.md',
  'README.pt-PT.md',
  'README.es.md',
  'AGENTS.md',
  'GEMINI.md',
  'CLAUDE.md',
  'CONTRIBUTING.md',
  'SECURITY.md',
];

/** Text files, plus extensionless templates (`host-rules/clinerules`). */
const TEXT_FILE = /\.(?:md|mdc|ts|mjs|js|json)$|^[^.]+$/;

/**
 * dev-guardian's own `spec_*` identifiers: `map_attack_surface`'s OpenAPI
 * input and result fields and the snapshot they are stored in — not
 * dev-spec-driven tools. A name added here is one this test can no longer
 * tell from a dev-spec-driven tool, so each must still be in `mcp/src`.
 */
const OWN_NAMES = new Set([
  'spec_diff',
  'spec_diff_summary',
  'spec_files',
  'spec_only',
  'spec_only_withheld',
  'spec_paths',
  'spec_route',
  'spec_routes_excluded',
  'spec_routes_total',
  'spec_sample',
]);

const TOOL_NAME = /(?<![A-Za-z0-9_])((?:spec|ears|steering|trace)_[a-z0-9_]+)/g;

/** `/spec…`, or a retired command, as a word of its own — never `/guardian-grill`, `docs/spec-x` or `.specs/`. */
const COMMAND_NAME = new RegExp(
  `(?<![\\w/.~:-])/(spec[\\w-]*|${Object.keys(DEV_SPEC_RETIRED_COMMANDS).join('|')})(?![\\w-])`,
  'g',
);

interface Prose {
  rel: string;
  text: string;
}

function walk(abs: string, out: string[]): void {
  if (!existsSync(abs)) return;
  if (statSync(abs).isDirectory()) {
    for (const entry of readdirSync(abs)) if (entry !== 'node_modules') walk(join(abs, entry), out);
  } else if (TEXT_FILE.test(abs.split(sep).pop() ?? '')) {
    out.push(abs);
  }
}

function proseFiles(): Prose[] {
  const files: string[] = [];
  for (const root of PROSE_ROOTS) walk(resolve(REPO_ROOT, root), files);
  return files.map((abs) => ({ rel: relative(REPO_ROOT, abs).split(sep).join('/'), text: readFileSync(abs, 'utf8') }));
}

const toolNames = (text: string): string[] => [...text.matchAll(TOOL_NAME)].map((m) => m[1] ?? '');
const commandNames = (text: string): string[] => [...text.matchAll(COMMAND_NAME)].map((m) => m[1] ?? '');

const TOOLS = new Set(DEV_SPEC_TOOLS);
const COMMANDS = new Set(DEV_SPEC_COMMANDS);

function badTool(name: string): string | null {
  if (TOOLS.has(name) || OWN_NAMES.has(name)) return null;
  const instead = DEV_SPEC_HIDDEN_ALIASES[name];
  return instead !== undefined
    ? `${name} — a hidden alias since dev-spec-driven 1.26, not in tools/list: cite ${instead}`
    : `${name} — not a dev-spec-driven tool (devSpecNames.ts lists them)`;
}

function badCommand(name: string): string | null {
  if (COMMANDS.has(name)) return null;
  const instead = DEV_SPEC_RETIRED_COMMANDS[name];
  return instead !== undefined
    ? `/${name} — retired in dev-spec-driven 1.26: cite ${instead}`
    : `/${name} — not a dev-spec-driven command (devSpecNames.ts lists them)`;
}

describe('the matchers', () => {
  it('find dev-spec-driven names and leave dev-guardian names alone', () => {
    const text = [
      'call `spec_backlog` then spec_roadmap_edit { kind: "backlog" }, then ears_validate and trace_check;',
      'run /grill, /prReview or /spec-ff, then /spec-finish and (/spec <feature>).',
      'not these: has_spec_files, specPaths, /guardian-grill, docs/spec-x.md, .specs/feature, https://x.io/spec-y',
    ].join('\n');
    expect(toolNames(text)).toEqual(['spec_backlog', 'spec_roadmap_edit', 'ears_validate', 'trace_check']);
    expect(commandNames(text)).toEqual(['grill', 'prReview', 'spec-ff', 'spec-finish', 'spec']);
    expect(badTool('spec_backlog')).toMatch(/hidden alias.*spec_roadmap_edit/);
    expect(badCommand('grill')).toMatch(/retired.*\/clarify --grill/);
    expect(badCommand('spec-ff')).toMatch(/not a dev-spec-driven command/);
  });
});

describe("dev-guardian's prose cites only current dev-spec-driven names", () => {
  const prose = proseFiles();

  it('reads the prose it says it does, and finds the citations in it', () => {
    expect(prose.length).toBeGreaterThan(100);
    const rels = new Set(prose.map((p) => p.rel));
    for (const rel of ['skills/guardian-improve/SKILL.md', 'host-rules/clinerules', 'docs/tools.md', 'mcp/src/server.ts']) {
      expect(rels.has(rel), rel).toBe(true);
    }
    // A positive control: the handoff skill cites dev-spec-driven, so a matcher
    // that finds nothing fails here instead of passing every file below.
    const improve = prose.find((p) => p.rel === 'skills/guardian-improve/SKILL.md')?.text ?? '';
    expect(toolNames(improve)).toContain('spec_roadmap_edit');
    expect(commandNames(improve)).toContain('spec');
  });

  it('every dev-spec-driven tool it names is listed', () => {
    const problems = prose.flatMap(({ rel, text }) =>
      [...new Set(toolNames(text))].flatMap((n) => {
        const why = badTool(n);
        return why === null ? [] : [`${rel}: ${why}`];
      }),
    );
    expect(problems).toEqual([]);
  });

  it('every dev-spec-driven command it names exists', () => {
    const problems = prose.flatMap(({ rel, text }) =>
      [...new Set(commandNames(text))].flatMap((n) => {
        const why = badCommand(n);
        return why === null ? [] : [`${rel}: ${why}`];
      }),
    );
    expect(problems).toEqual([]);
  });

  it("dev-guardian's own spec_* names are still its own, and none is a dev-spec-driven tool", () => {
    const src: string[] = [];
    walk(resolve(REPO_ROOT, 'mcp', 'src'), src);
    const used = new Set(src.flatMap((f) => toolNames(readFileSync(f, 'utf8'))));
    expect([...OWN_NAMES].filter((n) => !used.has(n))).toEqual([]);
    expect([...OWN_NAMES].filter((n) => TOOLS.has(n))).toEqual([]);
  });

  it('the fixture lists no name twice, and no retired name as current', () => {
    expect(DEV_SPEC_TOOLS.length).toBe(TOOLS.size);
    expect(DEV_SPEC_COMMANDS.length).toBe(COMMANDS.size);
    expect(Object.keys(DEV_SPEC_HIDDEN_ALIASES).filter((n) => TOOLS.has(n))).toEqual([]);
    expect(Object.keys(DEV_SPEC_RETIRED_COMMANDS).filter((n) => COMMANDS.has(n))).toEqual([]);
  });
});

// ------------------------------------------------- a live dev-spec-driven

interface LiveDevSpec {
  root: string;
  version: string;
  where: string;
}

function versionKey(v: string): number[] {
  return v.split(/[.+-]/).slice(0, 3).map((p) => Number.parseInt(p, 10) || 0);
}

function compareVersions(a: string, b: string): number {
  const [x, y] = [versionKey(a), versionKey(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return 0;
}

function pluginVersion(root: string, fallback: string): string {
  try {
    const manifest = JSON.parse(readFileSync(join(root, '.claude-plugin', 'plugin.json'), 'utf8')) as { version?: unknown };
    return typeof manifest.version === 'string' ? manifest.version : fallback;
  } catch {
    return fallback;
  }
}

function listDirs(abs: string): string[] {
  try {
    return readdirSync(abs, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
  } catch {
    return [];
  }
}

/** The sibling checkout, then the newest install, of the fixture's version or newer; null and why when there is none. */
function findLiveDevSpec(): { live: LiveDevSpec | null; reason: string } {
  const found: LiveDevSpec[] = [];
  const sibling = resolve(REPO_ROOT, '..', 'dev-spec-driven');
  if (existsSync(join(sibling, 'mcp', 'server.js'))) {
    found.push({ root: sibling, version: pluginVersion(sibling, '0.0.0'), where: 'the sibling checkout' });
  }
  const configDirs = [process.env['CLAUDE_CONFIG_DIR'], join(homedir(), '.claude')].filter(
    (d): d is string => d !== undefined && d !== '',
  );
  for (const configDir of [...new Set(configDirs)]) {
    const cache = join(configDir, 'plugins', 'cache');
    for (const marketplace of listDirs(cache)) {
      const plugin = join(cache, marketplace, 'dev-spec-driven');
      for (const version of listDirs(plugin)) {
        const root = join(plugin, version);
        if (existsSync(join(root, 'mcp', 'server.js'))) {
          found.push({ root, version: pluginVersion(root, version), where: `the install in ${cache}` });
        }
      }
    }
  }
  const usable = found.filter((f) => compareVersions(f.version, DEV_SPEC_FIXTURE_VERSION) >= 0);
  const pick =
    usable.find((f) => f.where === 'the sibling checkout') ??
    usable.sort((a, b) => compareVersions(b.version, a.version))[0];
  if (pick !== undefined) return { live: pick, reason: '' };
  const newest = found.sort((a, b) => compareVersions(b.version, a.version))[0];
  return {
    live: null,
    reason:
      newest === undefined
        ? 'no dev-spec-driven checkout (../dev-spec-driven) or install (<claude config>/plugins/cache) on this machine'
        : `the newest dev-spec-driven here, ${newest.version} (${newest.where}), is older than the fixture's ${DEV_SPEC_FIXTURE_VERSION}`,
  };
}

/** `tools/list` from a real handshake, in Claude Code plugin mode, in an empty project. */
function listedTools(live: LiveDevSpec): string[] {
  const project = makeTempDir('dg-devspec-');
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.startsWith('SPEC_') && !k.startsWith('DEV_SPEC_') && k !== 'CLAUDE_PROJECT_DIR') env[k] = v;
  }
  Object.assign(env, { SPEC_MCP_APPROVAL_HOOK: 'on', SPEC_MCP_PROMPTS: 'off', SPEC_PROJECT_DIR: project });
  const requests = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'dev-guardian-contract-test', version: '0' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ];
  const r = spawnSync(process.execPath, [join(live.root, 'mcp', 'server.js')], {
    cwd: project,
    env,
    input: requests.map((m) => JSON.stringify(m)).join('\n') + '\n',
    encoding: 'utf8',
    timeout: 30_000,
  });
  const reply = r.stdout
    .split(/\r?\n/)
    .filter((l) => l.trim().startsWith('{'))
    .map((l) => JSON.parse(l) as { id?: number; result?: { tools?: { name: string }[]; nextCursor?: string } })
    .find((m) => m.id === 2);
  if (reply?.result?.tools === undefined) {
    throw new Error(`no tools/list reply from ${live.root} (exit ${String(r.status)}): ${r.stderr.slice(0, 500)}`);
  }
  if (reply.result.nextCursor !== undefined) throw new Error('tools/list is paginated now: read the next pages too');
  return reply.result.tools.map((t) => t.name);
}

const { live, reason } = findLiveDevSpec();
const SOURCE = live === null ? `skipped: ${reason}` : `${live.version}, ${live.where}`;

describe(`the fixture against a live dev-spec-driven (${SOURCE})`, () => {
  it.skipIf(live === null)('every tool the fixture allows is in its tools/list in Claude Code plugin mode', { timeout: 40_000 }, () => {
    if (live === null) return;
    const listed = new Set(listedTools(live));
    expect(listed.size).toBeGreaterThan(10);
    expect(DEV_SPEC_TOOLS.filter((n) => !listed.has(n))).toEqual([]);
    expect(Object.keys(DEV_SPEC_HIDDEN_ALIASES).filter((n) => listed.has(n))).toEqual([]);
  });

  it.skipIf(live === null)('every command the fixture allows is one of its command files', () => {
    if (live === null) return;
    const files = new Set(
      readdirSync(join(live.root, 'commands'))
        .filter((f) => f.endsWith('.md'))
        .map((f) => f.slice(0, -'.md'.length)),
    );
    expect(DEV_SPEC_COMMANDS.filter((n) => !files.has(n))).toEqual([]);
    expect(Object.keys(DEV_SPEC_RETIRED_COMMANDS).filter((n) => files.has(n))).toEqual([]);
  });
});
