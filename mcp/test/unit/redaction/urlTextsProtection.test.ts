/**
 * deps-tools-host-other-texts, task 1: the GUARD tests T-01 and T-02. They are green on the tree before the fix and
 * stay green after it: what the tools say today of a URL or a network path read from a file, for the only forms the
 * fix leaves untouched (a text with no `@`, a loose version, an `npm:` alias, the scp form with the name `git`, a URL
 * whose userinfo is empty), and the decisions the tools take for every form — malformed ones included.
 *
 * T-01 compares each text to the reference outputs recorded ONCE, on the tree before any change in `src/`
 * (`test/fixtures/urlTexts/reference-aadf4b40.json`). The recorder is this file run with
 * `GUARDIAN_RECORD_URL_TEXTS=1`; it refuses to write over a fixture that exists, because a difference later is a
 * regression, never a re-recording. The recording also holds what `remoteReasonOf` says of every form of the
 * measurement, in `url`, in an argument and in `env`: the reference of the T-08 protection line (US-1.AC-8).
 *
 * Nothing runs a package manager, `dotnet`, `git push` or a scanner. Every credential-looking value is MADE UP and
 * built from parts; the fixture holds a mark in their place (`<T>`, `<T:lower>`, `<T:upper>`, `<K>`, `<U>`, `<W>`,
 * `<P>`), put back by parts when the texts are compared.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { McpServerEntry } from '../../../src/agentaudit/mcpServers.js';
import { checkPlainHttpRemotes } from '../../../src/agentaudit/rules.js';
import { checkRequirements } from '../../../src/deps/pipRequirements.js';
import { checkPyproject, checkSetupCfg } from '../../../src/deps/pythonProject.js';
import { classifyRestoreFailure, planDotnetRestore } from '../../../src/deps/dotnetRestore.js';
import { checkNpmSources } from '../../../src/fixpr/repoPackageConfig.js';
import { openPr } from '../../../src/fixpr/pr.js';
import { remoteReasonOf } from '../../../src/mcpaudit/launch.js';
import { importSpec } from '../../../src/surface/specImport.js';
import { projectNpmRegistry } from '../../../src/tools/depsAudit.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const FEATURE = 'deps-tools-host-other-texts';
const WIN = process.platform === 'win32';
const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, '..', '..', 'fixtures', 'urlTexts', 'reference-aadf4b40.json');
const RECORDING = process.env['GUARDIAN_RECORD_URL_TEXTS'] === '1';

// ── the made-up values ───────────────────────────────────────────────────────────────────────────────────────────
const T = ['tok', 'ZzQ', '7731'].join(''); // a token
const K = ['ken', 'Qq', '88'].join(''); // what follows an unencoded separator
const U = ['dg', 'user', 'zq'].join(''); // a user name
const W = ['pw', 'ZzQ', '55'].join(''); // the start of a password
const P = ['dgprobe', 'zzq7731', 'p'].join('-'); // a made-up package name
const H = 'host.example';
const DIGITS = ['44', '55'].join('');

/** The parts a mark stands for, longest first. */
const PARTS: ReadonlyArray<{ mark: string; value: string }> = [
  { mark: 'T', value: T },
  { mark: 'K', value: K },
  { mark: 'U', value: U },
  { mark: 'W', value: W },
  { mark: 'P', value: P },
].sort((a, b) => b.value.length - a.value.length);

const MARK = /<([TKUWP])(?::(lower|upper))?>/g;

/** Each made-up part, found without regard to case, is replaced by a mark that says the part and the form it came in. */
function mask(text: string): string {
  if (/<[TKUWP](?::(?:lower|upper))?>/.test(text)) throw new Error('a text holds a mark already');
  const lower = text.toLowerCase();
  let out = '';
  let i = 0;
  while (i < text.length) {
    const part = PARTS.find((p) => lower.startsWith(p.value.toLowerCase(), i));
    if (part === undefined) {
      out += text.charAt(i);
      i += 1;
      continue;
    }
    const seen = text.slice(i, i + part.value.length);
    const form = seen === part.value ? '' : seen === part.value.toLowerCase() ? ':lower' : seen === part.value.toUpperCase() ? ':upper' : null;
    if (form === null) throw new Error(`a made-up part appears in a form no mark names: ${part.mark}`);
    out += `<${part.mark}${form}>`;
    i += part.value.length;
  }
  return out;
}

/** The marks put back, each assembled by parts in its own form. */
function unmask(text: string): string {
  return text.replace(MARK, (_whole, mark: string, form: string | undefined) => {
    const value = PARTS.find((p) => p.mark === mark)?.value ?? '';
    return form === 'lower' ? value.toLowerCase() : form === 'upper' ? value.toUpperCase() : value;
  });
}

// ── the forms ────────────────────────────────────────────────────────────────────────────────────────────────────
interface Cred {
  id: string;
  /** What stands between the scheme and the host. */
  cred: string;
}
/** The forms of the measurement (tool-texts.scratch.test.ts): the first ten are malformed, the last three are controls. */
const CREDS: readonly Cred[] = [
  { id: 'T/K@', cred: `${T}/${K}@` },
  { id: 'T?K@', cred: `${T}?${K}@` },
  { id: 'T#K@', cred: `${T}#${K}@` },
  { id: 'T\\K@', cred: `${T}\\${K}@` },
  { id: 'U:4455/K@', cred: `${U}:${DIGITS}/${K}@` },
  { id: 'U:W/K@', cred: `${U}:${W}/${K}@` },
  { id: 'T/@', cred: `${T}/@` },
  { id: 'T;K@', cred: `${T};${K}@` },
  { id: 'T #K@', cred: `${T} #${K}@` },
  { id: 'T ;K@', cred: `${T} ;${K}@` },
  { id: 'U:T@', cred: `${U}:${T}@` },
  { id: 'T@', cred: `${T}@` },
  { id: 'none', cred: '' },
];
/** The forms a parser reads without `//` (EC-10): the whole text of a URL, as written. */
const NO_SLASHES = (host: string, path: string, scheme = 'https'): Array<{ id: string; text: string }> => [
  { id: 'https:U:T@H', text: `${scheme}:${U}:${T}@${host}${path}` },
  { id: 'https:/U:T@H', text: `${scheme}:/${U}:${T}@${host}${path}` },
  { id: 'http:\\U:T@H', text: `${scheme}:\\${U}:${T}@${host}${path}` },
  { id: ' https://U:T@H', text: ` ${scheme}://${U}:${T}@${host}${path}` },
  { id: 'ht<TAB>tps://U:T@H', text: `${scheme.slice(0, 2)}${'\t'}${scheme.slice(2)}://${U}:${T}@${host}${path}` },
];
/** The scp forms and the one that is not (EC-11). */
const SCP = [
  { id: 'git@H:o/r.git', text: `git@${H}:o/r.git` },
  { id: 'T@H:o/r.git', text: `${T}@${H}:o/r.git` },
  { id: 'U:T@H:path', text: `${U}:${T}@${H}:path` },
];

/** URLs with no `@`: six schemes, a host with and without a port, a path, a query and a fragment. */
const URLS_NO_AT: string[] = (() => {
  const out: string[] = [];
  for (const scheme of ['https', 'http', 'git+https', 'ssh', 'postgres', 'file']) {
    // `file://host:port/` is not a URL a parser reads: it is said as text, which is not one of the five forms.
    const tails = scheme === 'file' ? [`${H}/`, `${H}/org/r.git?ref=main#frag`] : [`${H}/`, `${H}:8443/`, `${H}/org/r.git?ref=main#frag`];
    for (const tail of tails) out.push(`${scheme}://${tail}`);
  }
  out.push('file:///x', `https://@${H}/`);
  return out;
})();
const HTTP_URLS_NO_AT = URLS_NO_AT.filter((u) => /^https?:\/\/[a-z]/.test(u));
const NET_NO_AT = [`\\\\${H}\\share\\x.tgz`, `//${H}/share/x.tgz`];
/** The `%40` forms: no `@` is written, so the text is said as it is. */
const PERCENT_HOST = `//${T}/${K}%40${H}/x.tgz`;
const PERCENT_URL = `https://${T}/${K}%40${H}/x.tgz`;
const ALIASES = [`npm:${P}@1.2.3`, `npm:@scope/${P}@^1.0.0`];
const VERSIONS = ['1.0.0', '^1.2.3', '>=2 <3', 'latest'];

// ── files ────────────────────────────────────────────────────────────────────────────────────────────────────────
const J = (o: unknown): string => `${JSON.stringify(o, null, 2)}\n`;
function project(files: Record<string, string>): string {
  const dir = makeTempDir('dg-urltexts-');
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}

// ── the sites: each returns the text the tool says ───────────────────────────────────────────────────────────────
const npmrc = (value: string): string => String(projectNpmRegistry(project({ '.npmrc': `registry=${value}\n` })));
const npmSources = (files: Record<string, string>): string => JSON.stringify(checkNpmSources(project(files)));
const npmValue = (value: string): string => npmSources({ 'package.json': J({ name: 'x', dependencies: { [P]: value } }) });
const npmKey = (key: string): string =>
  npmSources({ 'package.json': J({ name: 'x', overrides: { [key]: `//files.${H}/share/x.tgz` } }) });
const yarnLock = (header: string, resolved: string): string =>
  npmSources({ 'yarn.lock': `# yarn lockfile v1\n\n\n${header}:\n  version "1.0.0"\n  resolved "${resolved}"\n` });
const yarnHeader = (header: string): string => npmSources({ 'yarn.lock': `# yarn lockfile v1\n\n\n${header}:\n  version "1.0.0"\n` });
const requirements = (text: string): string => JSON.stringify(checkRequirements(project({ 'requirements.txt': `${text}\n` }), ['requirements.txt']).refusals);
const pyproject = (items: string[]): string => {
  const dir = project({ 'pyproject.toml': `[project]\nname = "x"\nversion = "0"\ndependencies = [\n${items.map((i) => `  ${JSON.stringify(i)},  # a note`).join('\n')}\n]\n` });
  return JSON.stringify(checkPyproject(dir, dir, false));
};
const setupCfg = (lines: string[]): string => {
  const dir = project({ 'setup.cfg': `[options]\ninstall_requires =\n${lines.map((l) => `    ${l}`).join('\n')}\n` });
  return JSON.stringify(checkSetupCfg(dir, dir));
};
function dotnetReference(path: string, kind: 'project' | 'solution'): string {
  const lib = '<Project Sdk="Microsoft.NET.Sdk"></Project>\n';
  const app = (include: string): string => `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="${include}" /></ItemGroup></Project>\n`;
  const sln = (entry: string): string =>
    `Microsoft Visual Studio Solution File, Format Version 12.00\nProject("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Lib", "${entry}", "{11111111-1111-1111-1111-111111111111}"\nEndProject\n`;
  const dir = project(kind === 'project' ? { 'App.csproj': app(path), 'Lib.csproj': lib } : { 'App.sln': sln(path), 'Lib.csproj': lib });
  const plan = planDotnetRestore(dir, join(dir, kind === 'project' ? 'App.csproj' : 'App.sln'));
  return JSON.stringify(plan.blocked ?? null);
}
const restoreError = (source: string): string => JSON.stringify(classifyRestoreFailure('', `error NU1301: Unable to load the service index for source ${source}.`));
const restoreErrorMsBuild = (source: string): string =>
  JSON.stringify(classifyRestoreFailure('', `App.csproj : error NU1301: Unable to load the service index for source ${source}. [App.csproj]`));

const server = (name: string, rest: Partial<McpServerEntry>): McpServerEntry => ({ sourceLabel: '.mcp.json', name, raw: {}, ...rest });
const reasonFromUrl = (url: string): string => String(remoteReasonOf(server('s', { url })));
const reasonFromArg = (arg: string): string => String(remoteReasonOf(server('s', { command: 'node', args: ['--endpoint', arg] })));
const reasonFromEnv = (value: string): string => String(remoteReasonOf(server('s', { command: 'node', args: ['server.js'], env: { HTTPS_PROXY: value } })));
const plainHttp = (url: string, name = 'a'): ReturnType<typeof checkPlainHttpRemotes> => checkPlainHttpRemotes([server(name, { url })]);
/** The finding's text and the fields its fingerprint is made of (tool, rule, file, snippet): the hash itself is not kept. */
const plainHttpText = (url: string): string =>
  JSON.stringify(plainHttp(url).map((f) => ({ rule_id: f.rule_id, severity: f.severity, title: f.title, message: f.message, file_path: f.file_path, snippet: f.snippet })));
const spec = (serverUrl: string): string => {
  const doc = J({ openapi: '3.0.0', servers: [{ url: serverUrl }], paths: { '/items': { get: { responses: { 200: { description: 'ok' } } } }, '/items/{id}': { delete: {} } } });
  return JSON.stringify(importSpec('openapi.json', doc).routes.map((r) => ({ method: r.method, path_raw: r.path_raw, path_resolved: r.path_resolved, path_partial: r.path_partial })));
};

// `fakeRunWithCwd` of test/unit/fixpr/pr.test.ts, trimmed to what the push refusal needs: the script is matched on a
// prefix of the command line (longest first) and every call is written down.
type Scripted = { outcome: string; exitCode: number | null; stdout?: string; stderr?: string };
function fakeRun(script: Record<string, Scripted>): { run: never; calls: string[][] } {
  const calls: string[][] = [];
  const run = (opts: { command: string; args?: string[] }) => {
    const args = opts.args ?? [];
    calls.push([opts.command, ...args]);
    const line = [opts.command, ...args].join(' ');
    const key = Object.keys(script)
      .sort((a, b) => b.length - a.length)
      .find((k) => line.startsWith(k));
    const hit = (key === undefined ? undefined : script[key]) ?? { outcome: 'completed', exitCode: 0 };
    return Promise.resolve({ outcome: hit.outcome, exitCode: hit.exitCode, stdout: hit.stdout ?? '', stderr: hit.stderr ?? '', truncated: false });
  };
  return { run: run as never, calls };
}
const REAL_CHANGES = { outcome: 'completed', exitCode: 0, stdout: ' M file.txt\0' };
/** `origin` is `raw`; the repository's own `url.<base>.insteadOf = <prefix>` turns it into `effective`. */
async function pushRefusal(raw: string, prefix: string, base: string, effective: string): Promise<{ text: string; pushed: boolean }> {
  const { run, calls } = fakeRun({
    'gh pr list': { outcome: 'completed', exitCode: 0, stdout: '[]' },
    'git status': REAL_CHANGES,
    'git remote': { outcome: 'completed', exitCode: 0, stdout: `${effective}\n` },
    'git config': { outcome: 'completed', exitCode: 0, stdout: `local\0remote.origin.url\n${raw}\0local\0url.${base}.insteadof\n${prefix}\0` },
  });
  const r = await openPr({ projectPath: '/p', worktreePath: '/w', branch: 'dev-guardian/fix-npm-abc', title: 'T', body: 'B', scope: { allows: () => true }, run });
  return { text: `${r.status}: ${r.detail ?? ''}`, pushed: calls.some((c) => c[0] === 'git' && c[1] === 'push') };
}
/** A push the repository's own rewrite sends to another host: `<raw>`, as `<prefix>` is replaced by `https://other.example/`. */
const OTHER = 'other.example';
const pushForm = (raw: string): { raw: string; prefix: string; base: string; effective: string } => {
  const scp = /^[^:/\\]+@[^:/\\]+:/.exec(raw);
  const prefix = scp !== null ? scp[0] : `${raw.slice(0, raw.indexOf('://') + 3)}`;
  const base = scp !== null ? `git@${OTHER}:` : `https://${OTHER}/`;
  return { raw, prefix, base, effective: `${base}${raw.slice(prefix.length)}` };
};

// ── T-01: the reference ──────────────────────────────────────────────────────────────────────────────────────────
interface Case {
  /** The site: `<site> <input>` is the key of the reference. */
  site: string;
  input: string;
  /** `t01`: compared by T-01. `t08`: recorded for the T-08 protection line, not compared here. */
  group: 't01' | 't08';
  /** Asked only on Windows (a `\\host\share` path is a file name elsewhere). */
  windows?: true;
  run: () => string | Promise<string>;
}
const CASES: Case[] = [];
const add = (site: string, input: string, run: () => string | Promise<string>, extra: Partial<Case> = {}): void => {
  CASES.push({ site, input, group: 't01', run, ...extra });
};

for (const u of [...URLS_NO_AT, PERCENT_URL, `https://${T}/${K}%40${H}/`, `//${H}/npm/`]) add('projectNpmRegistry', u, () => npmrc(u));

for (const v of [...VERSIONS, ...ALIASES, ...URLS_NO_AT, PERCENT_URL]) add('checkNpmSources value', v, () => npmValue(v));
for (const v of [...NET_NO_AT, PERCENT_HOST, `file://${H}/share/x.tgz`]) add('checkNpmSources value', v, () => npmValue(v));
for (const k of [P, `${P}/sub`, `https://${H}/x.tgz`, `//${H}/x.tgz`, ...ALIASES, `git@${H}:o/r.git`, `https://@${H}/x.tgz`]) add('checkNpmSources key', k, () => npmKey(k));
add('checkNpmSources yarn.lock header', `q@file://${H}/share/q.tgz`, () => yarnHeader(`q@file://${H}/share/q.tgz`));
add('checkNpmSources yarn.lock header', `${P}@npm:other@1.2.3`, () => yarnHeader(`"${P}@npm:other@1.2.3"`));
for (const r of [...NET_NO_AT, PERCENT_HOST, `file://${H}/share/q.tgz`, ...URLS_NO_AT, PERCENT_URL]) add('checkNpmSources yarn.lock resolved', r, () => yarnLock(`${P}@^1.0.0`, r));
for (let i = 0; i < 3; i += 1) {
  const lines = Array.from({ length: i + 1 }, (_, j) => `  resolved "https://${H}/${String(j)}.tgz"\n`).join('');
  const net = `  resolved "\\\\${H}\\share\\q.tgz"\n`;
  add('checkNpmSources yarn.lock lines', `${String(i + 1)} https lines, then a network path`, () => npmSources({ 'yarn.lock': `${lines}${net}` }));
}

const REQ_LINES: Array<{ id: string; line: string }> = [
  ...[...URLS_NO_AT, PERCENT_URL].map((u) => ({ id: `direct ${u}`, line: `${P} @ ${u}` })),
  ...[...HTTP_URLS_NO_AT, PERCENT_URL].flatMap((u) => [
    { id: `--index-url ${u}`, line: `--index-url ${u}` },
    { id: `--extra-index-url ${u}`, line: `--extra-index-url ${u}` },
    { id: `-r ${u}`, line: `-r ${u}` },
  ]),
  ...[...NET_NO_AT, `//${T}/${K}%40${H}/share`].flatMap((n) => [
    { id: `--find-links ${n}`, line: `--find-links ${n}` },
    { id: `network path ${n}`, line: n },
  ]),
  ...VERSIONS.filter((v) => /^\d/.test(v)).map((v) => ({ id: `==${v}`, line: `${P}==${v}` })),
  { id: 'comment without @', line: `${P}==1.0.0  # a note` },
  { id: 'marker', line: `${P}==1.0.0 ; python_version >= "3.8"` },
  { id: 'marker without space', line: `${P}==1.0.0; python_version >= "3.8"` },
  { id: 'marker and comment', line: `${P}==1.0.0; python_version >= "3.8"  # a note` },
  { id: 'compatible', line: `${P}~=1.2` },
];
for (const { id, line } of REQ_LINES) add('checkRequirements', id, () => requirements(line));

const PY_ITEMS = [...URLS_NO_AT.filter((u) => /^(https|git\+https|ssh|file):\/\/[a-z]/.test(u)), PERCENT_URL].map((u) => `${P} @ ${u}`);
for (const item of [...PY_ITEMS, `${P}==1.0.0`, `${P}==1.0.0; python_version >= "3.8"`]) add('checkPyproject', item, () => pyproject([item]));
for (const item of [...PY_ITEMS, `${P}==1.0.0`, `${P}==1.0.0 ; python_version >= "3.8"`]) add('checkSetupCfg', item, () => setupCfg([`${item}  # a note`]));

const DOTNET_PATHS = [`\\\\${H}\\share\\Lib.csproj`, `//${H}/share/Lib.csproj`, `\\\\${T}\\${K}%40${H}\\share\\Lib.csproj`, `//${T}/${K}%40${H}/share/Lib.csproj`];
for (const p of DOTNET_PATHS) {
  add('planDotnetRestore ProjectReference', p, () => dotnetReference(p, 'project'), { windows: true });
  add('planDotnetRestore .sln', p, () => dotnetReference(p, 'solution'), { windows: true });
}

const FEED_SOURCES = [...['https', 'http'].flatMap((scheme) => [`${scheme}://${H}/v3/index.json`, `${scheme}://${H}:8443/v3/index.json`, `${scheme}://${H}/v3/index.json?x=1#frag`]), PERCENT_URL.replace('x.tgz', 'v3/index.json'), `https://@${H}/v3/index.json`, 'file:///feed', `\\\\${H}\\feed`];
for (const s of FEED_SOURCES) {
  add('classifyRestoreFailure', s, () => restoreError(s));
  add('classifyRestoreFailure msbuild line', s, () => restoreErrorMsBuild(s));
}
add('classifyRestoreFailure', `NU1101 ${P}`, () => JSON.stringify(classifyRestoreFailure('', `error NU1101: Unable to find package ${P}. No packages exist with this id in source(s): nuget.org`)));

const REMOTE_URLS = [...new Set([...URLS_NO_AT.filter((u) => u !== 'https://'), PERCENT_URL, `https://${T}/${K}%40${H}/mcp`, `wss://${H}/mcp`])];
for (const u of REMOTE_URLS) add('remoteReasonOf url', u, () => reasonFromUrl(u));
for (const u of [...REMOTE_URLS, ...NET_NO_AT, ...ALIASES, ...VERSIONS, `git@${H}:o/r.git`]) {
  add('remoteReasonOf arg', u, () => reasonFromArg(u));
  add('remoteReasonOf env', u, () => reasonFromEnv(u));
}

for (const u of [...HTTP_URLS_NO_AT.filter((x) => x.startsWith('http')), `http://${T}/${K}%40${H}/mcp`, `http://@${H}/mcp`, `https://${H}/mcp`, `ssh://${H}/mcp`]) add('checkPlainHttpRemotes', u, () => plainHttpText(u));

const SPEC_URLS = [...['https', 'http'].flatMap((scheme) => [`${scheme}://${H}/v1`, `${scheme}://${H}:8443/v1`, `${scheme}://${H}/api/v1?x=1#frag`]), '/v1', `https://@${H}/v1`, `https://${T}/${K}%40${H}/v1`, `https://${H}/v1/`];
for (const u of SPEC_URLS) add('importSpec', u, () => spec(u));

const PUSH_RAWS = [`https://${H}/org/repo.git`, `https://${H}:8443/org/repo.git`, `http://${H}/org/repo.git`, `ssh://${H}/org/repo.git`, `git@${H}:org/repo.git`, `https://${T}/${K}%40${H}/org/repo.git`];
for (const raw of PUSH_RAWS) {
  const f = pushForm(raw);
  add('openPr push refusal', raw, async () => (await pushRefusal(f.raw, f.prefix, f.base, f.effective)).text);
}

// The inputs of the T-08 protection line: every form of the measurement, of EC-10 and of EC-11, in `url`, in an
// argument and in `env` — the malformed ones, which today show a part of the credential.
const T08_FORMS: Array<{ id: string; text: string }> = [
  ...CREDS.map((c) => ({ id: `https://${c.id}H/mcp`, text: `https://${c.cred}${H}/mcp` })),
  ...NO_SLASHES(H, '/mcp').map((f) => ({ id: f.id, text: f.text })),
  ...SCP,
];
const T08_RUNNERS: Array<[string, (text: string) => string]> = [
  ['url', reasonFromUrl],
  ['arg', reasonFromArg],
  ['env', reasonFromEnv],
];
for (const [where, fn] of T08_RUNNERS) {
  for (const f of T08_FORMS) CASES.push({ site: `remoteReasonOf.t08 ${where}`, input: f.id, group: 't08', run: () => fn(f.text) });
}

const keyOf = (c: Case): string => `${c.site} ${c.input}`;
/** Each key is written once: two inputs with the same name would overwrite one another in the reference. */
function assertUniqueKeys(): void {
  const seen = new Set<string>();
  for (const c of CASES) {
    const key = keyOf(c);
    if (seen.has(key)) throw new Error(`two cases have the key ${key}`);
    seen.add(key);
  }
}

const sites = [...new Set(CASES.map((c) => c.site))];
const recorded: Record<string, string> = {};
let reference: Record<string, string> = {};

function loadReference(): void {
  assertUniqueKeys();
  if (RECORDING) {
    if (existsSync(FIXTURE)) throw new Error(`the fixture ${FIXTURE} exists: the reference outputs are recorded once and never again (delete it by hand to record anew in task 1)`);
    return;
  }
  if (!existsSync(FIXTURE)) throw new Error(`the reference outputs are missing (${FIXTURE}): record them once with GUARDIAN_RECORD_URL_TEXTS=1`);
  const stored = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Record<string, string>;
  // The keys, like the texts, hold marks where a made-up part stood.
  reference = Object.fromEntries(Object.entries(stored).map(([key, text]) => [unmask(key), unmask(text)]));
}

afterAll(() => {
  if (!RECORDING || Object.keys(recorded).length === 0) return;
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(recorded).sort()) sorted[key] = recorded[key] ?? '';
  const text = `${JSON.stringify(sorted, null, 2)}\n`;
  const lower = text.toLowerCase();
  for (const part of PARTS) if (lower.includes(part.value.toLowerCase())) throw new Error(`the reference would hold the made-up part ${part.mark}`);
  mkdirSync(dirname(FIXTURE), { recursive: true });
  writeFileSync(FIXTURE, text, { flag: 'wx' });
});

describe(`${FEATURE} T-01 protection: the texts of the five forms, character by character`, () => {
  beforeAll(loadReference);

  for (const site of sites) {
    const cases = CASES.filter((c) => c.site === site);
    const skip = cases.some((c) => c.windows === true) && !WIN;
    it.skipIf(skip)(`T-01 ${site}: ${String(cases.length)} inputs say what the reference says`, async () => {
      for (const c of cases) {
        const text = await c.run();
        if (RECORDING) {
          recorded[mask(keyOf(c))] = mask(text);
        } else if (c.group === 't01') {
          expect(text, mask(keyOf(c))).toBe(reference[keyOf(c)] ?? '<no reference>');
        }
      }
    }, 120_000);
  }

  it('T-01 the reference holds exactly the inputs generated here, the T-08 recording of remoteReasonOf among them', () => {
    if (RECORDING) return;
    expect(Object.keys(reference).sort()).toEqual(CASES.map(keyOf).sort());
    expect(Object.keys(reference).filter((k) => k.startsWith('remoteReasonOf.t08 ')).length).toBe(T08_RUNNERS.length * T08_FORMS.length);
  });

  it('T-01 the reference holds no made-up part, only marks', () => {
    if (RECORDING) return;
    const lower = readFileSync(FIXTURE, 'utf8').toLowerCase();
    for (const part of PARTS) expect(lower.includes(part.value.toLowerCase()), part.mark).toBe(false);
  });
});


// ── T-02: the decisions of today, form by form ───────────────────────────────────────────────────────────────────
// The tests below say what each tool DECIDES (a count, a kind, a code, a rule and its severity), never the host or the
// path it writes: those texts are the business of T-01 (the five forms) and of the regression tests (the rest).
const PAD = 'p'.repeat(2100); // puts the `@` more than 2048 characters after the start of the path
const bareUrl = (cred: Cred): string => `https://${cred.cred}${H}`;

/** The network paths of the measurement (npm: a whole value, a `resolved`, a key's value). */
const NET_FORMS: Array<{ id: string; value: string }> = [
  { id: '//T/K@H', value: `//${T}/${K}@${H}/x.tgz` },
  { id: '\\\\T\\K@H', value: `\\\\${T}\\${K}@${H}\\share\\x.tgz` },
  { id: 'file://T/K@H', value: `file://${T}/${K}@${H}/x.tgz` },
  { id: 'git+file://T/K@H', value: `git+file://${T}/${K}@${H}/r.git` },
  { id: 'file:////T/K@H', value: `file:////${T}/${K}@${H}/share/x.tgz` },
  { id: 'link://T/K@H', value: `link://${T}/${K}@${H}/x` },
  { id: 'portal://T/K@H', value: `portal://${T}/${K}@${H}/x` },
  { id: '//U:4455/K@H', value: `//${U}:${DIGITS}/${K}@${H}/x.tgz` },
  { id: '//T@H', value: `//${T}@${H}/x.tgz` },
  { id: '//T/a,K@H', value: `//${T}/a,${K}@${H}/x.tgz` },
  { id: "//T/a'K@H", value: `//${T}/a'${K}@${H}/x.tgz` },
  { id: '//T/a K@H', value: `//${T}/a ${K}@${H}/x.tgz` },
  { id: '//T/a"K@H', value: `//${T}/a"${K}@${H}/x.tgz` },
  { id: '//T/<2100>/K@H', value: `//${T}/${PAD}/${K}@${H}/x.tgz` },
  { id: '//T/K%40H', value: PERCENT_HOST },
  { id: 'https://T/K@H', value: `https://${T}/${K}@${H}/x.tgz` },
  { id: '//files.H/share', value: `//files.${H}/share/x.tgz` },
  { id: '\\\\files.H\\share', value: `\\\\files.${H}\\share\\x.tgz` },
  { id: 'https://U:T@H', value: `https://${U}:${T}@${H}/x.tgz` },
];
/** Where a requirement line of the measurement holds a URL, whatever its credentials. */
const REQ_SHAPES: Array<{ id: string; line: (cred: string) => string }> = [
  { id: 'direct reference', line: (c) => `${P} @ https://${c}${H}/x.tar.gz` },
  { id: 'VCS requirement', line: (c) => `${P} @ git+https://${c}${H}/r.git` },
  { id: 'bare URL', line: (c) => `https://${c}${H}/x.tar.gz` },
  { id: '--index-url', line: (c) => `--index-url https://${c}${H}/simple` },
  { id: '--extra-index-url', line: (c) => `--extra-index-url https://${c}${H}/simple` },
  { id: '-r URL', line: (c) => `-r https://${c}${H}/more.txt` },
];
const REQ_NETWORK: Array<{ id: string; line: string }> = [
  { id: '--find-links //T/a=K@H', line: `--find-links //${T}/a=${K}@${H}/share` },
  { id: '-r //T/a=K@H', line: `-r //${T}/a=${K}@${H}/more.txt` },
  { id: '--find-links "//T/a K@H"', line: `--find-links "//${T}/a ${K}@${H}/share"` },
  { id: '//T/a;K@H', line: `//${T}/a;${K}@${H}/share` },
];

/** The decision of a site for a form, against what it was on the tree before the fix (`EXPECTED`, below). */
const decide = (table: string, id: string, value: string): void => {
  expect(value, `${table} | ${id}`).toBe(EXPECTED[`${table} | ${id}`]);
};
const kinds = (json: string): string => (JSON.parse(json) as Array<{ kind: string }>).map((r) => r.kind).join('|') || 'none';
const networkCount = (json: string): string => {
  const r = JSON.parse(json) as { network: string[]; unchecked: string[] };
  return `${String(r.network.length)}/${String(r.unchecked.length)}`;
};

const BS = String.fromCharCode(92);
const UNC_FORMS = [
  { id: 'UNC T/K@H', path: `${BS}${BS}${T}${BS}${K}@${H}${BS}share${BS}Lib.csproj` },
  { id: '//T/K@H', path: `//${T}/${K}@${H}/share/Lib.csproj` },
];
const FAR = 'a'.repeat(240);
/** Every URL form of the measurement, of EC-10 and of EC-11, written whole around a path. */
const URL_FORMS = (path: string, scheme = 'https'): Array<{ id: string; text: string }> => [
  ...CREDS.map((c) => ({ id: c.id, text: `${scheme}://${c.cred}${H}${path}` })),
  ...NO_SLASHES(H, path, scheme),
  ...SCP,
];
const YARN_FORMS: Array<{ id: string; text: string }> = [
  { id: 'resolved, quoted', text: `${P}@^1.0.0:\n  version "1.0.0"\n  resolved "//${T}/a,${K}@${H}/x.tgz"\n` },
  { id: 'resolved, unquoted', text: `${P}@^1.0.0:\n  version "1.0.0"\n  resolved //${T}/a,${K}@${H}/x.tgz\n` },
  { id: 'the key of the entry', text: `"${P}@file://${T}/a,${K}@${H}/x.tgz":\n  version "1.0.0"\n` },
  { id: 'resolution of Berry', text: `"${P}@npm:1.0.0":\n  resolution: "${P}@file://${T}/a,${K}@${H}/x.tgz"\n` },
];

describe(`${FEATURE} T-02 protection: the decisions do not change, whatever the form`, () => {
  it('T-02 checkNpmSources lists the same entries', () => {
    for (const f of NET_FORMS) decide('npm value', f.id, networkCount(npmValue(f.value)));
    for (const f of NET_FORMS) decide('npm yarn resolved', f.id, networkCount(yarnLock(`${P}@^1.0.0`, f.value)));
    for (const f of YARN_FORMS) decide('npm yarn.lock', f.id, networkCount(npmSources({ 'yarn.lock': `# yarn lockfile v1\n\n\n${f.text}` })));
    for (const c of CREDS) decide('npm override key', c.id, networkCount(npmKey(`${P}@${bareUrl(c)}/x.tgz`)));
  });

  it('T-02 checkRequirements and the Python readers give the same kinds of refusal', () => {
    for (const shape of REQ_SHAPES) for (const c of CREDS) decide('requirements', `${shape.id} ${c.id}`, kinds(requirements(shape.line(c.cred))));
    for (const r of REQ_NETWORK) decide('requirements', r.id, kinds(requirements(r.line)));
    for (const c of CREDS) decide('pyproject', c.id, kinds(pyproject([`${P} @ https://${c.cred}${H}/x.tar.gz`])));
    for (const c of CREDS) decide('setup.cfg', c.id, kinds(setupCfg([`${P} @ https://${c.cred}${H}/x.tar.gz`])));
  });

  it.skipIf(!WIN)('T-02 planDotnetRestore refuses a network path with network_path_reference', () => {
    for (const f of UNC_FORMS) {
      for (const kind of ['project', 'solution'] as const) {
        const refused = dotnetReference(f.path, kind);
        decide('planDotnetRestore', `${kind} ${f.id}`, (JSON.parse(refused) as { code: string } | null)?.code ?? 'none');
      }
    }
  });

  it('T-02 classifyRestoreFailure gives the same code and kind', () => {
    for (const f of URL_FORMS('/v3/index.json')) decide('classifyRestoreFailure', f.id, (({ code, kind }) => `${code}/${kind}`)(JSON.parse(restoreError(f.text)) as { code: string; kind: string }));
    const far = `https://${T}/${FAR}${K}@${H}/v3/index.json`;
    decide('classifyRestoreFailure', '@ after 240 characters', (({ code, kind }) => `${code}/${kind}`)(JSON.parse(restoreError(far)) as { code: string; kind: string }));
  });

  it('T-02 remoteReasonOf gives a reason for every form given as the url of the remote', () => {
    for (const f of URL_FORMS('/mcp')) decide('remoteReasonOf url', f.id, reasonFromUrl(f.text) === 'null' ? 'null' : 'a reason');
    // given as an argument or in env, a form with no scheme and no `//` is no URL to the gate: null, as today (the scp forms)
    for (const f of URL_FORMS('/mcp')) decide('remoteReasonOf arg', f.id, reasonFromArg(f.text) === 'null' ? 'null' : 'a reason');
    for (const f of URL_FORMS('/mcp')) decide('remoteReasonOf env', f.id, reasonFromEnv(f.text) === 'null' ? 'null' : 'a reason');
  });

  it('T-02 checkPlainHttpRemotes gives agent-audit-http-remote at high where the parser reads an http: URL, and nothing else', () => {
    for (const f of URL_FORMS('/mcp', 'http')) {
      const found = plainHttp(f.text);
      decide('checkPlainHttpRemotes', f.id, found.map((x) => `${x.rule_id}/${x.severity}`).join('|') || 'none');
    }
  });

  it('T-02 two servers with credentials of their own are two findings, two with the same URL are one identity (EC-15)', () => {
    const a = checkPlainHttpRemotes([server('a', { url: `http://${U}1:${T}1@${H}/mcp` })]);
    const b = checkPlainHttpRemotes([server('b', { url: `http://${U}2:${T}2@${H}/mcp` })]);
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
    expect(a[0]?.fingerprint).not.toBe(b[0]?.fingerprint);
    const same = checkPlainHttpRemotes([server('a', { url: `http://${H}/mcp` }), server('b', { url: `http://${H}/mcp` })]);
    expect(same).toHaveLength(2);
    expect(same[0]?.fingerprint).toBe(same[1]?.fingerprint);
  });

  it('T-02 importSpec gives the same routes, in number and method', () => {
    for (const c of CREDS) {
      const routes = JSON.parse(spec(`https://${c.cred}${H}/v1`)) as Array<{ method: string }>;
      decide('importSpec', c.id, `${String(routes.length)}:${routes.map((r) => r.method).join(',')}`);
    }
  });

  it('T-02 openPr refuses with push_failed and never runs git push', async () => {
    const raws = [...CREDS.map((c) => ({ id: c.id, raw: `https://${c.cred}${H}/org/repo.git` })), { id: 'scp, any name', raw: `${T}@${H}:org/repo.git` }];
    for (const { id, raw } of raws) {
      const f = pushForm(raw);
      const r = await pushRefusal(f.raw, f.prefix, f.base, f.effective);
      decide('openPr', id, `${r.text.split(':')[0] ?? ''}|${r.pushed ? 'pushed' : 'not pushed'}`);
    }
  });
});

/** What each tool decided on the tree before the fix, form by form (a run on 2026-11-22, `aadf4b40` in the paths the fix touches). */
const EXPECTED: Record<string, string> = {
  "npm value | //T/K@H": "1/0",
  "npm value | \\\\T\\K@H": "1/0",
  "npm value | file://T/K@H": "1/0",
  "npm value | git+file://T/K@H": "1/0",
  "npm value | file:////T/K@H": "1/0",
  "npm value | link://T/K@H": "1/0",
  "npm value | portal://T/K@H": "1/0",
  "npm value | //U:4455/K@H": "1/0",
  "npm value | //T@H": "1/0",
  "npm value | //T/a,K@H": "1/0",
  "npm value | //T/a'K@H": "1/0",
  "npm value | //T/a K@H": "1/0",
  "npm value | //T/a\"K@H": "1/0",
  "npm value | //T/<2100>/K@H": "1/0",
  "npm value | //T/K%40H": "1/0",
  "npm value | https://T/K@H": "0/0",
  "npm value | //files.H/share": "1/0",
  "npm value | \\\\files.H\\share": "1/0",
  "npm value | https://U:T@H": "0/0",
  "npm yarn resolved | //T/K@H": "1/0",
  "npm yarn resolved | \\\\T\\K@H": "1/0",
  "npm yarn resolved | file://T/K@H": "1/0",
  "npm yarn resolved | git+file://T/K@H": "1/0",
  "npm yarn resolved | file:////T/K@H": "0/0",
  "npm yarn resolved | link://T/K@H": "1/0",
  "npm yarn resolved | portal://T/K@H": "1/0",
  "npm yarn resolved | //U:4455/K@H": "1/0",
  "npm yarn resolved | //T@H": "1/0",
  "npm yarn resolved | //T/a,K@H": "1/0",
  "npm yarn resolved | //T/a'K@H": "1/0",
  "npm yarn resolved | //T/a K@H": "1/0",
  "npm yarn resolved | //T/a\"K@H": "1/0",
  "npm yarn resolved | //T/<2100>/K@H": "1/0",
  "npm yarn resolved | //T/K%40H": "1/0",
  "npm yarn resolved | https://T/K@H": "0/0",
  "npm yarn resolved | //files.H/share": "1/0",
  "npm yarn resolved | \\\\files.H\\share": "1/0",
  "npm yarn resolved | https://U:T@H": "0/0",
  "npm yarn.lock | resolved, quoted": "1/0",
  "npm yarn.lock | resolved, unquoted": "1/0",
  "npm yarn.lock | the key of the entry": "1/0",
  "npm yarn.lock | resolution of Berry": "1/0",
  "npm override key | T/K@": "1/0",
  "npm override key | T?K@": "1/0",
  "npm override key | T#K@": "1/0",
  "npm override key | T\\K@": "1/0",
  "npm override key | U:4455/K@": "1/0",
  "npm override key | U:W/K@": "1/0",
  "npm override key | T/@": "1/0",
  "npm override key | T;K@": "1/0",
  "npm override key | T #K@": "1/0",
  "npm override key | T ;K@": "1/0",
  "npm override key | U:T@": "1/0",
  "npm override key | T@": "1/0",
  "npm override key | none": "1/0",
  "requirements | direct reference T/K@": "direct reference",
  "requirements | direct reference T?K@": "direct reference",
  "requirements | direct reference T#K@": "direct reference",
  "requirements | direct reference T\\K@": "direct reference",
  "requirements | direct reference U:4455/K@": "direct reference",
  "requirements | direct reference U:W/K@": "direct reference",
  "requirements | direct reference T/@": "direct reference",
  "requirements | direct reference T;K@": "direct reference",
  "requirements | direct reference T #K@": "direct reference",
  "requirements | direct reference T ;K@": "direct reference",
  "requirements | direct reference U:T@": "direct reference",
  "requirements | direct reference T@": "direct reference",
  "requirements | direct reference none": "direct reference",
  "requirements | VCS requirement T/K@": "VCS requirement",
  "requirements | VCS requirement T?K@": "VCS requirement",
  "requirements | VCS requirement T#K@": "VCS requirement",
  "requirements | VCS requirement T\\K@": "VCS requirement",
  "requirements | VCS requirement U:4455/K@": "VCS requirement",
  "requirements | VCS requirement U:W/K@": "VCS requirement",
  "requirements | VCS requirement T/@": "VCS requirement",
  "requirements | VCS requirement T;K@": "VCS requirement",
  "requirements | VCS requirement T #K@": "VCS requirement",
  "requirements | VCS requirement T ;K@": "VCS requirement",
  "requirements | VCS requirement U:T@": "VCS requirement",
  "requirements | VCS requirement T@": "VCS requirement",
  "requirements | VCS requirement none": "VCS requirement",
  "requirements | bare URL T/K@": "URL requirement",
  "requirements | bare URL T?K@": "URL requirement",
  "requirements | bare URL T#K@": "URL requirement",
  "requirements | bare URL T\\K@": "URL requirement",
  "requirements | bare URL U:4455/K@": "URL requirement",
  "requirements | bare URL U:W/K@": "URL requirement",
  "requirements | bare URL T/@": "URL requirement",
  "requirements | bare URL T;K@": "URL requirement",
  "requirements | bare URL T #K@": "URL requirement",
  "requirements | bare URL T ;K@": "URL requirement",
  "requirements | bare URL U:T@": "URL requirement",
  "requirements | bare URL T@": "URL requirement",
  "requirements | bare URL none": "URL requirement",
  "requirements | --index-url T/K@": "index option",
  "requirements | --index-url T?K@": "index option",
  "requirements | --index-url T#K@": "index option",
  "requirements | --index-url T\\K@": "quoted or escaped option",
  "requirements | --index-url U:4455/K@": "index option",
  "requirements | --index-url U:W/K@": "index option",
  "requirements | --index-url T/@": "index option",
  "requirements | --index-url T;K@": "index option",
  "requirements | --index-url T #K@": "index option",
  "requirements | --index-url T ;K@": "index option",
  "requirements | --index-url U:T@": "index option",
  "requirements | --index-url T@": "index option",
  "requirements | --index-url none": "index option",
  "requirements | --extra-index-url T/K@": "index option",
  "requirements | --extra-index-url T?K@": "index option",
  "requirements | --extra-index-url T#K@": "index option",
  "requirements | --extra-index-url T\\K@": "quoted or escaped option",
  "requirements | --extra-index-url U:4455/K@": "index option",
  "requirements | --extra-index-url U:W/K@": "index option",
  "requirements | --extra-index-url T/@": "index option",
  "requirements | --extra-index-url T;K@": "index option",
  "requirements | --extra-index-url T #K@": "index option",
  "requirements | --extra-index-url T ;K@": "index option",
  "requirements | --extra-index-url U:T@": "index option",
  "requirements | --extra-index-url T@": "index option",
  "requirements | --extra-index-url none": "index option",
  "requirements | -r URL T/K@": "include of a URL",
  "requirements | -r URL T?K@": "include of a URL",
  "requirements | -r URL T#K@": "include of a URL",
  "requirements | -r URL T\\K@": "quoted or escaped option",
  "requirements | -r URL U:4455/K@": "include of a URL",
  "requirements | -r URL U:W/K@": "include of a URL",
  "requirements | -r URL T/@": "include of a URL",
  "requirements | -r URL T;K@": "include of a URL",
  "requirements | -r URL T #K@": "include of a URL",
  "requirements | -r URL T ;K@": "option",
  "requirements | -r URL U:T@": "include of a URL",
  "requirements | -r URL T@": "include of a URL",
  "requirements | -r URL none": "include of a URL",
  "requirements | --find-links //T/a=K@H": "network path",
  "requirements | -r //T/a=K@H": "network path",
  "requirements | --find-links \"//T/a K@H\"": "network path",
  "requirements | //T/a;K@H": "network path",
  "pyproject | T/K@": "direct reference",
  "pyproject | T?K@": "direct reference",
  "pyproject | T#K@": "direct reference",
  "pyproject | T\\K@": "direct reference",
  "pyproject | U:4455/K@": "direct reference",
  "pyproject | U:W/K@": "direct reference",
  "pyproject | T/@": "direct reference",
  "pyproject | T;K@": "direct reference",
  "pyproject | T #K@": "direct reference",
  "pyproject | T ;K@": "direct reference",
  "pyproject | U:T@": "direct reference",
  "pyproject | T@": "direct reference",
  "pyproject | none": "direct reference",
  "setup.cfg | T/K@": "direct reference",
  "setup.cfg | T?K@": "direct reference",
  "setup.cfg | T#K@": "direct reference",
  "setup.cfg | T\\K@": "direct reference",
  "setup.cfg | U:4455/K@": "direct reference",
  "setup.cfg | U:W/K@": "direct reference",
  "setup.cfg | T/@": "direct reference",
  "setup.cfg | T;K@": "direct reference",
  "setup.cfg | T #K@": "direct reference",
  "setup.cfg | T ;K@": "direct reference",
  "setup.cfg | U:T@": "direct reference",
  "setup.cfg | T@": "direct reference",
  "setup.cfg | none": "direct reference",
  "planDotnetRestore | project UNC T/K@H": "network_path_reference",
  "planDotnetRestore | solution UNC T/K@H": "network_path_reference",
  "planDotnetRestore | project //T/K@H": "network_path_reference",
  "planDotnetRestore | solution //T/K@H": "network_path_reference",
  "classifyRestoreFailure | T/K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T?K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T#K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T\\K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | U:4455/K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | U:W/K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T/@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T;K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T #K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T ;K@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | U:T@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T@": "NU1301/feed_unreachable",
  "classifyRestoreFailure | none": "NU1301/feed_unreachable",
  "classifyRestoreFailure | https:U:T@H": "NU1301/feed_unreachable",
  "classifyRestoreFailure | https:/U:T@H": "NU1301/feed_unreachable",
  "classifyRestoreFailure | http:\\U:T@H": "NU1301/feed_unreachable",
  "classifyRestoreFailure |  https://U:T@H": "NU1301/feed_unreachable",
  "classifyRestoreFailure | ht<TAB>tps://U:T@H": "NU1301/feed_unreachable",
  "classifyRestoreFailure | git@H:o/r.git": "NU1301/feed_unreachable",
  "classifyRestoreFailure | T@H:o/r.git": "NU1301/feed_unreachable",
  "classifyRestoreFailure | U:T@H:path": "NU1301/feed_unreachable",
  "classifyRestoreFailure | @ after 240 characters": "NU1301/feed_unreachable",
  "remoteReasonOf url | T/K@": "a reason",
  "remoteReasonOf url | T?K@": "a reason",
  "remoteReasonOf url | T#K@": "a reason",
  "remoteReasonOf url | T\\K@": "a reason",
  "remoteReasonOf url | U:4455/K@": "a reason",
  "remoteReasonOf url | U:W/K@": "a reason",
  "remoteReasonOf url | T/@": "a reason",
  "remoteReasonOf url | T;K@": "a reason",
  "remoteReasonOf url | T #K@": "a reason",
  "remoteReasonOf url | T ;K@": "a reason",
  "remoteReasonOf url | U:T@": "a reason",
  "remoteReasonOf url | T@": "a reason",
  "remoteReasonOf url | none": "a reason",
  "remoteReasonOf url | https:U:T@H": "a reason",
  "remoteReasonOf url | https:/U:T@H": "a reason",
  "remoteReasonOf url | http:\\U:T@H": "a reason",
  "remoteReasonOf url |  https://U:T@H": "a reason",
  "remoteReasonOf url | ht<TAB>tps://U:T@H": "a reason",
  "remoteReasonOf url | git@H:o/r.git": "a reason",
  "remoteReasonOf url | T@H:o/r.git": "a reason",
  "remoteReasonOf url | U:T@H:path": "a reason",
  "remoteReasonOf arg | T/K@": "a reason",
  "remoteReasonOf arg | T?K@": "a reason",
  "remoteReasonOf arg | T#K@": "a reason",
  "remoteReasonOf arg | T\\K@": "a reason",
  "remoteReasonOf arg | U:4455/K@": "a reason",
  "remoteReasonOf arg | U:W/K@": "a reason",
  "remoteReasonOf arg | T/@": "a reason",
  "remoteReasonOf arg | T;K@": "a reason",
  "remoteReasonOf arg | T #K@": "a reason",
  "remoteReasonOf arg | T ;K@": "a reason",
  "remoteReasonOf arg | U:T@": "a reason",
  "remoteReasonOf arg | T@": "a reason",
  "remoteReasonOf arg | none": "a reason",
  "remoteReasonOf arg | https:U:T@H": "a reason",
  "remoteReasonOf arg | https:/U:T@H": "a reason",
  "remoteReasonOf arg | http:\\U:T@H": "a reason",
  "remoteReasonOf arg |  https://U:T@H": "a reason",
  "remoteReasonOf arg | ht<TAB>tps://U:T@H": "a reason",
  "remoteReasonOf arg | git@H:o/r.git": "null",
  "remoteReasonOf arg | T@H:o/r.git": "null",
  "remoteReasonOf arg | U:T@H:path": "null",
  "remoteReasonOf env | T/K@": "a reason",
  "remoteReasonOf env | T?K@": "a reason",
  "remoteReasonOf env | T#K@": "a reason",
  "remoteReasonOf env | T\\K@": "a reason",
  "remoteReasonOf env | U:4455/K@": "a reason",
  "remoteReasonOf env | U:W/K@": "a reason",
  "remoteReasonOf env | T/@": "a reason",
  "remoteReasonOf env | T;K@": "a reason",
  "remoteReasonOf env | T #K@": "a reason",
  "remoteReasonOf env | T ;K@": "a reason",
  "remoteReasonOf env | U:T@": "a reason",
  "remoteReasonOf env | T@": "a reason",
  "remoteReasonOf env | none": "a reason",
  "remoteReasonOf env | https:U:T@H": "a reason",
  "remoteReasonOf env | https:/U:T@H": "a reason",
  "remoteReasonOf env | http:\\U:T@H": "a reason",
  "remoteReasonOf env |  https://U:T@H": "a reason",
  "remoteReasonOf env | ht<TAB>tps://U:T@H": "a reason",
  "remoteReasonOf env | git@H:o/r.git": "null",
  "remoteReasonOf env | T@H:o/r.git": "null",
  "remoteReasonOf env | U:T@H:path": "null",
  "checkPlainHttpRemotes | T/K@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | T?K@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | T#K@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | T\\K@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | U:4455/K@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | U:W/K@": "none",
  "checkPlainHttpRemotes | T/@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | T;K@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | T #K@": "none",
  "checkPlainHttpRemotes | T ;K@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | U:T@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | T@": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | none": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | https:U:T@H": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | https:/U:T@H": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | http:\\U:T@H": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes |  https://U:T@H": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | ht<TAB>tps://U:T@H": "agent-audit-http-remote/high",
  "checkPlainHttpRemotes | git@H:o/r.git": "none",
  "checkPlainHttpRemotes | T@H:o/r.git": "none",
  "checkPlainHttpRemotes | U:T@H:path": "none",
  "importSpec | T/K@": "2:GET,DELETE",
  "importSpec | T?K@": "2:GET,DELETE",
  "importSpec | T#K@": "2:GET,DELETE",
  "importSpec | T\\K@": "2:GET,DELETE",
  "importSpec | U:4455/K@": "2:GET,DELETE",
  "importSpec | U:W/K@": "2:GET,DELETE",
  "importSpec | T/@": "2:GET,DELETE",
  "importSpec | T;K@": "2:GET,DELETE",
  "importSpec | T #K@": "2:GET,DELETE",
  "importSpec | T ;K@": "2:GET,DELETE",
  "importSpec | U:T@": "2:GET,DELETE",
  "importSpec | T@": "2:GET,DELETE",
  "importSpec | none": "2:GET,DELETE",
  "openPr | T/K@": "push_failed|not pushed",
  "openPr | T?K@": "push_failed|not pushed",
  "openPr | T#K@": "push_failed|not pushed",
  "openPr | T\\K@": "push_failed|not pushed",
  "openPr | U:4455/K@": "push_failed|not pushed",
  "openPr | U:W/K@": "push_failed|not pushed",
  "openPr | T/@": "push_failed|not pushed",
  "openPr | T;K@": "push_failed|not pushed",
  "openPr | T #K@": "push_failed|not pushed",
  "openPr | T ;K@": "push_failed|not pushed",
  "openPr | U:T@": "push_failed|not pushed",
  "openPr | T@": "push_failed|not pushed",
  "openPr | none": "push_failed|not pushed",
  "openPr | scp, any name": "push_failed|not pushed",
};
