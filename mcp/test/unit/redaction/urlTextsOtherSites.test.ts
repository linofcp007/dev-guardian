/**
 * deps-tools-host-other-texts, task 2, T-08 (red until the fix, but the (guard) row): what the `.mcp.json` and OpenAPI
 * sites say of a URL that holds a credential: the plain-HTTP finding of `audit_agent_config` (message and snippet), the
 * reason `remoteReasonOf` gives `audit_mcp_tools`, the `PATH` entries `resolveCommand` names when it cannot find a
 * command, and the base path `importSpec` takes from `servers[0].url`.
 *
 * The (guard) row is green before and after: for every form of the measurement, of EC-10 and of EC-11, in `url`, in an
 * argument and in `env`, the reason of `remoteReasonOf` is the one recorded before the fix
 * (`test/fixtures/urlTexts/reference-aadf4b40.json`), or that one with the label `scheme://host[:port]` changed to
 * `scheme://(host not shown)` or `(unparseable URL)`, or that one without the quotation of an unreadable URL
 * (US-1.AC-8): never a text of the entry that is not written today.
 *
 * Every credential-looking value is MADE UP and built from parts; the reference holds marks, put back by parts.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { McpServerEntry } from '../../../src/agentaudit/mcpServers.js';
import { checkPlainHttpRemotes } from '../../../src/agentaudit/rules.js';
import { remoteReasonOf, resolveCommand } from '../../../src/mcpaudit/launch.js';
import { importSpec } from '../../../src/surface/specImport.js';

const FEATURE = 'deps-tools-host-other-texts';
const WIN = process.platform === 'win32';
const T = ['tok', 'ZzQ', '7731'].join('');
const K = ['ken', 'Qq', '88'].join('');
const U = ['dg', 'user', 'zq'].join('');
const W = ['pw', 'ZzQ', '55'].join('');
const P = ['dgprobe', 'zzq7731', 'p'].join('-');
const H = 'host.example';
const DIGITS = ['44', '55'].join('');
const BS = String.fromCharCode(92);
const TAB = String.fromCharCode(9);

const partsIn = (text: string): string[] => [T, K, U, W].filter((p) => text.toLowerCase().includes(p.toLowerCase()));

const server = (name: string, rest: Partial<McpServerEntry>): McpServerEntry => ({ sourceLabel: '.mcp.json', name, raw: {}, ...rest });

// ── the forms ────────────────────────────────────────────────────────────────────────────────────────────────────
/** What stands between the scheme and the host, by the label the reference uses. */
const CREDS: Array<{ id: string; cred: string }> = [
  { id: 'T/K@', cred: `${T}/${K}@` },
  { id: 'T?K@', cred: `${T}?${K}@` },
  { id: 'T#K@', cred: `${T}#${K}@` },
  { id: `T${BS}K@`, cred: `${T}${BS}${K}@` },
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
const cred = (id: string): string => CREDS.find((c) => c.id === id)?.cred ?? '';
/** The forms a parser reads without `//` (EC-10). */
const noSlashes = (scheme: string, path: string): Array<{ id: string; text: string }> => [
  { id: 'https:U:T@H', text: `${scheme}:${U}:${T}@${H}${path}` },
  { id: 'https:/U:T@H', text: `${scheme}:/${U}:${T}@${H}${path}` },
  { id: `http:${BS}U:T@H`, text: `${scheme}:${BS}${U}:${T}@${H}${path}` },
  { id: ' https://U:T@H', text: ` ${scheme}://${U}:${T}@${H}${path}` },
  { id: 'ht<TAB>tps://U:T@H', text: `${scheme.slice(0, 2)}${TAB}${scheme.slice(2)}://${U}:${T}@${H}${path}` },
];
/** The scp forms and the one that is not (EC-11). */
const SCP = [
  { id: 'git@H:o/r.git', text: `git@${H}:o/r.git` },
  { id: 'T@H:o/r.git', text: `${T}@${H}:o/r.git` },
  { id: 'U:T@H:path', text: `${U}:${T}@${H}:path` },
];

// ── the plain-HTTP finding of audit_agent_config ─────────────────────────────────────────────────────────────────
const MALFORMED_HTTP = ['T/K@', 'T?K@', 'T#K@', `T${BS}K@`, 'U:4455/K@', 'T/@', 'T;K@', 'T ;K@'];
const WELL_FORMED_HTTP: Array<{ id: string; url: string }> = [
  { id: 'http://T@H/mcp', url: `http://${cred('T@')}${H}/mcp` },
  { id: 'http://U:T@H/mcp', url: `http://${cred('U:T@')}${H}/mcp` },
  ...noSlashes('http', '/mcp').map((f) => ({ id: f.id, url: f.text })),
];

describe(`${FEATURE} T-08 the plain-HTTP finding says the URL without credentials`, () => {
  it.each(MALFORMED_HTTP.map((id) => ({ id, url: `http://${cred(id)}${H}/mcp` })))('T-08 checkPlainHttpRemotes, $id: message and snippet hold no part, the snippet names the server', ({ url }) => {
    const found = checkPlainHttpRemotes([server('a', { url })]);
    expect(found).toHaveLength(1);
    const said = JSON.stringify([found[0]?.message, found[0]?.snippet]);
    expect(partsIn(said), said).toEqual([]);
    expect(found[0]?.snippet).toMatch(/ \(server 'a'\)$/);
  });

  it.each(WELL_FORMED_HTTP)('T-08 checkPlainHttpRemotes, $id: the snippet is the URL without its user part and the server name', ({ url }) => {
    const found = checkPlainHttpRemotes([server('dgsrv', { url })]);
    expect(found).toHaveLength(1);
    const said = JSON.stringify([found[0]?.message, found[0]?.snippet]);
    expect(partsIn(said), said).toEqual([]);
    expect(found[0]?.snippet).toBe(`http://${H}/mcp (server 'dgsrv')`);
  });
});

// ── remoteReasonOf ───────────────────────────────────────────────────────────────────────────────────────────────
const reasonFromUrl = (url: string): string | null => remoteReasonOf(server('s', { url }));
const reasonFromArg = (arg: string): string | null => remoteReasonOf(server('s', { command: 'node', args: ['--endpoint', arg] }));
const reasonFromEnv = (value: string): string | null => remoteReasonOf(server('s', { command: 'node', args: ['server.js'], env: { HTTPS_PROXY: value } }));

const REASON_URL_IDS = ['T/K@', 'T?K@', 'T#K@', `T${BS}K@`, 'U:4455/K@', 'T/@'];
const REASON_OTHER_IDS = [...REASON_URL_IDS, 'U:W/K@', 'T #K@', 'T ;K@'];

describe(`${FEATURE} T-08 remoteReasonOf says the URL without credentials, without a port, and quotes none it cannot read`, () => {
  const expectClean = (reason: string | null): void => {
    expect(reason, 'a reason').not.toBeNull();
    expect(partsIn(reason ?? ''), reason ?? '').toEqual([]);
    expect(reason ?? '', 'no port').not.toContain(`:${DIGITS}`);
    expect(reason ?? '', 'no quotation of a URL it cannot read').not.toContain('("');
  };
  it.each(REASON_URL_IDS)('T-08 remoteReasonOf, url https://%s…H/mcp', (id) => {
    expectClean(reasonFromUrl(`https://${cred(id)}${H}/mcp`));
  });
  it.each(REASON_OTHER_IDS)('T-08 remoteReasonOf, argument --endpoint https://%s…H/mcp', (id) => {
    expectClean(reasonFromArg(`https://${cred(id)}${H}/mcp`));
  });
  it.each(REASON_OTHER_IDS)('T-08 remoteReasonOf, env HTTPS_PROXY=https://%s…H/mcp', (id) => {
    expectClean(reasonFromEnv(`https://${cred(id)}${H}/mcp`));
  });
});

// ── resolveCommand (Windows only: elsewhere it does not search the PATH) ─────────────────────────────────────────
describe(`${FEATURE} T-08 resolveCommand names the network PATH entries it skipped`, () => {
  it.skipIf(!WIN)('T-08 resolveCommand, a PATH entry on a network path with credentials: the host is not shown (EC-14)', async () => {
    const entry = `${BS}${BS}${T}${BS}${K}@${H}${BS}share`;
    const r = await resolveCommand('dg-nonexistent-probe-zq', { PATH: entry }, process.cwd(), Date.now() + 10_000);
    expect(r.ok).toBe(false);
    const reason = r.ok ? '' : r.reason;
    expect(partsIn(reason), reason).toEqual([]);
    expect(reason).toContain(`${BS}${BS}(host not shown)`);
  });
});

// ── importSpec ───────────────────────────────────────────────────────────────────────────────────────────────────
const spec = (serverUrl: string): string =>
  `${JSON.stringify({ openapi: '3.0.0', info: { title: 't', version: '1' }, servers: [{ url: serverUrl }], paths: { '/items': { get: { responses: { 200: { description: 'ok' } } } } } })}\n`;

describe(`${FEATURE} T-08 importSpec takes no base path from a server URL with a credential`, () => {
  it.each([
    { id: 'https://T/K@H/v1', url: `https://${T}/${K}@${H}/v1` },
    { id: `https://T${BS}K@H/v1`, url: `https://${T}${BS}${K}@${H}/v1` },
    { id: 'https://U:4455/K@H/v1', url: `https://${U}:${DIGITS}/${K}@${H}/v1` },
  ])('T-08 importSpec, servers[0].url $id: every route is path_partial and none carries a piece of the URL', ({ url }) => {
    const { routes } = importSpec('openapi.json', spec(url));
    expect(routes.length).toBeGreaterThan(0);
    const said = JSON.stringify(routes.map((r) => [r.path_resolved, r.path_raw]));
    expect(partsIn(said), said).toEqual([]);
    expect(routes.every((r) => r.path_partial), JSON.stringify(routes.map((r) => r.path_partial))).toBe(true);
  });
});

// ── the (guard) row: the invariant of criterion 8 ────────────────────────────────────────────────────────────────
/** The parts a mark stands for. */
const MARKED: ReadonlyArray<{ mark: string; value: string }> = [
  { mark: 'T', value: T },
  { mark: 'K', value: K },
  { mark: 'U', value: U },
  { mark: 'W', value: W },
  { mark: 'P', value: P },
];
function unmask(text: string): string {
  return text.replace(/<([TKUWP])(?::(lower|upper))?>/g, (_whole, mark: string, form: string | undefined) => {
    const value = MARKED.find((m) => m.mark === mark)?.value ?? '';
    return form === 'lower' ? value.toLowerCase() : form === 'upper' ? value.toUpperCase() : value;
  });
}
const here = dirname(fileURLToPath(import.meta.url));
const stored = JSON.parse(readFileSync(join(here, '..', '..', 'fixtures', 'urlTexts', 'reference-aadf4b40.json'), 'utf8')) as Record<string, string>;
const reference = new Map(Object.entries(stored).map(([key, text]) => [unmask(key), unmask(text)]));

/** What a reason may be after the fix, given what it was before (US-1.AC-8). */
function allowedReasons(before: string): string[] {
  const out = [before];
  for (const label of before.match(/[a-z][a-z0-9+.-]*:\/\/[^\s)]*/gi) ?? []) {
    const scheme = label.slice(0, label.indexOf('://'));
    out.push(before.replace(label, `${scheme}://(host not shown)`), before.replace(label, '(unparseable URL)'));
  }
  const quote = before.indexOf(' ("');
  if (quote >= 0) out.push(before.slice(0, quote));
  return out;
}

const T08_FORMS: Array<{ id: string; text: string }> = [
  ...CREDS.map((c) => ({ id: `https://${c.id}H/mcp`, text: `https://${c.cred}${H}/mcp` })),
  ...noSlashes('https', '/mcp'),
  ...SCP,
];
const T08_PLACES: Array<{ where: string; reason: (text: string) => string | null }> = [
  { where: 'url', reason: reasonFromUrl },
  { where: 'arg', reason: reasonFromArg },
  { where: 'env', reason: reasonFromEnv },
];

describe(`${FEATURE} T-08 (guard) the reason of remoteReasonOf is today's, or today's with the label changed`, () => {
  for (const place of T08_PLACES) {
    it.each(T08_FORMS)(`T-08 (guard) remoteReasonOf in ${place.where}, $id`, ({ id, text }) => {
      const before = reference.get(`remoteReasonOf.t08 ${place.where} ${id}`);
      expect(before, `the reference holds remoteReasonOf.t08 ${place.where} ${id}`).toBeDefined();
      const now = String(place.reason(text));
      expect(allowedReasons(before ?? ''), now).toContain(now);
    });
  }
});
