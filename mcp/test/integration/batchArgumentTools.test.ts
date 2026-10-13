/**
 * The tools' half of the "BatBadBut" fix (review 10, finding 3): on Windows
 * WP-CLI, WPScan and Lighthouse are batch files (`wp.bat`, `wpscan.bat`,
 * `lighthouse.cmd`), and a `"` before an `&` in a slug, a URL, an install
 * path or the site's own `home` option ran a second command through
 * `cmd.exe`. Each tool now takes only what its value can be
 * (`platform/toolArgs.ts`): a slug as a slug, a URL parsed and re-serialised
 * (http or https), a path with no `"`; `runners/spawn.ts` refuses what is left
 * for every caller (`test/unit/runners/childProcess.test.ts`).
 *
 * Every payload below puts the `"` BEFORE the `&`. The Windows block runs the
 * reviewer's repro against fake batch files on PATH, with a control proving
 * the fakes are what the tools run.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { execPath } from 'node:process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import '../../src/registerAll.js';
import { httpUrl, pathArgProblem, WP_PLUGIN_SLUG } from '../../src/platform/toolArgs.js';
import { attachAllTools, TOOLS } from '../../src/tools/index.js';
import { freshPlugin, projectDir, type Seeded } from '../helpers/historySeed.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

const WIN = process.platform === 'win32';

let s: Seeded;
let client: Client;

beforeAll(async () => {
  vi.stubEnv('GUARDIAN_CACHE_DIR', makeTempDir('batarg-cache-'));
  vi.stubEnv('WPSCAN_API_TOKEN', '');
  s = freshPlugin();
  const server = new McpServer({ name: 'test', version: '0.0.0' });
  attachAllTools(server, s.plugin);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-client', version: '0.0.0' });
  await client.connect(clientTransport);
});
afterAll(() => {
  vi.unstubAllEnvs();
  cleanupTempDirs();
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

/** A payload whose `"` comes before the `&`: it closes cmd.exe's quotes, and `echo` writes `marker`. */
const payload = (marker: string): string => `x"&echo PWNED>${marker}&"`;

describe('platform/toolArgs — what a program may be handed', () => {
  it('httpUrl: http and https only, re-serialised — a " is %22, a space %20, a line break gone', () => {
    expect(httpUrl('https://site.example')).toBe('https://site.example/');
    expect(httpUrl('http://127.0.0.1:9/?a="&echo PWNED>f&"')).toBe('http://127.0.0.1:9/?a=%22&echo%20PWNED%3Ef&%22');
    expect(httpUrl('https://site.example/a\nb')).toBe('https://site.example/ab');
    for (const bad of ['javascript:alert(1)', 'file:///C:/x', 'ftp://site.example/', 'x"&echo PWNED>f&"', '']) {
      expect(httpUrl(bad), bad).toBeNull();
    }
  });

  it('pathArgProblem: a " or a control character is no path', () => {
    expect(pathArgProblem('p', 'C:/sites/wp')).toBeNull();
    expect(pathArgProblem('p', '/var/www/100% done')).toBeNull();
    expect(pathArgProblem('p', 'C:/nonexistent"&echo PWNED>f&"')).toMatch(/double quote/);
    expect(pathArgProblem('p', 'C:/a\r\necho PWNED')).toMatch(/control character/);
  });

  it('WP_PLUGIN_SLUG: letters, digits, _ and -', () => {
    for (const ok of ['contact-form-7', 'akismet', 'wp_mail', 'My-Plugin']) expect(WP_PLUGIN_SLUG.test(ok), ok).toBe(true);
    for (const bad of ['x"&echo PWNED>f&"', 'a b', 'a/b', '../x', '%PATH%', '']) expect(WP_PLUGIN_SLUG.test(bad), bad).toBe(false);
  });
});

describe('each tool refuses the payload where it enters', () => {
  it('wp_report {kind: "plugin"}: a slug with " & is -32602 through the fold, invalid_input through the alias handler', async () => {
    const folded = await call('wp_report', { kind: 'plugin', slug: payload('f') });
    expect(folded.isError).toBe(true);
    expect(text(folded)).toMatch(/-32602|slug must be a plugin slug/);
    const alias = await call('wp_plugin_check', { slug: payload('f') });
    expect(alias.isError).toBe(true);
    expect(text(alias)).toContain('-32602');
    const plugin = TOOLS.find((t) => t.name === 'wp_plugin_check');
    if (plugin === undefined) throw new Error('wp_plugin_check is not registered');
    const direct = await plugin.handler({ slug: payload('f') }, s.plugin);
    expect(direct.ok).toBe(false);
    if (!direct.ok) expect(direct.error.code).toBe('invalid_input');
  });

  it.each([
    ['wp_vuln_check', {}],
    ['wp_vuln_check', { mode: 'rest' }],
    ['wp_report', { kind: 'plugin', slug: 'akismet' }],
    ['wp_report', { kind: 'setup' }],
    ['perf_check', {}],
  ])('%s %j: a target_url that is not http(s) is -32602', async (name, extra) => {
    for (const url of ['javascript:alert(1)', 'file:///C:/Windows/win.ini']) {
      const r = await call(name, { ...extra, target_url: url });
      expect(r.isError, `${name} ${url}`).toBe(true);
      expect(text(r)).toMatch(/-32602|http:\/\/ or https:\/\//);
    }
  });

  it('wp_vuln_check: an install path with a " is refused before WP-CLI; an api_token with one is -32602', async () => {
    const path = await call('wp_vuln_check', { wp_install_path: `C:/nonexistent${payload('f')}`, api_token: 'x' });
    expect(path.isError).toBe(true);
    expect(text(path)).toMatch(/unsupported_target.*double quote/s);
    const token = await call('wp_vuln_check', { target_url: 'https://site.example/', api_token: 'abc"&echo PWNED>f&"' });
    expect(token.isError).toBe(true);
    expect(text(token)).toContain('-32602');
  });

  it('perf_check: a k6 script path with a " is invalid_input', async () => {
    const r = await call('perf_check', { project_path: projectDir('batarg-perf-'), k6_script_path: `load${payload('f')}.js` });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/invalid_input.*double quote/s);
  });

  it('scan_containers: an image reference with " or % is -32602', async () => {
    for (const image of ['nginx"&echo PWNED>f&"', 'nginx:%PATH%']) {
      const r = await call('scan_containers', { project_path: projectDir('batarg-img-'), image });
      expect(r.isError, image).toBe(true);
      expect(text(r)).toContain('-32602');
    }
  });
});

/**
 * The reviewer's repro (rev10 agent2 t2/t3), against fake batch files on PATH
 * that record their arguments and answer what WP-CLI would.
 */
describe.runIf(WIN)('Windows — through fake wp.bat, wpscan.bat and lighthouse.cmd, no payload runs', () => {
  let dir: string;
  let marker: string;
  let calls: string;
  let homeFile: string;
  let site: string;

  beforeAll(() => {
    dir = makeTempDir('batarg-win-');
    marker = join(dir, 'pwned.txt');
    calls = join(dir, 'calls.jsonl');
    homeFile = join(dir, 'home.txt');
    const bin = join(dir, 'fakebin');
    mkdirSync(bin);
    const rec = join(bin, 'rec.cjs');
    writeFileSync(
      rec,
      [
        "const fs = require('fs');",
        `fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify({ tool: process.env.FAKE_TOOL, argv: process.argv.slice(2) }) + '\\n');`,
        "if (process.env.FAKE_TOOL === 'wp' && process.argv[2] === 'option')",
        `  process.stdout.write(fs.readFileSync(${JSON.stringify(homeFile)}, 'utf8'));`,
        "else if (process.env.FAKE_TOOL === 'wp') process.stdout.write('[]');",
      ].join('\n'),
    );
    const bat = (tool: string): string => `@echo off\r\nset FAKE_TOOL=${tool}\r\n"${execPath}" "${rec}" %*\r\n`;
    writeFileSync(join(bin, 'wp.bat'), bat('wp'));
    writeFileSync(join(bin, 'wpscan.bat'), bat('wpscan'));
    writeFileSync(join(bin, 'lighthouse.cmd'), bat('lighthouse'));
    site = join(dir, 'wpsite');
    mkdirSync(join(site, 'wp-content'), { recursive: true });
    writeFileSync(join(site, 'wp-config.php'), "<?php define('DB_NAME','x');\n");
    vi.stubEnv('PATH', `${bin}${delimiter}${process.env['PATH'] ?? ''}`);
  });

  /** What the fakes recorded, by tool. */
  const ran = (tool: string): string[][] =>
    existsSync(calls)
      ? readFileSync(calls, 'utf8')
          .split('\n')
          .filter((l) => l.trim() !== '')
          .map((l) => JSON.parse(l) as { tool: string; argv: string[] })
          .filter((c) => c.tool === tool)
          .map((c) => c.argv)
      : [];

  it('the control: wp_report {kind: "plugin"} with a real slug runs the fake wp.bat', async () => {
    const r = await call('wp_report', { kind: 'plugin', slug: 'akismet', wp_install_path: site });
    expect(r.isError, text(r)).toBeFalsy();
    expect(ran('wp').some((argv) => argv.includes('--name=akismet')), text(r)).toBe(true);
  });

  it('wp_report {kind: "plugin", slug: x"&…}: refused, WP-CLI never handed it', async () => {
    const before = ran('wp').length;
    const r = await call('wp_report', { kind: 'plugin', slug: payload(marker), wp_install_path: site });
    expect(r.isError).toBe(true);
    expect(ran('wp').length).toBe(before);
    expect(existsSync(marker)).toBe(false);
  });

  it('wp_vuln_check {target_url: …?a="&…}: WPScan is handed the re-serialised URL, which a batch file is not handed at all', async () => {
    const r = await call('wp_vuln_check', { target_url: `http://127.0.0.1:9/?a=${payload(marker)}`, api_token: 'x' });
    expect(r.isError, text(r)).toBeFalsy();
    const tools = r.structuredContent?.['tools_run'] as Array<{ name: string; status: string; reason?: string }>;
    expect(tools[0]?.status).toBe('failed');
    expect(tools[0]?.reason, JSON.stringify(tools)).toMatch(/cmd\.exe.*percent sign/);
    expect(ran('wpscan')).toEqual([]);
    expect(existsSync(marker)).toBe(false);
  });

  it('wp_vuln_check {wp_install_path: …"&…}: refused before WP-CLI', async () => {
    const before = ran('wp').length;
    const r = await call('wp_vuln_check', { wp_install_path: `C:/nonexistent${payload(marker)}`, api_token: 'x' });
    expect(r.isError).toBe(true);
    expect(ran('wp').length).toBe(before);
    expect(existsSync(marker)).toBe(false);
  });

  it("wp_vuln_check on an install whose own home option is the payload: a URL is re-serialised, anything else refused", async () => {
    writeFileSync(homeFile, `http://127.0.0.1:9/?a=${payload(marker)}`);
    const asUrl = await call('wp_vuln_check', { wp_install_path: site, api_token: 'x' });
    expect(asUrl.isError, text(asUrl)).toBeFalsy();
    expect(asUrl.structuredContent?.['url']).toMatch(/%22&echo%20PWNED/);
    writeFileSync(homeFile, payload(marker));
    const notUrl = await call('wp_vuln_check', { wp_install_path: site, api_token: 'x' });
    expect(notUrl.isError).toBe(true);
    expect(text(notUrl)).toMatch(/home option is not an http/);
    expect(ran('wpscan')).toEqual([]);
    expect(existsSync(marker)).toBe(false);
  });

  it('perf_check {target_url: …?a="&…}: Lighthouse is never handed it', async () => {
    const r = await call('perf_check', { project_path: projectDir('batarg-lh-'), target_url: `http://127.0.0.1:9/?a=${payload(marker)}` });
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/lighthouse\.cmd.*cmd\.exe/);
    expect(ran('lighthouse')).toEqual([]);
    expect(existsSync(marker)).toBe(false);
  });
});
