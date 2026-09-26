/**
 * Install-time package vetting through the REAL hook process:
 * `hooks/guardian-hook.mjs` spawned with the JSON payload Claude Code sends,
 * loading the compiled `mcp/dist/pkgvet/*` and the committed
 * `configs/popular-packages/*` exactly as an installed plugin would.
 *
 * The network is replaced in the child by `test/helpers/fetchMockPreload.mjs`
 * (`node --import`), which rejects every URL it has no route for — no case
 * here can reach a real registry. User-level registry configuration is
 * pointed at an empty temp home, and the npm/pip/uv variables `npm test`
 * itself exports are removed, so this machine's own setup cannot leak in.
 *
 * Requires a built `mcp/dist` (`npm run build`).
 */

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, '..', '..', '..');
const HOOK = resolve(REPO_ROOT, 'hooks', 'guardian-hook.mjs');
const PRELOAD = pathToFileURL(resolve(here, '..', 'helpers', 'fetchMockPreload.mjs')).href;
const OSV = 'https://api.osv.dev/v1/querybatch';

interface Route {
  status?: number;
  body?: unknown;
  hang?: boolean;
  accept?: string;
  osv?: Record<string, string[]>;
}

interface HookOut {
  status: number | null;
  output: { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string; additionalContext?: string } } | undefined;
  requests: string[];
  ms: number;
}

let project: string;
let home: string;
let logFile: string;

beforeEach(() => {
  project = mkdtempSync(join(tmpdir(), 'pkgvet-e2e-project-'));
  home = mkdtempSync(join(tmpdir(), 'pkgvet-e2e-home-'));
  logFile = join(home, 'fetch.log');
});
afterEach(() => {
  rmSync(project, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

const LEAKY_ENV = /^(?:npm_config_|NPM_CONFIG_|PIP_|UV_|YARN_|BUN_|NUGET_|COMPOSER|VIRTUAL_ENV$|XDG_CONFIG_DIRS$|GUARDIAN_)/i;

function runHook(command: string, routes: Record<string, Route | Route[]>, opts: { tool?: string; env?: Record<string, string> } = {}): HookOut {
  const base: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !LEAKY_ENV.test(k)) base[k] = v;
  const t0 = Date.now();
  const r = spawnSync(process.execPath, ['--import', PRELOAD, HOOK], {
    cwd: project,
    input: JSON.stringify({
      hook_event_name: 'PreToolUse',
      tool_name: opts.tool ?? 'Bash',
      tool_input: { command },
      cwd: project,
    }),
    encoding: 'utf8',
    timeout: 20_000,
    env: {
      ...base,
      HOME: home,
      USERPROFILE: home,
      APPDATA: home,
      LOCALAPPDATA: home,
      ProgramData: home,
      XDG_CONFIG_HOME: home,
      GUARDIAN_OFFLINE: '0',
      GUARDIAN_TEST_FETCH_ROUTES: JSON.stringify(routes),
      GUARDIAN_TEST_FETCH_LOG: logFile,
      ...opts.env,
    },
  });
  const ms = Date.now() - t0;
  const trimmed = (r.stdout ?? '').trim();
  const output = trimmed === '' ? undefined : (JSON.parse(trimmed) as HookOut['output']);
  const requests = existsSync(logFile) ? readFileSync(logFile, 'utf8').split('\n').filter(Boolean) : [];
  return { status: r.status, output, requests, ms };
}

const npmDoc = (version: string, extra: Record<string, unknown> = {}): Route => ({
  accept: 'install-v1',
  body: { 'dist-tags': { latest: version }, modified: '2020-01-01T00:00:00.000Z', versions: { [version]: extra } },
});

describe('guardian-hook PreToolUse — install-time package vetting (real subprocess)', () => {
  it('DENIES installing a package that does not exist (likely hallucinated)', () => {
    const r = runHook('npm install react-form-autopilot-helperz', {
      'https://registry.npmjs.org/react-form-autopilot-helperz': { status: 404 },
      [OSV]: { osv: {} },
    });
    expect(r.status).toBe(0);
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(r.output?.hookSpecificOutput?.permissionDecisionReason).toMatch(/react-form-autopilot-helperz.*does not exist/);
  });

  it('DENIES the same via the PowerShell tool', () => {
    const r = runHook(
      'npm install react-form-autopilot-helperz',
      { 'https://registry.npmjs.org/react-form-autopilot-helperz': { status: 404 }, [OSV]: { osv: {} } },
      { tool: 'PowerShell' },
    );
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBe('deny');
  });

  it('DENIES a version OSV lists as malicious', () => {
    const r = runHook('pip install evil-lib==1.0.0', {
      'https://pypi.org/pypi/evil-lib/json': {
        body: { info: { version: '1.0.0' }, releases: { '1.0.0': [{ upload_time_iso_8601: '2020-01-01T00:00:00Z' }] } },
      },
      [OSV]: { osv: { 'evil-lib@1.0.0': ['MAL-2026-0001'] } },
    });
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(r.output?.hookSpecificOutput?.permissionDecisionReason).toContain('MAL-2026-0001');
  });

  it('WARNS, without denying, on a typosquat of a popular name (the committed npm list)', () => {
    const r = runHook('npm install lodahs', { 'https://registry.npmjs.org/lodahs': npmDoc('1.0.0'), [OSV]: { osv: {} } });
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/lodahs.*lodash/s);
  });

  it('stays silent for an established, clean package', () => {
    const r = runHook('npm install express', { 'https://registry.npmjs.org/express': npmDoc('4.21.2'), [OSV]: { osv: {} } });
    expect(r.status).toBe(0);
    expect(r.output).toBeUndefined();
    expect(r.requests).toEqual(['https://registry.npmjs.org/express', OSV]);
  });

  it('makes no request at all for a command that installs nothing', () => {
    const r = runHook('npm run build && pip install -r requirements.txt', {});
    expect(r.output).toBeUndefined();
    expect(r.requests).toEqual([]);
  });

  it('GUARDIAN_PKG_VET=0 opts out: no request, no deny', () => {
    const r = runHook('npm install react-form-autopilot-helperz', {}, { env: { GUARDIAN_PKG_VET: '0' } });
    expect(r.output).toBeUndefined();
    expect(r.requests).toEqual([]);
  });

  // Task 23 fix round 1, C1: a project `.guardian/hooks.config.json` with
  // `"enabled": false` switched install vetting off too. A project file may
  // only make the protective hooks stricter; the user-level config may not.
  it('project "enabled": false does not switch off the missing-package deny', () => {
    mkdirSync(join(project, '.guardian'), { recursive: true });
    writeFileSync(join(project, '.guardian', 'hooks.config.json'), JSON.stringify({ enabled: false }));
    const r = runHook('npm install react-form-autopilot-helperz', {
      'https://registry.npmjs.org/react-form-autopilot-helperz': { status: 404 },
      [OSV]: { osv: {} },
    });
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBe('deny');
  });

  it('the user-level "enabled": false still switches vetting off: no request, no deny', () => {
    mkdirSync(join(home, '.config', 'dev-guardian'), { recursive: true });
    writeFileSync(join(home, '.config', 'dev-guardian', 'hooks.json'), JSON.stringify({ enabled: false }));
    const r = runHook('npm install react-form-autopilot-helperz', {});
    expect(r.output).toBeUndefined();
    expect(r.requests).toEqual([]);
  });

  it('a command the catastrophic guard denies is not vetted', () => {
    const r = runHook('rm -rf / && npm install react-form-autopilot-helperz', {});
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(r.output?.hookSpecificOutput?.permissionDecisionReason).toMatch(/catastrophic/);
    expect(r.requests).toEqual([]);
  });

  it('a risky-command warning and a vetting warning are delivered together', () => {
    const r = runHook('sudo npm install -g lodahs', { 'https://registry.npmjs.org/lodahs': npmDoc('1.0.0'), [OSV]: { osv: {} } });
    const ctx = r.output?.hookSpecificOutput?.additionalContext ?? '';
    expect(ctx).toMatch(/risky shell command/);
    expect(ctx).toMatch(/lodash/);
  });

  it('a private registry in the project .npmrc turns a missing name into a warning, not a deny', () => {
    writeFileSync(join(project, '.npmrc'), 'registry=https://npm.acme.local/\n');
    const r = runHook('npm install acme-private-lib', {
      'https://registry.npmjs.org/acme-private-lib': { status: 404 },
      [OSV]: { osv: {} },
    });
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(
      /acme-private-lib.*not found on the public registry — if it is private or local, ignore this/s,
    );
  });

  it('fails open inside the 3 s budget when the registry never answers', () => {
    const r = runHook('npm install express', { 'https://registry.npmjs.org/express': { hang: true }, [OSV]: { hang: true } });
    expect(r.status).toBe(0);
    expect(r.ms).toBeLessThan(6000);
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/could not vet express.*not verified/s);
  }, 20_000);

  it('fix round 1 — a missing name after a `cd` is a warning, never a deny (uncertain parse)', () => {
    const r = runHook('cd packages/web && npm install react-form-autopilot-helperz', {
      'https://registry.npmjs.org/react-form-autopilot-helperz': { status: 404 },
      [OSV]: { osv: {} },
    });
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/not found on the public registry.*directory/s);
  });

  it('fix round 1 — C1: `pip install -qr req.txt` looks nothing up and says nothing', () => {
    const r = runHook('pip install -qr req.txt', {});
    expect(r.output).toBeUndefined();
    expect(r.requests).toEqual([]);
  });

  it('exits 0 with its answer after REAL sockets were used (no process.exit() with live handles)', async () => {
    // Measured on Windows / Node 24: process.exit() after a real fetch aborts
    // the process (libuv `UV_HANDLE_CLOSING` assertion, exit 127 or
    // 3221226505), and Claude Code ignores the JSON of a hook that exits
    // non-zero — the deny would be dropped. A local server keeps it off the
    // real network while still going through real sockets.
    const server = createServer((req, res) => {
      if ((req.url ?? '').startsWith('/api.osv.dev/')) {
        let raw = '';
        req.on('data', (c: Buffer) => (raw += c.toString()));
        req.on('end', () => {
          const queries = (JSON.parse(raw) as { queries: unknown[] }).queries;
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ results: queries.map(() => ({})) }));
        });
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":"Not found"}');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;
    try {
      const base: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !LEAKY_ENV.test(k)) base[k] = v;
      const child = spawn(process.execPath, ['--import', PRELOAD, HOOK], {
        cwd: project,
        env: {
          ...base,
          HOME: home,
          USERPROFILE: home,
          APPDATA: home,
      LOCALAPPDATA: home,
      ProgramData: home,
          GUARDIAN_OFFLINE: '0',
          GUARDIAN_TEST_FETCH_PROXY: `http://127.0.0.1:${port}`,
        },
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
      child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
      child.stdin.end(
        JSON.stringify({
          hook_event_name: 'PreToolUse',
          tool_name: 'Bash',
          tool_input: { command: 'npm install react-form-autopilot-helperz' },
          cwd: project,
        }),
      );
      const code = await new Promise<number | null>((r) => child.on('exit', (c) => r(c)));
      expect(stderr).not.toMatch(/Assertion failed/);
      expect(code).toBe(0);
      const out = JSON.parse(stdout) as HookOut['output'];
      expect(out?.hookSpecificOutput?.permissionDecision).toBe('deny');
    } finally {
      server.close();
    }
  }, 20_000);

  describe('fix round 2 — the reviewer\'s probes through the real hook', () => {
    it.each([
      ['a trailing comment', 'pip install requests  # for http calls'],
      ['a registry set earlier in the command', 'npm config set @org:registry https://npm.corp.local && npm i @org/x'],
      ['a venv pip by path', '.venv/bin/pip install corp-lib'],
      ['a config-file flag', 'bun add -c ./bunfig.toml corp-lib'],
      ['two sources, public last', 'dotnet add package Corp.Lib -s https://nuget.corp.local/v3/index.json -s https://api.nuget.org/v3/index.json'],
    ])('%s: never a deny', (_label, command) => {
      const r = runHook(command, {
        'https://pypi.org/pypi/requests/json': {
          body: { info: { version: '2.32.0' }, releases: { '2.32.0': [{ upload_time_iso_8601: '2020-01-01T00:00:00Z' }] } },
        },
        'https://registry.npmjs.org/@org%2Fx': { status: 404 },
        'https://registry.npmjs.org/corp-lib': { status: 404 },
        'https://pypi.org/pypi/corp-lib/json': { status: 404 },
        'https://api.nuget.org/v3-flatcontainer/corp.lib/index.json': { status: 404 },
        [OSV]: { osv: {} },
      });
      expect(r.status).toBe(0);
      expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
      expect(r.requests.some((u) => /\/pypi\/(?:for|http|calls)\/json$/.test(u))).toBe(false);
    });

    it('control: one plain statement with an allowlisted flag is still denied, with the escape hatch', () => {
      const r = runHook('npm i -D react-form-autopilot-helperz', {
        'https://registry.npmjs.org/react-form-autopilot-helperz': { status: 404 },
        [OSV]: { osv: {} },
      });
      expect(r.output?.hookSpecificOutput?.permissionDecision).toBe('deny');
      expect(r.output?.hookSpecificOutput?.permissionDecisionReason).toContain(
        're-run the install with an explicit --registry / --index-url / --source, or set GUARDIAN_PKG_VET=0',
      );
    });
  });

  it('GUARDIAN_OFFLINE=1: no request, a not-verified note', () => {
    const r = runHook('npm install express', {}, { env: { GUARDIAN_OFFLINE: '1' } });
    expect(r.requests).toEqual([]);
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/GUARDIAN_OFFLINE/);
  });
});
