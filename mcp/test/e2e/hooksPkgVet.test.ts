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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
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

/** Whether this account may create symlinks (Windows needs admin or Developer Mode). */
const CAN_SYMLINK = ((): boolean => {
  const probe = mkdtempSync(join(tmpdir(), 'pkgvet-e2e-symlink-probe-'));
  try {
    writeFileSync(join(probe, 't'), 'x');
    symlinkSync(join(probe, 't'), join(probe, 'l'));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();

const LEAKY_ENV =
  /^(?:npm_config_|NPM_CONFIG_|PIP_|UV_|YARN_|BUN_|NUGET_|NuGetPackageSourceCredentials_|COMPOSER|VIRTUAL_ENV$|CONDA_PREFIX$|XDG_CONFIG_DIRS$|GUARDIAN_)/i;

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
      'ProgramFiles(x86)': home,
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

  // Follow-up Part Y (item 4): the registry-context reads were not walked for
  // a network link. A project `.npmrc` linked to an unreachable share held the
  // hook on its open until the 15 s kill, and the install then ran unvetted.
  // TEST-NET-1 (192.0.2.1) is never routed; on POSIX `//192.0.2.1/…` is a
  // local path, so only Windows can fail this.
  it.skipIf(!CAN_SYMLINK)(
    'a project .npmrc linked to an unreachable share: answered at once, not after the hook timeout (needs symlink rights; skipped without them)',
    () => {
      const unc = process.platform === 'win32' ? '\\\\192.0.2.1\\share\\npmrc' : '//192.0.2.1/share/npmrc';
      symlinkSync(unc, join(project, '.npmrc'), 'file');
      const r = runHook('npm i @corp/internal', {
        'https://registry.npmjs.org/@corp%2Finternal': { status: 404 },
        [OSV]: { osv: {} },
      });
      expect(r.status).toBe(0);
      expect(r.ms).toBeLessThan(10_000);
      // Fix round 1 (controller ruling): a registry configuration that could
      // not be read may name a private registry — UNKNOWN, so a warning, never
      // a deny. The reviewer's repro was exactly this: WARN at 166117a, DENY
      // after the first round.
      expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
      expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(
        /@corp\/internal.*not found on the public registry.*could not be read — possibly a private registry/s,
      );
    },
    30_000,
  );

  // Fix round 2: every install was vetted, one by one — 60 KB of `npm i x; `
  // (6 800 installs) took ~57 s through the hook, past its 15 s timeout.
  it('fix round 2 — 6 800 installs of one package answer in well under 5 s', () => {
    const r = runHook('npm i express; '.repeat(6_800), {
      'https://registry.npmjs.org/express': npmDoc('4.21.2'),
      [OSV]: { osv: {} },
    });
    expect(r.status).toBe(0);
    expect(r.ms).toBeLessThan(5000);
    expect(r.requests.filter((u) => u.includes('registry.npmjs.org/express'))).toHaveLength(1);
  }, 30_000);

  it('fix round 1 — an unreadable project .npmrc (here a directory) warns, never denies', () => {
    mkdirSync(join(project, '.npmrc'));
    const r = runHook('npm i @corp/internal', {
      'https://registry.npmjs.org/@corp%2Finternal': { status: 404 },
      [OSV]: { osv: {} },
    });
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/could not be read — possibly a private registry/);
  });

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
        're-run the install with an explicit `--registry <url>`, or prefix the command with `GUARDIAN_PKG_VET=0`.',
      );
    });

    it('control: the escape hatch it names really works — the prefixed command is not denied', () => {
      const r = runHook('GUARDIAN_PKG_VET=0 npm i -D react-form-autopilot-helperz', {
        'https://registry.npmjs.org/react-form-autopilot-helperz': { status: 404 },
        [OSV]: { osv: {} },
      });
      expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
      expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/not found on the public registry/);
    });
  });

  // Follow-up Part Y: PowerShell hands a native command each element of
  // `a,b` as its own argument and continues a line after a backtick. Those
  // packages were never vetted; a MALICIOUS one is now denied through the real
  // hook, while a missing name there only warns.
  describe('Part Y — PowerShell shapes through the real hook', () => {
    const routes = (missing: boolean): Record<string, Route> => ({
      'https://registry.npmjs.org/lodash': npmDoc('4.17.21'),
      'https://registry.npmjs.org/evil-helper-zz': missing ? { status: 404 } : npmDoc('1.0.0'),
      [OSV]: { osv: missing ? {} : { 'evil-helper-zz@1.0.0': ['MAL-2026-0042'] } },
    });

    it.each([
      ['a comma list', 'npm i lodash,evil-helper-zz'],
      ['a backtick continuation', 'npm i lodash `\n  evil-helper-zz'],
    ])('%s: a malicious package is denied', (_label, command) => {
      const r = runHook(command, routes(false), { tool: 'PowerShell' });
      expect(r.output?.hookSpecificOutput?.permissionDecision).toBe('deny');
      expect(r.output?.hookSpecificOutput?.permissionDecisionReason).toContain('MAL-2026-0042');
    });

    it('a comma list: a missing name warns, never denies', () => {
      const r = runHook('npm i lodash,evil-helper-zz', routes(true), { tool: 'PowerShell' });
      expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
      expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/evil-helper-zz.*not found on the public registry/s);
    });

    it('the PowerShell deny spells its escape hatch the PowerShell way', () => {
      const r = runHook('npm i evil-helper-zz', routes(true), { tool: 'PowerShell' });
      expect(r.output?.hookSpecificOutput?.permissionDecisionReason).toContain("`$env:GUARDIAN_PKG_VET = '0'`");
    });
  });

  it('GUARDIAN_OFFLINE=1: no request, a not-verified note', () => {
    const r = runHook('npm install express', {}, { env: { GUARDIAN_OFFLINE: '1' } });
    expect(r.requests).toEqual([]);
    expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
    expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/GUARDIAN_OFFLINE/);
  });

  // Review of 3.0.0, I4: 17 packages in a 3000-directory monorepo took 16.5 s
  // through the hook with GUARDIAN_OFFLINE=1 — past Claude Code's 15 s, after
  // which the command runs with no verdict.
  describe('a 3000-directory monorepo (review I4)', () => {
    const NAMES = Array.from({ length: 17 }, (_, i) => `zz-no-such-pkg-${String(i).padStart(2, '0')}`);
    const monorepo = (): void => {
      mkdirSync(join(project, '.git'));
      writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'mono', private: true, workspaces: ['packages/*'] }));
      for (let i = 0; i < 3000; i += 1) {
        const dir = join(project, 'packages', `p${String(i).padStart(4, '0')}`);
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: `@mono/p${String(i).padStart(4, '0')}` }));
      }
    };

    it('17 packages offline answer well inside the deadline', () => {
      monorepo();
      const r = runHook(`npm i ${NAMES.join(' ')}`, {}, { env: { GUARDIAN_OFFLINE: '1' } });
      expect(r.ms).toBeLessThan(8000);
      expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/not verified/);
    }, 120_000);

    it('17 names the registry does not have are all answered, well inside the deadline', () => {
      monorepo();
      const routes: Record<string, Route> = { [OSV]: { osv: {} } };
      for (const name of NAMES) routes[`https://registry.npmjs.org/${name}`] = { status: 404 };
      const r = runHook(`npm i ${NAMES.join(' ')}`, routes);
      expect(r.ms).toBeLessThan(8000);
      const said = `${r.output?.hookSpecificOutput?.permissionDecisionReason ?? ''}${r.output?.hookSpecificOutput?.additionalContext ?? ''}`;
      for (const name of NAMES) expect(said).toContain(name);
    }, 120_000);

    it('GUARDIAN_PKG_VET_DEADLINE_MS=0: every package reads "time budget", never silence', () => {
      const routes: Record<string, Route> = { [OSV]: { osv: {} } };
      for (const name of NAMES) routes[`https://registry.npmjs.org/${name}`] = { status: 404 };
      const r = runHook(`npm i ${NAMES.join(' ')}`, routes, { env: { GUARDIAN_PKG_VET_DEADLINE_MS: '0' } });
      expect(r.output?.hookSpecificOutput?.permissionDecision).toBeUndefined();
      expect(r.output?.hookSpecificOutput?.additionalContext).toMatch(/time budget/);
    });
  });
});
