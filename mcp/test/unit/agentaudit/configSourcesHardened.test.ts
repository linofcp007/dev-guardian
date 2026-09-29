/**
 * `readConfigSources` never hangs on what sits at a config path.
 *
 * It used to `existsSync` and then `readFileSync`: a FIFO at `.mcp.json`
 * blocked the read for ever, a link to `/dev/zero` read without end, and a
 * link to `\\<unreachable host>\share` waited on the network — each one
 * hanging `audit_agent_config` and `audit_mcp_tools`, the user-level configs
 * included. It now reads through the hooks' hardened reader
 * (`hooks/configFile.ts`: links walked for a network target first, then open
 * non-blocking and judge the DESCRIPTOR), and a refused file is a named
 * refusal — it exists, it was not read.
 *
 * Each read runs in a CHILD process with a kill timer, because a synchronous
 * read that blocks cannot be interrupted from inside the process: without the
 * child, the old code would hang the test worker instead of failing a test.
 * Link targets use 192.0.2.1 (TEST-NET-1, never routed).
 */

import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { claudeDesktopConfigPath } from '../../../src/hostsetup/mcpConfig.js';
import { detectOs } from '../../../src/platform/osDetect.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { MCP_ROOT, TSX_NODE_ARGS } from '../../helpers/tsxNode.js';

afterAll(cleanupTempDirs);

const POSIX = process.platform !== 'win32';
const UNC = POSIX ? '//192.0.2.1/share' : '\\\\192.0.2.1\\share';
const SEP = POSIX ? '/' : '\\';

/** Whether this account may create symlinks (Windows needs admin or Developer Mode). */
const CAN_SYMLINK = ((): boolean => {
  const probe = mkdtempSync(join(tmpdir(), 'agentaudit-symlink-probe-'));
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

interface SourceView {
  label: string;
  exists: boolean;
  refusal?: string;
  parseError?: string;
}

interface ChildRead {
  timedOut: boolean;
  sources: SourceView[];
  readMs: number;
}

/** `readConfigSources(project, includeUser)` in a child whose home is `home`. */
function readInChild(project: string, includeUser: boolean, home: string, timeoutMs = 45_000): Promise<ChildRead> {
  const scriptDir = makeTempDir('agentaudit-child-');
  const script = join(scriptDir, 'read.mjs');
  const moduleUrl = pathToFileURL(resolve(MCP_ROOT, 'src', 'agentaudit', 'configSources.ts')).href;
  writeFileSync(
    script,
    `import { readConfigSources } from ${JSON.stringify(moduleUrl)};\n` +
      'const [project, user] = process.argv.slice(2);\n' +
      'const t0 = Date.now();\n' +
      "const sources = readConfigSources(project, user === '1');\n" +
      'const readMs = Date.now() - t0;\n' +
      'process.stdout.write(JSON.stringify({ readMs, sources: sources.map((s) => ({ label: s.label, exists: s.exists, refusal: s.refusal, parseError: s.parseError })) }));\n',
  );
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, 'AppData', 'Roaming') };
  // Claude Code's own override would point .claude.json elsewhere (this
  // machine sets it): the child must see only the fake home.
  delete env['CLAUDE_CONFIG_DIR'];
  return new Promise((done) => {
    const child = spawn(process.execPath, [...TSX_NODE_ARGS, script, project, includeUser ? '1' : '0'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });
    let out = '';
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString('utf8');
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      done({ timedOut: true, sources: [], readMs: Number.NaN });
    }, timeoutMs);
    child.on('exit', () => {
      clearTimeout(timer);
      let parsed: { sources: SourceView[]; readMs: number } = { sources: [], readMs: Number.NaN };
      try {
        parsed = JSON.parse(out) as typeof parsed;
      } catch {
        /* reported through the assertions */
      }
      done({ timedOut: false, ...parsed });
    });
  });
}

function source(r: ChildRead, label: string): SourceView | undefined {
  return r.sources.find((s) => s.label === label);
}

function expectRefused(r: ChildRead, label: string, refusal: string): void {
  expect(r.timedOut, 'the read hung and was killed').toBe(false);
  const s = source(r, label);
  expect(s, `${label} in ${JSON.stringify(r.sources.map((x) => x.label))}`).toBeDefined();
  expect(s?.exists).toBe(true);
  expect(s?.refusal).toBe(refusal);
  expect(typeof s?.parseError).toBe('string');
  expect(r.readMs).toBeLessThan(5_000);
}

describe('readConfigSources: a project config that would hang a plain read', () => {
  it.skipIf(!POSIX)('refuses a FIFO at .mcp.json at once (POSIX only: Windows has no FIFOs)', async () => {
    const project = makeTempDir('agentaudit-hard-');
    expect(spawnSync('mkfifo', [join(project, '.mcp.json')]).status).toBe(0);
    expectRefused(await readInChild(project, false, makeTempDir('agentaudit-home-')), '.mcp.json', 'not-a-regular-file');
  }, 60_000);

  it.skipIf(!POSIX)('refuses .cursor/mcp.json linked to /dev/zero (POSIX only)', async () => {
    const project = makeTempDir('agentaudit-hard-');
    mkdirSync(join(project, '.cursor'));
    symlinkSync('/dev/zero', join(project, '.cursor', 'mcp.json'));
    expectRefused(
      await readInChild(project, false, makeTempDir('agentaudit-home-')),
      '.cursor/mcp.json',
      'not-a-regular-file',
    );
  }, 60_000);

  it.skipIf(!CAN_SYMLINK)('refuses .mcp.json linked to a UNC path without touching it (needs symlink rights)', async () => {
    const project = makeTempDir('agentaudit-hard-');
    symlinkSync(`${UNC}${SEP}mcp.json`, join(project, '.mcp.json'), 'file');
    expectRefused(await readInChild(project, false, makeTempDir('agentaudit-home-')), '.mcp.json', 'remote-link');
  }, 60_000);

  it.skipIf(!CAN_SYMLINK)('refuses a config under a directory linked to a UNC path (needs symlink rights)', async () => {
    const project = makeTempDir('agentaudit-hard-');
    symlinkSync(UNC, join(project, '.vscode'), 'dir');
    expectRefused(await readInChild(project, false, makeTempDir('agentaudit-home-')), '.vscode/mcp.json', 'remote-link');
  }, 60_000);
});

describe('readConfigSources: the user-level configs, with include_user_config', () => {
  it.skipIf(!POSIX)('refuses a FIFO at ~/.cursor/mcp.json (POSIX only)', async () => {
    const home = makeTempDir('agentaudit-home-');
    mkdirSync(join(home, '.cursor'));
    expect(spawnSync('mkfifo', [join(home, '.cursor', 'mcp.json')]).status).toBe(0);
    expectRefused(await readInChild(makeTempDir('agentaudit-hard-'), true, home), '~/.cursor/mcp.json', 'not-a-regular-file');
  }, 60_000);

  it.skipIf(!CAN_SYMLINK)('refuses ~/.gemini linked to a UNC path (needs symlink rights)', async () => {
    const home = makeTempDir('agentaudit-home-');
    symlinkSync(UNC, join(home, '.gemini'), 'dir');
    expectRefused(await readInChild(makeTempDir('agentaudit-hard-'), true, home), '~/.gemini/settings.json', 'remote-link');
  }, 60_000);

  it.skipIf(!CAN_SYMLINK)("refuses Claude Desktop's config directory linked to a UNC path (needs symlink rights)", async () => {
    const home = makeTempDir('agentaudit-home-');
    const desktop = claudeDesktopConfigPath({ os: detectOs(), home, appData: join(home, 'AppData', 'Roaming') });
    expect(desktop).not.toBeNull();
    if (desktop === null) return;
    mkdirSync(dirname(dirname(desktop)), { recursive: true });
    symlinkSync(UNC, dirname(desktop), 'dir');
    expectRefused(
      await readInChild(makeTempDir('agentaudit-hard-'), true, home),
      'claude_desktop_config.json',
      'remote-link',
    );
  }, 60_000);

  it('still reads an ordinary user-level config, and a local link to one', async () => {
    const home = makeTempDir('agentaudit-home-');
    mkdirSync(join(home, '.cursor'));
    writeFileSync(join(home, '.cursor', 'mcp.json'), '{"mcpServers":{}}');
    const r = await readInChild(makeTempDir('agentaudit-hard-'), true, home);
    expect(r.timedOut).toBe(false);
    expect(source(r, '~/.cursor/mcp.json')).toMatchObject({ exists: true });
    expect(source(r, '~/.cursor/mcp.json')?.refusal).toBeUndefined();
    if (CAN_SYMLINK) {
      const real = join(home, 'dotfiles-gemini.json');
      writeFileSync(real, '{"mcpServers":{}}');
      mkdirSync(join(home, '.gemini'));
      symlinkSync(real, join(home, '.gemini', 'settings.json'), 'file');
      const linked = await readInChild(makeTempDir('agentaudit-hard-'), true, home);
      expect(source(linked, '~/.gemini/settings.json')).toMatchObject({ exists: true });
      expect(source(linked, '~/.gemini/settings.json')?.parseError).toBeUndefined();
    }
  }, 60_000);
});
