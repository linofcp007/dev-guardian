/**
 * `deps_audit`'s .NET restore on a repository that renames the user's NuGet
 * feed, with the real SDK (gated on it, so a skip reports as a skip) — the
 * attack `src/deps/nugetCredentials.ts` measured on SDK 10.0.403: a
 * repository `NuGet.config` declaring `corp` at its own URL received the
 * user name and password the user's configuration binds to the name `corp`.
 *
 * Two local HTTP feeds stand in for the attacker's and the user's own; each
 * records every request's path and `Authorization` header and answers 401
 * until a request carries credentials (so a credential NuGet holds is sent),
 * then a v3 service index and a 404 for every package. The user's
 * configuration is in a temporary APPDATA / HOME (`vi.stubEnv`), never the
 * real one; the packages folder and HTTP cache are temporary too. Trivy is
 * left out (`scannerAvailable`), so nothing but NuGet speaks to the network.
 *
 * A faked home is a user the SDK has never seen, and the SDK's first run does
 * two things that no faked home contains: on Windows it appends
 * `<home>\.dotnet\tools` to the user's PATH in the registry of the real
 * account, and it consults (and, finding none, fills) that account's
 * certificate store. Every run of this file left up to three dead entries in
 * the PATH of whoever ran it, until `userHome()` set the SDK's own switches
 * for those two steps; the last test holds it there.
 */

import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isDotnetSdkInstalled } from '../helpers/toolchain.js';

vi.mock('../../src/tools/scanHelpers.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/tools/scanHelpers.js')>();
  return { ...actual, scannerAvailable: async (name: string) => (name === 'trivy' ? null : actual.scannerAvailable(name)) };
});

const DOTNET = await isDotnetSdkInstalled();
const TIMEOUT_MS = 240_000;
const PASSWORD = `pw-${process.pid}-${Date.now()}`;

interface Seen {
  url: string;
  authorization: string | undefined;
}

async function feed(): Promise<{ port: number; seen: Seen[]; close(): Promise<void> }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    seen.push({ url: req.url ?? '', authorization: req.headers.authorization });
    req.resume();
    if (req.headers.authorization === undefined) {
      res.writeHead(401, { 'www-authenticate': 'Basic realm="feed"' });
      res.end();
      return;
    }
    if (req.url === '/index.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ version: '3.0.0', resources: [{ '@id': `http://${req.headers.host}/flat/`, '@type': 'PackageBaseAddress/3.0.0' }] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const address = server.address();
  return {
    port: typeof address === 'object' && address !== null ? address.port : 0,
    seen,
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}

let attacker: Awaited<ReturnType<typeof feed>>;
let own: Awaited<ReturnType<typeof feed>>;

beforeAll(async () => {
  await import('../../src/tools/depsAudit.js');
  resetScannerCache();
  attacker = await feed();
  own = await feed();
});

afterEach(() => {
  vi.unstubAllEnvs();
  attacker.seen.length = 0;
  own.seen.length = 0;
});

afterAll(async () => {
  await attacker.close();
  await own.close();
  cleanupTempDirs();
});

function makePlugin(projectPath: string): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: projectPath, progressNotifier: { send: () => {} } };
}

const feedUrl = (port: number): string => `http://127.0.0.1:${port}/index.json`;
const source = (key: string, url: string): string => `<add key="${key}" value="${url}" allowInsecureConnections="true" />`;
const nugetConfig = (body: string): string => `<?xml version="1.0" encoding="utf-8"?><configuration>${body}</configuration>`;
const CSPROJ = (extra = ''): string =>
  '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework>' +
  `${extra}</PropertyGroup><ItemGroup><PackageReference Include="Dg.Fake" Version="1.0.0" /></ItemGroup></Project>`;

/** Every faked home this file made, for the last test to look at. */
const homes: string[] = [];

/** The user's own configuration — `corp` at their feed, with its credential — in a temporary home this process now points at. */
function userHome(): void {
  const home = makeTempDir('nuget-e2e-home-');
  homes.push(home);
  const roaming = join(home, 'Roaming');
  const userDir = process.platform === 'win32' ? join(roaming, 'NuGet') : join(home, '.nuget', 'NuGet');
  mkdirSync(userDir, { recursive: true });
  writeFileSync(
    join(userDir, 'NuGet.Config'),
    nugetConfig(
      `<packageSources>${source('corp', feedUrl(own.port))}</packageSources>` +
        `<packageSourceCredentials><corp><add key="Username" value="me" /><add key="ClearTextPassword" value="${PASSWORD}" /></corp></packageSourceCredentials>`,
    ),
  );
  vi.stubEnv('APPDATA', roaming);
  vi.stubEnv('LOCALAPPDATA', join(home, 'Local'));
  vi.stubEnv('USERPROFILE', home);
  vi.stubEnv('HOME', home);
  vi.stubEnv('DOTNET_CLI_HOME', home);
  // The SDK's first run in a home it has never seen, kept inside that home:
  // its own two switches for the steps that write to the account instead —
  // the user's PATH in the registry, the account's certificate store (T-01).
  vi.stubEnv('DOTNET_ADD_GLOBAL_TOOLS_TO_PATH', '0');
  vi.stubEnv('DOTNET_GENERATE_ASPNET_CERTIFICATE', '0');
  vi.stubEnv('NUGET_PACKAGES', join(home, 'packages'));
  vi.stubEnv('NUGET_HTTP_CACHE_PATH', join(home, 'http-cache'));
}

async function audit(project: string): Promise<ToolRun | undefined> {
  const tool = TOOLS.find((t) => t.name === 'deps_audit');
  if (tool === undefined) throw new Error('deps_audit not registered');
  const r = await tool.handler({ project_path: project, force: true }, makePlugin(project));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return (r as unknown as { tools_run: ToolRun[] }).tools_run.find((t) => t.name === 'dotnet');
}

const credentialed = (seen: Seen[]): Seen[] => seen.filter((s) => s.authorization !== undefined);
const basic = `Basic ${Buffer.from(`me:${PASSWORD}`).toString('base64')}`;

/** The names in `<home>/.dotnet`, where the SDK marks each step of its first run that it has done. */
function firstRunMarks(home: string): string[] {
  const dir = join(home, '.dotnet');
  return existsSync(dir) ? readdirSync(dir) : [];
}

/**
 * The user's PATH as the registry holds it — `HKCU\Environment`, value `Path` —
 * read, never written. No `catch`: a `reg` that cannot be run fails the test
 * rather than reading as "nothing there".
 */
function userPathEntries(): string[] {
  const out = execFileSync('reg', ['query', 'HKCU\\Environment'], { encoding: 'utf8' });
  const value = /^\s+Path\s+REG_(?:EXPAND_)?SZ\s+(.*)$/im.exec(out)?.[1] ?? '';
  return value.split(';').map((entry) => entry.trim()).filter((entry) => entry !== '');
}

describe('deps_audit .NET restore and the NuGet feed names (real SDK, gated)', () => {
  it.skipIf(!DOTNET)(
    "a repository NuGet.config that re-points the user's feed name is not restored: neither feed is asked, the gap names the feed",
    async () => {
      userHome();
      const project = makeTempDir('nuget-e2e-hostile-');
      writeFileSync(join(project, 'App.csproj'), CSPROJ());
      writeFileSync(join(project, 'NuGet.config'), nugetConfig(`<packageSources>${source('corp', feedUrl(attacker.port))}</packageSources>`));

      const dotnet = await audit(project);
      expect(attacker.seen).toEqual([]);
      expect(own.seen).toEqual([]);
      expect(dotnet?.status).toBe('failed');
      expect(dotnet?.reason).toContain('NuGet.config points the NuGet feed "corp" at http://127.0.0.1');
      expect(dotnet?.reason).not.toContain(PASSWORD);
    },
    TIMEOUT_MS,
  );

  it.skipIf(!DOTNET)(
    "a project's RestoreRootConfigDirectory is overridden from the command line: the user's feed answers, the repository's never",
    async () => {
      userHome();
      const project = makeTempDir('nuget-e2e-redirect-');
      writeFileSync(join(project, 'App.csproj'), CSPROJ('<RestoreRootConfigDirectory>$(MSBuildThisFileDirectory)cfg</RestoreRootConfigDirectory>'));
      mkdirSync(join(project, 'cfg'));
      writeFileSync(join(project, 'cfg', 'NuGet.config'), nugetConfig(`<packageSources>${source('corp', feedUrl(attacker.port))}</packageSources>`));

      const dotnet = await audit(project);
      expect(attacker.seen).toEqual([]);
      expect(credentialed(own.seen).length).toBeGreaterThan(0);
      expect(credentialed(own.seen).every((s) => s.authorization === basic)).toBe(true);
      // Dg.Fake is on no feed: the restore ran, and failed as it should.
      expect(dotnet?.reason).toMatch(/NU1101/);
    },
    TIMEOUT_MS,
  );

  it.skipIf(!DOTNET)(
    "T-02 positive control: a solution whose NuGet.config names the user's own feed is restored, the credential going to that feed",
    async () => {
      userHome();
      const project = makeTempDir('nuget-e2e-own-');
      mkdirSync(join(project, 'src', 'App'), { recursive: true });
      writeFileSync(join(project, 'src', 'App', 'App.csproj'), CSPROJ());
      writeFileSync(join(project, 'App.slnx'), '<Solution><Project Path="src/App/App.csproj" /></Solution>');
      writeFileSync(join(project, 'NuGet.config'), nugetConfig(`<packageSources><clear />${source('corp', feedUrl(own.port))}</packageSources>`));

      const dotnet = await audit(project);
      expect(attacker.seen).toEqual([]);
      expect(credentialed(own.seen).length).toBeGreaterThan(0);
      expect(credentialed(own.seen).every((s) => s.authorization === basic)).toBe(true);
      expect(dotnet?.reason).toMatch(/NU1101/);
    },
    TIMEOUT_MS,
  );

  // Last, on purpose: it looks at what the three tests above left behind. A
  // faked home is a user the SDK has never seen, so its first run happens
  // there — and two steps of a first run write to the ACCOUNT, not to the
  // home: the tools-path step (on Windows, `<home>\.dotnet\tools` appended to
  // the user's PATH in the registry) and the certificate step (the account's
  // certificate store). 28 dead `nuget-e2e-home-*` entries had piled up in a
  // maintainer's PATH before this test existed.
  it.skipIf(!DOTNET)(
    "T-01 the faked homes leave nothing in the account: no first-run step that writes outside the home ran, and no entry of the user's PATH is inside one",
    () => {
      expect(homes.length).toBeGreaterThan(0);
      // Measured on SDK 10.0.404: `<version>.toolpath.sentinel` and
      // `<version>.aspNetCertificateSentinel` beside `<version>.dotnetFirstUseSentinel`.
      const accountSteps = homes.flatMap((home) =>
        firstRunMarks(home)
          .filter((name) => /toolpath|aspnetcertificate/i.test(name))
          .map((name) => `${basename(home)}: ${name}`),
      );
      // Windows only — there is no such registry elsewhere. By the home's own
      // random name: the registry is read through a console code page, and
      // nothing else of the path is certain to survive it.
      const inUserPath =
        process.platform === 'win32'
          ? userPathEntries().filter((entry) => homes.some((home) => entry.toLowerCase().includes(`\\${basename(home).toLowerCase()}\\`)))
          : [];
      // One comparison, so a failure names both.
      expect({ accountSteps, inUserPath }).toEqual({ accountSteps: [], inUserPath: [] });
    },
  );
});
