/**
 * Where `create_fix_pr`'s installs fetch from, when the repository names the
 * host in something other than a package-manager configuration file (review
 * of 3.0, W2E; the `.npmrc` route is `createFixPrRegistry.test.ts`'s).
 *
 *   - A `package-lock.json` whose `resolved` URLs point at another host: the
 *     fix's `npm ci` / `npm install` fetch every locked tarball from where the
 *     lock says. The user's registry token must reach their own registry only
 *     — never the host the lock chose. Real npm, two local HTTP servers, no
 *     internet: each records every request's path and `Authorization`.
 *   - A pip requirement that names its host itself (`name @ https://…`, a
 *     bare URL, `git+https://…`): refused like an index option, named in the
 *     group's note, and the host never contacted.
 */
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/registerAll.js';
import { rmDirOrDefer } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const NPM_INSTALLED = await isInstalled('npm');
const TOKEN = `npm_devguardian_${randomUUID().replace(/-/g, '')}`;
const TIMEOUT_MS = 180_000;

interface Seen {
  method: string;
  url: string;
  authorization: string | undefined;
}

/** One ustar entry: a 512-byte header (checksum over the header with its own field blank) and the padded body. */
function tarEntry(name: string, body: Buffer): Buffer {
  const header = Buffer.alloc(512, 0);
  const put = (text: string, offset: number, length: number): void => {
    header.write(text.slice(0, length), offset, length, 'ascii');
  };
  const octal = (n: number, length: number): string => `${n.toString(8).padStart(length - 1, '0')}\0`;
  put(name, 0, 100);
  put(octal(0o644, 8), 100, 8);
  put(octal(0, 8), 108, 8);
  put(octal(0, 8), 116, 8);
  put(octal(body.length, 12), 124, 12);
  put(octal(1_700_000_000, 12), 136, 12);
  put('        ', 148, 8);
  put('0', 156, 1);
  put('ustar\0', 257, 6);
  put('00', 263, 2);
  let sum = 0;
  for (const byte of header) sum += byte;
  put(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8);
  const padded = Buffer.alloc(Math.ceil(body.length / 512) * 512, 0);
  body.copy(padded);
  return Buffer.concat([header, padded]);
}

/** An npm package tarball: `package/package.json` and nothing else. */
function packageTarball(name: string, version: string): Buffer {
  const manifest = Buffer.from(JSON.stringify({ name, version, main: 'index.js' }));
  return gzipSync(Buffer.concat([tarEntry('package/package.json', manifest), Buffer.alloc(1024, 0)]));
}

interface Registry {
  server: Server;
  port: number;
  seen: Seen[];
  /** name → versions this registry serves. */
  packages: Map<string, string[]>;
}

/** A registry serving `packages`: packuments at `/<name>`, tarballs at `/<name>/-/<name>-<v>.tgz`, `{}` for audits. */
function registry(): Promise<Registry> {
  const seen: Seen[] = [];
  const packages = new Map<string, string[]>();
  const server = createServer((req, res) => {
    const url = req.url ?? '';
    seen.push({ method: req.method ?? '', url, authorization: req.headers.authorization });
    const port = (server.address() as { port: number }).port;
    const tgz = /^\/([^/]+)\/-\/[^/]+-(\d+\.\d+\.\d+)\.tgz$/.exec(url);
    if (tgz?.[1] !== undefined && tgz[2] !== undefined && (packages.get(tgz[1]) ?? []).includes(tgz[2])) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(packageTarball(tgz[1], tgz[2]));
      return;
    }
    const name = decodeURIComponent(url.slice(1).split('?')[0] ?? '');
    const versions = packages.get(name);
    if (req.method === 'GET' && versions !== undefined) {
      const doc = {
        name,
        'dist-tags': { latest: versions[versions.length - 1] },
        versions: Object.fromEntries(
          versions.map((v) => [v, { name, version: v, dist: { tarball: `http://127.0.0.1:${port}/${name}/-/${name}-${v}.tgz` } }]),
        ),
      };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(doc));
      return;
    }
    if (req.method === 'POST' && url.includes('/-/npm/v1/security/')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === 'object' && addr !== null ? addr.port : 0, seen, packages });
    });
  });
}

let attacker: Registry;
let own: Registry;
let repo: string;
let home: string;

beforeAll(async () => {
  attacker = await registry();
  own = await registry();
});

afterAll(async () => {
  await new Promise((r) => attacker.server.close(r));
  await new Promise((r) => own.server.close(r));
});

beforeEach(() => {
  attacker.seen.length = 0;
  own.seen.length = 0;
  attacker.packages.clear();
  own.packages.clear();
  home = mkdtempSync(join(tmpdir(), 'fixpr-src-home-'));
  const userNpmrc = join(home, '.npmrc');
  writeFileSync(userNpmrc, `registry=http://127.0.0.1:${own.port}/\n//127.0.0.1:${own.port}/:_authToken=\${NPM_TOKEN}\n`);
  vi.stubEnv('NPM_TOKEN', TOKEN);
  vi.stubEnv('NPM_CONFIG_USERCONFIG', userNpmrc);
  vi.stubEnv('npm_config_cache', join(home, 'npm-cache'));
  vi.stubEnv('npm_config_audit', 'false');
  vi.stubEnv('npm_config_fund', 'false');
  vi.stubEnv('npm_config_update_notifier', 'false');
  repo = mkdtempSync(join(tmpdir(), 'fixpr-src-'));
  execFileSync('git', ['init', '-q', '-b', 'main', repo]);
  execFileSync('git', ['-C', repo, 'config', 'user.email', 't@example.com']);
  execFileSync('git', ['-C', repo, 'config', 'user.name', 'T']);
});

afterEach(() => {
  vi.unstubAllEnvs();
  rmDirOrDefer(repo);
  rmDirOrDefer(home);
});

function commitProject(files: Record<string, string>): void {
  for (const [name, body] of Object.entries(files)) writeFileSync(join(repo, name), body);
  execFileSync('git', ['-C', repo, 'add', '-A']);
  execFileSync('git', ['-C', repo, 'commit', '-q', '-m', 'project']);
}

function ctx() {
  const { db } = openDatabase({ inMemory: true, projectPath: tmpdir() });
  return { storage: new Storage(db) };
}

/** One open dependency finding with its CVE row — enough for create_fix_pr to plan `pkg` → `fixed`. */
function seedCve(c: ReturnType<typeof ctx>, pkg: string, file: string, installed: string, fixed: string): void {
  const scanId = randomUUID();
  const cve = `CVE-2099-${Math.floor(Math.random() * 9000 + 1000)}`;
  c.storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: repo, tree_hash: 'deadbeef' });
  c.storage.findings.bulkInsert([
    {
      fingerprint: `fp-${pkg}`,
      tool: 'trivy',
      rule_id: cve,
      severity: 'high',
      category: 'security',
      subcategory: 'cve',
      title: `${pkg}: a vulnerability`,
      file_path: file,
      snippet: `${pkg}@${installed}->${fixed}`,
      fix_available: true,
      scan_id: scanId,
    },
  ]);
  c.storage.cves.upsert({ cve_id: cve, package_name: pkg, installed_version: installed, fixed_version: fixed, severity: 'high', scan_id: scanId });
  c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] });
}

interface GroupView {
  key: string;
  outcome: string;
  note: string;
  commands?: string[];
}

async function runCreateFixPr(c: ReturnType<typeof ctx>): Promise<GroupView[]> {
  const tool = TOOLS.find((t) => t.name === 'create_fix_pr');
  if (tool === undefined) throw new Error('create_fix_pr not registered');
  const res = (await tool.handler({ project_path: repo, sources: ['deps'], apply: false }, c as never)) as {
    ok: boolean;
    groups?: GroupView[];
  };
  expect(res.ok).toBe(true);
  return res.groups ?? [];
}

const carriesToken = (s: Seen): boolean => s.authorization !== undefined && s.authorization.includes(TOKEN);

describe("create_fix_pr — a lockfile's resolved URLs never carry the user's registry token", () => {
  it.skipIf(!NPM_INSTALLED)(
    'npm fetches the locked tarball from the host the lock names, without the Authorization header',
    async () => {
      own.packages.set('dg-leftpad', ['1.0.0', '1.0.1']);
      attacker.packages.set('dg-other', ['1.0.0']);
      const lock = {
        name: 'x',
        version: '1.0.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': { name: 'x', version: '1.0.0', dependencies: { 'dg-leftpad': '1.0.0', 'dg-other': '1.0.0' } },
          'node_modules/dg-leftpad': { version: '1.0.0', resolved: `http://127.0.0.1:${own.port}/dg-leftpad/-/dg-leftpad-1.0.0.tgz` },
          'node_modules/dg-other': { version: '1.0.0', resolved: `http://127.0.0.1:${attacker.port}/dg-other/-/dg-other-1.0.0.tgz` },
        },
      };
      commitProject({
        // A test script: create_fix_pr then prepares both trees with `npm ci`, and the fix is a full install.
        'package.json': JSON.stringify({
          name: 'x',
          version: '1.0.0',
          scripts: { test: 'node -e "process.exit(0)"' },
          dependencies: { 'dg-leftpad': '1.0.0', 'dg-other': '1.0.0' },
        }),
        'package-lock.json': JSON.stringify(lock, null, 2),
        // Without the trailing slash: `git check-ignore node_modules` must say yes before anything
        // exists there, or the test environment is not prepared (fixpr/testEnv.ts).
        '.gitignore': 'node_modules\n',
      });
      const c = ctx();
      seedCve(c, 'dg-leftpad', 'package-lock.json', '1.0.0', '1.0.1');

      const groups = await runCreateFixPr(c);

      // The install really happened, and really fetched from the host the lock named …
      // Both install paths ran: the test environment's `npm ci` and the fix's full `npm install`.
      const fetched = attacker.seen.filter((s) => s.url.includes('/dg-other/-/dg-other-1.0.0.tgz'));
      const evidence = JSON.stringify({ groups, attacker: attacker.seen, own: own.seen });
      expect(groups.find((g) => g.key === 'npm')?.commands, evidence).toEqual([
        'npm ci --ignore-scripts (test environment)',
        'npm install dg-leftpad@1.0.1 --ignore-scripts',
      ]);
      expect(fetched.length, evidence).toBeGreaterThan(0);
      // … and nothing it received carried the token. The control: a TARBALL fetched from the
      // user's own registry did carry it, so its absence above is npm's scoping, not a token
      // that never reached npm.
      expect(attacker.seen.filter((s) => s.authorization !== undefined)).toEqual([]);
      expect(own.seen.some((s) => s.url.includes('/dg-leftpad/-/dg-leftpad-') && carriesToken(s)), evidence).toBe(true);
    },
    TIMEOUT_MS,
  );
});

describe('create_fix_pr — a pip requirement that names its own host is refused', () => {
  it.each([
    [`pkg @ http://127.0.0.1:{port}/pkg-1.0.tar.gz`, 'direct reference (http://127.0.0.1)'],
    [`http://127.0.0.1:{port}/pkg-1.0.tar.gz`, 'URL requirement (http://127.0.0.1)'],
    [`git+http://127.0.0.1:{port}/repo.git#egg=pkg`, 'VCS requirement (git+http://127.0.0.1)'],
    [`-r http://127.0.0.1:{port}/more.txt`, 'include of a URL (http://127.0.0.1)'],
    // Round 2: bypasses of the first version, measured against pip 26's own parser.
    [`--index http://127.0.0.1:{port}/simple`, 'index option (--index, http://127.0.0.1)'],
    [`-egit+http://127.0.0.1:{port}/r.git#egg=x`, 'editable requirement (-e, git+http://127.0.0.1)'],
    [`pkg @ http://ci:S3CRET@127.0.0.1:{port}/p.tgz`, 'direct reference (http://127.0.0.1)'],
  ])(
    '%s: refused, named, and never contacted',
    async (line, what) => {
      commitProject({ 'requirements.txt': `django==3.2.0\n${line.replace('{port}', String(attacker.port))}\n` });
      const c = ctx();
      seedCve(c, 'django', 'requirements.txt', '3.2.0', '3.2.25');

      const groups = await runCreateFixPr(c);

      expect(groups).toHaveLength(1);
      expect(groups[0]?.outcome).toBe('refused');
      expect(groups[0]?.note).toBe(
        `refused: the project's Python requirements name where pip installs from, or could not be checked (requirements.txt:2: ${what}); ` +
          'dev-guardian installs only plain requirements it has read — a name, extras, versions and markers',
      );
      expect(groups[0]?.note).not.toContain('S3CRET');
      expect(attacker.seen).toEqual([]);
    },
    TIMEOUT_MS,
  );
});
