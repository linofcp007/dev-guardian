/**
 * Trivy's version check and usage telemetry (`check.trivy.dev`) never leave
 * the machine from a dev-guardian scan — against the REAL Trivy on PATH,
 * through a logging HTTP proxy on 127.0.0.1 that refuses to forward
 * anything and records every host it was asked for.
 *
 * Measured by the plugin-surface review on Trivy 0.69.3: every Trivy run —
 * `fs --scanners license` included, which needs no vulnerability database —
 * asked for check.trivy.dev, and only BOTH `TRIVY_SKIP_VERSION_CHECK=true`
 * and `TRIVY_DISABLE_TELEMETRY=true` stopped it.
 *
 * The control run (Trivy spawned bare, exactly as every pass used to be)
 * must ask for check.trivy.dev through the proxy, or this test proves
 * nothing: if a future Trivy drops the check, the control fails and says
 * so.
 */

import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { resetTrivyVersionCache, runTrivy } from '../../src/runners/trivyRun.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { isInstalled } from '../helpers/toolchain.js';

vi.setConfig({ testTimeout: 180_000 });

const TRIVY_INSTALLED = await isInstalled('trivy');
const REQUIRE_TOOLCHAIN = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

/** Every host a client asked the proxy for (CONNECT host:port, or an absolute-URI request). */
const asked: string[] = [];
let proxy: Server;
let proxyUrl = '';

beforeAll(async () => {
  proxy = createServer((req, res) => {
    asked.push(req.url ?? '');
    res.writeHead(403).end();
  });
  proxy.on('connect', (req, socket) => {
    // A client that resets the refused tunnel must not take the proxy down.
    socket.on('error', () => {});
    asked.push(req.url ?? '');
    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
  });
  proxy.on('clientError', (_e, socket) => socket.destroy());
  await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((resolve) => proxy.close(() => resolve()));
  cleanupTempDirs();
});

function proxied(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl };
  delete env['NO_PROXY'];
  delete env['no_proxy'];
  delete env['TRIVY_SKIP_VERSION_CHECK'];
  delete env['TRIVY_DISABLE_TELEMETRY'];
  return env;
}

function project(): string {
  const dir = makeTempDir('trivy-phone-home-');
  writeFileSync(join(dir, 'Dockerfile'), 'FROM alpine:3.18\n');
  return dir;
}

/**
 * `trivy config`, not a license scan: the check runs in a goroutine with a
 * 3 s timeout (`pkg/notification/notice.go`) that a sub-second `fs` scan can
 * exit before starting — measured here, a license scan's control asked for
 * nothing in 5 of 6 runs, so it could not tell the fix from luck. A config
 * scan loads its checks bundle (~1.5 s) and asked every time: bare, --quiet,
 * --skip-version-check alone and --disable-telemetry alone all asked; both
 * flags, or both environment variables, never did.
 */
const CONFIG_ARGS = ['config', '--format', 'json', '--quiet'];

describe('Trivy runs never contact check.trivy.dev (real Trivy, logging proxy)', () => {
  it.runIf(REQUIRE_TOOLCHAIN)('GUARDIAN_REQUIRE_SEMGREP=1 — Trivy must be on PATH', () => {
    expect(TRIVY_INSTALLED).toBe(true);
  });

  it.skipIf(!TRIVY_INSTALLED)('control: a bare Trivy run asks for check.trivy.dev', async () => {
    asked.length = 0;
    const dir = project();
    const empty = join(makeTempDir('trivy-phone-home-work-'), 'empty.yaml');
    writeFileSync(empty, '');
    // Asynchronous: the proxy lives in this process, and a synchronous spawn
    // would block it from ever answering the request it is here to record.
    await new Promise<void>((resolve) => {
      const child = spawn('trivy', [...CONFIG_ARGS, '--config', empty, '--output', join(dir, 'out.json'), dir], {
        env: proxied(),
        stdio: 'ignore',
      });
      child.on('close', () => resolve());
      child.on('error', () => resolve());
    });
    expect(asked.some((h) => h.includes('check.trivy.dev'))).toBe(true);
  });

  it.skipIf(!TRIVY_INSTALLED)('a run through runTrivy asks for nothing there', async () => {
    asked.length = 0;
    resetTrivyVersionCache();
    const dir = project();
    const work = makeTempDir('trivy-phone-home-work-');
    const r = await runTrivy({
      args: [...CONFIG_ARGS, '--output', join(work, 'out.json')],
      target: dir,
      workDir: work,
      env: proxied(),
    });
    expect(r.outcome).toBe('completed');
    expect(asked.filter((h) => h.includes('check.trivy.dev'))).toEqual([]);
  });
});
