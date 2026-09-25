/**
 * Three tools called `require('node:fs')` inside ESM. That works in the
 * esbuild bundle, whose banner defines `require`, and under vitest, whose
 * module runner hands every module one. Everywhere else — `tsx`, and the
 * per-file `dist/` the CLI imports — it throws `require is not defined`, each
 * call site swallowed that in a `catch`, and the tool quietly answered wrong:
 *
 *   - wp_vuln_check read no report and returned 0 findings;
 *   - deps_update_plan never detected a .NET project;
 *   - observability_setup never inferred the `dotnet` stack.
 *
 * Because vitest itself cannot show the failure, each case runs the tool in a
 * child `node --import tsx` process (`helpers/esmFsHarness.ts`) — real,
 * unbundled ES modules — on exactly the input that reaches those lines.
 */
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, resolve } from 'node:path';
import { execPath } from 'node:process';
import { fileURLToPath } from 'node:url';
import { execa } from 'execa';
import { afterAll, describe, expect, it } from 'vitest';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const MCP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HARNESS = join(MCP_ROOT, 'test', 'helpers', 'esmFsHarness.ts');
const WPSCAN_FIXTURE = join(MCP_ROOT, 'test', 'fixtures', 'scanners', 'wpscan.json');

async function runTool(
  name: string,
  input: Record<string, unknown>,
  extraPath?: string,
): Promise<Record<string, unknown>> {
  const env: NodeJS.ProcessEnv = {};
  if (extraPath !== undefined) {
    const key = Object.keys(process.env).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH';
    env[key] = `${extraPath}${delimiter}${process.env[key] ?? ''}`;
  }
  const r = await execa(execPath, ['--import', 'tsx', HARNESS, name, JSON.stringify(input)], {
    cwd: MCP_ROOT,
    env,
    reject: false,
    timeout: 60_000,
  });
  expect(r.exitCode, r.stderr).toBe(0);
  return JSON.parse(r.stdout.trim().split(/\r?\n/).at(-1) ?? '{}') as Record<string, unknown>;
}

/** A `wpscan` on PATH that writes the recorded report to `--output` and
 *  prints nothing — so the stdout fallback cannot hide a failed file read. */
function fakeWpscanDir(): string {
  const dir = makeTempDir('fake-wpscan-');
  const impl = join(dir, 'fake-wpscan.cjs');
  writeFileSync(
    impl,
    [
      "const { copyFileSync } = require('node:fs');",
      "const at = process.argv.indexOf('--output');",
      `if (at > 0) copyFileSync(${JSON.stringify(WPSCAN_FIXTURE)}, process.argv[at + 1]);`,
    ].join('\n'),
  );
  if (process.platform === 'win32') {
    writeFileSync(join(dir, 'wpscan.cmd'), `@"${execPath}" "${impl}" %*\r\n`);
  } else {
    const sh = join(dir, 'wpscan');
    writeFileSync(sh, `#!/bin/sh\nexec "${execPath}" "${impl}" "$@"\n`);
    chmodSync(sh, 0o755);
  }
  return dir;
}

describe('the three former require() sites, unbundled', () => {
  it('wp_vuln_check reads the WPScan report file it asked for', async () => {
    expect(readFileSync(WPSCAN_FIXTURE, 'utf8').length).toBeGreaterThan(0);
    const site = makeTempDir('wpvuln-');
    const r = await runTool(
      'wp_vuln_check',
      { target_url: 'https://example.test', wp_install_path: site },
      fakeWpscanDir(),
    );
    expect(r['ok']).toBe(true);
    expect(r['findings_count']).toBeGreaterThan(0);
    expect(r['warnings']).not.toContain('WPScan produced no parseable JSON output.');
  }, 90_000);

  it('deps_update_plan detects a .NET project from its .csproj', async () => {
    const project = makeTempDir('deps-dotnet-');
    // Not a loadable project on purpose: `dotnet restore` (where dotnet
    // exists) fails fast and the plan is empty — detection is what is tested.
    writeFileSync(join(project, 'App.csproj'), 'not a project\n');
    const r = await runTool('deps_update_plan', { project_path: project });
    expect(r['ok']).toBe(true);
    expect(r['stack_detected']).toContain('dotnet');
  }, 90_000);

  it('observability_setup infers the dotnet stack from a .sln', async () => {
    const project = makeTempDir('obs-dotnet-');
    writeFileSync(join(project, 'App.sln'), '\n');
    const r = await runTool('observability_setup', { project_path: project });
    expect(r['ok']).toBe(true);
    expect(r['stack_inferred']).toBe('dotnet');
  }, 90_000);
});
