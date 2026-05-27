#!/usr/bin/env node
/**
 * Smoke test for the WordPress + C# / .NET tools (spec wp-csharp-support
 * task E2 — "manual smoke against a WP / .NET fixture").
 *
 * Creates two synthetic fixtures in a temp dir, then exercises every new
 * tool in-process via the same TOOLS registry the MCP server uses. Tools
 * for which the underlying scanner is not on PATH are expected to return
 * a graceful `missing_scanner` / `missing_tools` response — NOT throw.
 *
 * The script is non-fatal: it prints a one-line verdict per tool and
 * exits 0 even if every scanner is missing, because the point is to
 * confirm the tools handle their own absence without crashing. The
 * script DOES exit 1 if a tool throws or returns a structurally broken
 * envelope (no `ok` field).
 *
 * Run after `npm run build`:
 *   node scripts/smoke-wp-dotnet.mjs
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';
import { TOOLS } from '../dist/tools/index.js';
import { detectOs } from '../dist/platform/osDetect.js';
import { probeShell } from '../dist/platform/shellProbe.js';
import { Storage } from '../dist/storage/index.js';
import { runMigrations } from '../dist/storage/migrations/runner.js';

// Side-effect imports so the relevant tool modules register themselves.
await import('../dist/tools/scanWordpress.js');
await import('../dist/tools/wpAudit.js');
await import('../dist/tools/wpVulnCheck.js');
await import('../dist/tools/detectStack.js');
await import('../dist/tools/depsUpdatePlan.js');
await import('../dist/tools/observabilitySetup.js');
await import('../dist/tools/scanSast.js');

const here = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = resolve(here, '..', '..', 'scripts');

// ---------- fixtures ----------

const root = mkdtempSync(join(tmpdir(), 'dg-smoke-'));
const dotnetDir = join(root, 'dotnet-fx');
const wpDir = join(root, 'wp-fx');
mkdirSync(dotnetDir, { recursive: true });
mkdirSync(wpDir, { recursive: true });

// .NET fixture — csproj references security-code-scan + a vulnerable
// package version, so the scan_sast C# branch has something to look at,
// and observability_setup picks up the dotnet stack.
writeFileSync(
  join(dotnetDir, 'Project.csproj'),
  `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <OutputType>Exe</OutputType>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="SecurityCodeScan.VS2019" Version="5.6.7">
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  </ItemGroup>
</Project>
`,
);
writeFileSync(
  join(dotnetDir, 'Program.cs'),
  `using System;
using System.Security.Cryptography;

namespace Smoke;

public class Program
{
    public static void Main()
    {
        // SCS0006: weak hashing algorithm — security-code-scan should flag.
        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes("secret"));
        Console.WriteLine(Convert.ToBase64String(hash));
    }
}
`,
);
writeFileSync(
  join(dotnetDir, 'global.json'),
  `{ "sdk": { "version": "8.0.0", "rollForward": "latestMajor" } }
`,
);
writeFileSync(
  join(dotnetDir, 'appsettings.json'),
  `{ "Logging": { "LogLevel": { "Default": "Information" } } }
`,
);

// WordPress fixture — minimal wp-config + a plugin file with a smell so
// PHPCS (if installed) would have something to flag, and composer.lock
// so Trivy fs (if installed) has a target.
writeFileSync(
  join(wpDir, 'wp-config.php'),
  `<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp');
define('DB_PASSWORD', 'wp');
define('DB_HOST', 'localhost');
define('WP_DEBUG', false);
$table_prefix = 'wp_';
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
`,
);
mkdirSync(join(wpDir, 'wp-content', 'plugins', 'smoke-plugin'), {
  recursive: true,
});
writeFileSync(
  join(wpDir, 'wp-content', 'plugins', 'smoke-plugin', 'smoke-plugin.php'),
  `<?php
/* Plugin Name: Smoke */
function smoke_render() {
    // WordPress.Security.EscapeOutput.OutputNotEscaped — unsafe echo.
    echo $_GET['name'];
}
add_action('init', 'smoke_render');
`,
);
writeFileSync(
  join(wpDir, 'composer.json'),
  `{ "name": "smoke/wp", "require": { "guzzlehttp/guzzle": "6.0.0" } }
`,
);

// Initialize git in each fixture (some tools/scripts treat absence of
// .git as a misuse signal).
function gitInit(dir) {
  spawnSync('git', ['init', '-q'], { cwd: dir, stdio: 'ignore' });
  spawnSync('git', ['-c', 'user.email=s@s', '-c', 'user.name=s', 'commit',
    '--allow-empty', '-q', '-m', 'init'], { cwd: dir, stdio: 'ignore' });
}
gitInit(dotnetDir);
gitInit(wpDir);

// ---------- plugin context ----------

const db = new Database(':memory:');
runMigrations(db);
const storage = new Storage(db);
const runtimeMeta = storage.runtimeMeta;
const shell = await probeShell(runtimeMeta);

const ctx = {
  storage,
  shell,
  scriptsDir: SCRIPTS_DIR,
  progressNotifier: { send: () => {} },
};

// ---------- runner ----------

const REPORT = [];
let throws = 0;
let structurallyBroken = 0;

async function run(label, toolName, input) {
  const tool = TOOLS.find((t) => t.name === toolName);
  if (!tool) {
    REPORT.push([label, 'FAIL', `tool '${toolName}' not registered`]);
    structurallyBroken++;
    return null;
  }
  try {
    const result = await tool.handler(input, ctx);
    if (typeof result !== 'object' || result === null || !('ok' in result)) {
      REPORT.push([label, 'FAIL', 'result missing `ok` field']);
      structurallyBroken++;
      return null;
    }
    const verdict = result.ok ? 'OK' : `ERR:${result.error?.code ?? '?'}`;
    REPORT.push([label, verdict, summarize(result)]);
    return result;
  } catch (e) {
    REPORT.push([label, 'THROW', e instanceof Error ? e.message : String(e)]);
    throws++;
    return null;
  }
}

function summarize(r) {
  if (!r.ok) return r.error?.message?.slice(0, 80) ?? '';
  const bits = [];
  if (typeof r.scan_id === 'string') bits.push(`scan=${r.scan_id.slice(0, 8)}`);
  if (r.findings_count_by_severity) {
    const total = Object.values(r.findings_count_by_severity).reduce(
      (a, b) => a + b, 0);
    bits.push(`findings=${total}`);
  }
  if (Array.isArray(r.missing_tools) && r.missing_tools.length)
    bits.push(`missing=[${r.missing_tools.join(',')}]`);
  if (Array.isArray(r.tools_run)) {
    const skipped = r.tools_run.filter((x) => x.status === 'skipped').length;
    const ok = r.tools_run.filter((x) => x.status === 'ok').length;
    bits.push(`tools=${ok}ok/${skipped}skip`);
  }
  if (Array.isArray(r.steps)) bits.push(`steps=${r.steps.length}`);
  if (Array.isArray(r.proposals)) bits.push(`proposals=${r.proposals.length}`);
  if (typeof r.stack === 'string') bits.push(`stack=${r.stack}`);
  if (r.snapshot?.languages) bits.push(`langs=[${r.snapshot.languages.join(',')}]`);
  if (Array.isArray(r.warnings) && r.warnings.length)
    bits.push(`warn=${r.warnings.length}`);
  return bits.join(' ');
}

// ---------- exercise tools ----------

console.log(`[smoke] root=${root}`);
console.log(`[smoke] OS=${detectOs()} shell=${shell ? 'ok' : 'none'}`);
console.log(`[smoke] running ${TOOLS.length} tools registered total\n`);

// .NET tools (real dotnet SDK available)
await run('detect_stack(.NET)', 'detect_stack',
  { project_path: dotnetDir });
await run('deps_update_plan(.NET)', 'deps_update_plan',
  { project_path: dotnetDir });
await run('observability_setup(.NET, dry-run)', 'observability_setup',
  { project_path: dotnetDir, apply: false });
await run('scan_sast(.NET, degraded)', 'scan_sast',
  { project_path: dotnetDir, force: true, allow_dirty: true });

// WordPress tools (no scanners — expect graceful degradation)
await run('detect_stack(WP)', 'detect_stack',
  { project_path: wpDir });
await run('scan_wordpress(degraded)', 'scan_wordpress',
  { project_path: wpDir, force: true, allow_dirty: true });
await run('wp_audit(missing_scanner)', 'wp_audit',
  { wp_install_path: wpDir });
await run('wp_vuln_check(missing_scanner)', 'wp_vuln_check',
  { wp_install_path: wpDir });

// ---------- report ----------

console.log('Tool                                  Verdict     Detail');
console.log('-'.repeat(100));
for (const [label, verdict, detail] of REPORT) {
  console.log(
    `${label.padEnd(38)} ${verdict.padEnd(11)} ${detail}`,
  );
}
console.log();
console.log(
  `Verdict: ${REPORT.length} tools exercised, ${throws} threw, ` +
    `${structurallyBroken} structurally broken.`,
);

if (throws > 0 || structurallyBroken > 0) {
  process.exit(1);
}
process.exit(0);
