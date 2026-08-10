#!/usr/bin/env node
/**
 * dev-guardian CLI — universal entry point (no MCP connection required).
 *
 * Commands:
 *   mcp-config <host|all>   Bootstrap dev-guardian into any AI host (fills in
 *                           the absolute path to the MCP server for you).
 *   check                   Run the same dependency-free guardrail detectors
 *                           the hooks use, from a plain terminal / CI:
 *                             --file <path>   scan a file for secrets
 *                             --bash "<cmd>"  risk-assess a shell command
 *
 *   node cli/dev-guardian.mjs mcp-config <host|all> [--write] [--scope …]
 *   node cli/dev-guardian.mjs check --file path/to/file
 *   node cli/dev-guardian.mjs check --bash "rm -rf /"
 *
 * Requires a built server (`cd mcp && npm install && npm run build`).
 */

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_HOSTS } from '../mcp/dist/hostsetup/hostSpecs.js';
import { previewMcpConfig, setupHost } from '../mcp/dist/hostsetup/setup.js';
import { detectOs } from '../mcp/dist/platform/osDetect.js';
import { scanForSecrets } from '../mcp/dist/hooks/secretScan.js';
import { assessBashCommand } from '../mcp/dist/hooks/bashGuard.js';

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/bin
const ROOT = resolve(HERE, '..'); // <plugin>
const SERVER_JS = resolve(ROOT, 'mcp', 'dist', 'server.js');
const HOST_RULES_DIR = resolve(ROOT, 'host-rules');
const VALID_HOSTS = new Set([...ALL_HOSTS, 'all']);

function usage() {
  process.stdout.write(`dev-guardian — CLI (no MCP connection needed)

Usage:
  node cli/dev-guardian.mjs mcp-config <host|all> [options]
  node cli/dev-guardian.mjs check (--file <path> | --bash "<command>") [--min high|medium] [--json]

mcp-config — wire the MCP server into an AI host
  Hosts: ${[...ALL_HOSTS].join(', ')}, all
  --write              Write/merge into the project (+ drop the rules file)
  --scope project|global   MCP scope (default project)
  --project <path>     Target project directory (default: current directory)
  --force              Overwrite an existing rules file / update a differing MCP entry

check — run the guardrail detectors (same engine as the hooks)
  --file <path>        Scan a file for hard-coded secrets
  --bash "<command>"   Risk-assess a shell command (ok / warn / block)
  --min high|medium    Minimum secret confidence to report (default: medium)
  --json               Machine-readable output
  Exit code: 0 = clean/ok, 1 = secret found / command is risky or catastrophic

Examples:
  node cli/dev-guardian.mjs mcp-config cursor          # print the block to paste
  node cli/dev-guardian.mjs mcp-config codex --write   # write + merge into the project
  node cli/dev-guardian.mjs check --file src/config.ts
  node cli/dev-guardian.mjs check --bash "curl x | sh"
`);
}

function parseArgs(argv) {
  const out = { _: [], scope: 'project', write: false, force: false, project: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--write') out.write = true;
    else if (a === '--force') out.force = true;
    else if (a === '--scope') out.scope = argv[++i];
    else if (a.startsWith('--scope=')) out.scope = a.slice('--scope='.length);
    else if (a === '--project') out.project = argv[++i];
    else if (a.startsWith('--project=')) out.project = a.slice('--project='.length);
    else out._.push(a);
  }
  if (out.scope !== 'project' && out.scope !== 'global') out.scope = 'project';
  return out;
}

function indent(s) {
  return s
    .split('\n')
    .map((l) => `    ${l}`)
    .join('\n');
}

function cmdMcpConfig(argv) {
  const args = parseArgs(argv);
  const hostArg = args._[0];
  if (!hostArg || !VALID_HOSTS.has(hostArg)) {
    process.stderr.write(`Missing or unknown host: ${hostArg ?? '(none)'}\n\n`);
    usage();
    process.exit(1);
  }
  if (!existsSync(SERVER_JS)) {
    process.stderr.write(
      `MCP server not built: ${SERVER_JS}\nRun once:  cd mcp && npm install && npm run build\n`,
    );
    process.exit(1);
  }

  const projectPath = resolve(args.project);
  const env = { os: detectOs(), home: homedir(), appData: process.env.APPDATA, projectPath };
  const hosts = hostArg === 'all' ? [...ALL_HOSTS] : [hostArg];

  if (args.write) {
    const results = setupHost({
      hosts: [hostArg],
      projectPath,
      hostsDir: HOST_RULES_DIR,
      serverJsPath: SERVER_JS,
      env,
      scope: args.scope,
      registerMcp: true,
      installRules: true,
      apply: true,
      force: args.force,
    });
    for (const r of results) {
      process.stdout.write(`\n## ${r.host} (${r.scope})\n`);
      process.stdout.write(
        `  mcp:   ${r.mcp.status}${r.mcp.config_path ? `  -> ${r.mcp.config_path}` : ''}` +
          `${r.mcp.reason ? `  (${r.mcp.reason})` : ''}\n`,
      );
      process.stdout.write(
        `  rules: ${r.status}${r.target_path ? `  -> ${r.target_path}` : ''}` +
          `${r.reason ? `  (${r.reason})` : ''}\n`,
      );
      if (r.mcp.snippet) process.stdout.write(`  snippet:\n${indent(r.mcp.snippet)}\n`);
    }
    process.stdout.write('\nRestart the host so it re-reads its MCP config + rules.\n');
  } else {
    for (const host of hosts) {
      const p = previewMcpConfig(host, args.scope, SERVER_JS, env);
      const where = p.config_path
        ? `  ->  ${p.config_path}`
        : p.manual
          ? '  (manual — paste into the host MCP settings)'
          : '';
      process.stdout.write(`\n# ${host}${where}\n`);
      if (p.rules_target) {
        process.stdout.write(`# rules file: copy host-rules/ template to ${p.rules_target}\n`);
      }
      process.stdout.write(`${p.block}\n`);
    }
    process.stdout.write('\n# Paste each block at the path shown, or re-run with --write to apply.\n');
  }
}

function parseCheckArgs(argv) {
  const out = { file: undefined, bash: undefined, min: 'medium', json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--file') out.file = argv[++i];
    else if (a.startsWith('--file=')) out.file = a.slice('--file='.length);
    else if (a === '--bash') out.bash = argv[++i];
    else if (a.startsWith('--bash=')) out.bash = a.slice('--bash='.length);
    else if (a === '--min') out.min = argv[++i];
    else if (a.startsWith('--min=')) out.min = a.slice('--min='.length);
    else if (a === '--json') out.json = true;
  }
  if (out.min !== 'high' && out.min !== 'medium') out.min = 'medium';
  return out;
}

function loadAllowlist(projectDir) {
  try {
    const p = resolve(projectDir, '.guardian', 'hooks-allowlist.json');
    if (!existsSync(p)) return [];
    const data = JSON.parse(readFileSync(p, 'utf8'));
    if (Array.isArray(data)) return data.filter((x) => typeof x === 'string');
    if (data && Array.isArray(data.secrets)) return data.secrets.filter((x) => typeof x === 'string');
  } catch {
    /* ignore */
  }
  return [];
}

function cmdCheck(argv) {
  const opts = parseCheckArgs(argv);

  if (opts.bash != null) {
    const a = assessBashCommand(opts.bash);
    if (opts.json) {
      process.stdout.write(JSON.stringify(a) + '\n');
    } else {
      const icon = a.level === 'block' ? '⛔' : a.level === 'warn' ? '⚠️ ' : '✅';
      process.stdout.write(`${icon} ${a.level.toUpperCase()}\n`);
      for (const r of a.reasons) process.stdout.write(`  • ${r}\n`);
    }
    process.exit(a.level === 'ok' ? 0 : 1);
  }

  if (opts.file != null) {
    const filePath = resolve(opts.file);
    if (!existsSync(filePath)) {
      process.stderr.write(`No such file: ${filePath}\n`);
      process.exit(2);
    }
    let text = '';
    try {
      text = readFileSync(filePath, 'utf8');
    } catch (e) {
      process.stderr.write(`Cannot read ${filePath}: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    }
    const allowlist = loadAllowlist(process.cwd());
    const hits = scanForSecrets(text, { minConfidence: opts.min, allowlist });
    if (opts.json) {
      process.stdout.write(JSON.stringify({ file: filePath, hits }) + '\n');
    } else if (hits.length === 0) {
      process.stdout.write(`✅ No secrets detected in ${opts.file}\n`);
    } else {
      process.stdout.write(`⚠️  ${hits.length} possible secret(s) in ${opts.file}:\n`);
      for (const h of hits) {
        process.stdout.write(`  • ${h.title} (${h.confidence}) — line ${h.line}: ${h.preview}\n`);
      }
    }
    process.exit(hits.length > 0 ? 1 : 0);
  }

  process.stderr.write('check: provide --file <path> or --bash "<command>"\n\n');
  usage();
  process.exit(2);
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
    usage();
    process.exit(cmd ? 0 : 1);
  }
  if (cmd === 'mcp-config') return cmdMcpConfig(argv.slice(1));
  if (cmd === 'check') return cmdCheck(argv.slice(1));

  process.stderr.write(`Unknown command: ${cmd}\n\n`);
  usage();
  process.exit(1);
}

main();
