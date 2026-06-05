#!/usr/bin/env node
/**
 * dev-guardian CLI — universal entry point (no MCP connection required).
 *
 * Today it has one command, `mcp-config`, which bootstraps dev-guardian into any
 * AI host from a plain terminal — it fills in the absolute path to the MCP
 * server for you, so there is no chicken-and-egg (unlike calling a tool that
 * needs the server to already be wired up).
 *
 *   node bin/dev-guardian.mjs mcp-config <host|all> [--write]
 *        [--scope project|global] [--project <path>] [--force]
 *
 * Default: print the ready-to-paste config block (+ where it goes).
 * --write:  merge it into the project and drop the rules file.
 *
 * Hosts: cursor · windsurf · copilot · cline · codex · gemini · claude-desktop.
 * Requires a built server (`cd mcp && npm install && npm run build`).
 */

import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_HOSTS } from '../mcp/dist/hostsetup/hostSpecs.js';
import { previewMcpConfig, setupHost } from '../mcp/dist/hostsetup/setup.js';
import { detectOs } from '../mcp/dist/platform/osDetect.js';

const HERE = dirname(fileURLToPath(import.meta.url)); // <plugin>/bin
const ROOT = resolve(HERE, '..'); // <plugin>
const SERVER_JS = resolve(ROOT, 'mcp', 'dist', 'server.js');
const HOST_RULES_DIR = resolve(ROOT, 'host-rules');
const VALID_HOSTS = new Set([...ALL_HOSTS, 'all']);

function usage() {
  process.stdout.write(`dev-guardian — wire the MCP server into any AI host (no MCP connection needed)

Usage:
  node bin/dev-guardian.mjs mcp-config <host|all> [options]

Hosts: ${[...ALL_HOSTS].join(', ')}, all

Options:
  --write              Write/merge into the project (+ drop the rules file)
  --scope project|global   MCP scope (default project; windsurf & claude-desktop are global-only)
  --project <path>     Target project directory (default: current directory)
  --force              Overwrite an existing rules file / update a differing MCP entry

Examples:
  node bin/dev-guardian.mjs mcp-config cursor          # print the block to paste
  node bin/dev-guardian.mjs mcp-config all             # every host
  node bin/dev-guardian.mjs mcp-config codex --write   # write + merge into the project
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

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
    usage();
    process.exit(cmd ? 0 : 1);
  }
  if (cmd !== 'mcp-config') {
    process.stderr.write(`Unknown command: ${cmd}\n\n`);
    usage();
    process.exit(1);
  }

  const args = parseArgs(argv.slice(1));
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

main();
