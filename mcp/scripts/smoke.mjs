#!/usr/bin/env node
/**
 * Smoke test for the dev-guardian MCP server.
 *
 * Spawns `node dist/server.js`, sends a single JSON-RPC `initialize`
 * followed by `tools/list` and `resources/list` over stdio, prints
 * counts, and exits non-zero on any handshake failure. Designed for CI
 * and the post-Phase-13 final-checklist task.
 */

import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const SERVER = resolve(root, 'dist', 'server.js');

const child = spawn('node', [SERVER], {
  stdio: ['pipe', 'pipe', 'inherit'],
  env: { ...process.env, NO_COLOR: '1' },
});

const pending = new Map();
let nextId = 1;
let buf = '';
let exitCode = 0;

child.stdout.on('data', (chunk) => {
  buf += chunk.toString('utf8');
  let nl = buf.indexOf('\n');
  while (nl !== -1) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    nl = buf.indexOf('\n');
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      if (msg.id !== undefined && pending.has(msg.id)) {
        const { resolve: r } = pending.get(msg.id);
        pending.delete(msg.id);
        r(msg);
      }
    } catch (e) {
      console.error('FAIL: bad stdout line:', line, e);
      exitCode = 1;
    }
  }
});

function send(method, params = {}) {
  const id = nextId++;
  const message = { jsonrpc: '2.0', id, method, params };
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify(message) + '\n');
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error(`timeout waiting for ${method} (id ${id})`));
      }
    }, 10000);
  });
}

try {
  const init = await send('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'smoke', version: '0.0.0' },
  });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);

  child.stdin.write(
    JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n',
  );

  const tools = await send('tools/list');
  const resources = await send('resources/list');

  const toolCount = tools.result?.tools?.length ?? -1;
  const resourceCount = resources.result?.resources?.length ?? -1;
  console.log(`OK tools=${toolCount} resources=${resourceCount} server=${init.result?.serverInfo?.name ?? '?'}`);
} catch (e) {
  console.error('FAIL', e.message);
  exitCode = 1;
} finally {
  child.kill();
  process.exit(exitCode);
}
