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

/**
 * Fix round 5, I-4: a special scheme (http, https, ws, wss, ftp) followed by
 * `:` is a URL to WHATWG with or without `//` — `https:evil.example/mcp`
 * reaches evil.example — and a parse failure is remote.
 */
describe('remoteReasonOf: special schemes without //', () => {
  it.each([
    ['https: with no slashes', entry('npx', ['mcp-remote', 'https:evil.example/mcp'])],
    ['upper-case HTTPS:', entry('npx', ['mcp-remote', 'HTTPS:evil.example/mcp'])],
    ['ws: with no slashes', entry('node', ['server.js', '--cdp=ws:evil.example:9222'])],
    ['ftp: with no slashes', entry('node', ['server.js'], { SOURCE: 'ftp:evil.example/x' })],
    ['http: with backslashes', entry('node', ['server.js', '--url=http:\\evil.example\\x'])],
    ['a special scheme that does not parse', entry('node', ['server.js', '--url=http:'])],
    ['an IPv6 literal that does not parse', entry('node', ['server.js', '--url=https://[::1/'])],
  ])('%s', (_what, e) => {
    expect(remoteReasonOf(e)).not.toBeNull();
  });
});

/**
 * Fix round 5, LOOPBACK: `DATABASE_URL=postgres://localhost/…` must not need
 * allow_remote. Exempt is an exact parsed hostname — localhost, a 127.x.x.x
 * dotted quad, [::1] — never a prefix, never with `\` or `@` in the
 * authority, never with a query on a scheme other than http(s)/ws(s); and
 * every URL in a string is checked, not only the first.
 */
describe('remoteReasonOf: loopback URLs are local', () => {
  it.each([
    ['postgres://localhost', entry('node', ['server.js'], { DATABASE_URL: 'postgres://localhost/app' })],
    ['postgres on 127.0.0.1 with a port', entry('node', ['server.js'], { DATABASE_URL: 'postgres://127.0.0.1:5432/app' })],
    ['postgres on [::1]', entry('node', ['server.js'], { DATABASE_URL: 'postgres://[::1]/app' })],
    ['redis on [::1]', entry('node', ['server.js'], { REDIS_URL: 'redis://[::1]:6379' })],
    ['mysql on 127.0.0.1', entry('node', ['server.js'], { DB: 'mysql://127.0.0.1:3306/db' })],
    ['http://localhost with a port and a query', entry('node', ['server.js', '--api=http://localhost:3000/v1?x=1'])],
    ['ws:localhost with no slashes', entry('node', ['server.js', '--cdp=ws:localhost:9222'])],
    ['http://127.1 (WHATWG reads 127.0.0.1)', entry('node', ['server.js', '--api=http://127.1:8080/'])],
    ['http://0x7f000001 (WHATWG reads 127.0.0.1)', entry('node', ['server.js', '--api=http://0x7f000001/'])],
    ['http://[0:0:0:0:0:0:0:1] (WHATWG reads [::1])', entry('node', ['server.js', '--api=http://[0:0:0:0:0:0:0:1]/'])],
    ['two loopback URLs in one string', entry('node', ['server.js', '--a=http://localhost:1/ --b=http://127.0.0.1:2/'])],
    ['docker run with sh -c after the image', entry('docker', ['run', '-i', 'img', 'sh', '-c', 'echo hi'])],
    ['docker --context default', entry('docker', ['--context', 'default', 'run', '-i', 'img'])],
  ])('%s', (_what, e) => {
    expect(remoteReasonOf(e)).toBeNull();
  });
});

describe('remoteReasonOf: loopback look-alikes stay remote', () => {
  it.each([
    ['a localhost prefix', 'http://localhost.evil.example/'],
    ['a 127.0.0.1 prefix', 'http://127.0.0.1.evil.example/'],
    ['userinfo naming localhost', 'http://localhost@evil.example/'],
    ['userinfo before localhost', 'http://evil.example@localhost/'],
    ['credentials before localhost', 'postgres://user:pw@localhost/app'],
    ['a backslash in the authority', 'http://localhost\\@evil.example/'],
    ['a query on a database URL (libpq host=)', 'postgres://localhost/app?host=evil.example'],
    ['a multi-host database URL', 'postgres://localhost,evil.example/app'],
    ['a multi-host URL with ports (does not parse)', 'mongodb://localhost:27017,evil.example:27017/db'],
    ['an IPv4-mapped IPv6 loopback', 'http://[::ffff:127.0.0.1]/'],
    ['a DNS name that resolves to loopback', 'http://localtest.me/'],
    ['a 127.1 on a non-special scheme (opaque host)', 'postgres://127.1/app'],
    ['an octet over 255', 'postgres://127.0.0.256/app'],
    ['a remote URL after a loopback one', 'http://localhost:1/ https://evil.example/'],
  ])('%s', (_what, url) => {
    expect(remoteReasonOf(entry('node', ['server.js'], { TARGET: url }))).not.toBeNull();
  });

  it('checks a URL after a loopback one in the same argument', () => {
    expect(remoteReasonOf(entry('node', ['--a=http://localhost:1/', '--b=https://evil.example/']))).not.toBeNull();
    expect(remoteReasonOf(entry('node', ['--x=http://localhost/;https:evil.example']))).not.toBeNull();
  });

  it('a UNC path after a loopback URL is still remote', () => {
    expect(remoteReasonOf(entry('cmd', ['/c', 'curl http://localhost/ & type \\\\192.0.2.1\\s\\x']))).not.toBeNull();
  });
});

/** Fix round 5, minor 1: the command-name check reads every token of the command line. */
describe('remoteReasonOf: a remote-shell or remote-engine command anywhere in the command line', () => {
  it.each([
    ['ssh inside cmd /c', entry('cmd', ['/c', 'ssh host mcp-server'])],
    ['ssh inside sh -c', entry('sh', ['-c', 'exec ssh -T host mcp-server'])],
    ['ssh after a shell operator', entry('sh', ['-c', 'cd /tmp&&ssh host mcp-server'])],
    ['sshpass', entry('sshpass', ['-p', 'x', 'ssh', 'host'])],
    ['plink.exe by path', entry('C:\\Program Files\\PuTTY\\plink.exe', ['host', 'mcp-server'])],
    ['kubectl', entry('kubectl', ['exec', '-i', 'pod', '--', 'mcp-server'])],
    ['kubectl inside sh -c', entry('sh', ['-c', 'kubectl exec -i pod -- mcp-server'])],
    ['oc', entry('oc', ['exec', '-i', 'pod', '--', 'mcp-server'])],
    ['docker -H inside sh -c', entry('sh', ['-c', 'docker -H tcp://192.0.2.1:2375 run -i img'])],
    ['docker --context inside cmd /c', entry('cmd', ['/c', 'docker --context prod run -i img'])],
    ['docker -c as a global flag', entry('docker', ['-c', 'prod', 'run', '-i', 'img'])],
    ['nerdctl --host', entry('nerdctl', ['--host', '/run/other.sock', 'run', '-i', 'img'])],
    ['podman --connection', entry('podman', ['--connection', 'prod', 'run', '-i', 'img'])],
    ['podman --url', entry('podman', ['--url=unix:///run/other.sock', 'run', '-i', 'img'])],
    ['podman -r as a global flag', entry('podman', ['-r', 'run', '-i', 'img'])],
    ['CONTAINER_CONNECTION for podman', entry('podman', ['run', '-i', 'img'], { CONTAINER_CONNECTION: 'prod' })],
  ])('%s', (_what, e) => {
    expect(remoteReasonOf(e)).not.toBeNull();
  });
});

/** Fix round 5, minor 2: the reason names the host — `origin` is "null" for a non-special scheme. */
describe('remoteReasonOf: the reason names the host', () => {
  it('names the host of a database URL', () => {
    const reason = remoteReasonOf(entry('node', ['server.js'], { DATABASE_URL: 'postgres://db.example/app' }));
    expect(reason).toContain('db.example');
    expect(reason).not.toContain('null');
  });
});
