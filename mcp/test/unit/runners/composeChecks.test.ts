/**
 * Docker Compose hardening checks (task 15, brief item 3): `/guardian-docker`
 * promised checks for privileged containers, host networking, a mounted
 * `docker.sock`, and `:latest` image tags — none of which `scan_containers`
 * ever ran. Pure function over the compose file's text; no scanner involved.
 */

import { describe, expect, it } from 'vitest';
import { checkCompose } from '../../../src/runners/composeChecks.js';

function rule(findings: ReturnType<typeof checkCompose>, id: string) {
  return findings.filter((f) => f.rule_id === id);
}

describe('checkCompose', () => {
  it('flags a privileged service', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    privileged: true
`;
    const findings = checkCompose(yaml, 'docker-compose.yml');
    expect(rule(findings, 'compose-privileged')).toHaveLength(1);
    expect(rule(findings, 'compose-privileged')[0]?.file_path).toBe('docker-compose.yml');
  });

  it('does not flag a service without privileged, or with privileged: false', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    privileged: false
  other:
    image: myapp:1.0
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-privileged')).toHaveLength(0);
  });

  it('flags host network mode', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    network_mode: host
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-host-network')).toHaveLength(1);
  });

  it('does not flag a normal network_mode', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    network_mode: bridge
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-host-network')).toHaveLength(0);
  });

  it('flags a mounted docker.sock, short syntax', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-docker-sock')).toHaveLength(1);
  });

  it('flags a mounted docker.sock, long (object) syntax', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-docker-sock')).toHaveLength(1);
  });

  it('does not flag an ordinary named volume or bind mount', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    volumes:
      - app-data:/data
      - ./config:/etc/app
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-docker-sock')).toHaveLength(0);
  });

  it('flags an explicit :latest tag', () => {
    const yaml = `
services:
  app:
    image: myapp:latest
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-latest-tag')).toHaveLength(1);
  });

  it('flags an image with no tag at all (implicit :latest)', () => {
    const yaml = `
services:
  app:
    image: myapp
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-latest-tag')).toHaveLength(1);
  });

  it('does not flag a pinned tag', () => {
    const yaml = `
services:
  app:
    image: myapp:1.4.2
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-latest-tag')).toHaveLength(0);
  });

  it('does not flag an image pinned by digest', () => {
    const yaml = `
services:
  app:
    image: myapp@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-latest-tag')).toHaveLength(0);
  });

  it('does not flag a tagged image on a registry with a port in its host (colon before the last slash)', () => {
    const yaml = `
services:
  app:
    image: registry.internal:5000/team/myapp:1.4.2
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-latest-tag')).toHaveLength(0);
  });

  it('flags an unpinned image on a registry with a port in its host', () => {
    const yaml = `
services:
  app:
    image: registry.internal:5000/team/myapp
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-latest-tag')).toHaveLength(1);
  });

  it('checks every service, not just the first', () => {
    const yaml = `
services:
  a:
    image: a:latest
  b:
    image: b:latest
`;
    expect(rule(checkCompose(yaml, 'c.yml'), 'compose-latest-tag')).toHaveLength(2);
  });

  it('returns no findings for a clean compose file', () => {
    const yaml = `
services:
  app:
    image: myapp:1.4.2
    volumes:
      - app-data:/data
`;
    expect(checkCompose(yaml, 'c.yml')).toEqual([]);
  });

  it('returns no findings, never throws, on a file with no services block', () => {
    expect(checkCompose('version: "3"\n', 'c.yml')).toEqual([]);
  });

  it('returns no findings, never throws, on unparseable YAML', () => {
    expect(checkCompose('not: [valid: yaml: at all', 'c.yml')).toEqual([]);
  });

  it('every finding is category=security and carries a fix-oriented message', () => {
    const yaml = `
services:
  app:
    image: myapp:1.0
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`;
    const findings = checkCompose(yaml, 'c.yml');
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.category).toBe('security');
      expect(f.tool).toBe('docker-compose');
      expect(f.message?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
