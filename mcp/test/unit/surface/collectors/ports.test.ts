import { describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectPorts } from '../../../../src/surface/collectors/ports.js';

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-ports-'));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

describe('collectPorts', () => {
  it('reads EXPOSE directives from a Dockerfile', () => {
    const dir = project({ Dockerfile: 'FROM node:20\nEXPOSE 3000\nEXPOSE 8080/tcp\n' });
    expect(collectPorts(dir)).toEqual([
      { port: 3000, source: 'Dockerfile' },
      { port: 8080, source: 'Dockerfile' },
    ]);
  });

  it('reads short-form compose port mappings', () => {
    const dir = project({
      'docker-compose.yml': 'services:\n  web:\n    ports:\n      - "8000:80"\n      - 9000\n',
    });
    expect(collectPorts(dir)).toEqual([
      { port: 8000, source: 'docker-compose.yml' },
      { port: 9000, source: 'docker-compose.yml' },
    ]);
  });

  it('reads long-form compose port mappings', () => {
    const dir = project({
      'compose.yml': 'services:\n  web:\n    ports:\n      - target: 80\n        published: 8080\n',
    });
    expect(collectPorts(dir)).toEqual([{ port: 8080, source: 'compose.yml' }]);
  });

  it('returns an empty array when no container files exist', () => {
    expect(collectPorts(project({ 'README.md': 'hi' }))).toEqual([]);
  });

  it('ignores unparseable port values instead of emitting NaN', () => {
    const dir = project({ Dockerfile: 'EXPOSE $PORT\nEXPOSE 3000\n' });
    expect(collectPorts(dir)).toEqual([{ port: 3000, source: 'Dockerfile' }]);
  });
});
