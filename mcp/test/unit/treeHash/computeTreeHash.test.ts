import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { computeTreeHash } from '../../../src/treeHash/computeTreeHash.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function fixture(): string {
  const dir = makeTempDir('dev-guardian-treehash-');
  return dir;
}

describe('computeTreeHash (filesystem walk)', () => {
  it('is deterministic across two runs', async () => {
    const dir = fixture();
    writeFileSync(join(dir, 'a.txt'), 'hello');
    mkdirSync(join(dir, 'sub'));
    writeFileSync(join(dir, 'sub', 'b.txt'), 'world');

    const h1 = await computeTreeHash(dir, { forceFilesystemWalk: true });
    const h2 = await computeTreeHash(dir, { forceFilesystemWalk: true });
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes when a single byte changes', async () => {
    const dir = fixture();
    writeFileSync(join(dir, 'a.txt'), 'hello');
    const before = await computeTreeHash(dir, { forceFilesystemWalk: true });

    writeFileSync(join(dir, 'a.txt'), 'hellp');
    const after = await computeTreeHash(dir, { forceFilesystemWalk: true });
    expect(before).not.toBe(after);
  });

  it('excludes .guardian/, node_modules/, .git/ from the walk', async () => {
    const dir = fixture();
    writeFileSync(join(dir, 'a.txt'), 'real');

    const baseline = await computeTreeHash(dir, { forceFilesystemWalk: true });

    mkdirSync(join(dir, '.guardian'));
    writeFileSync(join(dir, '.guardian', 'noise.json'), 'x');
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'node_modules', 'pkg.txt'), 'y');
    mkdirSync(join(dir, '.git'));
    writeFileSync(join(dir, '.git', 'HEAD'), 'z');

    const afterNoise = await computeTreeHash(dir, { forceFilesystemWalk: true });
    expect(baseline).toBe(afterNoise);
  });

  it('hash depends only on contents, not on directory entry order', async () => {
    const dirA = fixture();
    writeFileSync(join(dirA, 'a.txt'), '1');
    writeFileSync(join(dirA, 'b.txt'), '2');

    const dirB = fixture();
    // Different write order
    writeFileSync(join(dirB, 'b.txt'), '2');
    writeFileSync(join(dirB, 'a.txt'), '1');

    expect(await computeTreeHash(dirA, { forceFilesystemWalk: true })).toBe(
      await computeTreeHash(dirB, { forceFilesystemWalk: true }),
    );
  });
});
