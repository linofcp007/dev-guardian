import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  hashInput,
  hashRulePacks,
  scanCacheKey,
  stableStringify,
  surfaceCacheKey,
  type ScanCacheKeyParts,
  type SurfaceCacheKeyParts,
} from '../../../src/treeHash/cacheKey.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const SCAN: ScanCacheKeyParts = {
  projectPath: '/work/app',
  tool: 'scan_containers',
  scanType: 'containers',
  treeHash: 'a'.repeat(64),
  inputHash: hashInput({ image: 'nginx:1.19' }),
  pluginVersion: '2.0.0',
  rulePacksHash: hashRulePacks([]),
};

const SURFACE: SurfaceCacheKeyParts = {
  projectPath: '/work/app',
  treeHash: 'a'.repeat(64),
  routesPackHash: hashRulePacks([]),
  pluginVersion: '2.0.0',
  includeEnvVars: true,
};

describe('stableStringify / hashInput', () => {
  it('is independent of object key order at every depth, and drops undefined members', () => {
    expect(stableStringify({ b: 1, a: { d: [2, 1], c: undefined, e: 'x' } })).toBe(
      stableStringify({ a: { e: 'x', d: [2, 1] }, b: 1 }),
    );
    expect(hashInput({ base_ref: 'main', head_ref: 'HEAD' })).toBe(
      hashInput({ head_ref: 'HEAD', base_ref: 'main' }),
    );
  });

  it('keeps array order and distinguishes values', () => {
    expect(hashInput({ x: [1, 2] })).not.toBe(hashInput({ x: [2, 1] }));
    expect(hashInput({ image: 'nginx:1.19' })).not.toBe(hashInput({ image: 'nginx:1.20' }));
    expect(hashInput({})).not.toBe(hashInput({ image: 'nginx:1.19' }));
  });
});

describe('scanCacheKey', () => {
  it('changes when any single part changes', () => {
    const base = scanCacheKey(SCAN);
    const variants: Array<Partial<ScanCacheKeyParts>> = [
      { projectPath: '/work/other' },
      { tool: 'deps_audit' },
      { scanType: 'deps' },
      { treeHash: 'b'.repeat(64) },
      { inputHash: hashInput({}) },
      { pluginVersion: '2.0.1' },
      { rulePacksHash: hashRulePacks(['p/php']) },
    ];
    for (const variant of variants) {
      expect(scanCacheKey({ ...SCAN, ...variant }), JSON.stringify(variant)).not.toBe(base);
    }
    expect(scanCacheKey({ ...SCAN })).toBe(base);
  });
});

describe('surfaceCacheKey', () => {
  it('changes with project, tree, routes pack, plugin version and include_env_vars', () => {
    const base = surfaceCacheKey(SURFACE);
    const variants: Array<Partial<SurfaceCacheKeyParts>> = [
      { projectPath: '/work/other' },
      { treeHash: 'b'.repeat(64) },
      { routesPackHash: hashRulePacks(['p/php']) },
      { pluginVersion: '2.0.1' },
      { includeEnvVars: false },
    ];
    for (const variant of variants) {
      expect(surfaceCacheKey({ ...SURFACE, ...variant }), JSON.stringify(variant)).not.toBe(base);
    }
  });
});

describe('hashRulePacks', () => {
  it('keys a local file by its content', () => {
    const dir = makeTempDir('guardian-packs-');
    const pack = join(dir, 'rules.yml');
    writeFileSync(pack, 'rules: []\n');
    const before = hashRulePacks([pack]);
    expect(hashRulePacks([pack])).toBe(before);
    writeFileSync(pack, 'rules:\n  - id: x\n');
    expect(hashRulePacks([pack])).not.toBe(before);
  });

  it('keys a directory config by the content of every file under it', () => {
    const dir = makeTempDir('guardian-packs-dir-');
    mkdirSync(join(dir, 'nested'));
    writeFileSync(join(dir, 'a.yml'), 'rules: []\n');
    writeFileSync(join(dir, 'nested', 'b.yml'), 'rules: []\n');
    const before = hashRulePacks([dir]);
    writeFileSync(join(dir, 'nested', 'b.yml'), 'rules:\n  - id: y\n');
    expect(hashRulePacks([dir])).not.toBe(before);
  });

  it('keys a registry pack by its name, and the list by its order', () => {
    expect(hashRulePacks(['p/php'])).not.toBe(hashRulePacks(['p/wordpress']));
    expect(hashRulePacks(['p/php', 'p/wordpress'])).not.toBe(hashRulePacks(['p/wordpress', 'p/php']));
    expect(hashRulePacks([])).not.toBe(hashRulePacks(['auto']));
  });
});
