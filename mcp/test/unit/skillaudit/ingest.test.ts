/**
 * Unit tests for `skillaudit/ingest.ts`'s symlink/junction safety.
 *
 * Measured defect (task 4 brief, item 4): `collectDir` used `statSync`,
 * which FOLLOWS symlinks and (on Windows) junctions. A skill package
 * carrying a symlink pointing outside the ingestion root — e.g.
 * `docs -> ../../../.aws` — walked straight through it: the linked
 * directory's files were read as if they belonged to the package, and their
 * CONTENT was echoed into findings. `scan_skill` exists to vet an untrusted
 * artifact before installing it; reading arbitrary host files because the
 * artifact asked nicely is the exact failure this fixes.
 */
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, afterAll } from 'vitest';
import { ingestTarget, isPathWithinRoot } from '../../../src/skillaudit/ingest.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('isPathWithinRoot', () => {
  it('accepts the root itself', () => {
    expect(isPathWithinRoot('/pkg', '/pkg')).toBe(true);
  });

  it('accepts a real subdirectory', () => {
    expect(isPathWithinRoot('/pkg/sub', '/pkg')).toBe(true);
    expect(isPathWithinRoot('/pkg/sub/deeper', '/pkg')).toBe(true);
  });

  it('rejects a path outside the root entirely', () => {
    expect(isPathWithinRoot('/other', '/pkg')).toBe(false);
  });

  it('rejects a sibling directory whose name merely starts with the root name', () => {
    // `/pkg-evil` is NOT inside `/pkg` — a naive `startsWith` string check
    // would wrongly accept it.
    expect(isPathWithinRoot('/pkg-evil/x', '/pkg')).toBe(false);
  });
});

describe('ingestTarget — symlink and junction safety', () => {
  it('never reads through a file symlink that escapes the ingestion root, and reports it instead', async () => {
    const outside = makeTempDir('guardian-ingest-outside-');
    writeFileSync(join(outside, 'credentials'), 'AKIA-SUPER-SECRET-DO-NOT-LEAK', 'utf8');

    const pkg = makeTempDir('guardian-ingest-pkg-');
    mkdirSync(join(pkg, 'docs'));
    symlinkSync(join(outside, 'credentials'), join(pkg, 'docs', 'credentials'), 'file');
    writeFileSync(join(pkg, 'SKILL.md'), '# A normal skill file\n', 'utf8');

    const result = await ingestTarget(pkg);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    try {
      // The secret's content never reaches an IngestedFile.
      expect(result.files.some((f) => f.content.includes('AKIA-SUPER-SECRET'))).toBe(false);
      expect(result.files.some((f) => f.relPath.includes('credentials'))).toBe(false);
      // The ordinary file is still ingested normally.
      expect(result.files.some((f) => f.relPath === 'SKILL.md')).toBe(true);
      // The link itself is reported — target string only.
      expect(result.symlinks).toHaveLength(1);
      const link = result.symlinks[0];
      expect(link?.relPath).toBe('docs/credentials');
      expect(link?.kind).toBe('symlink');
      expect(link?.target).toContain('credentials');
    } finally {
      result.cleanup();
    }
  });

  it('never walks into a directory symlink that escapes the ingestion root', async () => {
    const outside = makeTempDir('guardian-ingest-outside-');
    writeFileSync(join(outside, 'secret.txt'), 'TOP SECRET', 'utf8');

    const pkg = makeTempDir('guardian-ingest-pkg-');
    symlinkSync(outside, join(pkg, 'linked'), 'dir');
    writeFileSync(join(pkg, 'SKILL.md'), '# ok\n', 'utf8');

    const result = await ingestTarget(pkg);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    try {
      expect(result.files.some((f) => f.content.includes('TOP SECRET'))).toBe(false);
      expect(result.files.some((f) => f.relPath.startsWith('linked'))).toBe(false);
      expect(result.symlinks.some((s) => s.relPath === 'linked')).toBe(true);
    } finally {
      result.cleanup();
    }
  });

  it('never walks into a junction that escapes the ingestion root', async () => {
    const outside = makeTempDir('guardian-ingest-outside-');
    writeFileSync(join(outside, 'secret.txt'), 'TOP SECRET JUNCTION', 'utf8');

    const pkg = makeTempDir('guardian-ingest-pkg-');
    // `junction` is honoured on Windows; on POSIX platforms `symlinkSync`
    // treats the type hint as a no-op and creates an ordinary directory
    // symlink, which the recursive-descent guard below (`isPathWithinRoot`)
    // catches on every platform regardless of how the OS classifies it.
    symlinkSync(outside, join(pkg, 'junctioned'), 'junction');

    const result = await ingestTarget(pkg);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    try {
      expect(result.files.some((f) => f.content.includes('TOP SECRET JUNCTION'))).toBe(false);
    } finally {
      result.cleanup();
    }
  });

  it('still ingests an ordinary nested directory tree normally', async () => {
    const pkg = makeTempDir('guardian-ingest-pkg-');
    mkdirSync(join(pkg, 'lib'), { recursive: true });
    writeFileSync(join(pkg, 'lib', 'helper.js'), 'module.exports = 1;\n', 'utf8');

    const result = await ingestTarget(pkg);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    try {
      expect(result.files.some((f) => f.relPath === 'lib/helper.js')).toBe(true);
      expect(result.symlinks).toEqual([]);
    } finally {
      result.cleanup();
    }
  });
});
