import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { discoverSpecs, MAX_SPEC_FILES } from '../../../src/surface/specDiscover.js';

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-spec-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

describe('discoverSpecs', () => {
  it('finds the conventional names at the project root', () => {
    const dir = project({
      'openapi.yaml': 'a', 'swagger.json': 'b', 'api-docs.json': 'c', 'README.md': 'd',
    });
    expect(discoverSpecs(dir).specs.map((s) => s.file.split(/[\\/]/).pop()).sort())
      .toEqual(['api-docs.json', 'openapi.yaml', 'swagger.json']);
  });

  it('finds documents inside an openapi/ directory', () => {
    const dir = project({ 'docs/openapi/v1.yml': 'a' });
    expect(discoverSpecs(dir).specs).toHaveLength(1);
  });

  it('skips node_modules and the other excluded directories', () => {
    const dir = project({ 'node_modules/pkg/openapi.yaml': 'a', 'dist/openapi.yaml': 'b' });
    expect(discoverSpecs(dir).specs).toEqual([]);
  });

  it('reads the file contents', () => {
    const dir = project({ 'openapi.yaml': 'openapi: "3.0.0"' });
    expect(discoverSpecs(dir).specs[0]?.text).toBe('openapi: "3.0.0"');
  });

  it('uses the explicit list instead of discovery when given one', () => {
    const dir = project({ 'openapi.yaml': 'discovered', 'custom/thing.yaml': 'explicit' });
    const out = discoverSpecs(dir, [join(dir, 'custom', 'thing.yaml')]);
    expect(out.specs).toHaveLength(1);
    expect(out.specs[0]?.text).toBe('explicit');
  });

  it('reports an explicit path that does not exist rather than throwing', () => {
    const dir = project({});
    expect(discoverSpecs(dir, [join(dir, 'missing.yaml')]).specs).toEqual([]);
  });

  it('reports the file cap instead of silently returning the first N', () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < MAX_SPEC_FILES + 3; i += 1) files[`openapi/s${i}.yaml`] = 'x';
    const out = discoverSpecs(project(files));
    expect(out.specs).toHaveLength(MAX_SPEC_FILES);
    expect(out.truncated).toBe(true);
  });

  it('reports an oversized file instead of reading it', () => {
    const dir = project({ 'openapi.yaml': 'x'.repeat(6 * 1024 * 1024) });
    const out = discoverSpecs(dir);
    expect(out.specs).toEqual([]);
    expect(out.oversized).toHaveLength(1);
  });

  it('does not match a project that merely lives beneath an ancestor directory named openapi', () => {
    // The project root itself sits under .../openapi/my-service — no
    // directory *inside* the project is named openapi. A file under an
    // unrelated subdirectory must not be swept in just because some
    // ancestor of the project root happens to be called "openapi".
    const outer = mkdtempSync(join(tmpdir(), 'guardian-outer-'));
    const projectRoot = join(outer, 'openapi', 'my-service');
    mkdirSync(join(projectRoot, 'config'), { recursive: true });
    writeFileSync(join(projectRoot, 'config', 'random-unrelated.yml'), 'not: a spec');

    expect(discoverSpecs(projectRoot).specs).toEqual([]);
  });

  it('dedupes explicit entries that resolve to the same file', () => {
    // Measured bug: two spellings of the same document — a clean path and
    // one carrying a redundant `.` segment — were read (and imported) twice,
    // silently doubling that document's routes and inflating
    // spec_routes_total / matched / spec_only downstream, even though
    // classification itself stayed correct. Built with raw string
    // concatenation, not `join`/`resolve`, so the `.` segment survives into
    // the candidate list exactly as a caller might type it.
    const dir = project({ 'openapi.yaml': 'openapi: "3.0.0"\npaths: {}\n' });
    const clean = join(dir, 'openapi.yaml');
    const withDotSegment = `${dir}${sep}.${sep}openapi.yaml`;

    const out = discoverSpecs(dir, [clean, withDotSegment]);
    expect(out.specs).toHaveLength(1);
  });

  it('applies the file cap to an over-cap explicit list too', () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < MAX_SPEC_FILES + 10; i += 1) files[`spec${i}.yaml`] = 'x';
    const dir = project(files);
    const explicit = Object.keys(files).map((rel) => join(dir, rel));

    const out = discoverSpecs(dir, explicit);
    expect(out.specs).toHaveLength(MAX_SPEC_FILES);
    expect(out.truncated).toBe(true);
  });
});
