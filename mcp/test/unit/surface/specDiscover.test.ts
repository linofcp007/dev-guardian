import { afterAll, describe, expect, it } from 'vitest';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { discoverSpecs, MAX_SPEC_FILES } from '../../../src/surface/specDiscover.js';
import { makeTempDir, cleanupTempDirs } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function project(files: Record<string, string>): string {
  const dir = makeTempDir('guardian-spec-');
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
    const outer = makeTempDir('guardian-outer-');
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

  // Measured on VAmPI (erev0s/VAmPI f16052d): its only route table is
  // `openapi_specs/openapi3.yml`, and discovery found nothing — the base name
  // is `openapi3`, the directory `openapi_specs`, and both rules matched
  // whole names only. `spec_paths` read the same file as 14 routes.
  it('T-01 finds a document whose name or directory only starts with openapi/swagger, or ends .openapi', () => {
    const dir = project({
      'openapi_specs/openapi3.yml': 'openapi: 3.0.0\npaths: {}\n',
      'docs/petstore.openapi.yaml': "swagger: '2.0'\npaths: {}\n",
      'swagger-docs/v2.json': '{"swagger": "2.0", "paths": {}}',
    });
    const names = discoverSpecs(dir).specs.map((s) => relative(dir, s.file).split(sep).join('/')).sort();
    expect(names).toEqual(['docs/petstore.openapi.yaml', 'openapi_specs/openapi3.yml', 'swagger-docs/v2.json']);
  });

  it('T-02 keeps the exact names as before and lists a widened candidate only when it declares openapi/swagger', () => {
    const dir = project({
      // Exact names: discovered whatever they hold, as before (US-1.AC-2).
      'openapi.yaml': 'not a spec',
      'docs/openapi/v1.yml': 'also not a spec',
      // Widened names without a top-level openapi/swagger key (EC-1).
      'openapi-generator-config.yaml': 'generatorName: typescript-axios\n',
      'openapitools.json': '{"generator-cli": {"version": "7.0.0"}}',
      'swagger-ui-config.json': '{"url": "/openapi.json"}',
      // Quoted keys, JSON and YAML (EC-2).
      'api-docs/public.json': '{ "openapi" : "3.1.0", "paths": {} }',
      "openapi.public.yaml": "'swagger': '2.0'\npaths: {}\n",
      // Excluded directories stay excluded (EC-3).
      'node_modules/pkg/openapi3.yml': 'openapi: 3.0.0\n',
    });
    const names = discoverSpecs(dir).specs.map((s) => relative(dir, s.file).split(sep).join('/')).sort();
    expect(names).toEqual(['api-docs/public.json', 'docs/openapi/v1.yml', 'openapi.public.yaml', 'openapi.yaml']);
  });

  it('T-03 reads every exact-name candidate before the widened ones when the cap truncates', () => {
    const files: Record<string, string> = { 'openapi.yaml': 'openapi: 3.0.0\n', 'swagger.json': '{"swagger": "2.0"}' };
    for (let i = 0; i < MAX_SPEC_FILES + 5; i += 1) files[`openapi_specs/s${String(i).padStart(2, '0')}.yaml`] = 'openapi: 3.0.0\n';
    const dir = project(files);
    const out = discoverSpecs(dir);
    const names = out.specs.map((s) => relative(dir, s.file).split(sep).join('/'));
    expect(names).toContain('openapi.yaml');
    expect(names).toContain('swagger.json');
    expect(out.specs.length).toBeLessThanOrEqual(MAX_SPEC_FILES);
    expect(out.truncated).toBe(true);
  });
});
