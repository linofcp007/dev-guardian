/**
 * `toolProjectPath` — the one opening every tool's `project_path` goes
 * through (dg-maint finding 14): the resolved path, or the refusal a handler
 * returns as it is, coded as `projectPathErrorCode` codes it.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { resolveProjectPath } from '../../../src/platform/projectPath.js';
import { toolProjectPath } from '../../../src/tools/projectArg.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('toolProjectPath', () => {
  it('an existing directory resolves to the path resolveProjectPath gives', () => {
    const dir = makeTempDir('projarg-');
    expect(toolProjectPath(dir)).toBe(resolveProjectPath(dir).path);
  });

  it('no project_path is the working directory, as before', () => {
    expect(toolProjectPath(undefined)).toBe(resolveProjectPath(undefined).path);
  });

  it('a path that does not exist is target_not_found; a file is unsupported_target — each with its message', () => {
    const dir = makeTempDir('projarg-');
    const missing = toolProjectPath(join(dir, 'nope'));
    expect(missing).toMatchObject({ ok: false, error: { code: 'target_not_found', message: expect.stringContaining('nope') } });
    const file = join(dir, 'f.txt');
    writeFileSync(file, 'x');
    expect(toolProjectPath(file)).toMatchObject({ ok: false, error: { code: 'unsupported_target' } });
  });

  it.runIf(process.platform === 'win32')('a network path is refused before any file call', () => {
    expect(toolProjectPath('\\\\nohost.invalid\\share\\proj')).toMatchObject({ ok: false, error: { code: 'unsupported_target' } });
  });
});
