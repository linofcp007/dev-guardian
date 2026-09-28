/**
 * Every exact pin of a PyPI distribution the project's own manifests hold —
 * what lets the dependency provider tell "the project pins one version" from
 * "an import may load a different pin" (review of part C, N1).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { makePypiPinResolver } from '../../../src/validate/pypiPins.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

function write(root: string, rel: string, content: string): void {
  const path = join(root, ...rel.split('/'));
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content, 'utf8');
}

describe('makePypiPinResolver', () => {
  const root = makeTempDir('guardian-pypi-pins-');
  write(root, 'deploy/requirements.txt', [
    '# production pins',
    'pyyaml==5.3',
    'Flask>=2.0',
    "requests==2.31.0 ; python_version >= '3.8'",
    '-r base.txt',
    'Pillow[extras]==10.0.0 \\',
    '    --hash=sha256:abc',
    '',
  ].join('\n'));
  write(root, 'requirements/base.txt', 'PyYAML==5.3\n');
  write(root, 'dev-requirements.txt', 'pyyaml==6.0.1  # newer for tests\n');
  write(root, 'svc/Pipfile.lock', JSON.stringify({ default: { pyyaml: { version: '==5.4' } }, develop: {} }));
  write(root, 'tool/poetry.lock', '[[package]]\nname = "PyYAML"\nversion = "6.0"\n\n[[package]]\nname = "flask"\nversion = "3.0.0"\n');
  write(root, 'node_modules/x/requirements.txt', 'pyyaml==1.0\n');
  write(root, 'docs/notes.txt', 'pyyaml==9.9\n');
  const pins = makePypiPinResolver(root);

  it('reads the exact pins of every requirement layout and lockfile, at any depth, by normalised name', () => {
    expect(pins('PyYAML')).toEqual([
      { manifest: 'deploy/requirements.txt', version: '5.3' },
      { manifest: 'dev-requirements.txt', version: '6.0.1' },
      { manifest: 'requirements/base.txt', version: '5.3' },
      { manifest: 'svc/Pipfile.lock', version: '5.4' },
      { manifest: 'tool/poetry.lock', version: '6.0' },
    ]);
  });

  it('reads a pin with extras, an environment marker or a continued hash line; a range is no pin', () => {
    expect(pins('pillow')).toEqual([{ manifest: 'deploy/requirements.txt', version: '10.0.0' }]);
    expect(pins('requests')).toEqual([{ manifest: 'deploy/requirements.txt', version: '2.31.0' }]);
    expect(pins('flask')).toEqual([{ manifest: 'tool/poetry.lock', version: '3.0.0' }]);
    expect(pins('left-pad')).toEqual([]);
  });

  it('answers null — cannot tell — when a manifest could not be read', () => {
    const broken = makeTempDir('guardian-pypi-pins-broken-');
    write(broken, 'Pipfile.lock', '{ not json');
    expect(makePypiPinResolver(broken)('pyyaml')).toBeNull();
  });
});
