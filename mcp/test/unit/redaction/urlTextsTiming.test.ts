/**
 * deps-tools-host-other-texts, task 1: the GUARD test T-03 — the SHAPE of the cost of the sites the fix will make read
 * a text once more (a requirement line's comment, an argument's URLs, a restore error line, a lock's lines). Eight times
 * the input must cost well under 22.6 times as much (`expectLinear`, test/helpers/timing.ts): linear reads about 8,
 * quadratic about 64. It asserts a shape, never milliseconds, and is green on the tree before the fix: a rule the fix
 * adds that reads a text once per word, or once per `@`, turns it red. If this is NOT green before the fix, that is a
 * new finding: stop and say so.
 *
 * Every function measured is synchronous, which `expectLinear` requires. Each input is built once per size (the file
 * on disk too), outside the measured call.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, it } from 'vitest';
import type { McpServerEntry } from '../../../src/agentaudit/mcpServers.js';
import { classifyRestoreFailure } from '../../../src/deps/dotnetRestore.js';
import { checkRequirements } from '../../../src/deps/pipRequirements.js';
import { checkNpmSources } from '../../../src/fixpr/repoPackageConfig.js';
import { remoteReasonOf } from '../../../src/mcpaudit/launch.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { expectLinear } from '../../helpers/timing.js';

afterAll(cleanupTempDirs);

const FEATURE = 'deps-tools-host-other-texts';
const H = 'host.example';

/** The input of one size, built once: the second call for the same size is a lookup. */
function once<T>(build: (n: number) => T): (n: number) => T {
  const made = new Map<number, T>();
  return (n) => {
    const hit = made.get(n);
    if (hit !== undefined) return hit;
    const fresh = build(n);
    made.set(n, fresh);
    return fresh;
  };
}

/** A project directory holding one file of `n` lines, built once per size. */
const fileOf = (name: string, line: (i: number) => string, tail = ''): ((n: number) => string) =>
  once((n) => {
    const dir = makeTempDir('dg-urltiming-');
    const text = `${Array.from({ length: n }, (_, i) => line(i)).join('\n')}\n${tail}`;
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, name), text);
    return dir;
  });

describe(`${FEATURE} T-03 protection: eight times the text costs well under 22.6 times as much`, () => {
  const requirementsOf = fileOf('requirements.txt', (i) => `n${String(i)}==1.0 # a note for x@y`);
  it('T-03 checkRequirements over N accepted lines, each with a comment that holds an @', () => {
    expectLinear('checkRequirements, a comment with an @ on every line', (n) => void checkRequirements(requirementsOf(n), ['requirements.txt']), 500);
  }, 120_000);

  const argumentOf = once((n) => Array.from({ length: n }, (_, i) => `http://127.0.0.1:${String(i + 1)}/`).join(' '));
  it('T-03 remoteReasonOf over an argument with N loopback URLs', () => {
    expectLinear(
      'remoteReasonOf, N loopback URLs in one argument',
      (n) => {
        const entry: McpServerEntry = { sourceLabel: '.mcp.json', name: 's', command: 'node', args: [argumentOf(n)], raw: {} };
        void remoteReasonOf(entry);
      },
      500,
    );
  }, 120_000);

  const errorLineOf = once((n) => `error NU1301: Unable to load the service index for source ${Array.from({ length: n }, (_, i) => `https://${H}/${String(i)}/index.json`).join(' ')} then x@y.`);
  it('T-03 classifyRestoreFailure over an error line with N URLs and an @ at the end', () => {
    expectLinear('classifyRestoreFailure, N URLs and an @ at the end of the line', (n) => void classifyRestoreFailure('', errorLineOf(n)), 500);
  }, 120_000);

  const yarnOf = fileOf('yarn.lock', (i) => `  resolved "https://${H}/${String(i)}.tgz"`, `  resolved "//${H}/share/x.tgz"\n`);
  it('T-03 checkNpmSources over a yarn.lock of N lines with https URLs and a network path at the end', () => {
    expectLinear('checkNpmSources, a yarn.lock of N https lines and a network path at the end', (n) => void checkNpmSources(yarnOf(n)), 500);
  }, 120_000);
});
