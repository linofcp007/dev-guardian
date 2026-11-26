/**
 * The file the `metrics` command reads (`src/metrics/metricFile.ts`): at most
 * `readBytes` of it, from its END (the lines printed last win), the cut line
 * never read; a directory or a FIFO refused, never waited on; UTF-16 read as
 * `check --file` reads it.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { readMetricFile } from '../../../src/metrics/metricFile.js';
import { readMetricOutput } from '../../../src/metrics/metricLine.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

describe('readMetricFile', () => {
  it('reads a whole file under the bound', () => {
    const dir = makeTempDir('metric-file-');
    const file = join(dir, 'out.txt');
    writeFileSync(file, 'METRIC a=1\nMETRIC b=2\n');
    expect(readMetricFile(file)).toEqual({ ok: true, text: 'METRIC a=1\nMETRIC b=2\n', truncated: false });
  });

  it('past the bound, reads the tail, says it, and its cut first line is never a line', () => {
    const dir = makeTempDir('metric-file-');
    const file = join(dir, 'out.txt');
    // `echo 'METRIC x=1'` cut after its first 7 bytes reads `METRIC x=1'` — a valid-looking line.
    const text = "METRIC early=1\n+ echo 'METRIC x=1'\nMETRIC late=2\n";
    writeFileSync(file, text);
    const cut = text.length - text.indexOf("METRIC x=1'");
    const read = readMetricFile(file, cut);
    expect(read).toEqual({ ok: true, text: text.slice(text.length - cut), truncated: true });
    if (!read.ok) return;
    const o = readMetricOutput(read.text, { truncated: read.truncated });
    expect([...o.metrics.keys()]).toEqual(['late']);
    expect(o.dropped).toEqual(['readBytes']);
  });

  it('reads UTF-16LE with a byte-order mark (PowerShell 5.1)', () => {
    const dir = makeTempDir('metric-file-');
    const file = join(dir, 'out.txt');
    writeFileSync(file, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('METRIC a=1 ms\r\n', 'utf16le')]));
    const read = readMetricFile(file);
    expect(read).toEqual({ ok: true, text: 'METRIC a=1 ms\r\n', truncated: false });
  });

  it('refuses what is not there, a directory, and (POSIX) a FIFO without waiting on it', () => {
    const dir = makeTempDir('metric-file-');
    expect(readMetricFile(join(dir, 'missing.txt'))).toEqual({ ok: false, reason: 'no such file' });
    mkdirSync(join(dir, 'sub'));
    expect(readMetricFile(join(dir, 'sub'))).toEqual({ ok: false, reason: 'a directory, not a file' });
    if (process.platform !== 'win32') {
      const fifo = join(dir, 'fifo');
      expect(spawnSync('mkfifo', [fifo]).status).toBe(0);
      expect(readMetricFile(fifo)).toEqual({ ok: false, reason: 'not a regular file' });
    }
  });
});
