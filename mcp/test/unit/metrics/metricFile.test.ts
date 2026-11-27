/**
 * The file the `metrics` command reads (`src/metrics/metricFile.ts`): at most
 * `readBytes` of it, from its END (the lines printed last win), the cut line
 * never read; a directory or a FIFO refused, never waited on; UTF-16 read as
 * `check --file` reads it. And every case of `metric-bytes/1` read in the file
 * mode, as its `file` column decides (the fixture: metricBytesFixture.test.ts).
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { readMetricFile } from '../../../src/metrics/metricFile.js';
import { type MetricOutput, type MetricReading, readMetricOutput } from '../../../src/metrics/metricLine.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

interface Reading {
  value: number;
  unit: string | null;
  better: string | null;
  tolerance: { amount: number; percent: boolean } | null;
}
interface FileReading {
  metrics: Record<string, Reading>;
  repeats: number;
  malformed: number;
  dropped: string[];
}
interface BytesCase {
  id: string;
  stdout: string;
  stderr: string;
  printed: 'stdout' | 'stderr';
  fileReadBytes: number | null;
  file: FileReading;
}
const BYTES = fileURLToPath(new URL('../../fixtures/metrics/metric-bytes.v1.json', import.meta.url));
const bytesCases = (JSON.parse(readFileSync(BYTES, 'utf8')) as { cases: BytesCase[] }).cases;

function asFixture(r: MetricReading): Reading {
  return {
    value: r.value,
    unit: r.unit,
    better: r.better,
    tolerance: r.tolerance === null ? null : { amount: Number(r.tolerance.raw), percent: r.tolerance.percent },
  };
}

function outputAsFixture(o: MetricOutput): FileReading {
  return {
    metrics: Object.fromEntries([...o.metrics].map(([name, r]) => [name, asFixture(r)])),
    repeats: o.repeats,
    malformed: o.malformed,
    dropped: [...o.dropped],
  };
}

describe('metric-bytes/1, the file mode', () => {
  // The capture a `2>&1` writes: the two streams in print order, one file. `fileReadBytes` stands for readBytes.
  it.each(bytesCases.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    const [first, second] = c.printed === 'stdout' ? [c.stdout, c.stderr] : [c.stderr, c.stdout];
    const file = join(makeTempDir('metric-bytes-'), 'head.txt');
    writeFileSync(file, Buffer.concat([Buffer.from(first, 'hex'), Buffer.from(second, 'hex')]));
    const read = readMetricFile(file, c.fileReadBytes ?? undefined);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    const got = outputAsFixture(readMetricOutput(read.text, { truncated: read.truncated }));
    expect(got).toEqual(c.file);
    // toEqual ignores key order; the reading's order is the file's line order, and the fixture states it.
    expect(Object.keys(got.metrics)).toEqual(Object.keys(c.file.metrics));
  });
});

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
