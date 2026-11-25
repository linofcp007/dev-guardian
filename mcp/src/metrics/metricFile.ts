/**
 * A file of METRIC lines the `metrics` command was named on its command line
 * (`--head`, `--base`) — the output a pipeline step wrote. The operator's
 * path, not the repository's: opened once, judged by its descriptor (a FIFO or
 * a device is refused, never waited on), and at most `metric-lines/1`'s
 * `readBytes` read — the END of a longer file, since the lines printed last
 * win; `truncated` then says so, and the reader never reads the cut line.
 * UTF-16 (PowerShell 5.1's `>`) is read as `check --file` reads it.
 */

import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { decodeText } from '../hooks/textEncoding.js';
import { METRIC_BOUNDS } from './metricLine.js';

type MetricFileRead = { ok: true; text: string; truncated: boolean } | { ok: false; reason: string };

/** `O_NONBLOCK` where the platform has it (not on Windows): a FIFO opens without a writer, and is refused. */
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);

function reasonOf(e: unknown): string {
  const code = e instanceof Error && 'code' in e && typeof e.code === 'string' ? e.code : '';
  if (code === 'ENOENT') return 'no such file';
  if (code === 'EISDIR') return 'a directory, not a file';
  if (code === 'EACCES' || code === 'EPERM') return 'permission denied';
  return code !== '' ? `could not be read (${code})` : 'could not be read';
}

export function readMetricFile(path: string, maxBytes: number = METRIC_BOUNDS.readBytes): MetricFileRead {
  let fd: number;
  try {
    fd = openSync(path, OPEN_FLAGS);
  } catch (e) {
    return { ok: false, reason: reasonOf(e) };
  }
  try {
    const st = fstatSync(fd);
    if (st.isDirectory()) return { ok: false, reason: 'a directory, not a file' };
    if (!st.isFile()) return { ok: false, reason: 'not a regular file' };
    const length = Math.min(st.size, maxBytes);
    const start = st.size - length;
    const buf = Buffer.alloc(length);
    let got = 0;
    while (got < length) {
      const n = readSync(fd, buf, got, length - got, start + got);
      if (n === 0) break;
      got += n;
    }
    return { ok: true, text: decodeText(buf.subarray(0, got)), truncated: start > 0 };
  } catch (e) {
    return { ok: false, reason: reasonOf(e) };
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* nothing left to do with it */
    }
  }
}
