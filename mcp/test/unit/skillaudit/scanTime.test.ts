/**
 * `scan_skill` reads files of up to 2 MB, and a minified script or a
 * generated document is one line that long. A rule whose regex is quadratic
 * on a line — an unbounded `[^…]*` before an alternation, a per-match rescan
 * of the line — is a scan that does not finish. Measured in wave 2 of the 3.0
 * review, on a 50 KB line: a `sed -i` rule did not finish in ten minutes; on
 * 500 KB, a Markdown line full of backtick spans took 6.8 s and one full of
 * quoted phrases 1.6 s, both growing with the square of the length.
 *
 * Each case is a line built to hand the slow shape as many starting points
 * as it can, scanned at two lengths 8x apart (`expectLinear`): linear code
 * costs about 8x as much, a quadratic rule about 64x. It was one 1 MB line
 * under a 4 s budget — a number of milliseconds, which measures the machine
 * (review 11, D).
 */

import { describe, it, vi } from 'vitest';

import { scanContent } from '../../../src/skillaudit/patterns.js';
import { expectLinear } from '../../helpers/timing.js';

vi.setConfig({ testTimeout: 120_000 });

/** The smaller of the two sizes compared (8x it is the other): a shape, never "under 4 s" (review 11, D). */
const SIZE = 4_000;

const line = (chunk: string, size: number): string => chunk.repeat(Math.ceil(size / chunk.length)).slice(0, size);

describe('every rule stays linear on a 1 MB line', () => {
  it.each([
    ['backtick spans', 'var nc=`a${b}`;nc(x);'],
    ['quoted injection phrases', '"ignore previous instructions" and '],
    ['sed -i', 'sed -i s x '],
    ['copies and installs', 'cp a b install x y '],
    ['PowerShell content cmdlets', 'Add-Content x y z '],
    ['env pipelines', 'env | x | env | y '],
    ['redirects', 'a > b >> c > d '],
    ['download words and URLs', 'download get fetch https://x.invalid/a '],
  ])('%s', (label, chunk) => {
    for (const isCode of [true, false]) {
      expectLinear(`${label} (${isCode ? 'code' : 'instruction'} file)`, (size) => {
        scanContent(line(chunk, size), isCode);
      }, SIZE);
    }
  });
});

// A client, then what it saves or reaches, in the same command: each such
// expression read the command again from every client — `curl ` 6 400 times
// in a code block took 3.9 s, a word of 32 000 `O` after `curl -` 2.2 s
// (review of the 3.7.0 self-scan, measured).
describe('downloads and fetch targets stay linear on a 1 MB line', () => {
  const block = (body: string): string => `# Setup\n\n\`\`\`bash\n${body}\n\`\`\`\n`;
  it.each([
    ['curl words', (n: number): string => line('curl ', n)],
    ['a word of O after curl -', (n: number): string => `curl -${line('O', n)}=`],
    ['wget words, then -O', (n: number): string => `${line('wget ', n)} -O`],
    ['iwr words', (n: number): string => line('iwr ', n)],
  ])('%s', (label, make) => {
    expectLinear(`${label} (code file)`, (size) => {
      scanContent(make(size), true);
    }, SIZE);
    expectLinear(`${label} (code block)`, (size) => {
      scanContent(block(make(size)), false);
    }, SIZE);
  });
});

// The `.env` read and decode-then-run rules looked for grep's `-q`, a path
// after `<` and a pipe after `base64 -d` to the end of the command, again
// from every start (review of the 3.7.0 self-scan).
describe('the read and decode rules stay linear on a 1 MB line', () => {
  it.each([
    ['grep words, then -q', (n: number): string => `${line('grep ', n)} -q`],
    ['a word of <', (n: number): string => line('<', n)],
    ['base64 -d words', (n: number): string => line('base64 -d ', n)],
  ])('%s', (label, make) => {
    for (const isCode of [true, false]) {
      expectLinear(`${label} (${isCode ? 'code' : 'instruction'} file)`, (size) => {
        scanContent(make(size), isCode);
      }, SIZE);
    }
  });
});

// An instruction file's HTML code: a `<code` or `<pre` tag with no `>`, and
// an element with no closing tag, were searched for again from every tag
// (review of the 3.7.0 self-scan).
describe('HTML code tags stay linear on a 1 MB line', () => {
  it.each([
    ['<code tags with no >', '<code '],
    ['<pre tags with no >', '<pre '],
    ['<code> elements never closed', '<code>'],
  ])('%s', (label, chunk) => {
    expectLinear(label, (size) => {
      scanContent(`x ${line(chunk, size)}`, false);
    }, SIZE);
  });
});

// Download, then run: every download was checked against every unit after
// it, and a run by its path was read again from every `(` of a word — 4 000
// lines of downloads took 23 s, the square of the file (review of the
// self-scan, 3.7.0).
describe('download-then-run stays linear in the file', () => {
  const lines = (count: number, make: (i: number) => string): string => Array.from({ length: count }, (_, i) => make(i)).join('\n');
  it.each([
    ['a line of downloads of one name, over and over', (n: number): string => lines(n / 32, () => 'curl https://x.invalid/a -o a.sh')],
    ['a line of downloads of a name of its own each', (n: number): string => lines(n / 32, (i) => `curl https://x.invalid/a -o a${String(i)}.sh`)],
    ['downloads of one name on one line', (n: number): string => line('curl https://x.invalid/a -o a.sh; ', n)],
    ['a download, then a word of (', (n: number): string => `curl https://x.invalid/a -o a.sh\n${line('(', n)}`],
    [
      'downloads, then a line mentioning every one',
      (n: number): string => {
        const count = Math.floor(n / 48);
        return `${lines(count, (i) => `curl https://x.invalid/a -o a${String(i)}.sh`)}\n${lines(count, (i) => `echo ./a${String(i)}.sh;`).replace(/\n/g, ' ')}`;
      },
    ],
  ])('%s', (label, make) => {
    for (const isCode of [true, false]) {
      expectLinear(`${label} (${isCode ? 'code' : 'instruction'} file)`, (size) => {
        scanContent(make(size), isCode);
      }, SIZE * 4);
    }
  });
});
