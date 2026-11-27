/**
 * The local modules a k6 script imports (`src/metrics/k6Inputs.ts`), an input of its series: found by the text,
 * walked breadth-first with one read per path, keyed by their bytes, and every failure of a read keyed as such —
 * never left out, which would give the key of a script that imports nothing (the 3.17.0 one) and join the series
 * of the runs from before the upgrade. The reader is injected: its reads are counted, the cost is a count.
 *
 * The real-shaped fixture is `test/fixtures/k6/project/`, laid out as grafana/quickpizza's k6/foundations
 * scripts are (the load shapes in `lib/load-options.js`, the requests in `lib/frontend/`).
 */

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  type K6InputReader,
  type K6ModuleRead,
  K6_INPUT_FILES_MAX,
  K6_WALK_FAILED,
  k6LocalInputs,
  k6Specifiers,
} from '../../../src/metrics/k6Inputs.js';
import { k6Series, k6Settings } from '../../../src/metrics/perfSeries.js';
import { expectLinear } from '../../helpers/timing.js';

const FIXTURE = fileURLToPath(new URL('../../fixtures/k6/project/', import.meta.url));
const sha = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex');

/** `resolve` as perfCheck's reader resolves: against the importing module's folder, `file://` by its path, null outside `root`. */
function resolverFor(root: string): K6InputReader['resolve'] {
  return (fromDir, spec) => {
    const abs = spec.startsWith('file://') ? fileURLToPath(spec) : resolve(root, fromDir, spec);
    const rel = relative(root, abs);
    return rel.startsWith('..') || isAbsolute(rel) ? null : rel.split(sep).join('/');
  };
}

/** A reader over a real folder, counting its reads. */
function dirReader(root: string): K6InputReader & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    read(rel): K6ModuleRead {
      reads.push(rel);
      try {
        if (!statSync(join(root, rel)).isFile()) return { kind: 'refused' };
        return { kind: 'ok', bytes: readFileSync(join(root, rel)) };
      } catch {
        return { kind: 'absent' };
      }
    },
    resolve: resolverFor(root),
  };
}

const ROOT = resolve('/k6-project');
/** A reader over modules held in memory (`path → text`, or a read's own answer), counting its reads. */
function memReader(modules: Record<string, string | Uint8Array | K6ModuleRead>): K6InputReader & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    read(rel): K6ModuleRead {
      reads.push(rel);
      const m = modules[rel];
      if (m === undefined) return { kind: 'absent' };
      if (typeof m === 'string') return { kind: 'ok', bytes: Buffer.from(m, 'utf8') };
      if (m instanceof Uint8Array) return { kind: 'ok', bytes: m };
      return m;
    },
    resolve: resolverFor(ROOT),
  };
}

const NONE = k6Settings({});
/** The 3.17.0 key, written out here as 3.17.0 computed it. */
const oldKey = (script: string, content: string): string =>
  createHash('sha256').update(JSON.stringify(['k6', script, content, NONE.digest])).digest('hex');

describe('k6Inputs — the local modules of a k6 script', () => {
  it('1: on the quickpizza-shaped fixture, every local module and only them, transitively, each by its bytes; a built-in and an open() are not', () => {
    const reader = dirReader(FIXTURE);
    const got = k6LocalInputs('load.js', reader);
    const expected = ['lib/frontend/basic.js', 'lib/frontend/util.js', 'lib/load-options.js', 'lib/spike-stages.js', 'lib/target.js'];
    expect(got.files.map(([p]) => p)).toEqual(expected);
    for (const [p, digest] of got.files) expect(digest, p).toBe(sha(readFileSync(join(FIXTURE, p))));
    expect(got.partial).toEqual([]);
    // One read per path, the entry included; data/tokens.json is opened, never imported.
    expect([...reader.reads].sort()).toEqual(['load.js', ...expected].sort());
  });

  it('1b: a remote module, a built-in or an extension, and a bare name are no local module; a file:// URL inside the project is one', () => {
    const local = pathToFileURL(join(ROOT, 'lib', 'local.js')).href;
    const reader = memReader({
      'load.js': [
        "import http from 'k6/http';",
        "import exec from 'k6/execution';",
        "import sql from 'k6/x/sql';",
        "import { randomItem } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';",
        "import lodash from 'lodash';",
        `import { a } from '${local}';`,
        "import { b } from './lib/b.js';",
      ].join('\n'),
      'lib/local.js': 'export const a = 1;\n',
      'lib/b.js': 'export const b = 2;\n',
    });
    const got = k6LocalInputs('load.js', reader);
    expect(got.files.map(([p]) => p)).toEqual(['lib/b.js', 'lib/local.js']);
    expect(got.partial).toEqual([]);
  });

  it('2: a specifier built at run time is dynamic, its module unkeyed; a template literal with ${…} included', () => {
    for (const call of ['require(name)', 'import(x)', 'import(`./${x}.js`)', "require('./a' + b)", 'import(__ENV.MODULE)']) {
      const got = k6LocalInputs('load.js', memReader({ 'load.js': `const m = ${call};\nexport default function () {}\n` }));
      expect(got, call).toEqual({ files: [], partial: ['dynamic'] });
    }
    // A literal call is a module like any other.
    const literal = k6LocalInputs('load.js', memReader({ 'load.js': "const m = require('./m.js');\nconst n = import(`./n.js`);\n", 'm.js': '', 'n.js': '' }));
    expect(literal.files.map(([p]) => p)).toEqual(['m.js', 'n.js']);
    expect(literal.partial).toEqual([]);
  });

  it('3: a module out of the project is never read, and the walk says so', () => {
    const reader = memReader({ 'load/load.js': "import { x } from '../../outside.js';\nimport { y } from '/etc/k6/y.js';\n" });
    expect(k6LocalInputs('load/load.js', reader)).toEqual({ files: [], partial: ['outside'] });
    expect(reader.reads).toEqual(['load/load.js']);
  });

  it('4: a cycle ends — back to a module or to the entry itself — with one read per path', () => {
    const toModule = memReader({ 'a.js': "import './b.js';\n", 'b.js': "import './c.js';\n", 'c.js': "import './b.js';\n" });
    expect(k6LocalInputs('a.js', toModule).files.map(([p]) => p)).toEqual(['b.js', 'c.js']);
    expect(toModule.reads).toEqual(['a.js', 'b.js', 'c.js']);
    const toEntry = memReader({ 'a.js': "import './b.js';\n", 'b.js': "import { main } from './a.js';\n" });
    expect(k6LocalInputs('a.js', toEntry).files.map(([p]) => p)).toEqual(['b.js']);
    expect(toEntry.reads).toEqual(['a.js', 'b.js']);
    // A module two others import (a diamond) is read once, before either has been read through.
    const diamond = memReader({ 'a.js': "import './b.js';\nimport './c.js';\n", 'b.js': "import './d.js';\n", 'c.js': "import './d.js';\n", 'd.js': '' });
    expect(k6LocalInputs('a.js', diamond).files.map(([p]) => p)).toEqual(['b.js', 'c.js', 'd.js']);
    expect(diamond.reads).toEqual(['a.js', 'b.js', 'c.js', 'd.js']);
  });

  it(`5: past ${String(K6_INPUT_FILES_MAX)} modules nothing more is read or keyed, and the bound is said`, () => {
    const chain: Record<string, string> = {};
    for (let i = 0; i < 100; i += 1) chain[`m${String(i)}.js`] = `import './m${String(i + 1)}.js';\n`;
    const reader = memReader(chain);
    const got = k6LocalInputs('m0.js', reader);
    expect(got.files).toHaveLength(K6_INPUT_FILES_MAX);
    expect(got.partial).toEqual(['bound']);
    expect(reader.reads).toHaveLength(K6_INPUT_FILES_MAX + 1);
    // A fan-out reads the same: one entry naming 100 modules.
    const fan: Record<string, string> = { 'load.js': Array.from({ length: 100 }, (_, i) => `import './f${String(i)}.js';`).join('\n') };
    const wide = memReader(fan);
    expect(k6LocalInputs('load.js', wide).files).toHaveLength(K6_INPUT_FILES_MAX);
    expect(wide.reads).toHaveLength(K6_INPUT_FILES_MAX + 1);
  });

  it('6: a module over the reader\'s cap is keyed by that alone and never scanned: what it imports is not followed', () => {
    const reader = memReader({ 'load.js': "import './big.js';\n", 'big.js': { kind: 'too-large' } });
    expect(k6LocalInputs('load.js', reader)).toEqual({ files: [['big.js', 'too-large']], partial: ['bound'] });
    expect(reader.reads).toEqual(['load.js', 'big.js']);
  });

  it('7: a refused read (a FIFO, a link out of the project) is keyed as unreadable, never as absent and never left out', () => {
    const got = k6LocalInputs('load.js', memReader({ 'load.js': "import './lib/fifo.js';\n", 'lib/fifo.js': { kind: 'refused' } }));
    expect(got).toEqual({ files: [['lib/fifo.js', 'unreadable']], partial: ['unreadable'] });
    // A missing module is keyed as missing (k6 fails that run, which is never kept): nothing partial about it.
    expect(k6LocalInputs('load.js', memReader({ 'load.js': "import './gone.js';\n" }))).toEqual({ files: [['gone.js', 'missing']], partial: [] });
  });

  it('8: comments are not stripped — a commented-out import of a file that exists is keyed (the stated over-key)', () => {
    const got = k6LocalInputs('load.js', memReader({ 'load.js': "// import { SpikeStages } from './lib/spike.js';\n", 'lib/spike.js': 'export const s = 1;\n' }));
    expect(got.files).toEqual([['lib/spike.js', sha('export const s = 1;\n')]]);
  });

  it('9: no local module — none given, or none found — is exactly the 3.17.0 key and label', () => {
    const content = 'a'.repeat(64);
    const old = oldKey('smoke.js', content);
    expect(k6Series('smoke.js', content, NONE).key).toBe(old);
    const none = k6LocalInputs('smoke.js', memReader({ 'smoke.js': "import http from 'k6/http';\nexport default function () {}\n" }));
    expect(none).toEqual({ files: [], partial: [] });
    expect(k6Series('smoke.js', content, NONE, none)).toEqual({ key: old, label: 'k6 · smoke.js (aaaaaaaaaaaa)' });
  });

  it('T15: a walk that throws keys a sentinel: a key neither of a script that imports nothing nor of a walk that read', () => {
    const throwing: K6InputReader = {
      read: () => {
        throw new Error('EIO');
      },
      resolve: resolverFor(ROOT),
    };
    expect(k6LocalInputs('load.js', throwing)).toEqual(K6_WALK_FAILED);
    const content = 'b'.repeat(64);
    const failed = k6Series('load.js', content, NONE, K6_WALK_FAILED);
    const read = k6Series('load.js', content, NONE, k6LocalInputs('load.js', memReader({ 'load.js': "import './m.js';\n", 'm.js': '' })));
    expect(failed.key).not.toBe(oldKey('load.js', content));
    expect(failed.key).not.toBe(read.key);
    expect(failed.label).toMatch(/ · inputs partly keyed$/);
  });

  it('T16: a refused module keys neither the 3.17.0 key nor the one of the same module read', () => {
    const content = 'c'.repeat(64);
    const refused = k6Series('load.js', content, NONE, k6LocalInputs('load.js', memReader({ 'load.js': "import './m.js';\n", 'm.js': { kind: 'refused' } })));
    const read = k6Series('load.js', content, NONE, k6LocalInputs('load.js', memReader({ 'load.js': "import './m.js';\n", 'm.js': 'export {};\n' })));
    expect(refused.key).not.toBe(oldKey('load.js', content));
    expect(refused.key).not.toBe(read.key);
    expect(refused.label).toMatch(/^k6 · load\.js \(cccccccccccc\) · 1 local module #[0-9a-f]{6} · inputs partly keyed$/);
    expect(read.label).toMatch(/^k6 · load\.js \(cccccccccccc\) · 1 local module #[0-9a-f]{6}$/);
  });

  it('T17: an import over several lines and an export … from are modules (real ESM shapes)', () => {
    const text = "import {\n  a,\n  b,\n} from './lib/x.js';\nexport * from './lib/y.js';\nexport { c } from \"./lib/z.js\";\n";
    expect(k6Specifiers(text)).toEqual({ specifiers: ['./lib/x.js', './lib/y.js', './lib/z.js'], dynamic: false });
  });

  it('18: a module is keyed by its bytes — two that decode to the same text (a byte-order mark, an invalid byte) are two modules', () => {
    const plain = Buffer.from('export const a = 1;\n', 'utf8');
    const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), plain]);
    const bad1 = Buffer.from([0x2f, 0x2f, 0xff, 0x0a]);
    const bad2 = Buffer.from([0x2f, 0x2f, 0xfe, 0x0a]);
    const digestOf = (m: Uint8Array): string | undefined => k6LocalInputs('load.js', memReader({ 'load.js': "import './m.js';\n", 'm.js': m })).files[0]?.[1];
    expect(digestOf(plain)).not.toBe(digestOf(bom));
    expect(digestOf(bad1)).not.toBe(digestOf(bad2));
  });

  it('19: an entry that cannot be read keys a sentinel too: what it imports is unknown', () => {
    expect(k6LocalInputs('load.js', memReader({ 'load.js': { kind: 'too-large' } }))).toEqual({ files: [['', 'too-large']], partial: ['bound'] });
    expect(k6LocalInputs('load.js', memReader({ 'load.js': { kind: 'refused' } }))).toEqual({ files: [['', 'unreadable']], partial: ['unreadable'] });
    // A module naming the project root is the path `.`, never the entry's marker.
    expect(k6LocalInputs('load.js', memReader({ 'load.js': "import './';\n", '.': { kind: 'refused' } })).files).toEqual([['.', 'unreadable']]);
  });

  // The patterns are linear (a keyword, then a bounded literal): 8x the text costs ~8x, at 64 KiB against 512 KiB.
  // A module is scanned up to the reader's cap (8 MiB), where the same patterns are the same linear pass.
  it('10: one linear pass over a module\'s text, whatever it holds', () => {
    // Each keyword after a blank, so every one starts a match (`aimport(` holds no word boundary, and would not).
    const shapes: Record<string, (n: number) => string> = {
      'import x n, no quote after': (n) => 'import '.repeat(Math.ceil(n / 7)).slice(0, n),
      'from then blanks, no quote': (n) => `from${' '.repeat(n)}`,
      'require( then blanks, no literal': (n) => `require(${' '.repeat(n)}`,
      'require( x n, no literal (every call a miss)': (n) => 'require( '.repeat(Math.ceil(n / 9)).slice(0, n),
      'import( then an unclosed literal, repeated': (n) => "import('aaaa ".repeat(Math.ceil(n / 13)).slice(0, n),
      'from \' then an unclosed specifier, repeated': (n) => "from 'a/b/c/d ".repeat(Math.ceil(n / 14)).slice(0, n),
      "require(' then 1,000 characters, repeated": (n) => `require('${'a'.repeat(1000)} `.repeat(Math.ceil(n / 1010)).slice(0, n),
    };
    for (const [label, make] of Object.entries(shapes)) {
      const texts = new Map<number, string>();
      const textOf = (n: number): string => {
        const cached = texts.get(n);
        if (cached !== undefined) return cached;
        const t = make(n);
        texts.set(n, t);
        return t;
      };
      expectLinear(`k6Specifiers: ${label}`, (n) => void k6Specifiers(textOf(n)), 64 * 1024);
    }
  });
});
