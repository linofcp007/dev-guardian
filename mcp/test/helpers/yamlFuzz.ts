/**
 * YAML shapes that make a parser work hard, for `platform/boundedParse.ts`'s
 * gates (review of 3.0, W2E round 3): each family is a text of `n`
 * repetitions of one construct, and {@link randomYaml} mixes them. Used by
 * `test/unit/platform/yamlBounds.test.ts` and by the `node:22 --memory 768m`
 * measurement that sizes every family to just under the gates.
 */

/** A small, seeded PRNG (mulberry32) — the fuzz is reproducible. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const lines = (n: number, f: (i: number) => string): string => Array.from({ length: n }, (_, i) => f(i)).join('\n') + '\n';

/** One construct repeated `n` times. */
export const YAML_FAMILIES: Record<string, (n: number) => string> = {
  // Nesting on one line — what the first node count missed.
  'nest-dash': (n) => `${'- '.repeat(n)}x\n`,
  'nest-qkey': (n) => `${'? '.repeat(n)}x\n`,
  'nest-flowseq': (n) => `${'['.repeat(n)}${']'.repeat(n)}\n`,
  'nest-flowmap': (n) => `${'{a: '.repeat(n)}x${'}'.repeat(n)}\n`,
  'nest-mixed': (n) => `${'- [{a: '.repeat(n)}x${'}]'.repeat(n)}\n`,
  // Nesting through lines.
  'nest-indent': (n) => lines(n, (i) => `${' '.repeat(i)}a:`),
  'nest-flow-lines': (n) => lines(n, () => '[') + ']'.repeat(n) + '\n',
  // Deep AND wide: nesting just under the depth gate, repeated until the indicator gate.
  'deep-many': (n) => lines(n, () => `${'- '.repeat(60)}x`),
  'flow-deep-many': (n) => lines(n, (i) => `k${i}: ${'['.repeat(60)}x${']'.repeat(60)}`),
  // Width.
  'wide-seq': (n) => lines(n, () => '- x'),
  'wide-map': (n) => lines(n, (i) => `k${i}: v`),
  'wide-map-dup': (n) => lines(n, () => 'k: v'),
  'wide-flow': (n) => `[${'1,'.repeat(n)}1]\n`,
  'wide-flowmap': (n) => `{${Array.from({ length: n }, (_, i) => `k${i}: 1`).join(', ')}}\n`,
  'maps-of-10': (n) =>
    lines(Math.max(1, Math.floor(n / 10)), (j) => `m${j}:\n${Array.from({ length: 10 }, (_, i) => `  k${i}: v`).join('\n')}`),
  'colon-chain': (n) => `${'a: '.repeat(n)}x\n`,
  // Anchors, aliases, merge keys.
  anchors: (n) => lines(n, (i) => `- &a${i} x`),
  aliases: (n) => `a: &a x\n${lines(n, (i) => `k${i}: *a`)}`,
  'alias-chain': (n) => `a0: &a0 x\n${lines(n, (i) => `a${i + 1}: &a${i + 1} [*a${i}, *a${i}]`)}`,
  merge: (n) => `b: &b {x: 1}\n${lines(n, (i) => `k${i}: {<<: *b}`)}`,
  // One anchored collection of n entries, aliased 90 times.
  'alias-big-target': (n) => `t: &t\n${lines(n, (i) => `  k${i}: v`)}${lines(90, (i) => `r${i}: *t`)}`,
  laughs: (n) => {
    let s = 'a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n';
    for (let i = 1; i <= Math.min(n, 12); i++) s += `a${i}: &a${i} [${Array(10).fill(`*a${i - 1}`).join(', ')}]\n`;
    return s;
  },
  // Tags, directives, documents, comments, scalars.
  tags: (n) => lines(n, () => '- !!str x'),
  'custom-tags': (n) => lines(n, (i) => `- !t${i} x`),
  directives: (n) => `${'%TAG !e! tag:e,2000:\n'.repeat(n)}---\na: 1\n`,
  documents: (n) => lines(n, () => '---\nx: 1'),
  comments: (n) => `${'# c\n'.repeat(n)}a: 1\n`,
  'block-scalar': (n) => `a: |\n${'  line\n'.repeat(n)}`,
  'quoted-escapes': (n) => lines(n, () => '- "a\\"b\\u263A\\x41"'),
  'big-scalar': (n) => `a: ${'x'.repeat(n)}\n`,
  // One error per line: what the composer builds for each.
  'error-lines': (n) => lines(n, (i) => `k${i}: a: b`),
  'error-seq-in-map': (n) => lines(n, (i) => `k${i}: - x`),
  'error-unclosed': (n) => lines(n, (i) => `k${i}: [x`),
};

/** A random scalar, sometimes tagged or anchored. */
function scalar(rand: () => number, anchors: string[]): string {
  const r = rand();
  if (r < 0.08 && anchors.length > 0) return `*${anchors[Math.floor(rand() * anchors.length)]}`;
  const base = ['x', '1', '-2.5', '"q u"', "'s'", 'true', '~', 'null', '"a\\"b"', 'a b c'][Math.floor(rand() * 10)] as string;
  if (r < 0.14) return `!!str ${base}`;
  if (r < 0.18) return `!custom ${base}`;
  return base;
}

/** A random flow collection, `depth` deep at most. */
function flow(rand: () => number, depth: number, anchors: string[]): string {
  if (depth <= 0 || rand() < 0.4) return scalar(rand, anchors);
  const n = 1 + Math.floor(rand() * 4);
  return rand() < 0.5
    ? `[${Array.from({ length: n }, () => flow(rand, depth - 1, anchors)).join(', ')}]`
    : `{${Array.from({ length: n }, (_, i) => `f${i}: ${flow(rand, depth - 1, anchors)}`).join(', ')}}`;
}

/**
 * A random, mostly VALID document of block maps and sequences, flow
 * collections, anchors and aliases, merge keys, tags, block scalars and
 * complex keys, about `size` entries long; `mutate` corrupts a few lines.
 */
export function randomYaml(rand: () => number, size: number, mutate = false): string {
  const out: string[] = [];
  const anchors: string[] = [];
  let emitted = 0;
  const block = (indent: string, depth: number, asSeq: boolean): void => {
    const entries = 1 + Math.floor(rand() * 12);
    for (let i = 0; i < entries && emitted < size; i++) {
      emitted += 1;
      const lead = asSeq ? `${indent}- ` : `${indent}k${emitted}: `;
      const r = rand();
      if (r < 0.25 && depth < 20) {
        const anchor = rand() < 0.2 ? `a${emitted}` : null;
        out.push(`${lead.trimEnd()}${anchor !== null ? ` &${anchor}` : ''}`);
        block(`${indent}  `, depth + 1, rand() < 0.4);
        // Aliased only once closed: an alias inside its own anchor is a cycle, refused (the mutated inputs try it).
        if (anchor !== null) anchors.push(anchor);
      } else if (r < 0.45) {
        out.push(`${lead}${flow(rand, 1 + Math.floor(rand() * 8), anchors)}`);
      } else if (r < 0.5 && !asSeq && anchors.length > 0) {
        out.push(`${indent}<<: *${anchors[Math.floor(rand() * anchors.length)]}`);
      } else if (r < 0.55) {
        out.push(`${lead}|`, `${indent}  line one`, `${indent}  line two`);
      } else if (r < 0.58 && !asSeq) {
        out.push(`${indent}? [c${emitted}, d]`, `${indent}: ${scalar(rand, anchors)}`);
      } else if (r < 0.6) {
        out.push(`${indent}# a comment ]]] }}} - - -`);
      } else {
        out.push(`${lead}${scalar(rand, anchors)}`);
      }
    }
  };
  while (emitted < size) block('', 0, false);
  if (mutate) {
    for (let k = 0; k < 1 + Math.floor(rand() * 5); k++) {
      const at = Math.floor(rand() * out.length);
      const line = out[at] ?? '';
      const pos = Math.floor(rand() * (line.length + 1));
      out[at] = `${line.slice(0, pos)}${['[', ']', '{', ': ', '- ', '&', '*', '!', '"', "'", '\t', '---'][Math.floor(rand() * 12)] ?? ''}${line.slice(pos)}`;
    }
  }
  return `${out.join('\n')}\n`;
}
