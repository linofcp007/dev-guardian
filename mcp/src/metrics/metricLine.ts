/**
 * The METRIC line, `metric-lines/1` — the one line format dev-guardian and
 * dev-spec-driven read, each with its own reader of the same contract: the
 * fixture `test/fixtures/metrics/metric-lines.v1.json`, committed byte-identical
 * in both repositories (docs/maintainers/build-and-test.md). This reader is
 * held to every case of it (`test/unit/metrics/metricLine.test.ts`).
 *
 *   METRIC <name>=<number>[ <unit>][ better=lower|higher][ tolerance=<n>[%]][ <key>=<value>…]
 *
 * - The keyword starts the line, after blanks or one `# ` (node's TAP reporter
 *   prints a test's output as `# …`), or blanks then `# ` (a nested subtest).
 *   A CR before the LF is no part of the line, and ANSI CSI sequences
 *   (`ESC [ … letter`, a coloured log) are removed before anything is read —
 *   but the keyword is read as printed: it is the line's first `METRIC`, with
 *   only blanks, the `# ` and CSI sequences before it, so a colour code inside
 *   it (`MET ESC[0m RIC`) splits it, as dev-spec-driven's reader, which finds
 *   the keyword in the raw output, reads it.
 * - An ATTEMPT is a line whose first token after the keyword holds `=`. An
 *   attempt the grammar refuses is `malformed` — counted and said; any other
 *   `METRIC …` line (a table header, a JSON payload, another tool's log) is
 *   ignored. Tokens split on runs of blanks.
 * - A name is ASCII (`[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}`): cmd.exe turns a
 *   micro sign into U+FFFD, so `total_µs` is malformed, never a second name.
 * - The token after the number, when it holds no `=`, is the unit (one token,
 *   at most 16 characters). There is no bare direction: `x=5 higher` has the
 *   unit `higher`. Every later token is `key=value`; the known keys in any
 *   order, each at most once; an unknown key is ignored.
 * - The last line of a name wins whole — its terms are never merged with an
 *   earlier line's — and the lines it replaced are counted as repeats. A
 *   malformed line never replaces a reading. Names are kept in a `Map`, so
 *   `__proto__` is an ordinary name.
 *
 * Bounds (one set for both readers, each said when it drops input): at most
 * 64 MiB read (`metricFile.ts`), a candidate of at most 512 bytes (a longer one
 * is dropped, never read as malformed), at most 1,000 candidates walked from
 * the END with `lastIndexOf` (never a split of the whole output), at most 20
 * names kept — the ones printed last.
 */

export const METRIC_FORMAT = 'metric-lines/1';

export const METRIC_BOUNDS = {
  readBytes: 64 * 1024 * 1024,
  candidateBytes: 512,
  candidates: 1000,
  names: 20,
} as const;

type MetricBound = keyof typeof METRIC_BOUNDS;
type MetricBounds = Record<MetricBound, number>;

/** The bounds in the order the fixture's vocabulary names them — `dropped` is listed in it. */
const BOUND_ORDER: readonly MetricBound[] = ['readBytes', 'candidateBytes', 'candidates', 'names'];

export type Better = 'lower' | 'higher';

export interface MetricTolerance {
  /** The printed amount, `2` of `tolerance=2%`. */
  readonly raw: string;
  /** True: a share of |reference|; false: an amount in the value's own units. */
  readonly percent: boolean;
}

export interface MetricReading {
  readonly name: string;
  readonly value: number;
  /** The number as printed — what the judge compares, exactly. */
  readonly raw: string;
  readonly unit: string | null;
  readonly better: Better | null;
  readonly tolerance: MetricTolerance | null;
}

/** Which part of an attempt the grammar refused. */
type MalformedPart = 'name' | 'value' | 'unit' | 'token' | 'better' | 'tolerance';

export type LineRead =
  | { kind: 'metric'; reading: MetricReading }
  | { kind: 'malformed'; part: MalformedPart }
  | { kind: 'ignored' };

interface MalformedLine {
  readonly text: string;
  readonly part: MalformedPart;
}

export interface MetricOutput {
  /** Each name's reading, in the order the winning lines were printed. */
  readonly metrics: ReadonlyMap<string, MetricReading>;
  /** Σ (valid lines of a kept name − 1). */
  readonly repeats: number;
  /** The failed attempts among the candidates read. */
  readonly malformed: number;
  /** The last {@link MALFORMED_KEPT} of them, in print order — to show, never to judge. */
  readonly malformedLines: readonly MalformedLine[];
  /** The bounds that dropped input, in the fixture's order. */
  readonly dropped: readonly MetricBound[];
}

const MALFORMED_KEPT = 5;

const NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;
const NUMBER = /^-?(?:0|[1-9][0-9]{0,14})(?:\.[0-9]{1,9})?(?:[eE][-+]?[0-9]{1,3})?$/;
/** A tolerance: the number's grammar without a sign, then an optional `%`. */
const TOLERANCE = /^((?:0|[1-9][0-9]{0,14})(?:\.[0-9]{1,9})?(?:[eE][-+]?[0-9]{1,3})?)(%?)$/;
const UNIT_MAX_CHARS = 16;
/** The keyword at the line's start: blanks, then at most one `# `, then `METRIC` and a blank or the end. */
const START = /^[ \t]*(?:# )?METRIC(?=[ \t]|$)/;
/** What may stand before the printed keyword once its CSI sequences are removed. */
const HEAD = /^[ \t]*(?:# )?$/;
const BLANKS = /[ \t]+/;
/** An ANSI CSI sequence: ESC [, parameter and intermediate bytes, a final letter. */
const CSI = /\u001B\[[0-?]*[ -/]*[A-Za-z]/g;
const KEYWORD = 'METRIC';

/**
 * One line (without its line break), read alone: a reading, a failed attempt,
 * or a line that is no attempt at all. No bound applies here —
 * {@link readMetricOutput} applies them.
 */
export function readMetricLine(line: string): LineRead {
  const text = cleanLine(line);
  const start = START.exec(text);
  return start === null || !keywordPrinted(line) ? { kind: 'ignored' } : readCandidate(text.slice(start[0].length));
}

/** A line as the grammar reads it: no CR at its end, no CSI sequence. */
function cleanLine(line: string): string {
  const noCr = line.endsWith('\r') ? line.slice(0, -1) : line;
  return noCr.includes('\u001B') ? noCr.replace(CSI, '') : noCr;
}

/**
 * Whether the raw line's first `METRIC` has only blanks, the `# ` and CSI
 * sequences before it — with {@link START} on the cleaned line, that the
 * keyword the grammar reads was printed whole, never made by removing a CSI
 * sequence inside it.
 */
function keywordPrinted(raw: string): boolean {
  const first = raw.indexOf(KEYWORD);
  if (first < 0) return false;
  const head = raw.slice(0, first);
  return HEAD.test(head.includes('\u001B') ? head.replace(CSI, '') : head);
}

function malformed(part: MalformedPart): LineRead {
  return { kind: 'malformed', part };
}

/** What follows the keyword: empty, or a blank and the tokens. */
function readCandidate(rest: string): LineRead {
  const tokens = rest.split(BLANKS).filter((t) => t.length > 0);
  const first = tokens[0];
  if (first === undefined) return { kind: 'ignored' };
  const eq = first.indexOf('=');
  if (eq < 0) return { kind: 'ignored' };
  const name = first.slice(0, eq);
  const raw = first.slice(eq + 1);
  if (!NAME.test(name)) return malformed('name');
  if (!NUMBER.test(raw)) return malformed('value');
  const value = Number(raw);
  if (!Number.isFinite(value)) return malformed('value');

  let at = 1;
  let unit: string | null = null;
  const second = tokens[1];
  if (second !== undefined && !second.includes('=')) {
    if (Array.from(second).length > UNIT_MAX_CHARS) return malformed('unit');
    unit = second;
    at = 2;
  }
  let better: Better | null = null;
  let tolerance: MetricTolerance | null = null;
  let sawBetter = false;
  let sawTolerance = false;
  for (const token of tokens.slice(at)) {
    const k = token.indexOf('=');
    if (k < 0) return malformed('token');
    const key = token.slice(0, k);
    const val = token.slice(k + 1);
    if (key === 'better') {
      if (sawBetter || (val !== 'lower' && val !== 'higher')) return malformed('better');
      sawBetter = true;
      better = val;
    } else if (key === 'tolerance') {
      const t = TOLERANCE.exec(val);
      if (sawTolerance || t === null || !Number.isFinite(Number(t[1]))) return malformed('tolerance');
      sawTolerance = true;
      tolerance = { raw: t[1] ?? '', percent: t[2] === '%' };
    }
    // Any other key is not this version's: ignored (room for a later `runs=`).
  }
  return { kind: 'metric', reading: { name, value, raw, unit, better, tolerance } };
}

/**
 * A whole output, read from its END: the last line of each name wins, and the
 * bounds keep what was printed last. `truncated`: `text` is the tail of a
 * longer output (`metricFile.ts` read only its last bytes), so its first line
 * is cut — never read — and `readBytes` is said.
 */
export function readMetricOutput(
  text: string,
  opts: { truncated?: boolean; bounds?: Partial<MetricBounds> } = {},
): MetricOutput {
  const bounds: MetricBounds = { ...METRIC_BOUNDS, ...opts.bounds };
  const kept = new Map<string, { reading: MetricReading; at: number }>();
  const dropped = new Set<MetricBound>();
  if (opts.truncated === true) dropped.add('readBytes');
  const malformedLines: Array<MalformedLine & { at: number }> = [];
  let repeats = 0;
  let malformedCount = 0;
  let candidates = 0;

  let from = text.length;
  while (from >= 0) {
    const hit = text.lastIndexOf(KEYWORD, from);
    if (hit < 0) break;
    // The whole line the hit is on, once: every other hit on it is passed over,
    // so a long line holding the keyword many times costs one pass.
    const lineStart = text.lastIndexOf('\n', hit) + 1;
    const nl = text.indexOf('\n', hit);
    const lineEnd = nl < 0 ? text.length : nl;
    const cut = opts.truncated === true && lineStart === 0;
    if (!cut) {
      const raw = text.slice(lineStart, lineEnd);
      const line = cleanLine(raw);
      const start = START.exec(line);
      if (start !== null && keywordPrinted(raw)) {
        candidates += 1;
        if (candidates > bounds.candidates) {
          dropped.add('candidates');
          break;
        }
        // A UTF-16 unit is at least one UTF-8 byte: the length decides most lines without encoding them.
        if (line.length > bounds.candidateBytes || Buffer.byteLength(line, 'utf8') > bounds.candidateBytes) {
          dropped.add('candidateBytes');
        } else {
          const read = readCandidate(line.slice(start[0].length));
          if (read.kind === 'malformed') {
            malformedCount += 1;
            if (malformedLines.length < MALFORMED_KEPT) malformedLines.push({ text: line, part: read.part, at: lineStart });
          } else if (read.kind === 'metric') {
            const name = read.reading.name;
            if (kept.has(name)) repeats += 1;
            else if (kept.size >= bounds.names) dropped.add('names');
            else kept.set(name, { reading: read.reading, at: lineStart });
          }
        }
      }
    }
    if (lineStart === 0) break;
    from = lineStart - 1;
  }

  const metrics = new Map<string, MetricReading>(
    [...kept.values()].sort((a, b) => a.at - b.at).map((k) => [k.reading.name, k.reading]),
  );
  return {
    metrics,
    repeats,
    malformed: malformedCount,
    malformedLines: malformedLines.sort((a, b) => a.at - b.at).map(({ text: t, part }) => ({ text: t, part })),
    dropped: BOUND_ORDER.filter((b) => dropped.has(b)),
  };
}
