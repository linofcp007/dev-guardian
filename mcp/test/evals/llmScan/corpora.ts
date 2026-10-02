/**
 * The corpora the LLM-scan evals run on, and the blind copies the model is
 * actually shown.
 *
 * Every corpus is read from an environment variable, the way the ablation
 * harness reads its real-code corpora (`test/ablate/packs.ts#envCorpus`):
 * UNSET means the corpus is `N/A` — its items are printed as not measured,
 * never silently dropped — and SET to a path that does not exist THROWS,
 * because a typo'd corpus that quietly becomes "not measured" is exactly the
 * failure an eval exists to prevent. Decision D-1: none of these corpora is
 * copied into the repository (BenchmarkPython is GPL-3.0; the others are
 * third-party), and no new vulnerable application is written.
 *
 * The model never sees an answer key. A run copies ONLY the application tree
 * into a fresh temp directory with a neutral name (`ws-…/app-v`), blinded by
 * `blind.ts` with every line kept in place, and the driver confines the
 * model's file tools to that copy. Keys stay where they are: in the spike
 * folder, in this harness's source, in the corpus's own expected-results
 * file — all outside the copy.
 */

import { execFileSync } from 'node:child_process';
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { canonicalPath } from '../../../src/platform/projectPath.js';
import { rmDir } from '../../helpers/tempDir.js';
import {
  BENCHMARK_PY_ROOTS,
  VAMPI_FILES,
  benchmarkBlindPath,
  blindBenchmarkText,
  blindDvwaText,
  blindJuiceText,
  blindVampiText,
  dvwaFiles,
  isJuiceFile,
  juiceAliases,
  juiceOutPath,
} from './blind.js';
import { fileKindOf, findTells, type Tell } from './tells.js';

export type CorpusId = 'app-s' | 'vampi' | 'juice-shop' | 'dvwa' | 'benchmark-python';
export const CORPUS_IDS: readonly CorpusId[] = ['app-s', 'vampi', 'juice-shop', 'dvwa', 'benchmark-python'];

export interface CorpusSpec {
  id: CorpusId;
  /** The environment variable naming it. */
  env: string;
  label: string;
  /** The commit every key line was measured against; null for the spike's own app. */
  commit: string | null;
  /** The directory name the model sees. Neutral on purpose. */
  blindName: string;
  /** Where to get it, said when the variable points nowhere. */
  hint: string;
}

/** The spike folder: app-s (corpus/app-s) and its key (answer-keys/). */
export const SPIKE_ENV = 'GUARDIAN_LLMSCAN_SPIKE';

export const CORPORA: Readonly<Record<CorpusId, CorpusSpec>> = {
  'app-s': {
    id: 'app-s',
    env: SPIKE_ENV,
    label: 'app-s (the spike\'s synthetic TS/Express app)',
    commit: null,
    blindName: 'app-s',
    hint: 'the spike folder .specs/llm-scan/evals/spike-2026-10-02 (it holds corpus/app-s and answer-keys/)',
  },
  vampi: {
    id: 'vampi',
    env: 'GUARDIAN_VAMPI_SRC',
    label: 'VAmPI (Python/Flask)',
    commit: 'f16052d',
    blindName: 'app-v',
    hint: 'a clone of erev0s/VAmPI at f16052d',
  },
  'juice-shop': {
    id: 'juice-shop',
    env: 'GUARDIAN_JUICESHOP_SRC',
    label: 'OWASP Juice Shop (TS/Express)',
    commit: '1618a61',
    blindName: 'app-j',
    hint: 'a clone of juice-shop/juice-shop at 1618a61 (on Windows: git -c core.longpaths=true clone)',
  },
  dvwa: {
    id: 'dvwa',
    env: 'GUARDIAN_DVWA_SRC',
    label: 'DVWA (PHP)',
    commit: '43b0f8b',
    blindName: 'app-d',
    hint: 'a clone of digininja/DVWA at 43b0f8b',
  },
  'benchmark-python': {
    id: 'benchmark-python',
    env: 'GUARDIAN_BENCHMARK_PY_SRC',
    label: 'OWASP BenchmarkPython (GPL-3.0, never copied into the repo)',
    commit: 'f129148',
    blindName: 'app-b',
    hint: 'a clone of OWASP-Benchmark/BenchmarkPython at f129148',
  },
};

export type CorpusState = { id: CorpusId; available: true; dir: string; commit: string | null } | { id: CorpusId; available: false; reason: string };

function envDir(env: Readonly<Record<string, string | undefined>>, name: string, hint: string): string | undefined {
  const raw = env[name];
  if (raw === undefined || raw.trim() === '') return undefined;
  const abs = resolve(raw.trim());
  if (!existsSync(abs)) {
    throw new Error(`${name} is set to ${abs}, which does not exist. Unset it to report this corpus as N/A, or point it at ${hint}.`);
  }
  return abs;
}

/** HEAD of a git checkout, or null when the directory is not one (or git is absent). */
export function gitHead(dir: string): string | null {
  try {
    return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null;
  } catch {
    return null;
  }
}

/**
 * Every corpus, available or `N/A` with the reason. Throws for a variable set
 * to a missing path, and — unless `allowCommitMismatch` — for a git checkout
 * at a commit other than the one the keys were written against (every key
 * line would silently point at something else).
 */
export function resolveCorpora(
  env: Readonly<Record<string, string | undefined>> = process.env,
  opts: { allowCommitMismatch?: boolean } = {},
): Record<CorpusId, CorpusState> {
  const out = {} as Record<CorpusId, CorpusState>;
  for (const id of CORPUS_IDS) {
    const spec = CORPORA[id];
    const base = envDir(env, spec.env, spec.hint);
    if (base === undefined) {
      out[id] = { id, available: false, reason: `${spec.env} is not set` };
      continue;
    }
    const dir = id === 'app-s' ? join(base, 'corpus', 'app-s') : base;
    if (!existsSync(dir)) throw new Error(`${spec.env} is set to ${base}, which holds no corpus/app-s. Point it at ${spec.hint}.`);
    const head = spec.commit === null ? null : gitHead(dir);
    if (spec.commit !== null && head !== null && !head.startsWith(spec.commit) && opts.allowCommitMismatch !== true) {
      throw new Error(
        `${spec.env} (${dir}) is at ${head.slice(0, 12)}, but the keys were written against ${spec.commit}: ` +
          `check out ${spec.commit}, or pass --allow-commit-mismatch to run anyway (line keys may then be wrong).`,
      );
    }
    out[id] = { id, available: true, dir, commit: head };
  }
  return out;
}

/** The spike folder itself (keys and app-s), or undefined when its variable is unset. */
export function spikeDir(env: Readonly<Record<string, string | undefined>> = process.env): string | undefined {
  return envDir(env, SPIKE_ENV, CORPORA['app-s'].hint);
}

// ---------- copying ----------

function walkFiles(dir: string, base: string = dir): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === '.git' || e.name === 'node_modules' || e.name === '.guardian') continue;
      out.push(...walkFiles(p, base));
    } else if (e.isFile()) {
      out.push(relative(base, p).split(sep).join('/'));
    }
  }
  return out;
}

function writeText(root: string, rel: string, text: string): void {
  const p = join(root, ...rel.split('/'));
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text, 'utf8');
}

function copyBytes(srcRoot: string, rel: string, destRoot: string, outRel: string = rel): void {
  const to = join(destRoot, ...outRel.split('/'));
  mkdirSync(dirname(to), { recursive: true });
  copyFileSync(join(srcRoot, ...rel.split('/')), to);
}

/** One file of a blind copy: where it comes from, where it goes, and how its text changes (null: copied as bytes). */
interface PlannedFile {
  from: string;
  to: string;
  transform: ((text: string) => string) | null;
}

function planCopy(id: CorpusId, src: string): PlannedFile[] {
  const read = (rel: string): string => readFileSync(join(src, ...rel.split('/')), 'utf8');
  switch (id) {
    case 'app-s':
      return walkFiles(src).map((rel) => ({ from: rel, to: rel, transform: null }));
    case 'vampi':
      return VAMPI_FILES.map((rel) => ({ from: rel, to: rel, transform: (t: string) => blindVampiText(rel, t) }));
    case 'juice-shop': {
      const rels = ['server.ts', 'app.ts']
        .concat(...['routes', 'lib', 'models'].map((d) => walkFiles(join(src, d)).map((r) => `${d}/${r}`)))
        .filter(isJuiceFile);
      const alias = juiceAliases(rels.map(read).join('\n'));
      return rels.map((rel) => ({ from: rel, to: juiceOutPath(rel), transform: (t: string) => blindJuiceText(rel, t, alias) }));
    }
    case 'dvwa':
      return dvwaFiles().map((f) => ({ from: f.source, to: f.out, transform: (t: string) => blindDvwaText(f.source, t) }));
    case 'benchmark-python':
      return BENCHMARK_PY_ROOTS.flatMap((top) => {
        const abs = join(src, top);
        if (!existsSync(abs)) return [];
        const rels = statSync(abs).isDirectory() ? walkFiles(abs).map((r) => `${top}/${r}`) : [top];
        return rels.map((rel) => ({
          from: rel,
          to: benchmarkBlindPath(rel),
          transform: fileKindOf(rel) === 'binary' ? null : (t: string) => blindBenchmarkText(rel, t),
        }));
      });
  }
}

export interface LocatedTell extends Tell {
  file: string;
}

export interface BlindCopyReport {
  files: number;
  /** Tells in the files the copy is made of, before blinding (paths included). */
  tells_before: number;
  /** Tells in the finished copy — always empty: a copy with any is refused. */
  tells_after: LocatedTell[];
}

/**
 * Builds the blind copy of corpus `id` (source `src`) at `dest`, which must
 * not exist yet, then greps the finished copy for tells (`tells.ts`) and
 * THROWS when any survives: a copy that tells the model what it is looking
 * at measures recall, not reasoning.
 */
export function buildBlindCopy(id: CorpusId, src: string, dest: string): BlindCopyReport {
  if (existsSync(dest)) throw new Error(`blind copy target already exists: ${dest}`);
  mkdirSync(dest, { recursive: true });
  const plan = planCopy(id, src);
  let before = 0;
  const after: LocatedTell[] = [];
  for (const f of plan) {
    const binary = fileKindOf(f.from) === 'binary';
    const original = binary ? null : readFileSync(join(src, ...f.from.split('/')), 'utf8');
    before += findTells(f.from, original).length;
    if (original === null || f.transform === null) {
      copyBytes(src, f.from, dest, f.to);
      after.push(...findTells(f.to, original).map((t) => ({ ...t, file: f.to })));
      continue;
    }
    const blinded = f.transform(original);
    writeText(dest, f.to, blinded);
    after.push(...findTells(f.to, blinded).map((t) => ({ ...t, file: f.to })));
  }
  if (after.length > 0) {
    const shown = after
      .slice(0, 20)
      .map((t) => `${t.file}:${t.line} [${t.where}] ${t.tell}`)
      .join('\n  ');
    throw new Error(`the blind copy of ${id} still carries ${after.length} tell(s); refusing to run on it:\n  ${shown}`);
  }
  return { files: plan.length, tells_before: before, tells_after: after };
}

/**
 * One run's temp workspace: a neutral `ws-…` directory holding the blind
 * copies, each built once, plus per-item variants (a copy of a blind copy
 * with one file replaced — the adversarial set's injected items).
 */
export class Workspace {
  readonly root: string;
  private readonly bases = new Map<CorpusId, string>();
  /** What each blind copy built so far held before and after blinding. */
  readonly reports = new Map<CorpusId, BlindCopyReport>();
  private variants = 0;

  constructor(private readonly corpora: Readonly<Record<CorpusId, CorpusState>>) {
    this.root = canonicalPath(mkdtempSync(join(tmpdir(), 'ws-')));
  }

  /** The blind copy of `id` (canonical path), built on first use; undefined when the corpus is N/A. */
  base(id: CorpusId): string | undefined {
    const done = this.bases.get(id);
    if (done !== undefined) return done;
    const state = this.corpora[id];
    if (!state.available) return undefined;
    const dest = join(this.root, CORPORA[id].blindName);
    this.reports.set(id, buildBlindCopy(id, state.dir, dest));
    const canonical = canonicalPath(dest);
    this.bases.set(id, canonical);
    return canonical;
  }

  /** A copy of the blind copy of `id` with `edits` written over it; undefined when the corpus is N/A. */
  variant(id: CorpusId, edits: ReadonlyArray<{ rel: string; text: string }>): string | undefined {
    const base = this.base(id);
    if (base === undefined) return undefined;
    this.variants += 1;
    const dest = join(this.root, `v${String(this.variants).padStart(2, '0')}`, CORPORA[id].blindName);
    cpSync(base, dest, { recursive: true });
    for (const e of edits) writeText(dest, e.rel, e.text);
    return canonicalPath(dest);
  }

  dispose(): void {
    rmDir(this.root);
  }
}
