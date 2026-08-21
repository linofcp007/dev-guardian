/**
 * The pack registry: which rule pack is ablated against which corpora.
 *
 * Axis 3 (does the clause raise the finding count on code nobody wrote as a
 * fixture?) needs a real-code corpus in a language the pack matches. That is
 * a property of the INVOCATION, recorded here per pack and overridable from
 * the command line, not a special case buried inside the harness: `mcp/src`
 * is the only large body of not-written-as-a-fixture code IN this repo, and
 * it is TypeScript, so the JS/TS pack is the only one whose corpus can be a
 * committed path.
 *
 * Three packs are the exception, and all three are opt-in rather than absent:
 * Rust, C# and Java, each reading a corpus path from an environment variable.
 *
 * Rust's standard library source is ~1400 `.rs` files nobody wrote as
 * a fixture, it is free (`rustup component add rust-src`, or copied out of
 * `<toolchain>/lib/rustlib/src/rust/library` in the `rust:1.79-alpine`
 * image after adding the component), and in the Rust probe it is what turned
 * "three rules ship" into "one": `mem-forget` scored 43 findings and zero
 * true positives on it, and `unwrap-in-drop` was found accusing the canonical
 * mitigation it is supposed to prescribe. Both had clean fixtures and would
 * have shipped under a C#-style round, where axis 3 was permanently N/A.
 *
 * It cannot be a committed path — the standard library does not belong in
 * this tree — so it is read from `GUARDIAN_RUST_SRC`. Unset, axis 3 reports
 * `N/A` for the pack, loudly, the same way it does for every pack with no
 * corpus. Set to a path that does not exist, it THROWS rather than degrading
 * to N/A: a typo'd corpus that silently becomes "not measured" is the exact
 * shape of failure this harness exists to prevent.
 *
 * KNOW WHAT THIS CORPUS IS WEAK AT, because a PASS on it is not the same
 * strength of evidence for every rule. Measured on the 1.79 library tree:
 * 1201 files scanned, and only **14 of them contain the string `async fn`**.
 * So for `blocking-sleep-in-async` — the only rule the pack currently has —
 * axis 3 is close to vacuous: the baseline is 0 findings and every clause
 * passes trivially, because there is barely any async Rust for the rule to be
 * wrong about. The corpus earned its keep against `mem-forget` and
 * `unwrap-in-drop`, which are about ownership and `Drop`, and the standard
 * library is saturated with both. A future async rule wanting real axis-3
 * evidence needs a corpus of async Rust, which this is not.
 *
 * **C#, `GUARDIAN_CS_SRC`, and why it is here at all.** The C# round shipped
 * with axis 3 recorded as permanently `N/A` — the design of record said so in
 * as many words — because this repo holds no C#. It shipped
 * `null-safety-as-cast-deref` under that gap, and the first axis-3 corpus the
 * pack ever had **deleted the rule**: 6490 findings on `dotnet/runtime`
 * (`src/libraries` product source, 11 800 files), against 402 for
 * `empty-catch` on the same corpus, and no true positives in a 75-finding
 * hand-read sample. 67.6 %
 * of them were not even about `as` — Semgrep's C# frontend puts `o as T` and
 * `(T)o` on the SAME node, so the rule's own premise ("`as` yields null where
 * a cast throws") is not expressible in this engine at all. Axes 0, 1 and 2
 * passed throughout, on fixtures written by the rule's own author.
 *
 * Any tree of real C# will do. What produced that measurement:
 * `git clone --filter=blob:none --no-checkout --depth 1` of `dotnet/runtime`,
 * then a NON-CONE sparse checkout of the `src/libraries` product-source glob
 * (each area's `src` subtree, tests excluded). Keep it at a SHORT path —
 * semgrep-core scans zero files with `Failed to obtain target files` on a long
 * Windows path, and that message points nowhere near its cause.
 *
 * **A corpus this size does not finish.** Roughly a dozen `dotnet/runtime`
 * files are big enough to trip semgrep-core's per-rule timeout, and three
 * timeouts on one file make it drop that file for every rule still to run.
 * `paths.scanned` reads 11 800 regardless. The whole-corpus total therefore
 * moves between identical runs — 793 and 798, measured — which is why axis 3
 * compares one rule at a time on the files every scan finished, and prints
 * both the excluded-file count and the measured floor. See `axis3.ts`. Nothing
 * to configure here; it is stated so that a future corpus is chosen knowing
 * that a bigger one is not automatically a better one.
 *
 * **Java, `GUARDIAN_JAVA_SRC`.** The Java pack shipped eight rules and took
 * nine fix waves without ever being pointed at code nobody here wrote, save
 * one hand-run measurement of `empty-catch`. What the first real round found
 * is why this entry exists rather than being a nicety:
 * `memory-leak-stream-not-closed` scored 12 findings on the OpenJDK and EIGHT
 * of them were two-resource try-with-resources headers — code that closes its
 * stream — because the exclusions named a single-resource header and a
 * two-resource one is a different node. `optional-get-no-ispresent` scored 26
 * and 15 were two guard shapes nobody had enumerated. In the other direction,
 * `race-condition-static-dateformat` was blind to the ONE genuine race either
 * corpus contained, and `off-by-one-loop-lte-length` was blind to `++i`,
 * `i += 1` and `for (var i = 0;`. None of that is visible from fixtures.
 *
 * What produced those numbers: `git clone --filter=blob:none --no-checkout
 * --depth 1` of `openjdk/jdk`, then a NON-CONE sparse checkout of
 * `/src/<module>/share/classes/**` — 12 596 files, 12 593 of which Semgrep
 * scans. A second corpus of `spring-projects/spring-framework`
 * (`/spring-<module>/src/main/java/**`, 5 212 files) is worth having beside it
 * and is not interchangeable with it: the two corpora disagree on five rules
 * of eight. Any tree of real Java will do. Keep it at a SHORT path, for the
 * same reason as the C# one.
 *
 * SIZE THE CORPUS TO THE RUN, because this pack has 169 clauses and every one
 * costs a full corpus scan. The whole OpenJDK tree scans in ~180s, so a full
 * `npm run ablate -- bugfix-java` over it is an eight-hour run and will not
 * survive whatever kills long jobs on the machine. The round that registered
 * this env var used `src/java.base` — 3 118 files, ~47s a scan, 327 baseline
 * findings across five of the eight rules — and drove it one rule at a time
 * with `--filter`. That is a real trade: `stream-not-closed` and
 * `modify-during-iteration` score ZERO on `java.base`, so axis 3 is close to
 * vacuous for them there in exactly the way it is for the Rust async rule. The
 * whole tree is the right corpus for reading findings; a module of it is the
 * right corpus for a clause sweep.
 *
 * KNOW WHAT THESE CORPORA ARE WEAK AT. Both are mature, heavily reviewed
 * LIBRARY code, where a map is nearly always populated in full by the class
 * that reads it. `null-safety-map-get-deref` scores 43 on the JDK and 12 on
 * Spring, and a hand-read of all 55 found no live defect — but every one of
 * the 55 is a map the same class fills, which is not how application code
 * keyed on external input behaves. That measurement is a reason to distrust
 * the rule, not yet a reason to delete it; the corpus that would settle it is
 * a body of application Java, which neither of these is.
 *
 * `base.yml` does contain JS/TS rules and would accept `mcp/src` as a corpus;
 * it is left off by default only because nobody has read that baseline yet.
 * Turn it on with `--real-code=../mcp/src` when someone is ready to triage
 * whatever it reports.
 *
 * `routes.yml` is deliberately absent: it is a route-inventory pack with no
 * `hits/` + `misses/` fixture pair, so axes 1 and 2 have nothing to measure
 * against. Give it a fixture corpus and it belongs here like the rest.
 */

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PackSpec, RealCorpus } from './harness.js';

/** `<repo>/mcp/test/ablate/packs.ts` -> `<repo>`. */
export const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));

const config = (name: string): string => resolve(REPO_ROOT, 'configs', 'semgrep', `${name}.yml`);
const fixtures = (name: string): string => resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', name);

/** Real-code corpus for the JS/TS pack: this repo's own server sources. */
export const MCP_SRC = { label: 'mcp/src', dir: resolve(REPO_ROOT, 'mcp', 'src') } as const;

/** Env var naming the Rust standard-library source tree, for axis 3. */
export const RUST_SRC_ENV = 'GUARDIAN_RUST_SRC';

/** Env var naming a tree of real C# source, for axis 3. */
export const CS_SRC_ENV = 'GUARDIAN_CS_SRC';

/** Env var naming a tree of real Java source, for axis 3. */
export const JAVA_SRC_ENV = 'GUARDIAN_JAVA_SRC';

/**
 * An opt-in axis-3 corpus read from an environment variable.
 *
 * Unset (or empty), the corpus is `undefined` and the harness prints axis 3 as
 * `N/A` for the pack — a verdict, printed, rather than a silent skip. Set to a
 * path that does not exist it THROWS, because a typo'd corpus that quietly
 * becomes "not measured" is the exact shape of failure this harness exists to
 * prevent.
 */
function envCorpus(envVar: string, label: string, hint: string): RealCorpus | undefined {
  const dir = process.env[envVar];
  if (dir === undefined || dir.trim() === '') return undefined;
  const abs = resolve(dir.trim());
  if (!existsSync(abs)) {
    throw new Error(
      `${envVar} is set to ${abs}, which does not exist. Unset it to run with ` +
        `axis 3 as N/A, or point it at ${hint}.`,
    );
  }
  return { label, dir: abs };
}

/** Axis-3 corpus for the Rust pack. See `envCorpus` and the file header. */
export function rustStdlibCorpus(): RealCorpus | undefined {
  return envCorpus(RUST_SRC_ENV, 'rust-src (standard library)', 'a rust-src library tree');
}

/** Axis-3 corpus for the C# pack. See `envCorpus` and the file header. */
export function csharpCorpus(): RealCorpus | undefined {
  return envCorpus(CS_SRC_ENV, 'C# corpus (GUARDIAN_CS_SRC)', 'a tree of real C# source');
}

/** Axis-3 corpus for the Java pack. See `envCorpus` and the file header. */
export function javaCorpus(): RealCorpus | undefined {
  return envCorpus(JAVA_SRC_ENV, 'Java corpus (GUARDIAN_JAVA_SRC)', 'a tree of real Java source');
}

const RUST_STDLIB = rustStdlibCorpus();
const CSHARP_SRC = csharpCorpus();
const JAVA_SRC = javaCorpus();

export const PACKS: readonly PackSpec[] = [
  {
    name: 'bugfix-js',
    config: config('bugfix-js'),
    fixtures: fixtures('bugfix-js'),
    hitsSubdir: 'hits',
    realCode: MCP_SRC,
  },
  { name: 'bugfix-py', config: config('bugfix-py'), fixtures: fixtures('bugfix-py'), hitsSubdir: 'hits' },
  { name: 'bugfix-go', config: config('bugfix-go'), fixtures: fixtures('bugfix-go'), hitsSubdir: 'hits' },
  {
    name: 'bugfix-java',
    config: config('bugfix-java'),
    fixtures: fixtures('bugfix-java'),
    hitsSubdir: 'hits',
    realCode: JAVA_SRC,
  },
  {
    name: 'bugfix-cs',
    config: config('bugfix-cs'),
    fixtures: fixtures('bugfix-cs'),
    hitsSubdir: 'hits',
    realCode: CSHARP_SRC,
  },
  // Axis 3 is N/A: this repo holds no PHP outside this fixture tree. The PHP
  // pack WAS measured against a real corpus — WordPress 6.9, 1467 files, and
  // that measurement changed four verdicts (design of record §1) — but the
  // corpus is a 60 MB third-party download, not something to vendor here.
  // Point the harness at one with `--real-code=<dir>` when you have a WordPress
  // (or any PHP) tree on disk; without it the report prints N/A rather than
  // pretending the axis ran.
  { name: 'bugfix-php', config: config('bugfix-php'), fixtures: fixtures('bugfix-php'), hitsSubdir: 'hits' },
  {
    name: 'bugfix-rs',
    config: config('bugfix-rs'),
    fixtures: fixtures('bugfix-rs'),
    hitsSubdir: 'hits',
    realCode: RUST_STDLIB,
  },
  { name: 'base', config: config('base'), fixtures: fixtures('base'), hitsSubdir: 'hits' },
];

export function packByName(name: string): PackSpec | undefined {
  return PACKS.find((p) => p.name === name);
}

export function packNames(): string[] {
  return PACKS.map((p) => p.name);
}
