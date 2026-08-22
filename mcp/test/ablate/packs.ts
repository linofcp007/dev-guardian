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
 * Every other pack is opt-in rather than absent: Rust, C#, Java, Python, Go and
 * PHP each read a corpus path from an environment variable. Unset, the pack
 * prints axis 3 as `N/A`; set to a path that does not exist, it THROWS. There
 * is exactly one code path for all six ({@link envCorpus}), and adding a
 * seventh means adding an env var and a one-line accessor, not a new idiom.
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
 * that reads it. `null-safety-map-get-deref` scored 43 on the JDK and 12 on
 * Spring, and a hand-read of all 55 found no live defect — but every one of
 * the 55 was a map the same class fills, which is not how application code
 * keyed on external input behaves. That measurement was recorded as a reason
 * to distrust the rule and NOT yet to delete it, with the corpus that would
 * settle it named: a body of application Java, which neither of these is.
 *
 * That corpus was then run, and it deleted the rule. Kafka (224 findings /
 * 3 892 files), Elasticsearch (749 / 20 485) and Jenkins (1 / 1 274) — 973
 * new findings, 45 read by hand, five defensible defects. The number that
 * decided it was not the count: 88% of the Elasticsearch findings and 97% of
 * the Kafka ones carry NO guard anywhere near the dereference. They are
 * correct for semantic reasons — parallel maps kept in sync, a map the class
 * filled in another method, a constant key, an API contract — and no
 * `pattern-not-inside` reaches any of that. See the pack header for the full
 * write-up. The lesson for THIS file is the one the paragraph above already
 * half-stated: a library corpus and an application corpus are different
 * distributions, and a rule that passes on one is not measured until it has
 * seen the other.
 *
 * `base.yml` does contain JS/TS rules and would accept `mcp/src` as a corpus;
 * it is left off by default only because nobody has read that baseline yet.
 * Turn it on with `--real-code=../mcp/src` when someone is ready to triage
 * whatever it reports.
 *
 * **`routes.yml`, and why its registration looks nothing like the others.**
 * It was left out of this file on the grounds that it had no `hits/` +
 * `misses/` fixture pair. It does have one; the directories are simply older
 * than the convention and named for what they are:
 *
 *   hits    `mcp/test/fixtures/surface/` -- `apps/` (whole sample
 *           applications), `annotations/` (each framework's own documented
 *           declaration style) and `frameworks/` (an auditor's corpus of every
 *           form the pack claims). Files that MUST produce routes.
 *   misses  `frameworks/fp/` -- five decoy files of ordinary code shaped like
 *           routes. Registered as `decoySubdirs`, i.e. subtracted from hits.
 *
 * They are not renamed to `hits/` and `misses/` because
 * `test/e2e/rulePackFixture.test.ts` and the surface tools address them by
 * name, so the harness takes `hitsSubdir: '.'` (the fixture root) instead.
 *
 * **The decoy baseline is 9, not 0**, and four of those are `guardian_kind:
 * route`. Every one is undecidable rather than untried, and the e2e test
 * enumerates them: `Route::get('not/a/leading/slash')` on a class that merely
 * happens to be called `Route` is indistinguishable from Laravel's facade, and
 * Ruby's `get 'config/value'` is exactly what a Sinatra route looks like. The
 * other five are an `app.use('/static', express.static(...))` mount, which is
 * a real mount, and four ordinary imports in the decoy files. So the number is
 * printed and pinned, never gated at zero.
 *
 * It was 8 until five decoys were added for the guards that the first full run
 * reported DEAD — three chi exclusions, `guardian-mount-express`'s `$PREFIX`
 * regex and `guardian-route-express`'s one-argument `pattern-not`. All five
 * are load-bearing and all five had no fixture that reached them; the decoys
 * are in `frameworks/fp/decoys.{go,js}`, marked `F07`, `F08` and `F31`-`F33`.
 * **Not one of them moved this number**, which is the point of them: on the
 * shipped pack every one is excluded by the guard it exists for, and each
 * becomes a finding only when that guard is ablated. The +1 is a single
 * ordinary `require('cors')` the `app.use` decoy needs to be plausible code —
 * an import, like the three that were already here.
 *
 * **Axis 3 is `mcp/src`, and it is nearly all vacuous.** Measured: 830 baseline
 * findings, and they belong to exactly TWO of the pack's 64 rules --
 * `guardian-import-esm` (824) and `guardian-env-node` (6). Those two are worth
 * the corpus on their own: `guardian-import-esm` fires 824 times on 190 files
 * of this repo's own TypeScript, so a clause of it that starts matching more
 * has a large, sensitive baseline to move. For the other 62 rules axis 3
 * compares an empty set against an empty set and passes by construction. That
 * is the same weakness `GUARDIAN_RUST_SRC` carries above, and the fix is the
 * same one: state it, and make the report say so per rule --
 * `RuleVerdict.realFindings` puts `real 0 -- axis 3 vacuous here` on the
 * coverage line of every rule the corpus never reached. The alternative
 * considered and rejected was axis 3 `N/A` for the whole pack, which would
 * have been cheaper (the corpus costs ~23s per clause, roughly doubling the
 * run) and would have thrown away the only real-code evidence available for
 * the highest-volume rule in the repo.
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

/** Env var naming a tree of real Python source, for axis 3. */
export const PY_SRC_ENV = 'GUARDIAN_PY_SRC';

/** Env var naming a tree of real Go source, for axis 3. */
export const GO_SRC_ENV = 'GUARDIAN_GO_SRC';

/** Env var naming a tree of real PHP source, for axis 3. */
export const PHP_SRC_ENV = 'GUARDIAN_PHP_SRC';

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

/** Axis-3 corpus for the Python pack. See `envCorpus` and the file header. */
export function pythonCorpus(): RealCorpus | undefined {
  return envCorpus(PY_SRC_ENV, 'Python corpus (GUARDIAN_PY_SRC)', 'a tree of real Python source');
}

/** Axis-3 corpus for the Go pack. See `envCorpus` and the file header. */
export function goCorpus(): RealCorpus | undefined {
  return envCorpus(GO_SRC_ENV, 'Go corpus (GUARDIAN_GO_SRC)', 'a tree of real Go source');
}

/** Axis-3 corpus for the PHP pack. See `envCorpus` and the file header. */
export function phpCorpus(): RealCorpus | undefined {
  return envCorpus(PHP_SRC_ENV, 'PHP corpus (GUARDIAN_PHP_SRC)', 'a WordPress (or any PHP) tree');
}

const RUST_STDLIB = rustStdlibCorpus();
const CSHARP_SRC = csharpCorpus();
const JAVA_SRC = javaCorpus();
const PYTHON_SRC = pythonCorpus();
const GO_SRC = goCorpus();
const PHP_SRC = phpCorpus();

export const PACKS: readonly PackSpec[] = [
  {
    name: 'bugfix-js',
    config: config('bugfix-js'),
    fixtures: fixtures('bugfix-js'),
    hitsSubdir: 'hits',
    realCode: MCP_SRC,
  },
  {
    name: 'bugfix-py',
    config: config('bugfix-py'),
    fixtures: fixtures('bugfix-py'),
    hitsSubdir: 'hits',
    realCode: PYTHON_SRC,
  },
  {
    name: 'bugfix-go',
    config: config('bugfix-go'),
    fixtures: fixtures('bugfix-go'),
    hitsSubdir: 'hits',
    realCode: GO_SRC,
  },
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
  // `GUARDIAN_PHP_SRC` — a WordPress tree, which is what the PHP design round
  // measured against and what keeps the numbers in the design of record
  // comparable. See the file header.
  {
    name: 'bugfix-php',
    config: config('bugfix-php'),
    fixtures: fixtures('bugfix-php'),
    hitsSubdir: 'hits',
    realCode: PHP_SRC,
  },
  {
    name: 'bugfix-rs',
    config: config('bugfix-rs'),
    fixtures: fixtures('bugfix-rs'),
    hitsSubdir: 'hits',
    realCode: RUST_STDLIB,
  },
  { name: 'base', config: config('base'), fixtures: fixtures('base'), hitsSubdir: 'hits' },
  // The route-inventory pack. See the file header for the corpus mapping, the
  // pinned decoy baseline and why axis 3 is `mcp/src` despite reaching only
  // two of its 64 rules.
  {
    name: 'routes',
    config: config('routes'),
    fixtures: fixtures('surface'),
    hitsSubdir: '.',
    decoySubdirs: ['frameworks/fp'],
    realCode: MCP_SRC,
  },
];

export function packByName(name: string): PackSpec | undefined {
  return PACKS.find((p) => p.name === name);
}

export function packNames(): string[] {
  return PACKS.map((p) => p.name);
}
