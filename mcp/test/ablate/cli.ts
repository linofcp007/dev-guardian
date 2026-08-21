/**
 * `npm run ablate -- <pack...> [options]`
 *
 * A tool someone runs deliberately, NOT a vitest test. A full ablation over
 * one pack takes minutes and scales with clause count -- `bugfix-java.yml`
 * alone is well over a hundred clauses at several seconds each -- and the
 * report is the product. Nothing about that belongs in a suite that has to
 * stay fast enough to run on every change.
 *
 * Examples:
 *
 *   npm run ablate -- all
 *   npm run ablate -- bugfix-js
 *   npm run ablate -- bugfix-js --filter=unchecked-match
 *   npm run ablate -- bugfix-js --list
 *   npm run ablate -- --name=scratch --config=/tmp/p.yml --fixtures=... \
 *                     --real-code=../mcp/src
 *
 * Semgrep is located from `--semgrep=`, then `GUARDIAN_SEMGREP`, then PATH.
 *
 * Exit code is 1 when any clause is flagged, errored or INCONCLUSIVE, or any
 * RULE fires on nothing in `hits/` (axis 0); 0 when every clause passes axes
 * 1-3 and every rule passes axis 0. Inconclusive counts as a failure on
 * purpose: it means the real corpus was noisier than the deltas being
 * measured, so the run's passes are not evidence either --
 * so it can gate a release check if anyone wants it to,
 * without being wired into the test suite. A rule with no ablatable clauses
 * is reported, never counted against the pack: there is nothing in it to
 * ablate, which is a fact about the rule and not a defect.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { clauseLabel, enumerateClauses } from './clauses.js';
import { overallVerdict, ruleFlagged, runPack, sha256 } from './harness.js';
import type { PackReport, PackSpec, RealCorpus } from './harness.js';
import { PACKS, packByName, packNames } from './packs.js';
import { renderPackReport, renderSummary } from './report.js';
import { rmDir } from '../helpers/tempDir.js';

interface Options {
  readonly packs: readonly PackSpec[];
  readonly semgrepBin: string;
  readonly filter: string | undefined;
  readonly listOnly: boolean;
  readonly jsonOut: string | undefined;
}

class UsageError extends Error {}

function flagValue(argv: readonly string[], name: string): string | undefined {
  const prefix = `--${name}=`;
  for (const arg of argv) if (arg.startsWith(prefix)) return arg.slice(prefix.length);
  return undefined;
}

function hasFlag(argv: readonly string[], name: string): boolean {
  return argv.includes(`--${name}`);
}

function parse(argv: readonly string[]): Options {
  const positional = argv.filter((a) => !a.startsWith('--'));
  const semgrepBin = flagValue(argv, 'semgrep') ?? process.env['GUARDIAN_SEMGREP'] ?? 'semgrep';
  const filter = flagValue(argv, 'filter');
  const listOnly = hasFlag(argv, 'list');
  const jsonOut = flagValue(argv, 'json');

  const adHocConfig = flagValue(argv, 'config');
  const realCodeFlag = flagValue(argv, 'real-code');
  const noRealCode = hasFlag(argv, 'no-real-code');
  const realCode: RealCorpus | undefined =
    realCodeFlag === undefined ? undefined : { label: realCodeFlag, dir: resolve(realCodeFlag) };

  // Ad-hoc pack: the shape used to prove the harness on a scratch copy of a
  // pack with a defect planted in it. Never touches the registry.
  if (adHocConfig !== undefined) {
    const fixtures = flagValue(argv, 'fixtures');
    if (fixtures === undefined) throw new UsageError('--config requires --fixtures');
    // `--hits=.` makes the fixture ROOT the hits corpus, and `--decoys=a,b`
    // subtracts decoy trees from it. Both exist for a corpus whose directories
    // predate the `hits/` + `misses/` convention -- see `packs.ts` on routes.
    const decoyFlag = flagValue(argv, 'decoys');
    const decoySubdirs =
      decoyFlag === undefined
        ? undefined
        : decoyFlag.split(',').map((d) => d.trim()).filter((d) => d !== '');
    const spec: PackSpec = {
      name: flagValue(argv, 'name') ?? 'scratch',
      config: resolve(adHocConfig),
      fixtures: resolve(fixtures),
      hitsSubdir: flagValue(argv, 'hits') ?? 'hits',
      ...(decoySubdirs === undefined ? {} : { decoySubdirs }),
      ...(realCode === undefined ? {} : { realCode }),
    };
    return { packs: [spec], semgrepBin, filter, listOnly, jsonOut };
  }

  if (positional.length === 0) throw new UsageError('name at least one pack, or `all`');
  const selected: PackSpec[] = [];
  for (const name of positional) {
    if (name === 'all') {
      selected.push(...PACKS);
      continue;
    }
    const pack = packByName(name);
    if (pack === undefined) {
      throw new UsageError(`unknown pack \`${name}\`. Known: ${packNames().join(', ')}, all`);
    }
    selected.push(pack);
  }

  // `--real-code` / `--no-real-code` override the registry for every selected
  // pack, so axis 3 stays a property of the invocation.
  const packs = selected.map<PackSpec>((p) => {
    if (noRealCode) {
      const { realCode: _dropped, ...rest } = p;
      return rest;
    }
    return realCode === undefined ? p : { ...p, realCode };
  });

  return { packs: [...new Map(packs.map((p) => [p.name, p])).values()], semgrepBin, filter, listOnly, jsonOut };
}

function listClauses(spec: PackSpec, filter: string | undefined): void {
  const source = readFileSync(spec.config, 'utf8');
  const inventory = enumerateClauses(source);
  const withClauses = inventory.rules.filter((r) => r.clauseCount > 0).length;
  process.stdout.write(`${spec.name}  sha256 ${sha256(source)}\n`);
  process.stdout.write(
    `  ${String(inventory.clauses.length)} ablatable clauses across ${String(withClauses)} ` +
      `of ${String(inventory.rules.length)} rules\n`,
  );
  let shown = 0;
  for (const c of inventory.clauses) {
    if (filter !== undefined && !`${c.ruleId} ${c.kind} ${c.body} ${c.hash}`.toLowerCase().includes(filter.toLowerCase())) {
      continue;
    }
    shown += 1;
    process.stdout.write(`  ${c.ruleId}\n    ${clauseLabel(c)}\n`);
  }
  if (filter !== undefined) process.stdout.write(`  (${String(shown)} shown by filter)\n`);
  for (const s of inventory.skipped) {
    process.stdout.write(`  SKIPPED ${s.ruleId} :: ${s.reason}\n`);
  }
  // Rules with nothing to ablate are listed HERE rather than left out, for
  // the same reason the report lists them: an enumeration that silently omits
  // a quarter of the pack reads as a complete one.
  for (const r of inventory.rules) {
    if (r.clauseCount > 0) continue;
    process.stdout.write(`  NO CLAUSES ${r.ruleId} :: ${r.noClausesReason ?? ''}\n`);
  }
  process.stdout.write('\n');
}

function main(): number {
  let options: Options;
  try {
    options = parse(process.argv.slice(2));
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`ablate: ${err.message}\n`);
      process.stderr.write(`usage: npm run ablate -- <${packNames().join('|')}|all> [--filter=X] [--list]\n`);
      return 2;
    }
    throw err;
  }

  for (const pack of options.packs) {
    if (!existsSync(pack.config)) {
      process.stderr.write(`ablate: no such pack config: ${pack.config}\n`);
      return 2;
    }
    if (!existsSync(pack.fixtures)) {
      process.stderr.write(`ablate: no such fixture root: ${pack.fixtures}\n`);
      return 2;
    }
  }

  if (options.listOnly) {
    for (const pack of options.packs) listClauses(pack, options.filter);
    return 0;
  }

  // Every temp directory the run makes, removed on normal exit and on Ctrl-C.
  // The pack itself is never written to, so its bytes are safe either way --
  // this is only about not leaving copies of the fixture corpus behind.
  const temps: string[] = [];
  const cleanup = (): void => {
    for (const dir of temps.splice(0)) {
      try {
        rmDir(dir);
      } catch {
        // Cleanup must never mask the result of the run.
      }
    }
  };
  process.on('exit', cleanup);
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
      cleanup();
      process.exit(130);
    });
  }

  const log = (line: string): void => {
    process.stdout.write(`${line}\n`);
  };

  const reports: PackReport[] = [];
  try {
    for (const pack of options.packs) {
      log('');
      const report = runPack(pack, {
        semgrepBin: options.semgrepBin,
        log,
        filter: options.filter,
        registerTempDir: (dir) => temps.push(dir),
      });
      reports.push(report);
      log('');
      log(renderPackReport(report));
    }
  } catch (err) {
    cleanup();
    process.stderr.write(`\nablate: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }

  if (reports.length > 1) log(renderSummary(reports));

  if (options.jsonOut !== undefined) {
    writeFileSync(options.jsonOut, `${JSON.stringify(reports, null, 2)}\n`, 'utf8');
    log(`json written to ${options.jsonOut}`);
  }

  const flagged = reports.flatMap((r) => r.verdicts).filter((v) => overallVerdict(v) !== 'ok');
  // A rule that fires on nothing is a defect in the pack exactly as much as a
  // DEAD clause is, so it gates the same way. Having NO clauses does not:
  // that is a property of the rule, reported and not counted against it.
  const silentRules = reports.flatMap((r) => r.rules).filter(ruleFlagged);
  return flagged.length === 0 && silentRules.length === 0 ? 0 : 1;
}

process.exitCode = main();
