/**
 * Report rendering. The report IS the product of an ablation run, so it is
 * written to be read months later by someone who was not there: it names the
 * pack, prints the hash of the exact bytes that were ablated, and identifies
 * every clause by its own content rather than by a line number that will have
 * moved by then.
 */

import { clauseLabel } from './clauses.js';
import { overallVerdict, ruleFlagged, short } from './harness.js';
import type { ClauseVerdict, PackReport, RuleVerdict } from './harness.js';
import type { Finding } from './semgrep.js';

function rule(char = '-'): string {
  return char.repeat(78);
}

function findingLine(f: Finding): string {
  return `      ${f.file}:${String(f.line)}:${String(f.col)}  ${f.ruleId}`;
}

function sample(findings: readonly Finding[], max = 6): string[] {
  const shown = findings.slice(0, max).map(findingLine);
  if (findings.length > max) shown.push(`      ... and ${String(findings.length - max)} more`);
  return shown;
}

function signed(n: number): string {
  return n > 0 ? `+${String(n)}` : String(n);
}

function detail(v: ClauseVerdict): string[] {
  const out: string[] = [];
  out.push(`  rule    ${v.clause.ruleId}`);
  out.push(`  clause  ${clauseLabel(v.clause)}`);
  out.push(`  at      ${v.clause.path}   (orientation only; identity is the hash above)`);
  if (v.error !== undefined) {
    out.push(`  ERROR   ${v.error.split('\n').join('\n          ')}`);
    return out;
  }
  if (v.live === 'FAIL') {
    out.push('  axis 1  DEAD -- removing this clause changed nothing, on any corpus.');
    out.push('          Two different defects look like this, and they have opposite');
    out.push('          fixes: the clause is genuinely inert, or the FIXTURE that would');
    out.push('          prove it is needed does not exist. Probe the shape by hand');
    out.push('          before deleting anything. See also the pair pass below --');
    out.push('          two clauses excluding the same shape both read DEAD here.');
  } else {
    out.push(`  axis 1  live -- result moved in: ${v.movedIn.join(', ')} (fixtures ${signed(v.fixtureDelta)})`);
  }
  if (v.keepsTruePositives === 'FAIL') {
    out.push(`  axis 2  SUPPRESSES ${String(v.revealedInHits.length)} finding(s) in hits/ --`);
    out.push('          these appear only once the clause is removed. Read the lines.');
    out.push('          A reveal is a candidate, not a verdict: several `hits/` fixtures');
    out.push('          here deliberately carry the EXCLUDED near-miss alongside the bug');
    out.push('          (the `real_bugs` files annotate them `// excluded: ...`), and a');
    out.push('          reveal on one of those is the clause working. The defect this');
    out.push('          axis exists for looked the same and was not: a `pattern-not-inside`');
    out.push('          written for an `if` swallowed the `else` arm, where the bug was.');
    out.push(...sample(v.revealedInHits));
  } else {
    out.push('  axis 2  keeps true positives -- removing it revealed nothing in hits/');
  }
  if (v.noAddedNoise === 'N/A') {
    out.push('  axis 3  N/A -- this pack has no real-code corpus registered');
  } else if (v.noAddedNoise === 'FAIL') {
    out.push(`  axis 3  RAISES the real-code count by ${String(v.addedByClause.length)} --`);
    out.push('          these findings exist only because of this clause. Read them.');
    out.push('          Only a clause whose removal makes the rule match LESS can land');
    out.push('          here: a positive `pattern-either` branch, or a constraint nested');
    out.push('          INSIDE a `pattern-not`, where dropping it widens the exclusion.');
    out.push('          So a working branch of a rule that legitimately fires on real');
    out.push('          code lands here too -- the verdict is an attribution, not a');
    out.push('          proof that the findings are false. The regression this axis');
    out.push('          exists for looked the same (0 -> 13 on mcp/src) and all 13 were.');
    out.push(...sample(v.addedByClause));
  } else {
    out.push(`  axis 3  does not raise the real-code count (${signed(v.realDelta ?? 0)} when removed)`);
  }
  return out;
}

/**
 * How much of the pack the clause axes actually cover, in a sentence that
 * cannot be mistaken for "all of it". `52/52` was true and useless: it counted
 * the clauses that were measured against the clauses that exist, and said
 * nothing about the rules that have none.
 */
function coverageSentence(report: PackReport): string {
  const clauseless = report.ruleCount - report.rulesWithClauses;
  // `clauseCount` is what this run MEASURED; the enumerated total is what the
  // pack declares. They differ under `--filter`, and whenever a clause was
  // collapsed as a duplicate ablation or skipped as load-bearing -- all three
  // of which have their own section, and none of which should be able to hide
  // inside a bare "52 clauses" headline.
  const enumerated = report.rules.reduce((n, r) => n + r.enumeratedClauses, 0);
  const measured =
    report.clauseCount === enumerated
      ? `${String(report.clauseCount)} clause(s)`
      : `${String(report.clauseCount)} of ${String(enumerated)} clause(s)`;
  return (
    `${measured} across ${String(report.rulesWithClauses)} of ${String(report.ruleCount)} rules` +
    (clauseless === 0
      ? ''
      : `; ${String(clauseless)} rule(s) have no ablatable clauses (axis 0 only)`)
  );
}

function ruleLine(r: RuleVerdict): string {
  const axis0 =
    r.firesOnHits === 'N/A'
      ? 'hits n/a'
      : r.firesOnHits === 'PASS'
        ? `hits ${String(r.hitsFindings)}`
        : 'FIRES ON NOTHING';
  const clauses =
    r.enumeratedClauses === 0
      ? 'no ablatable clauses'
      : r.ablatedClauses === r.enumeratedClauses
        ? `${String(r.ablatedClauses)} clause(s) ablated`
        : `${String(r.ablatedClauses)}/${String(r.enumeratedClauses)} clause(s) ablated`;
  return `  ${axis0.padEnd(17, ' ')} ${clauses.padEnd(24, ' ')} ${r.ruleId}`;
}

export function renderPackReport(report: PackReport): string {
  const lines: string[] = [];
  const flagged = report.verdicts.filter((v) => overallVerdict(v) === 'FLAG');
  const errored = report.verdicts.filter((v) => overallVerdict(v) === 'ERR');
  const dead = report.verdicts.filter((v) => v.live === 'FAIL');
  const suppressing = report.verdicts.filter((v) => v.keepsTruePositives === 'FAIL');
  const noisy = report.verdicts.filter((v) => v.noAddedNoise === 'FAIL');
  const silent = report.rules.filter(ruleFlagged);
  const hitsNA = report.rules.every((r) => r.firesOnHits === 'N/A');

  lines.push(rule('='));
  lines.push(`ABLATION REPORT -- ${report.pack}`);
  lines.push(rule('='));
  lines.push(`config          ${report.configPath}`);
  lines.push(`sha256          ${report.configSha256}`);
  lines.push(
    `rules           ${String(report.ruleCount)}  ` +
      `(${String(report.rulesWithClauses)} with ablatable clauses, ` +
      `${String(report.ruleCount - report.rulesWithClauses)} with none)`,
  );
  lines.push(`coverage        ${coverageSentence(report)}`);
  lines.push(`fixture corpus  ${report.fixtureCorpus}  (${String(report.baselineFixtures)} baseline findings, ${String(report.baselineHits)} in hits/)`);
  lines.push(
    `real corpus     ${report.realCorpus ?? '(none -- axis 3 N/A)'}` +
      (report.baselineReal === null ? '' : `  (${String(report.baselineReal)} baseline findings)`),
  );
  lines.push(`wall clock      ${report.seconds.toFixed(1)}s`);
  lines.push('');
  lines.push(
    hitsNA
      ? `axis 0 fires on hits/           N/A -- this pack has no hits/ fixture corpus`
      : `axis 0 fires on hits/           ${String(report.ruleCount - silent.length)}/${String(report.ruleCount)} rules fire, ${String(silent.length)} FIRING ON NOTHING`,
  );
  lines.push(`axis 1 live                     ${String(report.clauseCount - dead.length - errored.length)}/${String(report.clauseCount)} clauses pass, ${String(dead.length)} DEAD`);
  lines.push(`axis 2 keeps true positives     ${String(report.clauseCount - suppressing.length - errored.length)}/${String(report.clauseCount)} clauses pass, ${String(suppressing.length)} SUPPRESSING`);
  lines.push(
    report.realCorpus === null
      ? `axis 3 no rise in real-code count  N/A -- no real-code corpus for this pack`
      : `axis 3 no rise in real-code count  ${String(report.clauseCount - noisy.length - errored.length)}/${String(report.clauseCount)} clauses pass, ${String(noisy.length)} RAISING the count`,
  );
  lines.push('     (axes 1-3 are properties of a CLAUSE. Rules with none are');
  lines.push('      covered by axis 0 alone -- see RULE COVERAGE below.)');
  if (errored.length > 0) lines.push(`errors                          ${String(errored.length)}`);
  lines.push('');

  lines.push(rule());
  lines.push(`RULE COVERAGE (${String(report.ruleCount)}) -- every rule in the pack, measured or not`);
  lines.push(rule());
  for (const r of report.rules) lines.push(ruleLine(r));
  const clauseless = report.rules.filter((r) => r.enumeratedClauses === 0);
  if (clauseless.length > 0) {
    lines.push('');
    lines.push(`${String(clauseless.length)} rule(s) have nothing to ablate. This is a property of the rule,`);
    lines.push('not a gap in the harness -- but it is also not a pass on axes 1-3,');
    lines.push('which is why they are named here instead of rounding into the totals:');
    for (const r of clauseless) {
      lines.push(`  ${r.ruleId}`);
      lines.push(`    ${r.noClausesReason ?? 'no reason recorded'}`);
    }
  }
  if (silent.length > 0) {
    lines.push('');
    lines.push(`${String(silent.length)} rule(s) FIRE ON NOTHING in hits/. A rule that matches nothing is`);
    lines.push('this repo\'s sixth silent-failure mode: the C# pack shipped');
    lines.push('`foreach ($T $X in $C)` where `foreach (var $X in $C)` was needed and');
    lines.push('found 0 of 5 real bugs, with paths.scanned healthy and no errors.');
    lines.push('Either the rule does not match its own fixture, or no fixture exists:');
    for (const r of silent) lines.push(`  ${r.ruleId}`);
  }
  lines.push('');

  if (report.collapsed.length > 0) {
    lines.push(`Collapsed as duplicate ablations (${String(report.collapsed.length)}) -- removing either one`);
    lines.push('produces byte-identical YAML, so only the first was measured:');
    for (const c of report.collapsed) {
      lines.push(`  ${c.clause.ruleId}`);
      lines.push(`    ${c.clause.kind} [${c.clause.hash}] ${short(c.clause.body, 60)}`);
      lines.push(`    == ${c.sameAs.kind} [${c.sameAs.hash}] ${short(c.sameAs.body, 60)}`);
    }
    lines.push('');
  }

  if (report.skipped.length > 0) {
    lines.push(`Not ablatable in isolation (${String(report.skipped.length)}) -- structurally`);
    lines.push('load-bearing, so no measurement is possible. Listed, never silently dropped:');
    for (const s of report.skipped) {
      lines.push(`  ${s.ruleId}`);
      lines.push(`    ${s.kind} ${short(s.body, 70)}`);
      lines.push(`    ${s.reason}`);
    }
    lines.push('');
  }

  if (flagged.length === 0 && errored.length === 0) {
    lines.push('Every clause is live, suppresses nothing in hits/, and raises no count');
    lines.push('on real code.' + (silent.length === 0 ? ' Nothing to act on.' : ''));
  } else {
    lines.push(rule());
    lines.push(`FLAGGED CLAUSES (${String(flagged.length + errored.length)})`);
    lines.push(rule());
    for (const v of [...flagged, ...errored]) {
      lines.push('');
      lines.push(...detail(v));
    }
  }
  const moving = report.pairs.filter((p) => p.outcome === 'MOVES');
  if (report.pairs.length > 0) {
    lines.push('');
    lines.push(rule());
    lines.push(`PAIR PASS -- ${String(report.pairs.length)} same-rule DEAD pair(s)`);
    lines.push(rule());
    lines.push('Two clauses that exclude the same shape are each redundant with the');
    lines.push('other, so each one alone reads DEAD while removing BOTH is a');
    lines.push('regression. This repo has shipped that pair twice.');
    for (const p of report.pairs) {
      lines.push('');
      lines.push(`  rule    ${p.ruleId}`);
      lines.push(`  a       [${p.a.hash}] ${short(p.a.body, 66)}`);
      lines.push(`  b       [${p.b.hash}] ${short(p.b.body, 66)}`);
      if (p.outcome === 'ERROR') {
        lines.push(`  ERROR   ${(p.error ?? '').split('\n')[0] ?? ''}`);
      } else if (p.outcome === 'MOVES') {
        lines.push(`  MOVES   MUTUALLY REDUNDANT (fixtures ${signed(p.fixtureDelta)}` +
          (p.realDelta === null ? '' : `, real ${signed(p.realDelta)}`) + ').');
        lines.push('          Neither alone changed anything; together they do. Delete');
        lines.push('          EITHER one, never both, and say in the pack which is which.');
      } else {
        lines.push('  INERT   removing both still changes nothing. Not a redundant pair --');
        lines.push('          whatever these two are for, no corpus here exercises it.');
      }
    }
  }
  if (moving.length > 0) {
    lines.push('');
    lines.push(`${String(moving.length)} mutually redundant pair(s) -- see above.`);
  }
  lines.push('');
  return lines.join('\n');
}

export function renderSummary(reports: readonly PackReport[]): string {
  const lines: string[] = [];
  lines.push(rule('='));
  lines.push('ABLATION SUMMARY');
  lines.push(rule('='));
  lines.push('`rules` counts every rule; `covered` is the rules with at least one');
  lines.push('ablatable clause, so `rules - covered` were reached by axis 0 alone.');
  lines.push('`silent` is rules that fire on nothing in hits/ -- always act on those.');
  lines.push('');
  lines.push('pack         rules covered silent clauses  dead    suppress raise errors  secs');
  for (const r of reports) {
    const dead = r.verdicts.filter((v) => v.live === 'FAIL').length;
    const supp = r.verdicts.filter((v) => v.keepsTruePositives === 'FAIL').length;
    const noisy = r.verdicts.filter((v) => v.noAddedNoise === 'FAIL').length;
    const errs = r.verdicts.filter((v) => v.live === 'ERROR').length;
    const silent = r.rules.filter(ruleFlagged).length;
    const hitsNA = r.rules.every((v) => v.firesOnHits === 'N/A');
    lines.push(
      [
        r.pack.padEnd(13, ' '),
        String(r.ruleCount).padStart(5, ' '),
        String(r.rulesWithClauses).padStart(8, ' '),
        (hitsNA ? 'n/a' : String(silent)).padStart(7, ' '),
        String(r.clauseCount).padStart(8, ' '),
        String(dead).padStart(6, ' '),
        String(supp).padStart(12, ' '),
        String(noisy).padStart(6, ' '),
        String(errs).padStart(7, ' '),
        r.seconds.toFixed(0).padStart(6, ' '),
      ].join(''),
    );
  }
  lines.push('');
  for (const r of reports) lines.push(`${r.pack}  sha256 ${r.configSha256}`);
  lines.push('');
  return lines.join('\n');
}
