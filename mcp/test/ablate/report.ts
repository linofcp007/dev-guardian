/**
 * Report rendering. The report IS the product of an ablation run, so it is
 * written to be read months later by someone who was not there: it names the
 * pack, prints the hash of the exact bytes that were ablated, and identifies
 * every clause by its own content rather than by a line number that will have
 * moved by then.
 */

import { clauseLabel } from './clauses.js';
import { overallVerdict, short } from './harness.js';
import type { ClauseVerdict, PackReport } from './harness.js';
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
    out.push('          Nothing in the pack depends on it. Delete it, or add the');
    out.push('          fixture that proves it is needed.');
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

export function renderPackReport(report: PackReport): string {
  const lines: string[] = [];
  const flagged = report.verdicts.filter((v) => overallVerdict(v) === 'FLAG');
  const errored = report.verdicts.filter((v) => overallVerdict(v) === 'ERR');
  const dead = report.verdicts.filter((v) => v.live === 'FAIL');
  const suppressing = report.verdicts.filter((v) => v.keepsTruePositives === 'FAIL');
  const noisy = report.verdicts.filter((v) => v.noAddedNoise === 'FAIL');

  lines.push(rule('='));
  lines.push(`ABLATION REPORT -- ${report.pack}`);
  lines.push(rule('='));
  lines.push(`config          ${report.configPath}`);
  lines.push(`sha256          ${report.configSha256}`);
  lines.push(`rules           ${String(report.ruleCount)}`);
  lines.push(`clauses ablated ${String(report.clauseCount)}`);
  lines.push(`fixture corpus  ${report.fixtureCorpus}  (${String(report.baselineFixtures)} baseline findings, ${String(report.baselineHits)} in hits/)`);
  lines.push(
    `real corpus     ${report.realCorpus ?? '(none -- axis 3 N/A)'}` +
      (report.baselineReal === null ? '' : `  (${String(report.baselineReal)} baseline findings)`),
  );
  lines.push(`wall clock      ${report.seconds.toFixed(1)}s`);
  lines.push('');
  lines.push(`axis 1 live                     ${String(report.clauseCount - dead.length - errored.length)}/${String(report.clauseCount)} pass, ${String(dead.length)} DEAD`);
  lines.push(`axis 2 keeps true positives     ${String(report.clauseCount - suppressing.length - errored.length)}/${String(report.clauseCount)} pass, ${String(suppressing.length)} SUPPRESSING`);
  lines.push(
    report.realCorpus === null
      ? `axis 3 no rise in real-code count  N/A -- no real-code corpus for this pack`
      : `axis 3 no rise in real-code count  ${String(report.clauseCount - noisy.length - errored.length)}/${String(report.clauseCount)} pass, ${String(noisy.length)} RAISING the count`,
  );
  if (errored.length > 0) lines.push(`errors                          ${String(errored.length)}`);
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
    lines.push('on real code. Nothing to act on.');
  } else {
    lines.push(rule());
    lines.push(`FLAGGED CLAUSES (${String(flagged.length + errored.length)})`);
    lines.push(rule());
    for (const v of [...flagged, ...errored]) {
      lines.push('');
      lines.push(...detail(v));
    }
  }
  lines.push('');
  return lines.join('\n');
}

export function renderSummary(reports: readonly PackReport[]): string {
  const lines: string[] = [];
  lines.push(rule('='));
  lines.push('ABLATION SUMMARY');
  lines.push(rule('='));
  lines.push('pack         rules clauses  dead    suppress raise errors  secs');
  for (const r of reports) {
    const dead = r.verdicts.filter((v) => v.live === 'FAIL').length;
    const supp = r.verdicts.filter((v) => v.keepsTruePositives === 'FAIL').length;
    const noisy = r.verdicts.filter((v) => v.noAddedNoise === 'FAIL').length;
    const errs = r.verdicts.filter((v) => v.live === 'ERROR').length;
    lines.push(
      [
        r.pack.padEnd(13, ' '),
        String(r.ruleCount).padStart(5, ' '),
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
