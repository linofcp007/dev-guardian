/**
 * Review 8, findings 2, 3 and 18 — how the gate judges the gaps a scan names
 * per file, what each gap is as data, and where SARIF URIs point.
 *
 *   - a per-file Semgrep `Timeout` is accepted by the project's committed
 *     `.guardian/scan.yml` (`semgrep.accept_timeouts`), never by
 *     `--accept-partial-parse`;
 *   - a file at a path too long for Windows is never accepted;
 *   - a run whose gap is not only its files (`unscanned`, rules that did not
 *     load) is never cleared by naming files;
 *   - every gap carries a kind and a remedy (`coverage_gap_details`).
 */
import { describe, expect, it } from 'vitest';
import { evaluateGate, remedyFor, type GateInput } from '../../../src/ci/gate.js';
import { renderHuman, renderJson, renderSarif } from '../../../src/ci/report.js';
import { CI_EXIT, GAP_KINDS, type ScanStepResult } from '../../../src/ci/types.js';
import type { Finding, ToolRun } from '../../../src/types.js';

const F = 'src/huge.js';

function input(over: Partial<GateInput> = {}): GateInput {
  return { findings: [], baseline: null, failOn: 'high', steps: [], droppedBaselineEntries: 0, ...over };
}

function semgrepStep(refs: Array<{ file: string; type: string }>, run: Partial<ToolRun> = {}): ScanStepResult {
  return {
    tool: 'security_scan_full',
    ran: true,
    tools_run: [{ name: 'semgrep', status: 'ok', reason: 'partial', ...run }],
    missing_tools: ['semgrep'],
    partial_parses: { semgrep: refs },
  };
}

describe('a per-file Timeout: accepted by the committed .guardian/scan.yml, nothing else', () => {
  it('not listed: exit 2, kind file_timeout, the remedy names scan.yml', () => {
    const v = evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'Timeout' }])] }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps[0]).toMatch(/not accepted: Timeout on src\/huge\.js .*\.guardian\/scan\.yml semgrep\.accept_timeouts/);
    expect(v.coverageGapDetails[0]).toMatchObject({ tool: 'semgrep', kind: 'file_timeout', gating: true });
    expect(v.coverageGapDetails[0]?.remedy).toMatch(/\.guardian\/scan\.yml/);
  });

  it('listed in accept_timeouts: exit 0, an accepted line naming its source, coverage still partial', () => {
    const v = evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'Timeout' }])], acceptedTimeouts: [`./${F}`] }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.coverage).toBe('partial');
    expect(v.coverageGaps).toEqual([]);
    expect(v.acceptedGaps).toEqual([`security_scan_full: semgrep timed out on ${F} — accepted (.guardian/scan.yml semgrep.accept_timeouts)`]);
    expect(v.coverageGapDetails).toEqual([expect.objectContaining({ kind: 'file_timeout', gating: false })]);
    expect(v.unusedTimeoutAcceptances).toEqual([]);
  });

  it('an entry no step reported a Timeout on is named unused, on every run — a stale one never sits unnoticed (review 10)', () => {
    // The file timed out once and was accepted; it no longer does, or a
    // parse error on it is not what the entry accepts.
    const v = evaluateGate(
      input({ steps: [semgrepStep([{ file: 'src/other.js', type: 'PartialParsing' }, { file: F, type: 'PartialParsing' }])], acceptedTimeouts: [F, './src/gone.js'] }),
    );
    expect(v.unusedTimeoutAcceptances).toEqual([F, 'src/gone.js']);
    expect(renderJson(v)).toContain('"unused_timeout_acceptances"');
    expect(renderHuman(v)).toContain('note: .guardian/scan.yml semgrep.accept_timeouts src/gone.js: no step reported a Timeout on it (unused');
  });

  it('--accept-partial-parse never accepts a Timeout, and accept_timeouts never a parse error', () => {
    expect(evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'Timeout' }])], acceptedPartialParses: [F] })).exitCode)
      .toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'PartialParsing' }])], acceptedTimeouts: [F] })).exitCode)
      .toBe(CI_EXIT.INCOMPLETE_SCAN);
  });

  it('a parse error and a timeout, each accepted by its own list: exit 0, two accepted lines', () => {
    const v = evaluateGate(input({
      steps: [semgrepStep([{ file: 'a.php', type: 'PartialParsing' }, { file: F, type: 'Timeout' }])],
      acceptedPartialParses: ['a.php'],
      acceptedTimeouts: [F],
    }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.acceptedGaps).toHaveLength(2);
  });

  // Review 11, finding 1: the acceptance was by path alone, so a pull request
  // appended `exec('cat ' + req.query.file)` to an accepted file, the rule
  // timed out on it as on the rest, and the gate passed with exit 0.
  it('under a ref: a timeout on a listed file that changed since the ref is not accepted — exit 2, saying why', () => {
    const steps = [semgrepStep([{ file: F, type: 'Timeout' }])];
    const changed = evaluateGate(input({ steps, acceptedTimeouts: [F], timeoutAcceptanceRef: { ref: 'BASE', changed: new Set([F]) } }));
    expect(changed.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(changed.acceptedGaps).toEqual([]);
    expect(changed.acceptedGapDetails).toEqual([]);
    expect(changed.coverageGaps[0]).toMatch(/not accepted: Timeout on src\/huge\.js, listed in \.guardian\/scan\.yml semgrep\.accept_timeouts, but changed since BASE/);
    expect(changed.coverageGapDetails[0]).toMatchObject({ kind: 'file_timeout', gating: true });
    // Its own cause and remedy (review 12, finding 10): "list it under
    // accept_timeouts" said nothing to someone who had.
    expect(changed.coverageGapDetails[0]?.cause).toBe('accepted_file_changed');
    expect(changed.coverageGapDetails[0]?.remedy).toMatch(/^The file is listed in \.guardian\/scan\.yml semgrep\.accept_timeouts, but it changed/);
    expect(changed.coverageGapDetails[0]?.remedy).not.toMatch(/list the file under/);
    // An unlisted file's timeout keeps the usual remedy, and no cause.
    const unlisted = evaluateGate(input({ steps, timeoutAcceptanceRef: { ref: 'BASE', changed: new Set() } }));
    expect(unlisted.coverageGapDetails[0]?.cause).toBeUndefined();
    expect(unlisted.coverageGapDetails[0]?.remedy).toMatch(/list the file under semgrep\.accept_timeouts/);
    // Listed and timed out: used, never "unused".
    expect(changed.unusedTimeoutAcceptances).toEqual([]);

    const same = evaluateGate(input({ steps, acceptedTimeouts: [F], timeoutAcceptanceRef: { ref: 'BASE', changed: new Set(['src/other.js']) } }));
    expect(same.exitCode).toBe(CI_EXIT.PASS);
    expect(same.acceptedGaps).toHaveLength(1);

    // A comparison that could not be made accepts nothing: never read as "unchanged".
    const unknown = evaluateGate(
      input({ steps, acceptedTimeouts: [F], timeoutAcceptanceRef: { ref: 'BASE', changed: new Set(), error: 'bad object BASE' } }),
    );
    expect(unknown.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(unknown.coverageGaps[0]).toMatch(/could not be told \(bad object BASE\)/);

    // The path the ref's diff names is normalised like the list's.
    const spelled = evaluateGate(input({ steps, acceptedTimeouts: [F], timeoutAcceptanceRef: { ref: 'BASE', changed: new Set([`.\\${F.replace('/', '\\')}`]) } }));
    expect(spelled.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
  });

  it('a pass with accepted files says so under the headline, and in accepted_gap_details — one entry per file', () => {
    const v = evaluateGate(input({
      steps: [
        semgrepStep([{ file: F, type: 'Timeout' }, { file: 'src/gen.js', type: 'Timeout' }, { file: 'a.php', type: 'PartialParsing' }]),
        { ...semgrepStep([{ file: F, type: 'Timeout' }]), tool: 'map_attack_surface' },
      ],
      acceptedTimeouts: [F, 'src/gen.js'],
      acceptedPartialParses: ['a.php'],
    }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    // One line per file now (a step's two timed-out files were one line).
    expect(v.acceptedGaps).toEqual([
      'security_scan_full: semgrep only partly parsed a.php — accepted (--accept-partial-parse)',
      `security_scan_full: semgrep timed out on ${F} — accepted (.guardian/scan.yml semgrep.accept_timeouts)`,
      'security_scan_full: semgrep timed out on src/gen.js — accepted (.guardian/scan.yml semgrep.accept_timeouts)',
      `map_attack_surface: semgrep timed out on ${F} — accepted (.guardian/scan.yml semgrep.accept_timeouts)`,
    ]);
    expect(v.acceptedGapDetails.map((d) => [d.kind, d.file])).toEqual([
      ['partial_parse', 'a.php'],
      ['file_timeout', F],
      ['file_timeout', 'src/gen.js'],
      ['file_timeout', F],
    ]);
    expect(v.acceptedGapDetails[0]?.reason).toBe('PartialParsing — accepted by --accept-partial-parse');
    expect(v.acceptedGapDetails[1]?.reason).toBe('Timeout — accepted by .guardian/scan.yml semgrep.accept_timeouts');
    const human = renderHuman(v).split('\n');
    expect(human[0]).toBe('dev-guardian CI: PASS (exit code 0)');
    // Distinct files: src/huge.js is accepted in two steps, and counted once.
    expect(human[1]).toBe('2 file(s) not analysed (accepted), 1 file(s) only partly parsed (accepted) — listed under "accepted (not gating)"');
    const plain = renderHuman(evaluateGate(input())).split('\n');
    expect(plain[1]).toMatch(/^coverage: /);
  });
});

describe('a gap no acceptance clears', () => {
  it('a file at a path too long for Windows: exit 2, kind path_too_long, whatever is accepted', () => {
    const v = evaluateGate(input({
      steps: [semgrepStep([{ file: F, type: 'Path too long' }])],
      acceptedPartialParses: [F],
      acceptedTimeouts: [F],
    }));
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGapDetails[0]).toMatchObject({ kind: 'path_too_long', gating: true });
    expect(v.coverageGapDetails[0]?.remedy).toMatch(/LongPathsEnabled/);
  });

  it('a file git tracks in .guardian/’s generated output: a gap no flag clears, whose remedy is to stop tracking it (review 10, finding 1)', () => {
    const reason = "1 file(s) git tracks in .guardian/'s generated output were not scanned: .guardian/reports/evil.js — x";
    const v = evaluateGate(
      input({ steps: [semgrepStep([{ file: F, type: 'PartialParsing' }], { reason, unscanned: { guardian_output: 1 } })], acceptedPartialParses: [F] }),
    );
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.acceptedGaps).toEqual([]);
    expect(remedyFor('other', 'semgrep', `security_scan_full: semgrep ran with reduced coverage (${reason})`)).toMatch(/git rm --cached/);
  });

  it('a run that also missed files over the size limit (unscanned), or rules that did not load: never cleared by naming files', () => {
    for (const run of [{ unscanned: { oversized: 1 } }, { failed_rules: [{ rule_id: 'r', message: 'bad' }] }] as Array<Partial<ToolRun>>) {
      const v = evaluateGate(input({ steps: [semgrepStep([{ file: F, type: 'PartialParsing' }], run)], acceptedPartialParses: [F] }));
      expect(v.exitCode, JSON.stringify(run)).toBe(CI_EXIT.INCOMPLETE_SCAN);
      expect(v.acceptedGaps).toEqual([]);
    }
  });
});

describe('every gap as data', () => {
  it('a kind and a non-empty remedy for every kind; only missing_tool says install', () => {
    for (const kind of GAP_KINDS) {
      const remedy = remedyFor(kind, 'semgrep', 'x');
      expect(remedy.length, kind).toBeGreaterThan(10);
      if (kind === 'missing_tool') expect(remedy).toMatch(/^Install semgrep \(`pipx install semgrep`\)/);
      else expect(remedy, kind).not.toMatch(/^Install/);
    }
  });

  it('a Semgrep that refused --config=auto under SEMGREP_SEND_METRICS=off: the remedy says so, not "fix the rule" (review 11, finding 10)', () => {
    const detail =
      'security_scan_full: semgrep failed (semgrep wrote no JSON report (exit 2) — semgrep said: Cannot create auto config when ' +
      'metrics are off. — SEMGREP_SEND_METRICS=off is set in the environment, and Semgrep cannot build its registry rules ' +
      "(--config=auto) with metrics off: unset it for the scan, or scan local-only (local_only: true, the CLI's --local-only))";
    expect(remedyFor('scanner_failed', 'semgrep', detail)).toMatch(/^Unset SEMGREP_SEND_METRICS/);
    expect(remedyFor('scanner_failed', 'semgrep', 'semgrep failed (a rule did not load)')).toMatch(/rule/);
  });

  it("gosec's gaps: the Go toolchain is never install_toolchain's, and a package that does not type-check says how to make it build", () => {
    expect(remedyFor('missing_tool', 'go', 'security_scan_full: go not installed')).toMatch(
      /^Install the Go toolchain your go\.mod names .* install_toolchain never installs it\.$/,
    );
    expect(remedyFor('missing_tool', 'gosec', 'security_scan_full: gosec not installed')).toMatch(/^Install gosec and put it on PATH/);
    const detail =
      'security_scan_full: gosec ran with reduced coverage (…) — not accepted: Type error on broken/b.go (--accept-partial-parse accepts parse errors only: PartialParsing, Syntax error, Lexical error)';
    expect(remedyFor('other', 'gosec', detail)).toMatch(/go mod download/);
    expect(remedyFor('other', 'gosec', 'scan: gosec … Package not loaded on pkg')).toMatch(/go mod download/);
  });

  it('a gosec step: a type error gates as `other`, a syntax error is accepted by --accept-partial-parse', () => {
    const toolsRun = [
      {
        name: 'gosec',
        status: 'ok' as const,
        reason: 'partial',
        partially_parsed: [
          { file: 'broken/b.go', type: 'Type error', message: 'undefined: x' },
          { file: 'syntaxerr/s.go', type: 'Syntax error', message: "expected ')'" },
        ],
      },
    ];
    const step: ScanStepResult = {
      tool: 'security_scan_full',
      ran: true,
      tools_run: toolsRun,
      missing_tools: ['gosec'],
      partial_parses: {
        gosec: [
          { file: 'broken/b.go', type: 'Type error' },
          { file: 'syntaxerr/s.go', type: 'Syntax error' },
        ],
      },
    };
    const base: GateInput = { findings: [], baseline: null, failOn: 'high', steps: [step], droppedBaselineEntries: 0 };
    const onlySyntax = evaluateGate({ ...base, acceptedPartialParses: ['syntaxerr/s.go', 'broken/b.go'] });
    expect(onlySyntax.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(onlySyntax.coverageGaps.join('\n')).toMatch(/not accepted: Type error on broken\/b\.go/);
    expect(onlySyntax.coverageGapDetails.find((d) => d.gating)?.remedy).toMatch(/go mod download/);
  });

  it('a cppcheck step: a file it could not configure gates and says how to configure it; one too old says to upgrade', () => {
    const step: ScanStepResult = {
      tool: 'security_scan_full',
      ran: true,
      tools_run: [
        {
          name: 'cppcheck',
          status: 'ok' as const,
          reason: 'partial',
          partially_parsed: [
            { file: 'src/syntax.c', type: 'Syntax error', message: "Unmatched '('" },
            { file: 'src/macro.cpp', type: 'Unknown macro', message: 'There is an unknown macro here somewhere.' },
          ],
        },
      ],
      missing_tools: ['cppcheck'],
      partial_parses: {
        cppcheck: [
          { file: 'src/syntax.c', type: 'Syntax error' },
          { file: 'src/macro.cpp', type: 'Unknown macro' },
        ],
      },
    };
    const base: GateInput = { findings: [], baseline: null, failOn: 'high', steps: [step], droppedBaselineEntries: 0 };
    const v = evaluateGate({ ...base, acceptedPartialParses: ['src/syntax.c', 'src/macro.cpp'] });
    expect(v.exitCode).toBe(CI_EXIT.INCOMPLETE_SCAN);
    expect(v.coverageGaps.join('\n')).toMatch(/not accepted: Unknown macro on src\/macro\.cpp/);
    expect(v.coverageGapDetails.find((d) => d.gating)?.remedy).toMatch(/compile_commands\.json .*CMAKE_EXPORT_COMPILE_COMMANDS/);
    expect(remedyFor('other', 'cppcheck', 'scan: cppcheck … not accepted: Not read on src/gone.c')).toMatch(/exists and is readable/);

    const old = 'security_scan_full: cppcheck skipped (cppcheck 2.13 or newer is needed and it is 2.10: an older one skips a file …)';
    expect(remedyFor('skipped', 'cppcheck', old)).toBe(
      'Install a newer cppcheck — the detail names the oldest it runs — and put it first on PATH, then rerun the scan.',
    );
  });

  it("Psalm's gaps: PHP is never install_toolchain's, and one too old or a Psalm too old says to upgrade", () => {
    expect(remedyFor('missing_tool', 'php', 'security_scan_full: php not installed')).toMatch(
      /^Install PHP 8\.2 or newer with its xml and mbstring extensions .* install_toolchain never installs it\.$/,
    );
    expect(remedyFor('skipped', 'psalm', 'scan: psalm skipped (Psalm needs PHP 8.2 or newer and it is 8.1)')).toBe(
      'Install PHP 8.2 or newer and put it first on PATH, then rerun the scan.',
    );
    expect(remedyFor('skipped', 'psalm', 'scan: psalm skipped (Psalm 6 or newer is needed and it is 5.26)')).toMatch(/^Install a newer psalm/);
  });

  it('kinds from what a step says: not installed, no lockfile, a refused step, a failed run, a shallow clone', () => {
    const steps: ScanStepResult[] = [
      { tool: 'security_scan_full', ran: true, tools_run: [], missing_tools: ['bandit'] },
      { tool: 'scan_deps', ran: true, tools_run: [{ name: 'trivy', status: 'skipped', reason: 'no_supported_manifest' }], missing_tools: ['trivy'] },
      { tool: 'map_attack_surface', ran: false, reason: 'missing_scanner: semgrep is not installed', tools_run: [], missing_tools: [] },
      { tool: 'scan_iac', ran: true, tools_run: [{ name: 'zizmor', status: 'failed', reason: 'exit 2' }], missing_tools: [] },
      {
        tool: 'scan_secrets',
        ran: true,
        tools_run: [{ name: 'gitleaks', status: 'ok', reason: 'history truncated at abc — a shallow clone' }],
        missing_tools: ['gitleaks'],
      },
    ];
    const v = evaluateGate(input({ steps }));
    expect(v.coverageGapDetails.map((d) => [d.tool, d.kind])).toEqual([
      ['bandit', 'missing_tool'],
      ['trivy', 'no_lockfile'],
      ['map_attack_surface', 'missing_tool'],
      ['zizmor', 'scanner_failed'],
      ['gitleaks', 'other'],
    ]);
    expect(v.coverageGapDetails[4]?.remedy).toMatch(/git fetch --unshallow/);
    expect(v.coverageGapDetails.every((d) => d.gating)).toBe(true);
  });

  it('a dropped baseline entry is a gap line that never gates', () => {
    const v = evaluateGate(input({ droppedBaselineEntries: 2 }));
    expect(v.exitCode).toBe(CI_EXIT.PASS);
    expect(v.coverageGapDetails).toEqual([expect.objectContaining({ tool: 'baseline', kind: 'other', gating: false })]);
  });
});

describe('SARIF URIs resolve against the repository root (finding 18)', () => {
  const f: Finding = {
    fingerprint: 'fp',
    tool: 'semgrep',
    severity: 'high',
    category: 'security',
    title: 't',
    rule_id: 'r',
    file_path: 'src/app.js',
    line_start: 1,
    fix_available: false,
  } as Finding;
  const uriOf = (prefix: string | undefined): string => {
    const doc = JSON.parse(renderSarif(evaluateGate(input({ findings: [f] })), '/repo/packages/api', prefix === undefined ? {} : { repoPrefix: prefix })) as {
      runs: Array<{ results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }>;
    };
    return doc.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri ?? '';
  };

  it('a project below the root has its place in the repository put in front', () => {
    expect(uriOf('packages/api/')).toBe('packages/api/src/app.js');
    expect(uriOf('packages\\api')).toBe('packages/api/src/app.js');
  });

  it('at the root, or with nothing usable, the URI is project-relative as before', () => {
    expect(uriOf(undefined)).toBe('src/app.js');
    expect(uriOf('')).toBe('src/app.js');
    expect(uriOf('../escape/')).toBe('src/app.js');
  });
});
