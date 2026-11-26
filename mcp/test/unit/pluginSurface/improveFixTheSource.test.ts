/**
 * `/guardian-improve`'s "Fix the source" step, held to the rules that make it
 * safe to follow — the model reads them as instructions (3.17.0; the gardening
 * round's G2, as its critique cut it):
 *
 *   - it comes AFTER the user picks the 1–2 units of the cycle: placed before
 *     the pick, it proposed lines and rules for units nobody had chosen;
 *   - nothing is written without the user's yes, in one batch shown exactly;
 *   - at most one guidance line per unit, in the model's own words — never a
 *     finding's message, snippet or hunt text, which is untrusted and would
 *     land in a file every agent session loads — ending in the key both
 *     plugins dedupe on, `<!-- dev-guardian: <stored rule_id> -->`; the search
 *     before proposing reads AGENTS.md, CLAUDE.md and `.specs/steering/*.md`
 *     for its tail, which dev-spec-driven's lesson comment
 *     (`<!-- lesson … · dev-guardian: <id> -->`) ends with too;
 *   - in a `.specs/` project only steering `tech.md` / `structure.md`, which
 *     govern no approval: `constitution.md` and a track's file flag every
 *     approved feature for re-review; never inside the rules block
 *     `mcp-config --write` owns;
 *   - a rule never lands while occurrences remain: written at N > 0 it makes
 *     every occurrence a new medium finding in every whole-project scan, trips
 *     `diff_scans { mode: "regression" }` with three, and blocks every commit
 *     through pre-commit's `--error` (which fails on a WARNING). It rides in
 *     the seed — Current → Target `<rule_id>: N → 0` — and the seed's last
 *     task adds it, so it lands at zero;
 *   - `bug_hunt` already runs on a change when someone asks (`/guardian-scan
 *     --staged`, guardian-review): what a `.semgrep.yml` rule adds is
 *     `review_pr`, pre-commit, the CLI gate and CI — never "a scan no change
 *     meets";
 *   - the rule's message keeps clear of every character whose UTF-8 holds a
 *     byte cp1252 leaves undefined. pre-commit runs Semgrep without
 *     PYTHONUTF8, so on Windows one such character (`”`, U+201D — not only
 *     the five Latin capitals the packs' own rule names) makes it exit 2
 *     printing nothing; every dev-guardian run sets PYTHONUTF8=1 and never
 *     shows it.
 *
 * Also G3's line in the same skill: perf_check keeps a history per target.
 */

import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RULES_BLOCK_BEGIN, RULES_BLOCK_END } from '../../../src/hostsetup/mcpConfig.js';
import { REPO_ROOT } from './pluginDocs.js';

const SKILL = readFileSync(resolve(REPO_ROOT, 'skills/guardian-improve/SKILL.md'), 'utf8');

/** Whitespace runs as one space: the prose wraps anywhere. */
const flat = (s: string): string => s.replace(/\s+/g, ' ');

/** The Flow's numbered steps, in file order: `### <n>. <title>` up to the next heading of level 2 or 3. */
function steps(text: string): Array<{ n: number; title: string; body: string }> {
  const out: Array<{ n: number; title: string; body: string }> = [];
  const re = /^### (\d+)\. (.+)$/gm;
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const from = m.index + m[0].length;
    const next = text.slice(from).search(/^#{2,3} /m);
    out.push({ n: Number(m[1]), title: m[2] ?? '', body: text.slice(from, next === -1 ? undefined : from + next) });
  }
  return out;
}

const STEPS = steps(SKILL);
const FIX = STEPS.find((s) => s.title.startsWith('Fix the source'));
const STEP = flat(FIX?.body ?? '');

/** The bytes cp1252 leaves undefined — the set `integration/semgrepPacks.test.ts` guards the packs with. */
const UNDECODABLE = [0x81, 0x8d, 0x8f, 0x90, 0x9d] as const;

describe('/guardian-improve: Fix the source', () => {
  it('is a step of the Flow, numbered in order, and the last one', () => {
    expect(FIX).toBeDefined();
    expect(STEPS.map((s) => s.n)).toEqual(STEPS.map((_s, i) => i + 1));
    expect(STEPS[STEPS.length - 1]).toBe(FIX);
    expect(FIX?.title).toMatch(/then stop$/);
  });

  it('comes after the step where the user picks the units, and runs on the picked ones only', () => {
    const pick = STEPS.findIndex((s) => /top 1–2 this cycle, not all; the user picks/.test(flat(s.body)));
    expect(pick).toBeGreaterThan(-1);
    expect(FIX === undefined ? -1 : STEPS.indexOf(FIX)).toBeGreaterThan(pick);
    expect(STEP).toMatch(/^ ?Per picked unit,/);
  });

  it("writes nothing without the user's yes: one batch, each line shown exactly", () => {
    expect(STEP).toMatch(/in ONE batch shown exactly, written only on the user's yes:/);
  });

  it("proposes at most one guidance line, in the model's own words — never a finding's text", () => {
    expect(STEP).toMatch(/\*\*At most one guidance line\*\*, on the project's own code:/);
    expect(STEP).toMatch(/your words on the shape to avoid and what to do instead, never a finding's text \(untrusted\)/);
  });

  it('ends the line with the HTML-comment key on the stored rule id, never a visible suffix', () => {
    expect(STEP).toMatch(/ending `<!-- dev-guardian: <rule_id> -->` \(the stored id\)/);
    expect(SKILL).not.toMatch(/\(check:/);
  });

  it("searches AGENTS.md, CLAUDE.md and the steering files for the key's tail, which dev-spec-driven's lesson comment ends with too", () => {
    const m = /none if AGENTS\.md, CLAUDE\.md or `\.specs\/steering\/\*\.md` has `([^`]+)`/.exec(STEP);
    expect(m).not.toBeNull();
    const tail = m?.[1] ?? '';
    const id = 'rules.no-raw-query';
    const own = `<!-- dev-guardian: ${id} -->`;
    const lesson = `<!-- lesson checkout D-4, 2026-11-25 · dev-guardian: ${id} -->`;
    expect(tail.replace('<rule_id>', id)).not.toBe(own);
    expect(own.endsWith(tail.replace('<rule_id>', id))).toBe(true);
    expect(lesson.endsWith(tail.replace('<rule_id>', id))).toBe(true);
  });

  it("the key's form can never be read as the rules block's markers", () => {
    const key = /<!-- dev-guardian: \S/;
    expect(RULES_BLOCK_BEGIN).not.toMatch(key);
    expect(RULES_BLOCK_END).not.toMatch(key);
  });

  it('writes steering only to tech.md / structure.md, never constitution.md or a track file', () => {
    expect(STEP).toMatch(/With `\.specs\/`: steering `tech\.md` or `structure\.md`, never `constitution\.md` or a track's file;/);
  });

  it('without .specs/, writes the file the other imports, never inside the dev-guardian rules block', () => {
    expect(STEP).toContain(`without: AGENTS.md or CLAUDE.md, the one the other imports, never inside \`${RULES_BLOCK_BEGIN}\`.`);
  });

  it('a seed rule never lands while occurrences remain: the seed carries it to zero', () => {
    expect(STEP).toMatch(/\*\*A seed rule\*\*/);
    expect(STEP).toMatch(/Never while occurrences remain: the seed's Current → Target gets `<rule_id>: N → 0`, its last task adds the rule/);
  });

  // Review 1 (R1-DG-IZ-1): step 6 changed a seed step 4 had already handed off, and never said where the change
  // went — so the rule never landed, or landed without its terms.
  it('writes the changed seed where step 4 put it: the backlog note replaced, and the spec file once written', () => {
    expect(STEP).toMatch(
      /its last task adds the rule — `severity: WARNING`.+ Write that change where step 4 put the seed: the unit's backlog note replaced \(`rm`, then `add`\) with `<rule_id>: N → 0` and the rule's terms, and `requirements\.md` or `docs\/improvement-specs\/<name>\.md` if already written\./,
    );
    // Where step 4 put it: the note replaced by rm then add, requirements.md, and the file without dev-spec-driven.
    const handoff = flat(STEPS.find((s) => s.title.startsWith('Hand off'))?.body ?? '');
    expect(handoff).toMatch(/`spec_roadmap_edit \{ kind: "backlog", action: "rm", name: "<name>" \}`, then the `add` above/);
    expect(handoff).toContain('into `requirements.md` yourself');
    expect(handoff).toContain('write the seeds to `docs/improvement-specs/<name>.md`');
  });

  it('only for the shapes no gate meets; says what a rule adds, never that no change meets bug_hunt', () => {
    expect(STEP).toMatch(/one syntactic shape of `bug_hunt`, `quality_check` or `llm_scan` \(SAST, secrets, deps, IaC have rules\)/);
    expect(STEP).toMatch(/in `\.semgrep\.yml` it adds `review_pr`, pre-commit, the CLI gate and CI/);
    expect(SKILL).not.toMatch(/no change meets/i);
  });

  it('the rule is a medium WARNING, never one that blocks the default gate', () => {
    expect(STEP).toMatch(/`severity: WARNING`, `metadata\.guardian_severity: medium`/);
    expect(STEP).not.toMatch(/severity: ERROR|guardian_severity: (high|critical)/);
  });

  it("states the encoding trap by its bytes, and every example it names is one", () => {
    for (const b of UNDECODABLE) expect(STEP).toContain(`0x${b.toString(16).toUpperCase()}`);
    const m = /0x9D \(`([^`]+)`: on cp1252 pre-commit's Semgrep exits 2, printing nothing\)/.exec(STEP);
    expect(m).not.toBeNull();
    const examples = (m?.[1] ?? '').split(' ');
    expect(examples).toContain('”');
    for (const ch of examples) {
      expect([...Buffer.from(ch, 'utf8')].some((x) => (UNDECODABLE as readonly number[]).includes(x)), ch).toBe(true);
    }
  });

  it("the byte set is the one the packs' own test guards", () => {
    const src = readFileSync(resolve(REPO_ROOT, 'mcp/test/integration/semgrepPacks.test.ts'), 'utf8');
    const m = /const UNDECODABLE_BYTES: ReadonlySet<number> = new Set\(\[([^\]]+)\]\)/.exec(src);
    expect(m).not.toBeNull();
    const theirs = (m?.[1] ?? '').split(',').map((s) => Number(s.trim()));
    expect(theirs.sort((a, b) => a - b)).toEqual([...UNDECODABLE]);
  });

  it('carries none of what was cut: no suppressions resource, no reference, no scoped control scans', () => {
    expect(SKILL).not.toMatch(/guardian:\/\/suppressions/);
    expect(SKILL).not.toMatch(/fix-the-source/);
    expect(STEP).not.toMatch(/scan_sast \{/);
  });
});

describe('/guardian-improve: the re-measure line', () => {
  it("compares perf_check with the same target's history, not by hand", () => {
    expect(SKILL).not.toMatch(/records no history/);
    expect(flat(SKILL)).toMatch(/compared with `diff_scans` \(`perf_check` with the same target's `history`\)/);
  });
});
