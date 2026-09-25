/**
 * Drift test for the generated `host-rules/*` templates and the in-repo
 * ("dogfood") rules copies — item 7 (2026-09-25 full review).
 *
 * `mcp/scripts/generateHostRules.mjs` (run as part of `npm run build`)
 * writes every file this test reads, from the ONE canonical body in
 * `mcp/src/hostsetup/rulesTemplate.ts`. This test re-derives the exact bytes
 * each file should hold from that same source and compares them against
 * what is actually on disk — so a hand-edit to a generated copy (rather than
 * to the canonical source, followed by a rebuild) fails the suite instead of
 * silently drifting again, which is exactly how `.cursor/rules/
 * dev-guardian.mdc` ended up missing `scan_skill`/`check_toolchain` and root
 * `AGENTS.md` ended up missing the `severity_filter`/`filtered_reason`
 * guidance before this task.
 *
 * Reads `src/` (TypeScript), not `dist/`, on purpose — the same convention
 * `mcpConfig.test.ts` and every other unit test in this directory already
 * follows, and it means this test catches a content regression the moment
 * the source changes, without requiring `npm run build` to have already run.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { ALL_HOSTS, HOST_SPECS } from '../../../src/hostsetup/hostSpecs.js';
import {
  CLI_PATH_PLACEHOLDER,
  DOGFOOD_RULE_TARGETS,
  renderHostRulesFile,
  RULES_BODY,
  substituteCliPath,
} from '../../../src/hostsetup/rulesTemplate.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));
const HOST_RULES_DIR = resolve(REPO_ROOT, 'host-rules');

function readOrNull(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

describe('host-rules/* templates match the canonical body byte-for-byte', () => {
  for (const host of ALL_HOSTS) {
    const spec = HOST_SPECS[host];
    // Narrowed (Global Constraint 1: no `!` non-null assertions), not
    // `spec.rules!` — `rules` is `RulesSpec | null`, and a plain `continue`
    // both skips claude-desktop (no rules file) and lets every later use of
    // `rules` in this block narrow to `RulesSpec` for the rest of the loop
    // body.
    const rules = spec.rules;
    if (!rules) continue;
    it(`host-rules/${rules.template_file} (${host}) is generated, not hand-edited`, () => {
      const onDisk = readOrNull(resolve(HOST_RULES_DIR, rules.template_file));
      expect(onDisk, `run "npm run build" in mcp/ to regenerate host-rules/${rules.template_file}`).toBe(
        renderHostRulesFile(host),
      );
      // Shipped templates keep the placeholder UNRESOLVED — installRulesOne
      // substitutes it with the target install's own absolute CLI path.
      expect(onDisk).toContain(CLI_PATH_PLACEHOLDER);
    });
  }
});

describe('dogfood rules copies match the canonical body byte-for-byte', () => {
  for (const [host, targetPath] of Object.entries(DOGFOOD_RULE_TARGETS)) {
    it(`${targetPath} (${host}) is generated, not hand-edited`, () => {
      const onDisk = readOrNull(resolve(REPO_ROOT, targetPath));
      const expected = substituteCliPath(renderHostRulesFile(host as keyof typeof HOST_SPECS), 'cli/dev-guardian.mjs');
      expect(onDisk, `run "npm run build" in mcp/ to regenerate ${targetPath}`).toBe(expected);
      // The dogfood copy is a real, working invocation for THIS repo — no
      // unresolved placeholder should ever reach it.
      expect(onDisk).not.toContain(CLI_PATH_PLACEHOLDER);
      expect(onDisk).toContain('cli/dev-guardian.mjs');
    });
  }
});

describe('the canonical body carries every required fix (item 7)', () => {
  it('includes severity_filter / filtered_reason guidance', () => {
    expect(RULES_BODY).toMatch(/severity_filter/);
    expect(RULES_BODY).toMatch(/filtered_reason/);
  });

  it('documents init_project refresh=true', () => {
    expect(RULES_BODY).toMatch(/init_project.*refresh=true/);
  });

  it('mentions scan_skill and check_toolchain', () => {
    expect(RULES_BODY).toMatch(/scan_skill/);
    expect(RULES_BODY).toMatch(/check_toolchain/);
  });

  it('uses guardian://wp/audit/{scan_id}, never the old {id} form', () => {
    expect(RULES_BODY).toContain('guardian://wp/audit/{scan_id}');
    expect(RULES_BODY).not.toMatch(/wp\/audit\/\{id\}/);
  });

  it('replaces the unqualified "no telemetry" claim with the Semgrep registry-mode caveat', () => {
    // \s+ rather than a literal space between words: the source markdown
    // hard-wraps at ~80 columns, so a phrase can legitimately have a
    // newline where prose would have a space.
    expect(RULES_BODY).toMatch(/dev-guardian sends no\s+telemetry of its own/);
    expect(RULES_BODY).toMatch(/Semgrep's registry mode sends metrics/);
    expect(RULES_BODY).toMatch(/local_only:\s*true/);
  });

  it('never names a slash command (Task 14 renames them)', () => {
    expect(RULES_BODY).not.toMatch(/\/guardian-[a-z]+/);
  });

  it('carries the CLI placeholder, never a hard-coded repo-relative CLI path', () => {
    expect(RULES_BODY).toContain(CLI_PATH_PLACEHOLDER);
    expect(RULES_BODY).not.toMatch(/node cli\/dev-guardian\.mjs/);
  });

  // Fix round 1, item 8 (escalated from minor by the controller — it is
  // brief item 6a): the "CI" and "Local dashboard" sections named
  // `dev-guardian baseline update` / `dev-guardian dashboard` as bare
  // commands, with no CLI path at all — a target project has no
  // `dev-guardian` on PATH, only `node <absolute path> baseline update`.
  // Every dev-guardian CLI invocation in the body must go through the
  // placeholder, the same as `status`/`scan`/`mcp-config` already did.
  it('every dev-guardian CLI invocation goes through the placeholder — no bare "dev-guardian <subcommand>" left', () => {
    expect(RULES_BODY).not.toMatch(/(?<!node )dev-guardian (baseline|dashboard|status|scan|mcp-config)\b/);
    expect(RULES_BODY).toContain(`${CLI_PATH_PLACEHOLDER} baseline update`);
    expect(RULES_BODY).toContain(`${CLI_PATH_PLACEHOLDER} dashboard`);
  });
});
