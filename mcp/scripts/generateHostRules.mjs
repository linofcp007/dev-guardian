#!/usr/bin/env node
/**
 * Generates every `host-rules/*` template AND every in-repo ("dogfood")
 * rules copy from the single canonical body in
 * `mcp/src/hostsetup/rulesTemplate.ts` — item 7 (2026-09-25 full review).
 *
 * Before this: `host-rules/AGENTS.md`, `GEMINI.md`, `cursor.mdc`,
 * `windsurf.md`, `clinerules` and `copilot-instructions.md` were six
 * hand-maintained files that drifted from each other AND from the dogfood
 * copies (root `AGENTS.md`, `.cursor/rules/dev-guardian.mdc`, `.windsurf/
 * rules/dev-guardian.md`, `GEMINI.md`, `.github/copilot-instructions.md`) —
 * `.cursor/rules/dev-guardian.mdc` was missing `scan_skill` and
 * `check_toolchain`, `.windsurf/rules/dev-guardian.md` was missing
 * `scan_skill`, and root `AGENTS.md` was missing the
 * `severity_filter`/`filtered_reason` guidance `host-rules/AGENTS.md` itself
 * already had.
 *
 * Run as part of `npm run build` (after `tsc`, which is what makes
 * `dist/hostsetup/{hostSpecs,rulesTemplate}.js` importable here — this
 * script reads the COMPILED output, never `src/`, the same convention
 * `copy-assets.mjs` and `bundle.mjs` already follow). `mcp/test/unit/
 * hostsetup/hostRulesDrift.test.ts` fails the build if a generated file is
 * ever hand-edited without regenerating: it imports `rulesTemplate.ts`
 * straight from `src/` (TypeScript, type-checked by `tsconfig.test.json`)
 * and re-derives the exact bytes every file below should hold, then
 * compares them against what is actually on disk.
 *
 * Two passes over the SAME canonical content, differing only in what
 * `{{DEV_GUARDIAN_CLI}}` resolves to:
 *
 *   1. `host-rules/*` — the placeholder is left UNRESOLVED. These are
 *      shipped templates, installed into OTHER projects by `mcp-config
 *      --write`; `installRulesOne` (mcp/src/hostsetup/setup.ts) substitutes
 *      the placeholder with THAT install's own absolute CLI path (item 6a —
 *      a hard-coded `node cli/dev-guardian.mjs` only exists in this repo).
 *   2. Dogfood copies — the placeholder is resolved to the literal
 *      `cli/dev-guardian.mjs`, correct for the one repo where that relative
 *      path is real: this one.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_HOSTS, HOST_SPECS } from '../dist/hostsetup/hostSpecs.js';
import { DOGFOOD_RULE_TARGETS, renderHostRulesFile, substituteCliPath } from '../dist/hostsetup/rulesTemplate.js';

const here = dirname(fileURLToPath(import.meta.url));
const mcpRoot = resolve(here, '..');
const repoRoot = resolve(mcpRoot, '..');
const hostRulesDir = resolve(repoRoot, 'host-rules');

/** This repo's own relative CLI path — correct ONLY here, dogfooding the
 *  plugin's own install layout on itself. See the module doc above. */
const DOGFOOD_CLI_PATH = 'cli/dev-guardian.mjs';

function writeGenerated(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, 'utf8');
  console.log(`generated ${path}`);
}

for (const host of ALL_HOSTS) {
  const spec = HOST_SPECS[host];
  if (!spec.rules) continue; // e.g. claude-desktop: no rules-file mechanism
  writeGenerated(resolve(hostRulesDir, spec.rules.template_file), renderHostRulesFile(host));
}

for (const [host, targetPath] of Object.entries(DOGFOOD_RULE_TARGETS)) {
  const rendered = substituteCliPath(renderHostRulesFile(host), DOGFOOD_CLI_PATH);
  writeGenerated(resolve(repoRoot, targetPath), rendered);
}
