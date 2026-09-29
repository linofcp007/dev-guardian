/**
 * Every registered tool is named where the model learns when to call it.
 *
 * Review 3.0 I4: `vet_packages` — which checks a package BEFORE it is
 * installed — was named by no skill, no command and no host rules file, and
 * guardian-deps told the model "no tool detects typosquatting; that is your
 * check". The rules template named neither `vet_packages`, nor
 * `audit_agent_config`, nor `audit_mcp_tools`. A host other than Claude Code
 * gets only the rules file (docs/hosts.md), and no install hook: in Cursor,
 * Gemini, Windsurf or Copilot nothing told the model to vet a package before
 * installing it.
 *
 * Two surfaces, two tests, and both are "every tool":
 *
 *   - the host rules template (`RULES_BODY`), which is ALL a non-Claude host
 *     reads. Measured before choosing this over the weaker "every tool the
 *     intent map should cover": 56 of the 59 tools were already named there,
 *     and the three missing intents cost eight lines. A tool that is not
 *     worth one intent line is not worth registering;
 *   - the plugin's skills and commands, which is what Claude Code reads.
 *
 * A tool added later fails here until one line says when to use it.
 */

import { describe, expect, it } from 'vitest';
import { RULES_BODY } from '../../../src/hostsetup/rulesTemplate.js';
import { TOOLS } from '../../../src/tools/index.js';
import { allDocs } from './pluginDocs.js';
// Static: the registry must be full when the tests below read it.
import '../../../src/registerAll.js';

const named = (text: string, tool: string): boolean => text.includes(`\`${tool}\``) || new RegExp(`\\b${tool}\\b`).test(text);

describe('every registered tool is reachable from the prose that drives the model', () => {
  it('the registry is populated', () => {
    expect(TOOLS.length).toBeGreaterThanOrEqual(59);
  });

  it('every tool is named in the host rules template', () => {
    expect(TOOLS.map((t) => t.name).filter((name) => !RULES_BODY.includes(`\`${name}\``))).toEqual([]);
  });

  it('every tool is named by at least one skill or command', () => {
    const text = allDocs()
      .map((d) => d.text)
      .join('\n');
    expect(TOOLS.map((t) => t.name).filter((name) => !named(text, name))).toEqual([]);
  });

  it('the rules template tells the model to vet a package before installing it', () => {
    expect(RULES_BODY).toMatch(/vet_packages[^\n]*\n?[^\n]*BEFORE/);
  });
});
