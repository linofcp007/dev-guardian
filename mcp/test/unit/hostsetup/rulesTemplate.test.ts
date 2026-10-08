/**
 * The LLM-assisted scan's recipe, per host, in the rules every host is given
 * (US-3.AC-1): where a host's subagents can reach MCP, one fresh subagent per
 * task — with the explicit instruction Codex needs before it spawns any; where
 * they cannot (Cline, Claude Desktop's chat), the tasks run one after another
 * in the same context, declared `same_context`.
 *
 * `RULES_BODY` is shared verbatim by every host, so the recipe is a per-host
 * section of that one body; the generated copies on disk must carry it too
 * (the byte-for-byte drift test is `hostRulesDrift.test.ts`).
 *
 * T-25.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ALL_HOSTS, HOST_SPECS } from '../../../src/hostsetup/hostSpecs.js';
import { DOGFOOD_RULE_TARGETS, RULES_BODY, renderHostRulesFile } from '../../../src/hostsetup/rulesTemplate.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('../../../..', import.meta.url)));

/** Paragraphs and list items: a blank line or a new top-level bullet starts the next block. */
function blocks(text: string): string[] {
  const out: string[] = [];
  let cur: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '' || /^(- |\* |\d+\. |#)/.test(line)) {
      if (cur.length > 0) out.push(cur.join('\n'));
      cur = line.trim() === '' ? [] : [line];
      continue;
    }
    cur.push(line);
  }
  if (cur.length > 0) out.push(cur.join('\n'));
  return out;
}

function recipeProblems(text: string): string[] {
  const problems: string[] = [];
  for (const tool of ['llm_scan_start', 'llm_scan_task', 'llm_scan_submit']) {
    if (!text.includes(tool)) problems.push(`names ${tool}`);
  }
  const bs = blocks(text);
  if (!bs.some((b) => b.includes('llm_scan_task') && /sub-?agent/i.test(b) && /\b(per|each|every|one)\b[^.]*\btask\b/i.test(b))) {
    problems.push('says to run each task in a fresh subagent');
  }
  if (!bs.some((b) => /\bCodex\b/.test(b) && /sub-?agent/i.test(b) && /\b(spawn|launch|start|ask|explicit)/i.test(b))) {
    problems.push('gives Codex the explicit instruction to spawn subagents');
  }
  for (const host of ['Cline', 'Claude Desktop']) {
    if (!bs.some((b) => b.includes(host) && b.includes('same_context') && /sequential|one (task )?(at a time|after (the )?another)/i.test(b))) {
      problems.push(`runs ${host} sequentially, declaring same_context`);
    }
  }
  return problems;
}

describe('T-25 the rules give every host its llm-scan recipe (US-3.AC-1)', () => {
  it('T-25 RULES_BODY carries the recipe: subagent per task, the Codex instruction, sequential same_context for Cline and Claude Desktop', () => {
    expect(recipeProblems(RULES_BODY)).toEqual([]);
  });

  for (const host of ALL_HOSTS) {
    if (HOST_SPECS[host].rules === null) continue;
    it(`T-25 the rules file rendered for ${host} carries the recipe`, () => {
      expect(recipeProblems(renderHostRulesFile(host))).toEqual([]);
    });
  }

  it('T-25 the generated copies on disk carry it (run "npm run build" in mcp/ to regenerate)', () => {
    const generated: string[] = [];
    for (const host of ALL_HOSTS) {
      const rules = HOST_SPECS[host].rules;
      if (rules !== null) generated.push(resolve(REPO_ROOT, 'host-rules', rules.template_file));
    }
    for (const target of Object.values(DOGFOOD_RULE_TARGETS)) {
      if (target !== undefined) generated.push(resolve(REPO_ROOT, target));
    }
    expect(generated.length).toBeGreaterThan(0);
    for (const path of generated) {
      expect(recipeProblems(readFileSync(path, 'utf8')), path).toEqual([]);
    }
  });
});
