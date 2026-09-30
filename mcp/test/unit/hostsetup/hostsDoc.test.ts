/**
 * docs/hosts.md told Claude Desktop users to paste `host-rules/AGENTS.md`
 * into a Project's instructions — a template that carries the literal
 * `{{DEV_GUARDIAN_CLI}}`, which only `mcp-config --write` substitutes, and
 * `mcp-config` writes no rules file for Claude Desktop (it has no rules
 * mechanism). Pasted as told, the model was handed commands that name a
 * placeholder (review 3.0 M6).
 *
 * Every line that tells the reader to paste or copy a template by hand must
 * say to replace the placeholder, and the template must still carry it (or
 * the instruction would be stale the other way).
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CLI_PATH_PLACEHOLDER } from '../../../src/hostsetup/rulesTemplate.js';
import { REPO_ROOT } from '../pluginSurface/pluginDocs.js';

const hostsDoc = readFileSync(resolve(REPO_ROOT, 'docs', 'hosts.md'), 'utf8');

describe('docs/hosts.md, on the rules templates copied by hand', () => {
  it('the shipped template still carries the placeholder', () => {
    expect(readFileSync(resolve(REPO_ROOT, 'host-rules', 'AGENTS.md'), 'utf8')).toContain(CLI_PATH_PLACEHOLDER);
  });

  it('every line that says to paste or copy a host-rules template says to replace the placeholder', () => {
    const lines = hostsDoc
      .split('\n')
      .filter((l) => /\b(paste|copy)\b[^\n]*host-rules/i.test(l))
      .filter((l) => !l.includes(CLI_PATH_PLACEHOLDER));
    expect(lines).toEqual([]);
  });
});
