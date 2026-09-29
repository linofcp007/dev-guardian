/**
 * What `local_only` is said to do, held to what it does (review 3.0 M4).
 *
 * `local_only` keeps SEMGREP on the machine: rules on disk only — the
 * project's config, registered custom rules AND the plugin's LLM-application
 * pack, which every scan_sast / review_pr run carries — with --metrics=off.
 * It does not stop Trivy downloading its database, nor a .NET project's
 * restore contacting its NuGet feeds (SECURITY.md says so). The two tool
 * descriptions left the LLM pack out of the rules that run, and
 * /guardian-scan offered `local_only: true` "when nothing may leave the
 * machine".
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TOOLS } from '../../../src/tools/index.js';
import { REPO_ROOT } from './pluginDocs.js';
import '../../../src/registerAll.js';

function tool(name: string): (typeof TOOLS)[number] {
  const t = TOOLS.find((x) => x.name === name);
  if (t === undefined) throw new Error(`Tool '${name}' not registered`);
  return t;
}

describe.each(['security_scan_full', 'review_pr'])('%s local_only', (name) => {
  it('names the LLM pack among the rules on disk it still runs', () => {
    expect(tool(name).inputSchema['local_only']?.description ?? '').toMatch(/LLM/);
  });

  it('says it does not stop Trivy', () => {
    const t = tool(name);
    expect(`${t.description}\n${t.inputSchema['local_only']?.description ?? ''}`).toMatch(/Trivy[^.]*(still|not)|not[^.]*Trivy/);
  });
});

describe('/guardian-scan', () => {
  const text = readFileSync(resolve(REPO_ROOT, 'commands/guardian-scan.md'), 'utf8');

  it('does not offer local_only as "nothing leaves the machine"', () => {
    expect(text).not.toMatch(/nothing may leave the machine/);
  });

  it('says what still goes out under it', () => {
    const line = text.split('\n').find((l) => l.includes('local_only: true')) ?? '';
    expect(line).toMatch(/Trivy/);
    expect(line).toMatch(/NuGet/);
  });
});
