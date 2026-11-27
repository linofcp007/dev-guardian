/**
 * install-vet-manifest-install — what the `guardian-deps` skill tells the model about a manifest install.
 *
 * The hook vets a manifest install for malicious packages, typosquats and missing names only; an agent that reads
 * its silence as "the dependencies are fine" skips the audit that finds the vulnerabilities. The skill says which
 * is which, inside its budget.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SKILL = fileURLToPath(new URL('../../../../skills/guardian-deps/SKILL.md', import.meta.url));

describe('guardian-deps — a manifest install', () => {
  it('T-28 the skill names the manifest vetting by the hook and deps_audit for the vulnerabilities, inside the SKILL.md budget', () => {
    const text = readFileSync(SKILL, 'utf8');
    const from = text.indexOf('## 3.');
    const to = text.indexOf('## 4.');
    expect(from).toBeGreaterThan(-1);
    expect(to).toBeGreaterThan(from);
    const section = text.slice(from, to);
    expect(section).toContain('`npm ci`');
    expect(section).toMatch(/manifesto/);
    expect(section).toMatch(/malicios/);
    expect(section).toContain('deps_audit');
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(12 * 1024);
  });
});

// DG-13: sections 6 (Renovate) and 9 (VEX) moved into references/, read on demand. The one VEX rule that must hold
// when the reference is never opened — the user gives a `not_affected` justification, the model never picks it —
// stays inline in section 9, and the English reference keeps it.
const VEX_REFERENCE = fileURLToPath(new URL('../../../../skills/guardian-deps/references/vex.md', import.meta.url));

describe("guardian-deps — a not_affected justification is the user's", () => {
  it('DG-13 section 9 of SKILL.md asks the user for the justification, and references/vex.md says never to choose it', () => {
    const text = readFileSync(SKILL, 'utf8');
    const from = text.indexOf('## 9.');
    const to = text.indexOf('\n## ', from + 1);
    expect(from).toBeGreaterThan(-1);
    expect(to).toBeGreaterThan(from);
    const section = text.slice(from, to);
    expect(section).toContain('not_affected');
    expect(section).toMatch(/justificação/);
    expect(section).toMatch(/pergunta/);
    expect(section).toContain('references/vex.md');
    const reference = readFileSync(VEX_REFERENCE, 'utf8');
    expect(reference).toContain('Always ask the user for the justification — never choose it yourself.');
  });
});
