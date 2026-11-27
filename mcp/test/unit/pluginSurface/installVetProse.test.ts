/**
 * install-vet-manifest-install — what the `guardian-deps` skill tells the model about a manifest install.
 *
 * The hook vets a manifest install for malicious packages, typosquats and missing names only; an agent that reads
 * its silence as "the dependencies are fine" skips the audit that finds the vulnerabilities. The skill says which
 * is which, inside its budget. Also: guardian-deps' VEX rule left inline, and guardian-quality's Stryker line.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SKILL = fileURLToPath(new URL('../../../../skills/guardian-deps/SKILL.md', import.meta.url));
const QUALITY = fileURLToPath(new URL('../../../../skills/guardian-quality/SKILL.md', import.meta.url));

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
    // Fix round 1 (R1-DGTOOLS-5): the stub routes BOTH of the reference's triggers — export_vex, and the
    // suppress_finding that records the status, which comes first — and keeps that step's two answers inline.
    expect(reference).toMatch(/Read this before calling `export_vex`, or before recording a `not_affected` with `suppress_finding`\./);
    expect(section).toMatch(/antes de o chamar, ou de um `suppress_finding` com `vex_status`/);
    expect(section).toMatch(/`warning` e `vex\.other_open_findings`, mostra-os/);
    expect(section).toMatch(/com `vex\.exportable: false` a supressão fica registada mas não entra no documento/);
  });
});

// DG-9: guardian-quality gives the user a diff-scoped Stryker line to run. A bare `npx stryker` downloads and runs
// whatever the registry serves under that name when it is not installed; `npx --no` runs the project's own copy or
// nothing (the install gate reads `--no` as no fetch, parseCommand.ts).
describe('guardian-quality — the Stryker line never downloads', () => {
  it('DG-9 the mutation-testing line is `npx --no stryker`, and no bare `npx stryker` is offered', () => {
    const text = readFileSync(QUALITY, 'utf8');
    expect(text).toContain('npx --no stryker run --mutate');
    expect(text).not.toMatch(/npx stryker/);
  });
});
