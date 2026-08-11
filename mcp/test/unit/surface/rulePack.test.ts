import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';

const PACK_PATH = join(__dirname, '../../../../configs/semgrep/routes.yml');

interface Rule {
  id?: string;
  languages?: string[];
  severity?: string;
  message?: string;
  metadata?: Record<string, unknown>;
}

function rules(): Rule[] {
  const doc = parse(readFileSync(PACK_PATH, 'utf8')) as { rules?: Rule[] };
  return doc.rules ?? [];
}

const KINDS = new Set(['route', 'mount', 'import', 'env']);

describe('configs/semgrep/routes.yml', () => {
  it('parses and is non-empty', () => {
    expect(rules().length).toBeGreaterThan(0);
  });

  it('gives every rule a unique guardian- prefixed id', () => {
    const ids = rules().map((r) => r.id);
    expect(ids.every((id) => typeof id === 'string' && id.startsWith('guardian-'))).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('tags every rule with a known guardian_kind — the extractor contract', () => {
    for (const rule of rules()) {
      expect(KINDS.has(String(rule.metadata?.guardian_kind))).toBe(true);
    }
  });

  it('gives every route rule a framework and a confidence', () => {
    for (const rule of rules().filter((r) => r.metadata?.guardian_kind === 'route')) {
      expect(typeof rule.metadata?.framework).toBe('string');
      expect(['high', 'medium', 'low']).toContain(rule.metadata?.confidence);
    }
  });

  it('keeps every rule at INFO severity so it never reads as a finding', () => {
    for (const rule of rules()) {
      expect(rule.severity).toBe('INFO');
    }
  });

  it('covers all 8 supported stacks with at least one route rule', () => {
    const covered = new Set(
      rules()
        .filter((r) => r.metadata?.guardian_kind === 'route')
        .flatMap((r) => r.languages ?? []),
    );
    for (const lang of ['javascript', 'typescript', 'python', 'php', 'go', 'rust', 'ruby', 'java', 'csharp']) {
      expect(covered.has(lang), `no route rule covers ${lang}`).toBe(true);
    }
  });
});
