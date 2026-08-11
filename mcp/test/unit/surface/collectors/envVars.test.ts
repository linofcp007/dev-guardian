import { describe, expect, it } from 'vitest';
import { collectEnvVars } from '../../../../src/surface/collectors/envVars.js';

function envMatch(name: string, file: string, line: number): unknown {
  return {
    check_id: 'guardian-env',
    path: file,
    start: { line },
    extra: {
      metadata: { guardian_kind: 'env' },
      metavars: { $NAME: { abstract_content: name } },
    },
  };
}

describe('collectEnvVars', () => {
  it('collects env var references from guardian_kind: env matches', () => {
    const result = collectEnvVars({
      results: [envMatch('DATABASE_URL', 'src/db.ts', 3), envMatch('API_KEY', 'src/api.ts', 8)],
    });
    expect(result).toEqual([
      { name: 'DATABASE_URL', file: 'src/db.ts', line: 3 },
      { name: 'API_KEY', file: 'src/api.ts', line: 8 },
    ]);
  });

  it('deduplicates by name, keeping the first occurrence', () => {
    const result = collectEnvVars({
      results: [envMatch('API_KEY', 'a.ts', 1), envMatch('API_KEY', 'b.ts', 9)],
    });
    expect(result).toEqual([{ name: 'API_KEY', file: 'a.ts', line: 1 }]);
  });

  it('strips surrounding quotes left by the metavariable capture', () => {
    const result = collectEnvVars({ results: [envMatch("'API_KEY'", 'a.ts', 1)] });
    expect(result[0]?.name).toBe('API_KEY');
  });

  it('returns an empty array for malformed input', () => {
    expect(collectEnvVars(null)).toEqual([]);
    expect(collectEnvVars({ results: [{ extra: {} }] })).toEqual([]);
  });
});
