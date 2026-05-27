import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { detectFormat, summarize } from '../../../../src/runners/scannerParsers/syft.js';

const here = dirname(fileURLToPath(import.meta.url));
const CYCLONEDX = resolve(here, '../../../fixtures/scanners/syft-cyclonedx.json');
const SPDX = resolve(here, '../../../fixtures/scanners/syft-spdx.json');

describe('syft.detectFormat', () => {
  it('recognises CycloneDX', () => {
    expect(detectFormat(readFileSync(CYCLONEDX, 'utf8'))).toBe('cyclonedx-json');
  });

  it('recognises SPDX', () => {
    expect(detectFormat(readFileSync(SPDX, 'utf8'))).toBe('spdx-json');
  });

  it('returns "unknown" on garbage', () => {
    expect(detectFormat('{}')).toBe('unknown');
    expect(detectFormat('not json')).toBe('unknown');
  });
});

describe('syft.summarize', () => {
  it('summarises CycloneDX components', () => {
    const s = summarize(readFileSync(CYCLONEDX, 'utf8'));
    expect(s.format).toBe('cyclonedx-json');
    expect(s.components_count).toBe(3);
    expect(s.top_packages.map((p) => p.name).sort()).toEqual(['express', 'lodash', 'react']);
  });

  it('summarises SPDX packages', () => {
    const s = summarize(readFileSync(SPDX, 'utf8'));
    expect(s.format).toBe('spdx-json');
    expect(s.components_count).toBe(2);
    const express = s.top_packages.find((p) => p.name === 'express');
    expect(express?.version).toBe('4.18.2');
  });

  it('caps top_packages at the requested topN', () => {
    const components = Array.from({ length: 50 }, (_, i) => ({
      type: 'library',
      name: `pkg-${i}`,
      version: '1.0.0',
    }));
    const big = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components });
    const s = summarize(big, 5);
    expect(s.components_count).toBe(50);
    expect(s.top_packages).toHaveLength(5);
  });

  it('reports inline_size_bytes', () => {
    const raw = readFileSync(CYCLONEDX, 'utf8');
    expect(summarize(raw).inline_size_bytes).toBe(Buffer.byteLength(raw, 'utf8'));
  });
});
