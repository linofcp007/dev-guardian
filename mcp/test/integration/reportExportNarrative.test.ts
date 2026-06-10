/**
 * Integration tests for report_export's narrative (content_markdown) path —
 * stakeholder Markdown wrapped in the branded shell, no scan required.
 */

import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { PluginContext } from '../../src/context.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';

beforeAll(async () => {
  await import('../../src/tools/reportExport.js');
});

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: null,
    scriptsDir: '',
    progressNotifier: { send: () => {} },
  };
}

let project: string;
let plugin: PluginContext;

beforeEach(() => {
  project = mkdtempSync(join(tmpdir(), 'report-narr-'));
  plugin = makePlugin();
});

describe('report_export — narrative (content_markdown)', () => {
  it('wraps the Markdown in the branded shell, no scan tables', async () => {
    const r = (await getTool('report_export').handler(
      {
        project_path: project,
        format: 'html',
        title: 'PDK — Board Report',
        content_markdown: '# Executive summary\n\nWe are **green** this quarter.',
      },
      plugin,
    )) as { ok: true; kind: string; file_path: string };

    expect(r.ok).toBe(true);
    expect(r.kind).toBe('narrative');
    expect(r.file_path).toMatch(/report\.html$/);

    const html = readFileSync(r.file_path, 'utf8');
    expect(html).toContain('pdk-report-theme'); // branded shell + toggle
    expect(html).toContain('PDK — Board Report'); // title
    expect(html).toContain('<strong>green</strong>'); // markdown rendered
    expect(html).not.toContain('Severity distribution'); // not a scan report
    expect(html).not.toContain('https://'); // offline
  });

  it('can still emit raw Markdown when asked', async () => {
    const r = (await getTool('report_export').handler(
      { project_path: project, format: 'markdown', content_markdown: '# Hi' },
      plugin,
    )) as { ok: true; format: string; file_path: string };

    expect(r.format).toBe('markdown');
    expect(r.file_path).toMatch(/report\.md$/);
    expect(readFileSync(r.file_path, 'utf8')).toBe('# Hi');
  });
});
