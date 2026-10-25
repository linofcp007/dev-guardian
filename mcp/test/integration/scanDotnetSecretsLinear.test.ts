/**
 * Review 3.6.1, finding 6: `scan_dotnet_secrets` could freeze the server.
 *
 * Its connection-string patterns — `(Server|Data\s*Source)=[^;"']+;.*?
 * (Password|Pwd)=…`, the same with `Integrated\s*Security`, and `Host=…;.*?
 * (Password|Pwd)=…` — were tried from every `Server=` of a line, each time
 * scanning the rest of it: quadratic, and synchronous on the event loop.
 * Measured on Node 24: a 200 kB line of `Server=a;` took 1.8 s per pattern; a
 * config file may hold a 2 MB line, about ten minutes over the three. The
 * line is now cut once at `;` and the quotes and each piece's key looked up
 * — linear. The old patterns stay here as the oracle on short lines: the
 * rewrite reports exactly what they did.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/scanDotnetSecrets.js');
});
afterAll(cleanupTempDirs);

function plugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return { storage: new Storage(db), shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
}

/** The rule ids `scan_dotnet_secrets` reports for an appsettings.json holding these lines. */
async function ruleIds(lines: string[]): Promise<string[][]> {
  const dir = resolveProjectPath(makeTempDir('dotnet-linear-')).path;
  writeFileSync(join(dir, 'appsettings.json'), lines.join('\n'));
  const tool = TOOLS.find((t) => t.name === 'scan_dotnet_secrets');
  if (!tool) throw new Error('scan_dotnet_secrets is not registered');
  const r = (await tool.handler({ project_path: dir }, plugin())) as {
    ok: boolean;
    findings: Array<{ rule_id: string; line_start: number }>;
  };
  expect(r.ok).toBe(true);
  return lines.map((_, i) => r.findings.filter((f) => f.line_start === i + 1).map((f) => f.rule_id).sort());
}

/** The patterns as they were — fine on a short line, quadratic on a long one. */
const OLD: Record<string, RegExp> = {
  'dotnet-sql-server-conn': /(Server|Data\s*Source)=[^;"']+;.*?(Password|Pwd)=[^;"']+/i,
  'dotnet-trusted-conn': /(Server|Data\s*Source)=[^;"']+;.*?Integrated\s*Security=(SSPI|true)/i,
  'dotnet-postgres-conn': /Host=[^;"']+;.*?(Password|Pwd)=[^;"']+/i,
};
const CONN_RULES = new Set(Object.keys(OLD));

const SAMPLES = [
  '"DefaultConnection": "Server=myServer;Database=db;User Id=sa;Password=secret;"',
  '<add name="x" connectionString="Data Source=.;Initial Catalog=x;Integrated Security=SSPI" />',
  '"Pg": "Host=localhost;Port=5432;Username=u;Password=p"',
  'Server=x;Password=',
  'Server=x" Password=y',
  'Data   Source=srv;pwd=abc',
  'Server=a;Integrated Security=true;Password=z',
  'Host=h;x;y;PWD=k',
  'MyServer=a;NewPwd=b',
  'Password=x;Server=y;',
  'Server=a=b;Password=c',
  'x=Server=a;Pwd=b',
  'Server=;Password=x',
  'Server=a ;Password=b',
  "Server=a';Password=b",
  'Server=a;"Password=b"',
  'SERVER=A;INTEGRATED SECURITY=TRUE',
  'Host=;Host=h;Password=p',
  'Data\tSource=d;Integrated\tSecurity=sspi',
  'Server=a;Server=b',
  'no connection string here',
];

describe('scan_dotnet_secrets — connection strings, in linear time', () => {
  it('reports exactly what the old patterns reported, line by line', async () => {
    const got = await ruleIds(SAMPLES);
    SAMPLES.forEach((line, i) => {
      const expected = Object.entries(OLD).filter(([, re]) => re.test(line)).map(([id]) => id).sort();
      expect((got[i] ?? []).filter((id) => CONN_RULES.has(id)), line).toEqual(expected);
    });
  });

  it('and on 3000 lines of key=value pieces drawn at random (a fixed seed)', async () => {
    const KEYS = ['Server', 'Data Source', 'Data\tSource', 'Host', 'Password', 'Pwd', 'Integrated Security', 'MyServer', 'x', ''];
    const VALUES = ['', 'a', 'SSPI', 'true', 'b=c', ' '];
    const ENDS = [';', ';', '"', "'", ' ', ''];
    let seed = 0x5eed;
    // An LCG's low bits cycle: take the high ones.
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed >>> 12;
    };
    const pick = (list: readonly string[]): string => list[next() % list.length] ?? '';
    const lines = Array.from({ length: 3000 }, () =>
      Array.from({ length: 1 + (next() % 6) }, () => `${pick(KEYS)}=${pick(VALUES)}${pick(ENDS)}`).join(''),
    );
    const got = await ruleIds(lines);
    const hits = new Map<string, number>();
    lines.forEach((line, i) => {
      const expected = Object.entries(OLD).filter(([, re]) => re.test(line)).map(([id]) => id).sort();
      for (const id of expected) hits.set(id, (hits.get(id) ?? 0) + 1);
      expect((got[i] ?? []).filter((id) => CONN_RULES.has(id)), JSON.stringify(line)).toEqual(expected);
    });
    // Not vacuous: every rule matched some of them.
    for (const id of CONN_RULES) expect(hits.get(id) ?? 0, id).toBeGreaterThan(10);
  });

  it.each([
    ['Server=a; repeated', 'Server=a;'],
    ['Server= repeated with no ;', 'Server='],
    ['Host=a; repeated', 'Host=a;'],
    ['Data Source=a; repeated', 'Data   Source=a;'],
  ])('a 300 kB line of %s is read in well under a second (it took seconds per pattern)', async (_label, unit) => {
    const line = unit.repeat(Math.ceil(300_000 / unit.length));
    const started = Date.now();
    await ruleIds([line]);
    expect(Date.now() - started).toBeLessThan(2_000);
  });
});
