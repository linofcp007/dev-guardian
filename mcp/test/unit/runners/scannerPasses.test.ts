/**
 * One scan's scanners side by side (`runners/scannerPasses.ts`): the results
 * merged in the passes' order whichever finished first, at most `limit` at
 * once, `after` honoured, a pass that throws costing only its own entry.
 */
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_PARALLEL_SCANNERS,
  maxParallelScanners,
  runScannerPasses,
  type PassCollect,
  type ScannerPass,
} from '../../../src/runners/scannerPasses.js';

const tick = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** A pass that takes `ms`, records when it ran, and pushes an `ok` entry (and `missing`). */
function pass(name: string, ms: number, log: string[], opts: { after?: string[]; missing?: string[] } = {}): ScannerPass {
  return {
    name,
    ...(opts.after !== undefined ? { after: opts.after } : {}),
    run: async (into: PassCollect) => {
      log.push(`start ${name}`);
      await tick(ms);
      into.tools_run.push({ name, status: 'ok' });
      into.missing_tools.push(...(opts.missing ?? []));
      into.parser_inputs.push({ parser: { name, parse: () => ({ findings: [], cves: [] }) }, input: name });
      log.push(`end ${name}`);
    },
  };
}

describe('runScannerPasses', () => {
  it("side by side, the results in the passes' order whichever finished first; missing names once", async () => {
    const log: string[] = [];
    const out = await runScannerPasses(
      [pass('slow', 60, log, { missing: ['x'] }), pass('fast', 5, log, { missing: ['x', 'y'] }), pass('mid', 30, log)],
      3,
    );
    expect(log.slice(0, 3)).toEqual(['start slow', 'start fast', 'start mid']);
    expect(log.indexOf('end fast')).toBeLessThan(log.indexOf('end slow'));
    expect(out.tools_run.map((t) => t.name)).toEqual(['slow', 'fast', 'mid']);
    expect(out.parser_inputs.map((p) => p.input)).toEqual(['slow', 'fast', 'mid']);
    expect(out.missing_tools).toEqual(['x', 'y']);
  });

  it('at most `limit` at once; 1 runs them one after another', async () => {
    const log: string[] = [];
    await runScannerPasses([pass('a', 20, log), pass('b', 20, log), pass('c', 20, log)], 2);
    expect(log.indexOf('start c')).toBeGreaterThan(Math.min(log.indexOf('end a'), log.indexOf('end b')));
    const serial: string[] = [];
    await runScannerPasses([pass('a', 10, serial), pass('b', 1, serial), pass('c', 1, serial)], 1);
    expect(serial).toEqual(['start a', 'end a', 'start b', 'end b', 'start c', 'end c']);
  });

  it('a pass waits for the earlier ones it names in `after`, never holding a slot while it waits', async () => {
    const log: string[] = [];
    const out = await runScannerPasses(
      [pass('semgrep', 40, log), pass('dotnet', 5, log, { after: ['semgrep'] }), pass('psalm', 5, log)],
      2,
    );
    expect(log.indexOf('start dotnet')).toBeGreaterThan(log.indexOf('end semgrep'));
    // psalm took the free slot at once, not after dotnet.
    expect(log.indexOf('start psalm')).toBeLessThan(log.indexOf('end semgrep'));
    expect(out.tools_run.map((t) => t.name)).toEqual(['semgrep', 'dotnet', 'psalm']);
  });

  it('a pass that throws costs its own entry — failed, the error its reason — never the others', async () => {
    const log: string[] = [];
    const out = await runScannerPasses(
      [
        pass('a', 5, log),
        {
          name: 'boom',
          run: async (into) => {
            into.tools_run.push({ name: 'boom-part', status: 'ok' });
            throw new Error('no such file');
          },
        },
        pass('c', 5, log, { after: ['boom'] }),
      ],
      3,
    );
    expect(out.tools_run).toEqual([
      { name: 'a', status: 'ok' },
      { name: 'boom-part', status: 'ok' },
      { name: 'boom', status: 'failed', reason: 'boom could not run: no such file' },
      { name: 'c', status: 'ok' },
    ]);
  });
});

describe('maxParallelScanners', () => {
  it('GUARDIAN_MAX_PARALLEL_SCANNERS when a whole number of 1 or more, else the default', () => {
    expect(maxParallelScanners({})).toBe(DEFAULT_MAX_PARALLEL_SCANNERS);
    expect(maxParallelScanners({ GUARDIAN_MAX_PARALLEL_SCANNERS: '1' })).toBe(1);
    expect(maxParallelScanners({ GUARDIAN_MAX_PARALLEL_SCANNERS: '6' })).toBe(6);
    for (const bad of ['0', '-2', '1.5', 'many', '']) {
      expect(maxParallelScanners({ GUARDIAN_MAX_PARALLEL_SCANNERS: bad })).toBe(DEFAULT_MAX_PARALLEL_SCANNERS);
    }
  });
});
