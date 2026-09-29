/**
 * `scan_skill`'s `git clone` must end its options with `--` before the URL.
 *
 * A target is routed to `git clone` when it merely ENDS in `.git`, so
 * `--upload-pack=<command>;.git` reached git as an option: the temp directory
 * that followed became the "repository", and git ran the command to fetch
 * from it. `--` makes whatever the caller typed a repository argument, never
 * an option.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('execa', () => ({ execa: vi.fn() }));

import { execa } from 'execa';
import { ingestTarget } from '../../../src/skillaudit/ingest.js';

const execaMock = vi.mocked(execa);

afterEach(() => {
  execaMock.mockReset();
});

function cloneArgv(): string[] {
  const call = execaMock.mock.calls.find((c) => c[0] === 'git');
  expect(call).toBeDefined();
  const args = call?.[1];
  return Array.isArray(args) ? args.map(String) : [];
}

describe('ingestTarget — git clone argv', () => {
  it('puts `--` between the options and a URL that looks like an option', async () => {
    execaMock.mockRejectedValue(new Error('clone refused'));
    const target = '--upload-pack=touch pwned;.git';
    const r = await ingestTarget(target);
    expect(r.ok).toBe(false);
    const argv = cloneArgv();
    const sep = argv.indexOf('--');
    expect(sep).toBeGreaterThan(0);
    expect(argv[sep + 1]).toBe(target);
    // Nothing the caller typed appears before the separator.
    expect(argv.slice(0, sep)).not.toContain(target);
  });

  it('keeps `--` for an ordinary https repository URL too', async () => {
    execaMock.mockRejectedValue(new Error('offline'));
    await ingestTarget('https://github.com/acme/skill');
    const argv = cloneArgv();
    const sep = argv.indexOf('--');
    expect(argv[sep + 1]).toBe('https://github.com/acme/skill');
  });
});
