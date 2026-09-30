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

vi.mock('../../../src/platform/gitSafety.js', () => ({ execGit: vi.fn() }));

import { execGit, type GitExecResult } from '../../../src/platform/gitSafety.js';
import { ingestTarget } from '../../../src/skillaudit/ingest.js';

const execGitMock = vi.mocked(execGit);

afterEach(() => {
  execGitMock.mockReset();
});

/** A clone git refused — what the tests below answer every call with. */
const refused: GitExecResult<string> = {
  status: 128,
  stdout: '',
  stderr: 'fatal: clone refused',
  failure: null,
  notApplied: [],
};

function cloneArgv(): string[] {
  // execGit(dir, args, …): the clone runs, hardened, through platform/gitSafety.ts.
  const call = execGitMock.mock.calls.find((c) => c[1][0] === 'clone');
  expect(call).toBeDefined();
  return call === undefined ? [] : [...call[1]];
}

describe('ingestTarget — git clone argv', () => {
  it('puts `--` between the options and a URL that looks like an option', async () => {
    execGitMock.mockResolvedValue(refused);
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
    execGitMock.mockResolvedValue(refused);
    await ingestTarget('https://github.com/acme/skill');
    const argv = cloneArgv();
    const sep = argv.indexOf('--');
    expect(argv[sep + 1]).toBe('https://github.com/acme/skill');
  });
});
