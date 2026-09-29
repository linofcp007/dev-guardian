/**
 * Version parsing for `check_toolchain`. Every fixture string below is real
 * output captured on the Windows 11 machine this was written on (2026-09-25)
 * or from the tool's documented format; the two that broke the old bash
 * probe outright are marked.
 */
import { describe, expect, it } from 'vitest';
import { extractVersion, highestDotnetSdk } from '../../../src/runners/toolProbe.js';

describe('extractVersion', () => {
  it.each([
    ['semgrep', '1.176.1\n\nA new version of Semgrep is available.', '1.176.1'],
    ['gitleaks', '8.30.1', '8.30.1'],
    ['ruff', 'ruff 0.16.6', '0.16.6'],
    ['pre-commit', 'pre-commit 4.6.0', '4.6.0'],
    ['node', 'v24.19.0', '24.19.0'],
    ['python', 'Python 3.14.7', '3.14.7'],
    ['docker', 'Docker version 29.8.0, build 88096ef', '29.8.0'],
    ['k6 (go version later on the line)', 'k6.exe v2.2.0 (commit/00a9a1b7f5, go1.26.5, windows/amd64)', '2.2.0'],
    ['phpcs', 'PHP_CodeSniffer version 3.13.2 (stable) by Squiz and PHPCSStandards', '3.13.2'],
    ['wp-cli', 'WP-CLI 2.12.0', '2.12.0'],
    ['nuclei', '[INF] Nuclei Engine Version: v3.4.10', '3.4.10'],
    ['wpscan', 'Current Version: 3.8.28\nLast DB Update: 2026-09-24', '3.8.28'],
  ])('%s', (_name, output, expected) => {
    expect(extractVersion(output)).toBe(expected);
  });

  it('trivy: takes the tool version, not the vulnerability DB schema version', () => {
    const out = 'Version: 0.69.3\nVulnerability DB:\n  Version: 2\n  UpdatedAt: 2026-09-24 13:23:01';
    expect(extractVersion(out)).toBe('0.69.3');
  });

  it('syft: takes the `Version:` line, not GoVersion or SchemaVersion (broke check-tools.sh)', () => {
    const out = [
      'Application:     syft',
      'Version:         1.51.1',
      'BuildDate:       2026-08-27T17:01:15Z',
      'GoVersion:       go1.26.3',
      'SchemaVersion:   16.1.10',
    ].join('\n');
    expect(extractVersion(out)).toBe('1.51.1');
  });

  it('bandit: skips the interpreter path and the python version (broke check-tools.sh)', () => {
    const out =
      'python.exe C:\\Program Files\\Python314\\Scripts\\bandit 1.9.4\n' +
      '  python version = 3.14.7 (tags/v3.14.7:823f032, Aug  5 2026, 10:51:32)';
    expect(extractVersion(out)).toBe('1.9.4');
  });

  it('cosign: the GitVersion line, past the ASCII banner and before GoVersion (real v3.1.3 output)', () => {
    const out = [
      '  ______   ______        _______. __    _______ .__   __.',
      " /      | /  __  \\      /       ||  |  /  _____||  \\ |  |",
      'cosign: A tool for Container Signing, Verification and Storage in an OCI registry',
      '',
      'GitVersion:    v3.1.3',
      'GitCommit:     11926fa5bbbbde47e88fc006b625a17769b743b2',
      'GitTreeState:  clean',
      'BuildDate:     2026-08-05T23:43:27Z',
      'GoVersion:     go1.26.4',
      'Compiler:      gc',
      'Platform:      windows/amd64',
    ].join('\n');
    expect(extractVersion(out)).toBe('3.1.3');
  });

  it('returns null when there is no version at all', () => {
    expect(extractVersion('usage: tool [options]')).toBeNull();
  });
});

describe('highestDotnetSdk', () => {
  it('picks the highest listed SDK, not the first', () => {
    const out = [
      '8.0.414 [C:\\Program Files\\dotnet\\sdk]',
      '10.0.401 [C:\\Program Files\\dotnet\\sdk]',
      '9.0.305 [C:\\Program Files\\dotnet\\sdk]',
    ].join('\r\n');
    expect(highestDotnetSdk(out)).toBe('10.0.401');
  });

  it('is null for a runtime-only install (no SDK listed)', () => {
    expect(highestDotnetSdk('')).toBeNull();
  });
});
