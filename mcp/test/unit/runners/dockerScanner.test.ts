import { describe, expect, it } from 'vitest';
import {
  buildSemgrepDockerArgs,
  toContainerPath,
} from '../../../src/runners/dockerScanner.js';

const argAfter = (args: string[], flag: string): string | undefined =>
  args[args.indexOf(flag) + 1];

describe('buildSemgrepDockerArgs', () => {
  it('binds the project at /src, sets workdir, and writes output inside the mount', () => {
    const args = buildSemgrepDockerArgs({
      projectPath: 'C:\\Users\\me\\proj',
      outFileHost: 'C:\\Users\\me\\proj\\.guardian\\reports\\sast-abc12345\\sast.json',
    });
    expect(args[0]).toBe('run');
    expect(args).toContain('--rm');
    // --mount comma syntax avoids the Windows drive-colon ambiguity of -v.
    expect(argAfter(args, '--mount')).toBe('type=bind,source=C:\\Users\\me\\proj,target=/src');
    expect(argAfter(args, '-w')).toBe('/src');
    expect(args).toContain('semgrep/semgrep');
    expect(args).toContain('--config=auto');
    expect(argAfter(args, '--output')).toBe('/src/.guardian/reports/sast-abc12345/sast.json');
    // Scan target is the mount, and it is the final positional arg.
    expect(args[args.length - 1]).toBe('/src');
  });

  it('adds p/csharp config when csproj present and --autofix when requested', () => {
    const args = buildSemgrepDockerArgs({
      projectPath: '/home/u/p',
      outFileHost: '/home/u/p/out/sast.json',
      hasCsproj: true,
      autoFix: true,
    });
    expect(args).toContain('--config=p/csharp');
    expect(args).toContain('--autofix');
  });

  it('honours a custom image', () => {
    const args = buildSemgrepDockerArgs({
      projectPath: '/p',
      outFileHost: '/p/r/sast.json',
      image: 'returntocorp/semgrep:1.2.3',
    });
    expect(args).toContain('returntocorp/semgrep:1.2.3');
    expect(args).not.toContain('semgrep/semgrep');
  });

  it('tolerates project paths with spaces (single argv element, no shell split)', () => {
    const args = buildSemgrepDockerArgs({
      projectPath: '/home/My Proj',
      outFileHost: '/home/My Proj/r/sast.json',
    });
    expect(argAfter(args, '--mount')).toBe('type=bind,source=/home/My Proj,target=/src');
    expect(argAfter(args, '--output')).toBe('/src/r/sast.json');
  });
});

describe('toContainerPath', () => {
  it('maps a host path under the project to its /src-relative location', () => {
    expect(toContainerPath('/a/b', '/a/b/c/d.json')).toBe('/src/c/d.json');
  });

  it('is case-insensitive on the drive prefix (Windows)', () => {
    expect(toContainerPath('C:\\proj', 'c:\\proj\\out\\sast.json')).toBe('/src/out/sast.json');
  });

  it('falls back to the mount root when the path is outside the project', () => {
    expect(toContainerPath('/a/b', '/elsewhere/x.json')).toBe('/src/elsewhere/x.json');
  });
});
