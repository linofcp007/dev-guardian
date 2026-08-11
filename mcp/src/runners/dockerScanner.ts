/**
 * Docker fallbacks for scanners that may not be installed natively.
 *
 * When a scanner binary isn't on PATH but Docker is, we can still run it from
 * its official image. The arg-builders here are pure so they can be unit
 * tested without a daemon; the actual `docker run` happens in the scan tool.
 *
 * We bind-mount the project at `/src` using `--mount type=bind,...` rather than
 * `-v host:container`. On Windows `-v C:\proj:/src` is ambiguous (the drive
 * colon collides with the v-flag's own `:` separator); `--mount`'s comma-keyed
 * syntax has no such problem and tolerates spaces in the path (this repo lives
 * under "CLAUDE SKILLS"). Because we invoke Docker via execa with shell:false,
 * each arg is a single argv element — no shell quoting needed.
 */

export const DEFAULT_SEMGREP_IMAGE = 'semgrep/semgrep';

export interface SemgrepDockerOptions {
  /** Host absolute path to the project root (mounted at /src). */
  projectPath: string;
  /** Host absolute path where the JSON report should be written. */
  outFileHost: string;
  /** Pin the p/csharp rule pack in addition to --config=auto. */
  hasCsproj?: boolean;
  /** Pass --autofix (mutates files in the bind mount). */
  autoFix?: boolean;
  /** Override the image (default `semgrep/semgrep`). */
  image?: string;
  /**
   * `--config` values, one flag each. Defaults to `['auto']`, i.e.
   * `--config=auto`, which is what every findings scan wants.
   * `map_attack_surface` passes its own rule pack instead — the path must
   * already be expressed inside the mount (see `toContainerPath`), since the
   * container cannot see host paths.
   */
  configs?: string[];
}

/**
 * Build the argv for `docker run … semgrep …`, mirroring the native Semgrep
 * invocation in scan_sast (config=auto, +p/csharp for .NET, --json --quiet,
 * --output, optional --autofix). The report path is rewritten to its location
 * *inside* the mount so the file lands back on the host.
 */
export function buildSemgrepDockerArgs(opts: SemgrepDockerOptions): string[] {
  const image = opts.image ?? DEFAULT_SEMGREP_IMAGE;
  const containerOut = toContainerPath(opts.projectPath, opts.outFileHost);

  const args = [
    'run',
    '--rm',
    '--mount',
    `type=bind,source=${opts.projectPath},target=/src`,
    '-w',
    '/src',
    image,
    'semgrep',
  ];
  for (const config of opts.configs ?? ['auto']) args.push(`--config=${config}`);
  if (opts.hasCsproj) args.push('--config=p/csharp');
  args.push('--json', '--quiet', '--output', containerOut);
  if (opts.autoFix) args.push('--autofix');
  args.push('/src');
  return args;
}

/**
 * Express a host path that lives under `projectPath` as its path inside the
 * `/src` mount. POSIX-normalised; drive-letter comparison is case-insensitive
 * so Windows paths map correctly. Falls back to placing the file at the mount
 * root if the host path is unexpectedly outside the project.
 */
export function toContainerPath(projectPath: string, outFileHost: string): string {
  const norm = (p: string): string => p.replace(/\\/g, '/').replace(/\/+$/, '');
  const root = norm(projectPath);
  let rel = norm(outFileHost);
  if (rel.toLowerCase().startsWith(root.toLowerCase())) {
    rel = rel.slice(root.length);
  }
  rel = rel.replace(/^\/+/, '');
  return rel ? `/src/${rel}` : '/src';
}
