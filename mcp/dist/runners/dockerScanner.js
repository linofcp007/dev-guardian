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
import { join } from 'node:path';
export const DEFAULT_SEMGREP_IMAGE = 'semgrep/semgrep';
/**
 * Where the project is mounted inside the container. Semgrep run there
 * reports paths under it (`/src/app.js`); the Semgrep parser strips it so a
 * Docker run and a native run of the same tree give the same relative paths.
 */
export const CONTAINER_PROJECT_ROOT = '/src';
/**
 * Build the argv for `docker run … semgrep …`, mirroring the native Semgrep
 * invocation in scan_sast (config=auto, +p/csharp for .NET, --json --quiet,
 * --output, optional --autofix). The report path is rewritten to its location
 * *inside* the mount so the file lands back on the host.
 */
export function buildSemgrepDockerArgs(opts) {
    const image = opts.image ?? DEFAULT_SEMGREP_IMAGE;
    const containerOut = toContainerPath(opts.projectPath, opts.outFileHost);
    const args = [
        'run',
        '--rm',
        '--mount',
        `type=bind,source=${opts.projectPath},target=${CONTAINER_PROJECT_ROOT}`,
        '-w',
        CONTAINER_PROJECT_ROOT,
        image,
        'semgrep',
    ];
    for (const config of opts.configs ?? ['auto'])
        args.push(`--config=${config}`);
    if (opts.hasCsproj)
        args.push('--config=p/csharp');
    if (opts.metricsOff)
        args.push('--metrics=off');
    args.push('--json', '--quiet', '--output', containerOut);
    if (opts.autoFix)
        args.push('--autofix');
    args.push(CONTAINER_PROJECT_ROOT);
    return args;
}
/**
 * Express a host path that lives under `projectPath` as its path inside the
 * `/src` mount. POSIX-normalised; drive-letter comparison is case-insensitive
 * so Windows paths map correctly. Falls back to placing the file at the mount
 * root if the host path is unexpectedly outside the project.
 */
export function toContainerPath(projectPath, outFileHost) {
    return toContainerPathImpl(projectPath, outFileHost);
}
/**
 * The host file behind a path the container sees (`/src/<rel>` →
 * `<projectPath>/<rel>`) — {@link toContainerPath} in reverse. Any other
 * path is returned as it is.
 */
export function fromContainerPath(projectPath, containerPath) {
    const prefix = `${CONTAINER_PROJECT_ROOT}/`;
    if (containerPath === CONTAINER_PROJECT_ROOT)
        return projectPath;
    if (!containerPath.startsWith(prefix))
        return containerPath;
    return join(projectPath, ...containerPath.slice(prefix.length).split('/'));
}
function toContainerPathImpl(projectPath, outFileHost) {
    const norm = (p) => p.replace(/\\/g, '/').replace(/\/+$/, '');
    const root = norm(projectPath);
    let rel = norm(outFileHost);
    if (rel.toLowerCase().startsWith(root.toLowerCase())) {
        rel = rel.slice(root.length);
    }
    rel = rel.replace(/^\/+/, '');
    return rel ? `${CONTAINER_PROJECT_ROOT}/${rel}` : CONTAINER_PROJECT_ROOT;
}
//# sourceMappingURL=dockerScanner.js.map