/**
 * Ports the project declares it will listen on.
 *
 * Read straight from `Dockerfile` and compose files rather than through a
 * Semgrep rule — these formats are line-oriented and a regex reads them more
 * reliably than a pattern matcher would.
 *
 * This is declaration-reading, not port scanning: nothing here touches the
 * network or inspects a running host.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const DOCKERFILES = ['Dockerfile', 'dockerfile'];
const COMPOSE_FILES = [
  'docker-compose.yml',
  'docker-compose.yaml',
  'compose.yml',
  'compose.yaml',
];

export function collectPorts(projectPath: string): { port: number; source: string }[] {
  const out: { port: number; source: string }[] = [];
  const seen = new Set<string>();

  const push = (port: number, source: string): void => {
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return;
    const key = `${port}:${source}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ port, source });
  };

  const seenDockerfiles = new Set<string>();
  for (const name of DOCKERFILES) {
    const path = join(projectPath, name);
    // On case-insensitive filesystems (Windows, default macOS), `Dockerfile`
    // and `dockerfile` can be the very same on-disk file; comparing device +
    // inode (rather than the path string) keeps it from being read twice.
    const identity = fileIdentity(path);
    if (identity !== undefined) {
      if (seenDockerfiles.has(identity)) continue;
      seenDockerfiles.add(identity);
    }
    for (const line of readLines(path)) {
      const match = /^\s*EXPOSE\s+(.+)$/i.exec(line);
      if (match?.[1] === undefined) continue;
      for (const token of match[1].split(/\s+/)) {
        const portPart = token.split('/')[0];
        if (portPart === undefined) continue;
        const port = Number.parseInt(portPart, 10);
        if (Number.isNaN(port)) continue;
        push(port, name);
      }
    }
  }

  for (const name of COMPOSE_FILES) {
    for (const line of readLines(join(projectPath, name))) {
      // Long form: `published: 8080`
      const published = /^\s*published:\s*"?(\d+)"?\s*$/.exec(line);
      if (published?.[1] !== undefined) {
        push(Number.parseInt(published[1], 10), name);
        continue;
      }
      // Short form: `- "8000:80"` / `- 9000`
      const short = /^\s*-\s*"?(\d+)(?::\d+)?"?\s*$/.exec(line);
      if (short?.[1] !== undefined) {
        push(Number.parseInt(short[1], 10), name);
      }
    }
  }

  return out;
}

function readLines(path: string): string[] {
  if (!existsSync(path)) return [];
  try {
    return readFileSync(path, 'utf8').split(/\r?\n/);
  } catch {
    return [];
  }
}

/** `device:inode`, used to tell genuinely distinct files apart from the same
 *  file reached through two differently-cased paths. Undefined if the path
 *  doesn't exist or can't be stat'd. */
function fileIdentity(path: string): string | undefined {
  try {
    const stat = statSync(path);
    return `${stat.dev}:${stat.ino}`;
  } catch {
    return undefined;
  }
}
