/**
 * Ensure the target project's `.gitignore` excludes `.guardian/`.
 *
 * Called once at server startup (after the storage is opened, so we know
 * which project root we're operating on). Idempotent: a project with the
 * entry already in place is left alone.
 */

import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const HEADER = '# dev-guardian outputs';
const ENTRY = '.guardian/';

export interface GitignoreGuardResult {
  updated: boolean;
  reason: 'already_present' | 'added' | 'created' | 'not_a_repo' | 'unwritable';
}

export function ensureGuardianIgnored(projectPath: string): GitignoreGuardResult {
  const gitignorePath = join(projectPath, '.gitignore');
  if (!existsSync(join(projectPath, '.git'))) {
    return { updated: false, reason: 'not_a_repo' };
  }
  try {
    if (!existsSync(gitignorePath)) {
      writeFileSync(gitignorePath, `${HEADER}\n${ENTRY}\n`, 'utf8');
      return { updated: true, reason: 'created' };
    }
    const content = readFileSync(gitignorePath, 'utf8');
    if (alreadyIgnored(content)) {
      return { updated: false, reason: 'already_present' };
    }
    const suffix = content.endsWith('\n') ? '' : '\n';
    appendFileSync(gitignorePath, `${suffix}\n${HEADER}\n${ENTRY}\n`, 'utf8');
    return { updated: true, reason: 'added' };
  } catch {
    return { updated: false, reason: 'unwritable' };
  }
}

function alreadyIgnored(content: string): boolean {
  const lines = content.split(/\r?\n/).map((l) => l.trim());
  return lines.some(
    (l) => l === '.guardian' || l === '.guardian/' || l === '/.guardian' || l === '/.guardian/',
  );
}
