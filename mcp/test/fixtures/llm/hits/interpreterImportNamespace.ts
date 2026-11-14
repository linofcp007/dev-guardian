/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * `child_process` through a NAMESPACE import of `node:child_process` and
 * nothing else. Semgrep 1.182.0 resolves it on Windows and not on Linux: the
 * rule reads the import as written.
 */

import * as cp from 'node:child_process';
import util from 'node:util';
import OpenAI from 'openai';

export function namespaceImport(completion: OpenAI.Chat.ChatCompletion) {
  return cp.spawn(completion.choices[0].message.content ?? '', { shell: true }); // BUG: namespace import, node:
}

const viaUtil = util.promisify(cp.execFile);

export async function promisified(completion: OpenAI.Chat.ChatCompletion) {
  await viaUtil('bash', ['-c', completion.choices[0].message.content ?? '']); // BUG: util.promisify of the namespace's execFile, of bash
}
