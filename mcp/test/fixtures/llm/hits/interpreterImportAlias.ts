/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * `child_process` through NAMED imports WITH AN ALIAS from
 * `node:child_process` and nothing else: the name that runs a process in
 * this file is the alias.
 */

import { exec as run, execFileSync as runFile } from 'node:child_process';
import { promisify } from 'node:util';
import OpenAI from 'openai';

export function aliased(completion: OpenAI.Chat.ChatCompletion) {
  run(completion.choices[0].message.content ?? ''); // BUG: named import with an alias, node:
}

export function bashThroughAnAlias(completion: OpenAI.Chat.ChatCompletion) {
  return runFile('bash', ['-c', completion.choices[0].message.content ?? '']); // BUG: bash -c through an aliased import
}

const viaAliased = promisify(run);

export async function promisified(completion: OpenAI.Chat.ChatCompletion) {
  await viaAliased(completion.choices[0].message.content ?? ''); // BUG: promisify of an aliased import
}
