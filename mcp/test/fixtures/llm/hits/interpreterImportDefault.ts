/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * `child_process` through a DEFAULT import and nothing else, with and without
 * the `node:` prefix. No Semgrep measured resolves a default import of the
 * module on its own (1.182.0, Linux and Windows), so until 3.9.3 none of
 * these lines fired anywhere. One spelling a file: a clause that reads
 * another spelling cannot fire for this one.
 */

import cpNode from 'node:child_process';
import cpPlain from 'child_process';
import { promisify } from 'node:util';
import OpenAI from 'openai';

export function defaultImportNode(completion: OpenAI.Chat.ChatCompletion) {
  cpNode.exec(completion.choices[0].message.content ?? ''); // BUG: default import, node:
}

export function defaultImportPlain(completion: OpenAI.Chat.ChatCompletion) {
  return cpPlain.execSync(completion.choices[0].message.content ?? ''); // BUG: default import, no prefix
}

export function shellThroughTheDefaultImport(completion: OpenAI.Chat.ChatCompletion) {
  return cpNode.spawn('sh', ['-c', completion.choices[0].message.content ?? '']); // BUG: sh -c through the default import
}

const viaPromisify = promisify(cpNode.exec);

export async function promisified(completion: OpenAI.Chat.ChatCompletion) {
  await viaPromisify(completion.choices[0].message.content ?? ''); // BUG: promisify of the default import's exec
}
