/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * A namespace import of `node:child_process`, beside a fixed program and a
 * namespace import of another module.
 */

import * as cp from 'node:child_process';
import util from 'node:util';
import OpenAI from 'openai';
import * as tools from './tools';

export function fixedProgram(completion: OpenAI.Chat.ChatCompletion) {
  return cp.execFile('git', ['log', '--grep', completion.choices[0].message.content ?? ''], { shell: false });
}

// The namespace of another module, with a function named like one of child_process's.
export function otherModule(completion: OpenAI.Chat.ChatCompletion) {
  return tools.spawn(completion.choices[0].message.content ?? '');
}

const toolsRun = util.promisify(tools.execFile);

export async function promisifiedOther(completion: OpenAI.Chat.ChatCompletion) {
  return toolsRun(completion.choices[0].message.content ?? '');
}
