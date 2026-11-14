/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * Named imports of `node:child_process` with an alias, beside the names the
 * alias leaves free: `exec` is imported AS `run`, so the `exec` of this file
 * is another module's.
 */

import { exec as run, spawn } from 'node:child_process';
import OpenAI from 'openai';
import { exec, execSync } from './db';
import { medir } from './metricas';

// No model text in the command; a fixed program with it in the arguments.
export function constantAndFixed(completion: OpenAI.Chat.ChatCompletion) {
  run('ls -la');
  spawn('git', ['commit', '-m', completion.choices[0].message.content ?? '']);
}

// The ORIGINAL name of an aliased import, and a child_process name that was
// never imported from it: both are `./db`'s here.
export function otherModule(completion: OpenAI.Chat.ChatCompletion) {
  const t = completion.choices[0].message.content ?? '';
  exec(t);
  execSync(t);
}

// A parameter named like the alias, and like the unaliased import, shadows it.
export function shadowed(completion: OpenAI.Chat.ChatCompletion, run: (sql: string) => void, spawn: (job: string) => void) {
  run(completion.choices[0].message.content ?? '');
  spawn(completion.choices[0].message.content ?? '');
}

// The same in an arrow function, with a block and with an expression, and in a method.
export const shadowedArrow = (completion: OpenAI.Chat.ChatCompletion, spawn: (job: string) => void) => {
  spawn(completion.choices[0].message.content ?? '');
};

export const shadowedExpression = (completion: OpenAI.Chat.ChatCompletion, spawn: (job: string) => void) =>
  spawn(completion.choices[0].message.content ?? '');

export class Fila {
  enfileirar(completion: OpenAI.Chat.ChatCompletion, spawn: (job: string) => void) {
    spawn(completion.choices[0].message.content ?? '');
  }
}

// Only `promisify` is followed: what another wrapper returns is not known to
// run the function it was handed — here, a meter that records a label.
const cronometro = medir(run);

export function otherWrapper(completion: OpenAI.Chat.ChatCompletion) {
  return cronometro(completion.choices[0].message.content ?? '');
}

// A function of that name defined in the file is not child_process's.
function execFileSync(comando: string): number {
  return comando.length;
}

export function localFunction(completion: OpenAI.Chat.ChatCompletion) {
  return execFileSync(completion.choices[0].message.content ?? '');
}
