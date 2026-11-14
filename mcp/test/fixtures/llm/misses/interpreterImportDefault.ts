/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * A default import of `node:child_process`, beside what the rule must leave
 * alone: a fixed program, a constant command, a default import of another
 * module, and a local name that shadows the import.
 */

import cp from 'node:child_process';
import { promisify } from 'node:util';
import OpenAI from 'openai';
import db from './db';
import { medir } from './metricas';

// A fixed program that is neither an interpreter nor a shell, the model's
// text in its arguments.
export function fixedProgram(completion: OpenAI.Chat.ChatCompletion) {
  const t = completion.choices[0].message.content ?? '';
  cp.spawn('git', ['commit', '-m', t]);
  cp.execFile('git', ['log', '--grep', t], { shell: false });
}

// No model text in the command.
export function constantCommand() {
  return cp.execSync('git status --short');
}

// The default import of another module: `db.exec` runs SQL, not a process.
export function otherModule(completion: OpenAI.Chat.ChatCompletion) {
  return db.exec(completion.choices[0].message.content ?? '');
}

const dbQuery = promisify(db.exec);

export async function promisifiedOther(completion: OpenAI.Chat.ChatCompletion) {
  return dbQuery(completion.choices[0].message.content ?? '');
}

// Only `promisify` is followed: another wrapper of the module's function.
const cronometro = medir(cp.exec);

export function otherWrapper(completion: OpenAI.Chat.ChatCompletion) {
  return cronometro(completion.choices[0].message.content ?? '');
}

// A parameter named like the import is not the module: in a function, in an
// arrow function with a block, and in one with an expression.
export function shadowed(completion: OpenAI.Chat.ChatCompletion, cp: { exec(sql: string): void }) {
  cp.exec(completion.choices[0].message.content ?? '');
}

export const shadowedArrow = (completion: OpenAI.Chat.ChatCompletion, cp: { exec(sql: string): void }) => {
  cp.exec(completion.choices[0].message.content ?? '');
};

export const shadowedExpression = (completion: OpenAI.Chat.ChatCompletion, cp: { exec(sql: string): void }) =>
  cp.exec(completion.choices[0].message.content ?? '');
