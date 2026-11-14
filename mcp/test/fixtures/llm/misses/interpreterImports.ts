/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * Every spelling of the import the rule recognises, beside what it must leave
 * alone: the same spellings of ANOTHER module, a fixed program that is not an
 * interpreter, and a command with no model text in it.
 */

import cp from 'node:child_process';
import * as cpNs from 'node:child_process';
import { exec as run, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import OpenAI from 'openai';
import db from './db';
import * as tools from './tools';
import { exec as dbExec, execSync } from './db';

const cpRequire = require('node:child_process');
const other = require('./other');
const { execFile: otherExecFile } = require('./other');

// A fixed program that is neither an interpreter nor a shell, the model's
// text in its arguments, through each spelling: the same exclusion as for a
// named import.
export function fixedProgram(completion: OpenAI.Chat.ChatCompletion) {
  const t = completion.choices[0].message.content ?? '';
  cp.spawn('git', ['commit', '-m', t]);
  cpNs.execFile('git', ['log', '--grep', t], { shell: false });
  cpRequire.spawn('grep', ['-e', t, 'registo.txt']);
  spawn('git', ['commit', '-m', t]);
}

// No model text in the command.
export function constantCommand() {
  run('ls -la');
  cp.execSync('git status --short');
  cpRequire.exec('uptime');
}

// The same spellings of another module: a default import, a namespace, a
// named import with a child_process name, a require, a renamed require.
export function otherModules(completion: OpenAI.Chat.ChatCompletion) {
  const t = completion.choices[0].message.content ?? '';
  db.exec(t);
  tools.spawn(t);
  dbExec(t);
  execSync(t);
  other.exec(t);
  otherExecFile(t);
}

// promisify of another module's function runs no process.
const dbQuery = promisify(db.exec);

export async function promisifiedOther(completion: OpenAI.Chat.ChatCompletion) {
  return dbQuery(completion.choices[0].message.content ?? '');
}

// A function of that name defined in the file is not child_process's.
function execFileSync(comando: string): number {
  return comando.length;
}

export function localFunction(completion: OpenAI.Chat.ChatCompletion) {
  return execFileSync(completion.choices[0].message.content ?? '');
}
