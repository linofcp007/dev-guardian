/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * The near-miss each of the receiver regexes exists to exclude, and the fixes
 * the rule's message prescribes.
 */

import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import OpenAI from 'openai';
import vm from 'vm';
import { exec as dbExec } from './db';

// AWS Lambda's `invoke` returns a FUNCTION's output, not a model's: the
// receiver regex needs a model word at the end of the receiver's name.
export async function lambdaInvoke(lambdaClient: LambdaClient & { invoke(x: unknown): Promise<{ Payload: string }> }) {
  const r = await lambdaClient.invoke(new InvokeCommand({ FunctionName: 'relatorio' }));
  return eval(r.Payload);
}

// A Mongoose `model` has methods too: only invoke/call/predict count.
export async function mongooseModel(model: { findOne(q: unknown): Promise<{ script: string }> }, id: string) {
  const doc = await model.findOne({ id });
  return new Function(doc.script)();
}

// The prescribed fix: parse the model's text as DATA.
export function parseAsData(completion: OpenAI.Chat.ChatCompletion) {
  return JSON.parse(completion.choices[0].message.content ?? '{}');
}

// RegExp.prototype.exec is not child_process.exec.
export function regexExec(completion: OpenAI.Chat.ChatCompletion) {
  return /```(\w+)/.exec(completion.choices[0].message.content ?? '');
}

// Model text as a VARIABLE of a context is data; only the code argument is a sink.
export function vmContextData(completion: OpenAI.Chat.ChatCompletion) {
  return vm.runInNewContext('resposta.length', { resposta: completion.choices[0].message.content });
}

// An AI commit-message tool: the model's text is an ARGUMENT in an argv list,
// no shell parses it, and the program is fixed.
export function commitMessage(completion: OpenAI.Chat.ChatCompletion) {
  spawn('git', ['commit', '-m', completion.choices[0].message.content ?? '']);
  return execFile('git', ['commit', '-m', completion.choices[0].message.content ?? '']);
}

const execFileAsync = promisify(execFile);

// `shell: false` written out is no shell; a promisified or inline-required
// execFile/spawn of a fixed program is the same call.
export async function commitMessageNoShell(completion: OpenAI.Chat.ChatCompletion) {
  const t = completion.choices[0].message.content ?? '';
  spawn('git', ['commit', '-m', t], { shell: false });
  await execFileAsync('git', ['log', '--grep', t]);
  await execFileAsync('git', ['log', '--grep', t], { shell: false });
  require('child_process').spawn('git', ['log', '--grep', t]);
  require('child_process').execFile('git', ['log', '--grep', t], { shell: false });
}

// `-e` after a program that is not an interpreter is just an option value.
export function grepPattern(completion: OpenAI.Chat.ChatCompletion) {
  return spawn('grep', ['-e', completion.choices[0].message.content ?? '', 'registo.txt']);
}

// The interpreter list matches the WHOLE program name: perltidy formats Perl
// and runs none of it.
export function programNamedLikeAnInterpreter(completion: OpenAI.Chat.ChatCompletion) {
  return spawn('perltidy', ['-st', completion.choices[0].message.content ?? '']);
}

// A fixed program with its argv in a variable is the same call as with the
// array written in it (review of the pack, round 3).
export async function commitMessageArgvInAVariable(completion: OpenAI.Chat.ChatCompletion) {
  const t = completion.choices[0].message.content ?? '';
  const gitArgs = ['log', '--grep', t];
  spawn('git', gitArgs);
  await execFileAsync('git', gitArgs);
  require('child_process').execFile('git', gitArgs, { shell: false });
}

// A function called `exec` from any module but child_process runs nothing.
export async function databaseExec(completion: OpenAI.Chat.ChatCompletion) {
  return dbExec(completion.choices[0].message.content ?? '');
}

// Inline `require` of any module but child_process is not a process either.
export function inlineRequireOther(completion: OpenAI.Chat.ChatCompletion) {
  return require('./esquema').validar(completion.choices[0].message.content ?? '');
}
