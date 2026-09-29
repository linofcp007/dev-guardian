/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * The near-miss each of the receiver regexes exists to exclude, and the fixes
 * the rule's message prescribes.
 */

import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { execFile, spawn } from 'node:child_process';
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

// Only `-c` makes sh run the next argument: here it is an argument of a fixed script.
export function scriptArgument(completion: OpenAI.Chat.ChatCompletion) {
  return spawn('sh', ['./notificar.sh', completion.choices[0].message.content ?? '']);
}

// `-e` after a program that is not an interpreter is just an option value.
export function grepPattern(completion: OpenAI.Chat.ChatCompletion) {
  return spawn('grep', ['-e', completion.choices[0].message.content ?? '', 'registo.txt']);
}

// A function called `exec` from any module but child_process runs nothing.
export async function databaseExec(completion: OpenAI.Chat.ChatCompletion) {
  return dbExec(completion.choices[0].message.content ?? '');
}

// Inline `require` of any module but child_process is not a process either.
export function inlineRequireOther(completion: OpenAI.Chat.ChatCompletion) {
  return require('./esquema').validar(completion.choices[0].message.content ?? '');
}
