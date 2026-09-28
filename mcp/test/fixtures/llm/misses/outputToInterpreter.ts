/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * The near-miss each of the receiver regexes exists to exclude, and the fixes
 * the rule's message prescribes.
 */

import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import OpenAI from 'openai';
import vm from 'vm';

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
