/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * First block: the same sink (`eval`) from each source, one source per
 * function, none reachable from two. Second block: each sink from one source
 * (a response handed in as a parameter).
 */

import Anthropic from '@anthropic-ai/sdk';
import { generateObject, generateText } from 'ai';
import { exec, execSync, spawn } from 'node:child_process';
import OpenAI from 'openai';
import vm from 'vm';

// ---------------------------------------------------------------- sources

export async function openaiStream(openai: OpenAI, pergunta: string) {
  const stream = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: pergunta }], max_tokens: 512, stream: true }); // excluded: capped (llm-openai-no-max-tokens-js)
  for await (const chunk of stream) {
    eval(chunk.choices[0].delta.content ?? ''); // BUG: an OpenAI call's streamed chunk
  }
}

export async function responsesStream(openai: OpenAI, pergunta: string) {
  const stream = await openai.responses.create({ model: 'gpt-4o', input: pergunta, max_output_tokens: 512, stream: true }); // excluded: capped (llm-openai-no-max-tokens-js)
  for await (const event of stream) {
    if (event.type === 'response.output_text.delta') eval(event.delta); // BUG: a Responses API stream event
  }
}

export async function anthropicBlocks(anthropic: Anthropic, pergunta: string) {
  const msg = await anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 1024, messages: [{ role: 'user', content: pergunta }] });
  for (const block of msg.content) {
    if (block.type === 'text') eval(block.text); // BUG: an Anthropic message's text blocks
  }
}

export async function vercelText(model: string, pergunta: string) {
  const { text } = await generateText({ model, prompt: pergunta });
  return eval(text); // BUG: the AI SDK's generateText
}

export async function vercelObject(model: string, pergunta: string, schema: unknown) {
  const { object } = await generateObject({ model, schema, prompt: pergunta });
  return eval(object.codigo); // BUG: the AI SDK's generateObject
}

export async function langchainChain(chain: { invoke(x: unknown): Promise<string> }, pergunta: string) {
  const resposta = await chain.invoke({ pergunta });
  return eval(resposta); // BUG: a LangChain chain's invoke
}

export function fromParameter(completion: OpenAI.Chat.ChatCompletion) {
  return eval(completion.choices[0].message.content ?? ''); // BUG: a chat completion handed in
}

export function legacyText(completion: { choices: { text: string }[] }) {
  return eval(completion.choices[0].text); // BUG: a legacy completion's text
}

export function responsesOutput(response: { output_text: string }) {
  return eval(response.output_text); // BUG: the Responses API's output_text
}

export function anthropicContent(msg: { content: { text: string }[] }) {
  return eval(msg.content[0].text); // BUG: an Anthropic message's first block
}

export function toolArguments(call: { function: { arguments: string } }) {
  const args = JSON.parse(call.function.arguments);
  return eval(args.codigo); // BUG: tool-call arguments are written by the model
}

// ------------------------------------------------------------------ sinks

export function toFunction(completion: OpenAI.Chat.ChatCompletion) {
  return new Function(completion.choices[0].message.content ?? '')(); // BUG: new Function
}

export function toFunctionCall(completion: OpenAI.Chat.ChatCompletion) {
  return Function('dados', completion.choices[0].message.content ?? ''); // BUG: Function without new
}

export function toVmContext(completion: OpenAI.Chat.ChatCompletion) {
  return vm.runInNewContext(completion.choices[0].message.content ?? '', {}); // BUG: vm is not a sandbox
}

export function toVmThis(completion: OpenAI.Chat.ChatCompletion) {
  return vm.runInThisContext(completion.choices[0].message.content ?? ''); // BUG: vm, this context
}

export function toVmScript(completion: OpenAI.Chat.ChatCompletion) {
  return new vm.Script(completion.choices[0].message.content ?? ''); // BUG: a vm Script
}

export function toExec(completion: OpenAI.Chat.ChatCompletion) {
  exec(completion.choices[0].message.content ?? ''); // BUG: a shell
}

export function toExecSync(completion: OpenAI.Chat.ChatCompletion) {
  return execSync(completion.choices[0].message.content ?? ''); // BUG: a shell, synchronously
}

export function toSpawn(completion: OpenAI.Chat.ChatCompletion) {
  return spawn(completion.choices[0].message.content ?? '', { shell: true }); // BUG: a command the model chose
}
