/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * First block: the same sink (`eval`) from each source, one source per
 * function, none reachable from two. Second block: each sink from one source
 * (a response handed in as a parameter).
 */

import Anthropic from '@anthropic-ai/sdk';
import { generateObject, generateText, streamText } from 'ai';
import { exec, execFileSync, execSync, spawn, spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
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

export async function vercelStream(model: string, pergunta: string) {
  const result = streamText({ model, prompt: pergunta });
  return eval(await result.text); // BUG: the AI SDK's streamText
}

export async function anthropicStream(anthropic: Anthropic, pergunta: string) {
  const stream = anthropic.messages.stream({ model: 'claude-sonnet-4-5', max_tokens: 1024, messages: [{ role: 'user', content: pergunta }] });
  for await (const event of stream) {
    if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') eval(event.delta.text); // BUG: an Anthropic message stream
  }
}

export async function structuredOutput(openai: OpenAI, pergunta: string, formato: unknown) {
  const r = await openai.beta.chat.completions.parse({ model: 'gpt-4o', messages: [{ role: 'user', content: pergunta }], response_format: formato, max_completion_tokens: 512 }); // excluded: capped (llm-openai-no-max-tokens-js)
  return eval(r.choices[0].message.parsed.codigo); // BUG: structured output (chat.completions.parse)
}

export async function responsesStructured(openai: OpenAI, pergunta: string, formato: unknown) {
  const r = await openai.responses.parse({ model: 'gpt-4o', input: pergunta, text: { format: formato }, max_output_tokens: 512 }); // excluded: capped (llm-openai-no-max-tokens-js)
  return eval(r.output_parsed.codigo); // BUG: structured output (responses.parse)
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

export function toSpawnSync(completion: OpenAI.Chat.ChatCompletion) {
  return spawnSync(completion.choices[0].message.content ?? ''); // BUG: the model picks the program
}

export function toExecFile(completion: OpenAI.Chat.ChatCompletion) {
  return execFileSync(completion.choices[0].message.content ?? '', ['--help']); // BUG: the model picks the file to run
}

export function toShC(completion: OpenAI.Chat.ChatCompletion) {
  return spawn('sh', ['-c', completion.choices[0].message.content ?? '']); // BUG: sh -c runs its argument as a script
}

export function toInlineRequire(completion: OpenAI.Chat.ChatCompletion) {
  return require('child_process').execSync(completion.choices[0].message.content ?? ''); // BUG: child_process required inline
}

const execAsync = promisify(exec);

export async function toPromisified(completion: OpenAI.Chat.ChatCompletion) {
  return execAsync(completion.choices[0].message.content ?? ''); // BUG: exec through util.promisify
}
