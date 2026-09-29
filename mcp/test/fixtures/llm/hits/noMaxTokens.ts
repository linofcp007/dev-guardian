/**
 * llm-openai-no-max-tokens-js -- every `// BUG` line fires exactly once.
 */

import OpenAI from 'openai';

export async function conversar(openai: OpenAI, messages: OpenAI.Chat.ChatCompletionMessageParam[]) {
  return openai.chat.completions.create({ model: 'gpt-4o', messages }); // BUG: no cap
}

export async function conversarEmStream(openai: OpenAI, messages: OpenAI.Chat.ChatCompletionMessageParam[], signal: AbortSignal) {
  return openai.chat.completions.create({ model: 'gpt-4o', messages, stream: true }, { signal }); // BUG: an abort signal is not a cap
}

export async function responder(openai: OpenAI, input: string) {
  return openai.responses.create({ model: 'gpt-4o', input }); // BUG: the Responses API, no cap
}

export async function limiteIndefinido(openai: OpenAI, messages: OpenAI.Chat.ChatCompletionMessageParam[]) {
  return openai.chat.completions.create({ model: 'gpt-4o', messages, max_tokens: undefined }); // BUG: undefined is no cap
}

export async function estruturado(openai: OpenAI, messages: OpenAI.Chat.ChatCompletionMessageParam[], formato: unknown) {
  return openai.beta.chat.completions.parse({ model: 'gpt-4o', messages, response_format: formato }); // BUG: structured output, no cap
}

export async function responsesEstruturado(openai: OpenAI, input: string, formato: unknown) {
  return openai.responses.parse({ model: 'gpt-4o', input, text: { format: formato } }); // BUG: Responses structured output, no cap
}
