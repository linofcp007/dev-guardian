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
