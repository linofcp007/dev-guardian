/**
 * llm-openai-no-max-tokens-js -- nothing here may fire: every spelling of the
 * cap, and arguments spread from an object the rule cannot see into.
 */

import OpenAI from 'openai';

export async function comMaxTokens(openai: OpenAI, messages: OpenAI.Chat.ChatCompletionMessageParam[]) {
  return openai.chat.completions.create({ model: 'gpt-4o', messages, max_tokens: 512 });
}

export async function comAtalho(openai: OpenAI, messages: OpenAI.Chat.ChatCompletionMessageParam[], max_completion_tokens: number) {
  return openai.chat.completions.create({ model: 'o3', messages, max_completion_tokens });
}

export async function responsesComLimite(openai: OpenAI, input: string) {
  return openai.responses.create({ model: 'gpt-4o', input, max_output_tokens: 1024 });
}

export async function porParametros(openai: OpenAI, params: Record<string, unknown>, messages: OpenAI.Chat.ChatCompletionMessageParam[]) {
  return openai.chat.completions.create({ model: 'gpt-4o', messages, ...params });
}

export async function responsesPorParametros(openai: OpenAI, params: Record<string, unknown>) {
  return openai.responses.create({ ...params, model: 'gpt-4o' });
}

export async function estruturadoComLimite(openai: OpenAI, messages: OpenAI.Chat.ChatCompletionMessageParam[], formato: unknown) {
  return openai.beta.chat.completions.parse({ model: 'gpt-4o', messages, response_format: formato, max_completion_tokens: 512 });
}

export async function responsesEstruturadoComLimite(openai: OpenAI, input: string, formato: unknown) {
  return openai.responses.parse({ model: 'gpt-4o', input, text: { format: formato }, max_output_tokens: 256 });
}
