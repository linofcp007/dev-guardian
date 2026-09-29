/**
 * llm-request-in-system-prompt-js -- nothing here may fire.
 *
 * Request data in the USER message is what a chat is; retrieved documents
 * are not the request's text (measured: Anthropic's customer-support
 * quickstart); JSON from another service is not the request; and a key
 * named `system` in a call that is not a model call is not a prompt.
 */

import { ChatPromptTemplate } from '@langchain/core/prompts';
import type { Request } from 'express';
import OpenAI from 'openai';

const openai = new OpenAI();
const SYSTEM_PROMPT = 'Es o assistente de apoio. Responde so sobre os nossos produtos.';

export async function conversa(req: Request) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 512,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: req.body.pergunta },
    ],
  });
}

export async function conversaInvertida(req: Request) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 512,
    messages: [{ content: req.query.pergunta, role: 'user' }],
  });
}

export async function comContexto(request: Request, retrieveContext: (q: string) => Promise<string>) {
  const { pergunta } = await request.json();
  const contexto = await retrieveContext(pergunta);
  return openai.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 512,
    messages: [
      { role: 'system', content: `${SYSTEM_PROMPT}\nDocumentos:\n${contexto}` },
      { role: 'user', content: pergunta },
    ],
  });
}

export async function configuracaoRemota(upstream: Response) {
  const config = await upstream.json();
  return openai.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 512,
    messages: [{ role: 'system', content: config.instrucoes }],
  });
}

export function auditoria(req: Request, audit: { record(x: unknown): void }) {
  audit.record({ system: req.body.origem, at: Date.now() });
}

// A vector-store similarity search returns documents, not the request's text.
export async function porSemelhanca(req: Request, vectorStore: { similaritySearch(q: string): Promise<string> }) {
  const documentos = await vectorStore.similaritySearch(req.body.pergunta);
  return openai.chat.completions.create({
    model: 'gpt-4o',
    max_tokens: 512,
    messages: [{ role: 'system', content: `${SYSTEM_PROMPT}\n${documentos}` }],
  });
}

// The request in the HUMAN tuple of a LangChain.js template is a chat.
export function modeloHumano(req: Request) {
  return ChatPromptTemplate.fromMessages([['system', SYSTEM_PROMPT], ['human', req.body.pergunta]]);
}
