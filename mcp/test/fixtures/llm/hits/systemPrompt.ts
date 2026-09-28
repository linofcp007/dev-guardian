/**
 * llm-request-in-system-prompt-js -- every `// BUG` line fires the rule exactly once.
 *
 * Data from the HTTP request written into the SYSTEM (or developer) part of a
 * prompt: whoever sends the request edits the operator's instructions.
 */

import Anthropic from '@anthropic-ai/sdk';
import { SystemMessage } from '@langchain/core/messages';
import { generateText } from 'ai';
import type { Request, Response } from 'express';
import OpenAI from 'openai';

const openai = new OpenAI();
const anthropic = new Anthropic();

// Express: the body, interpolated into the operator's text.
export async function suporte(req: Request, res: Response) {
  const nome = req.body.empresa;
  const r = await openai.chat.completions.create({ // excluded: capped (llm-openai-no-max-tokens-js)
    model: 'gpt-4o',
    max_tokens: 512,
    messages: [
      { role: 'system', content: `Es o assistente de apoio da ${nome}. Responde so sobre os nossos produtos.` }, // BUG: request body in the system message
      { role: 'user', content: req.body.pergunta }, // excluded: the USER role (the $ROLE regex)
    ],
  });
  res.json(r);
}

// The same message with its keys the other way round.
export async function suporteInvertido(req: Request) {
  return openai.chat.completions.create({ // excluded: capped (llm-openai-no-max-tokens-js)
    model: 'gpt-4o',
    max_tokens: 512,
    messages: [{ content: 'Idioma: ' + req.query.lingua, role: 'system' }], // BUG: a query parameter, keys reversed
  });
}

// OpenAI's newer name for the same role.
export async function developer(request: Request) {
  const { persona } = await request.json();
  return openai.chat.completions.create({ // excluded: capped (llm-openai-no-max-tokens-js)
    model: 'o3',
    max_completion_tokens: 1024,
    messages: [{ role: 'developer', content: `Persona: ${persona}` }], // BUG: the developer role is the system role
  });
}

// Next.js route handler, Anthropic's top-level system parameter.
export async function POST(request: Request) {
  const form = await request.formData();
  const ficheiro = form.get('ficheiro');
  return anthropic.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 1024,
    system: `Revê este ficheiro:\n${ficheiro}`, // BUG: form data in Anthropic's system parameter
    messages: [{ role: 'user', content: 'Revê.' }],
  });
}

// The AI SDK's system option.
export async function assistente(req: Request) {
  return generateText({ model: 'gpt-4o', system: `Utilizador: ${req.body.nome}`, prompt: req.body.pergunta }); // BUG: the AI SDK's system option
}

// The Responses API's instructions.
export async function instrucoes(req: Request) {
  return openai.responses.create({ model: 'gpt-4o', max_output_tokens: 256, instructions: 'Tom: ' + req.body.tom, input: req.body.texto }); // BUG: Responses API instructions (excluded: capped, for llm-openai-no-max-tokens-js)
}

// LangChain's system message.
export function mensagemDeSistema(req: Request) {
  return [new SystemMessage(`Contexto do cliente: ${req.body.contexto}`)]; // BUG: a LangChain SystemMessage
}
