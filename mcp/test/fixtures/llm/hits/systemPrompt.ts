/**
 * llm-request-in-system-prompt-js -- every `// BUG` line fires the rule exactly once.
 *
 * Data from the HTTP request written into the SYSTEM (or developer) part of a
 * prompt: whoever sends the request edits the operator's instructions.
 */

import Anthropic from '@anthropic-ai/sdk';
import { SystemMessage } from '@langchain/core/messages';
import { ChatPromptTemplate } from '@langchain/core/prompts';
import { generateText } from 'ai';
import type { Request, Response } from 'express';
import type { NextRequest } from 'next/server';
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

// LangChain.js prompt templates take [role, text] tuples.
export function modelo(req: Request) {
  return ChatPromptTemplate.fromMessages([['system', `Persona: ${req.body.persona}`], ['human', '{input}']]); // BUG: a ['system', ...] tuple
}

// Express route parameters.
export async function porRota(req: Request) {
  return anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 256, system: `Loja: ${req.params.loja}`, messages: [] }); // BUG: a route parameter
}

// A request header.
export async function porCabecalho(req: Request) {
  return anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 256, system: `Responde em ${req.headers['accept-language']}`, messages: [] }); // BUG: a request header
}

// Next.js: the query string of a NextRequest.
export async function GET(request: NextRequest) {
  const tema = request.nextUrl.searchParams.get('tema');
  return anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 256, system: `Tema: ${tema}`, messages: [] }); // BUG: nextUrl.searchParams
}

// A web-standard Request's query string.
export async function PUT(request: Request) {
  const { searchParams } = new URL(request.url);
  return anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 256, system: `Modo: ${searchParams.get('modo')}`, messages: [] }); // BUG: new URL(request.url)
}

// Review of the pack, I-4: a name that CONTAINS "search" is not a retrieval.
export async function investigacao(request: Request, researchInstructions: (t: string) => string) {
  const { tema } = await request.json();
  return anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 256, system: researchInstructions(tema), messages: [] }); // BUG: research* is not a retrieval call
}

export async function substituir(req: Request, searchAndReplace: (t: string, a: string, b: string) => string) {
  return anthropic.messages.create({ model: 'claude-sonnet-4-5', max_tokens: 256, system: searchAndReplace(req.body.modelo, '{nome}', req.body.nome), messages: [] }); // BUG: searchAndReplace returns the request's own text
}
