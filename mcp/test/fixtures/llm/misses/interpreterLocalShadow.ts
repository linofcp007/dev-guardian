// A LOCAL name that shadows the import: the call is the local's, and there is nothing to report. Every way a
// function gives the name another value — `const`, `let`, a destructuring, a loop variable, a catch variable, a
// function declaration, and a `const` in an inner block for the module's name.
import OpenAI from 'openai';
import { spawn, exec } from 'node:child_process';
import cp from 'node:child_process';

export function aConst(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  const spawn = (job: string) => job.length;
  spawn(text); // a local const
}

export function aLet(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  let exec = (s: string) => s.length;
  exec(text); // a local let
}

export function aDestructuring(completion: OpenAI.Chat.ChatCompletion, db: { exec: (s: string) => number }) {
  const text = completion.choices[0].message.content ?? '';
  const { exec } = db;
  exec(text); // destructured from another object
}

export function aLoopVariable(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  for (const exec of [(s: string) => s.length]) exec(text); // a loop variable
}

export function aCatchVariable(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  try { throw new Error('x'); } catch (exec) { (exec as unknown as (s: string) => void)(text); } // a catch variable
}

export function aFunctionDeclaration(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  function spawn(job: string) { return job.length; }
  spawn(text); // a local function declaration
}

export function theModuleName(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  {
    const cp = { exec: (sql: string) => sql.length };
    cp.exec(text); // a local const of the module's name, in an inner block
  }
}
