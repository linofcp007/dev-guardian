// A function DESTRUCTURED from a name that is the child_process module — a namespace import and a default import.
import OpenAI from 'openai';
import * as ns from 'node:child_process';
import dflt from 'child_process';

const { exec: nsExec } = ns;
const { execSync } = dflt;

export function handle(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  nsExec(text); // BUG: destructured from a namespace import, renamed
  execSync(text); // BUG: destructured from a default import
}
