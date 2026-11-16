// The controls of the local-name exclusion: the import itself still fires — also in a function that stands beside
// one declaring a local of the same name — and so does a `require` made INSIDE a function, which is itself a
// declaration of the name. One call a line.
import OpenAI from 'openai';
import { spawn, exec } from 'node:child_process';
import cp from 'node:child_process';

export function theImportItself(completion: OpenAI.Chat.ChatCompletion) {
  exec(completion.choices[0].message.content ?? ''); // BUG: the named import
  cp.exec(completion.choices[0].message.content ?? ''); // BUG: the default import
  spawn('sh', ['-c', completion.choices[0].message.content ?? '']); // BUG: the named import, a shell
}

export function aLocalElsewhere(db: { exec: (sql: string) => number }) {
  const exec = db.exec;
  return exec('select 1');
}

export function besideIt(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  exec(text); // BUG: the import — the local `exec` belongs to ANOTHER function
}
