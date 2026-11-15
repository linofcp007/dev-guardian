// A function destructured from a namespace and a default import of ANOTHER module: nothing to report.
import OpenAI from 'openai';
import * as ns from './shell';
import dflt from './db';

const { exec: nsExec } = ns;
const { execSync } = dflt;

export function handle(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  nsExec(text); // the exec of ./shell
  execSync(text); // the execSync of ./db
}
