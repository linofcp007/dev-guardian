// A dynamic `import()` of ANOTHER module, awaited into a name and destructured: nothing to report.
import OpenAI from 'openai';

export async function handle(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  const db = await import('./db.js');
  db.exec(text); // the exec of ./db.js
  const { execSync: run } = await import('./shell.js');
  run(text); // the execSync of ./shell.js
}
