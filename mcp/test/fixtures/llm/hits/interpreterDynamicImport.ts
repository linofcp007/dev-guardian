// child_process through a dynamic `import()`, awaited into a name and destructured.
import OpenAI from 'openai';

export async function handle(completion: OpenAI.Chat.ChatCompletion) {
  const text = completion.choices[0].message.content ?? '';
  const cp = await import('child_process');
  cp.exec(text); // BUG: a dynamic import, the module in a name
  const cpNode = await import('node:child_process');
  cpNode.execSync(text); // BUG: the same, node:
  const { execSync: run } = await import('node:child_process');
  run(text); // BUG: a dynamic import, destructured and renamed
}
