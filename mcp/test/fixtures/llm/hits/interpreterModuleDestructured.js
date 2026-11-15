// A function DESTRUCTURED from a name that is the child_process module — here a `require` assigned to a name.
const OpenAI = require('openai');
const cp = require('child_process');
const { exec: run, execSync } = cp;

async function handle(client) {
  const completion = await client.chat.completions.create({ model: 'm', messages: [] });
  const text = completion.choices[0].message.content;
  run(text); // BUG: destructured from the module name, renamed
  execSync(text); // BUG: destructured from the module name
}

module.exports = { handle, OpenAI };
