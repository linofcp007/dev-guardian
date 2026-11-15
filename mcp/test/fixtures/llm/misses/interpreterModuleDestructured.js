// A function destructured from a name that is ANOTHER module: nothing to report.
const OpenAI = require('openai');
const db = require('./db');
const { exec: run, execSync } = db;

async function handle(client) {
  const completion = await client.chat.completions.create({ model: 'm', messages: [] });
  const text = completion.choices[0].message.content;
  run(text); // the exec of ./db
  execSync(text); // the execSync of ./db
}

module.exports = { handle, OpenAI };
