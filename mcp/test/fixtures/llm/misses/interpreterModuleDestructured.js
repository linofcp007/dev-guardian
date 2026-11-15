// A function destructured from a name that is ANOTHER module: nothing to report.
const OpenAI = require('openai');
const db = require('./db');
const { exec: run, execSync, spawn } = db;

async function handle(client) {
  const completion = await client.chat.completions.create({ model: 'm', max_tokens: 64, messages: [] });
  const text = completion.choices[0].message.content;
  run(text); // the exec of ./db
  execSync(text); // the execSync of ./db
  spawn('bash', ['-c', text]); // the spawn of ./db
}

module.exports = { handle, OpenAI };
