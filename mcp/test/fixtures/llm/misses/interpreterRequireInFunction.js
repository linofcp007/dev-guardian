// A lazy `require` of ANOTHER module inside the function: nothing to report.
const OpenAI = require('openai');

async function destructured(client) {
  const completion = await client.chat.completions.create({ model: 'm', max_tokens: 64, messages: [] });
  const text = completion.choices[0].message.content;
  const { exec } = require('./db');
  exec(text); // the exec of ./db
}

async function assigned(client) {
  const completion = await client.chat.completions.create({ model: 'm', max_tokens: 64, messages: [] });
  const text = completion.choices[0].message.content;
  const cp = require('./shell');
  cp.execSync(text); // the execSync of ./shell
}

module.exports = { destructured, assigned, OpenAI };
