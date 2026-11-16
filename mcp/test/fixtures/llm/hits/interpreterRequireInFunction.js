// A `require` made INSIDE the function that uses it (a lazy require). It is a `const` declaration of the name, the
// very shape a local shadow has: the exclusion of local names must not take it.
const OpenAI = require('openai');

async function destructured(client) {
  const completion = await client.chat.completions.create({ model: 'm', max_tokens: 64, messages: [] });
  const text = completion.choices[0].message.content;
  const { exec } = require('child_process');
  exec(text); // BUG: a require destructured inside the function
}

async function assigned(client) {
  const completion = await client.chat.completions.create({ model: 'm', max_tokens: 64, messages: [] });
  const text = completion.choices[0].message.content;
  const cp = require('node:child_process');
  cp.execSync(text); // BUG: a require assigned inside the function
}

module.exports = { destructured, assigned, OpenAI };
