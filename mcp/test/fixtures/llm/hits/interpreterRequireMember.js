// The FUNCTION taken from a `require` of child_process in the assignment itself — the common CommonJS spelling —
// and `promisify` of such a `require`, the idiom of Node's own documentation. One call a line.
const OpenAI = require('openai');
const { promisify } = require('util');
const util = require('node:util');

const exec = require('child_process').exec;
const execNode = require('node:child_process').exec;
const spawn = require('child_process').spawn;
const execAsync = promisify(require('child_process').exec);
const execFileAsync = util.promisify(require('node:child_process').execFile);

async function run(client) {
  const completion = await client.chat.completions.create({ model: 'm', messages: [] });
  const text = completion.choices[0].message.content;
  exec(text); // BUG: the function taken from require('child_process').exec
  execNode(text); // BUG: the same, node:
  spawn('bash', ['-c', text]); // BUG: spawn taken from a require, the text in the argument array
  await execAsync(text); // BUG: promisify(require('child_process').exec)
  await execFileAsync('sh', ['-c', text]); // BUG: util.promisify(require('node:child_process').execFile)
}

module.exports = { run, OpenAI };
