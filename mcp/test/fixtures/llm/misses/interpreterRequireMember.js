// The same shapes with nothing to report: a function taken from ANOTHER module, promisify of one, and a function
// taken from child_process that runs a fixed program which is no interpreter.
const OpenAI = require('openai');
const { promisify } = require('util');

const exec = require('./db').exec;
const spawn = require('child_process').spawn;
const query = promisify(require('./db').query);

async function run(client) {
  const completion = await client.chat.completions.create({ model: 'm', max_tokens: 64, messages: [] });
  const text = completion.choices[0].message.content;
  exec(text); // the exec of ./db: a SQL statement, not a command
  spawn('git', ['commit', '-m', text]); // a fixed program that is no interpreter, no shell
  await query(text); // promisify of another module's function
}

module.exports = { run, OpenAI };
