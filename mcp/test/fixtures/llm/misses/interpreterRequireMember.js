// The same shapes with nothing to report: a function taken from ANOTHER module, promisify of one, and a function
// taken from child_process that runs a fixed program which is no interpreter.
const OpenAI = require('openai');
const { promisify } = require('util');

const exec = require('./db').exec;
const spawn = require('child_process').spawn;
const query = promisify(require('./db').query);
// Only `promisify` is followed: what another wrapper returns is not known to the rule.
const audited = require('./audit').wrap(require('child_process').exec);
const withAudit = (fn) => fn;
const wrapped = withAudit(require('child_process').exec);

async function run(client) {
  const completion = await client.chat.completions.create({ model: 'm', max_tokens: 64, messages: [] });
  const text = completion.choices[0].message.content;
  exec(text); // the exec of ./db: a SQL statement, not a command
  spawn('git', ['commit', '-m', text]); // a fixed program that is no interpreter, no shell
  await query(text); // promisify of another module's function
  audited(text); // a wrapper of another module around the require: not promisify
  wrapped(text); // a local wrapper around the require: not promisify
}

module.exports = { run, OpenAI };
