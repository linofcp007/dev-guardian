/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * A `require` of `node:child_process` assigned to a name, beside a fixed
 * program, a constant command and a `require` of another module.
 */

const cp = require('node:child_process');
const other = require('./other');

function fixedProgram(completion) {
  return cp.spawn('grep', ['-e', completion.choices[0].message.content ?? '', 'registo.txt']);
}

function constantCommand() {
  return cp.exec('uptime');
}

function otherModule(completion) {
  return other.exec(completion.choices[0].message.content ?? '');
}

module.exports = { fixedProgram, constantCommand, otherModule };
