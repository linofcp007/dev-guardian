/**
 * llm-output-to-interpreter-js -- nothing here may fire.
 *
 * A destructured `require` of `node:child_process`, beside the names it
 * leaves free: `execFile` is taken AS `cpExecFile`, so the `execFile` of this
 * file is another module's.
 */

const { execFile: cpExecFile, spawn } = require('node:child_process');
const { execFile, exec } = require('./other');

function constantAndFixed(completion) {
  cpExecFile('git', ['status']);
  spawn('git', ['commit', '-m', completion.choices[0].message.content ?? '']);
}

// The ORIGINAL name of a renamed property, and a child_process name that was
// never taken from it.
function otherModule(completion) {
  const t = completion.choices[0].message.content ?? '';
  execFile(t);
  exec(t);
}

module.exports = { constantAndFixed, otherModule };
