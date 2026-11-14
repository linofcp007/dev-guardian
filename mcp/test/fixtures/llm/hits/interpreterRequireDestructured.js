/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * `child_process` through a DESTRUCTURED `require` of `node:child_process`,
 * with and without a new name, and nothing else.
 */

const { execSync } = require('node:child_process');
const { spawnSync: run } = require('node:child_process');

function destructured(completion) {
  return execSync(completion.choices[0].message.content ?? ''); // BUG: require destructured, node:
}

function renamed(completion) {
  return run(completion.choices[0].message.content ?? ''); // BUG: require destructured and renamed, node:
}

module.exports = { destructured, renamed };
