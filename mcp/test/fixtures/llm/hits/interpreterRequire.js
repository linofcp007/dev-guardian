/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * `child_process` through a `require` of `node:child_process` ASSIGNED to a
 * name, and nothing else. No Semgrep measured resolves it with the prefix.
 */

const cp = require('node:child_process');

function requireAssigned(completion) {
  cp.exec(completion.choices[0].message.content ?? ''); // BUG: require assigned, node:
}

module.exports = { requireAssigned };
