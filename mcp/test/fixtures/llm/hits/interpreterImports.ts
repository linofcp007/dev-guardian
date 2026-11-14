/**
 * llm-output-to-interpreter-js -- every `// BUG` line fires the rule exactly once.
 *
 * The sinks of outputToInterpreter.ts, reached through each way a file can
 * name `child_process`. The rule may not depend on which of them the engine
 * resolves: Semgrep 1.182.0 on Linux resolves none that carries the `node:`
 * prefix, the Windows build of the same version resolves the named, aliased
 * and namespace imports, and neither resolves a default import or a `require`
 * of `node:child_process` (measured 2026-11-14).
 */

import cpDefaultNode from 'node:child_process';
import cpDefaultPlain from 'child_process';
import * as cpNamespaceNode from 'node:child_process';
import { exec as aliasedNode, execFileSync as aliasedFileNode } from 'node:child_process';
import { promisify } from 'node:util';
import util from 'node:util';
import OpenAI from 'openai';

const cpRequireNode = require('node:child_process');
const { execSync } = require('node:child_process');
const { spawnSync: renamedNode } = require('node:child_process');

// ------------------------------------------------- one sink per spelling

export function defaultImportNode(completion: OpenAI.Chat.ChatCompletion) {
  cpDefaultNode.exec(completion.choices[0].message.content ?? ''); // BUG: default import, node:
}

export function defaultImportPlain(completion: OpenAI.Chat.ChatCompletion) {
  return cpDefaultPlain.execSync(completion.choices[0].message.content ?? ''); // BUG: default import, no prefix
}

export function namespaceImportNode(completion: OpenAI.Chat.ChatCompletion) {
  return cpNamespaceNode.spawn(completion.choices[0].message.content ?? '', { shell: true }); // BUG: namespace import, node:
}

export function aliasedImportNode(completion: OpenAI.Chat.ChatCompletion) {
  aliasedNode(completion.choices[0].message.content ?? ''); // BUG: named import with an alias, node:
}

export function requireAssignedNode(completion: OpenAI.Chat.ChatCompletion) {
  cpRequireNode.exec(completion.choices[0].message.content ?? ''); // BUG: require assigned, node:
}

export function requireDestructuredNode(completion: OpenAI.Chat.ChatCompletion) {
  return execSync(completion.choices[0].message.content ?? ''); // BUG: require destructured, node:
}

export function requireRenamedNode(completion: OpenAI.Chat.ChatCompletion) {
  return renamedNode(completion.choices[0].message.content ?? ''); // BUG: require destructured and renamed, node:
}

// ------------------------------- the argv positions, through the same spellings

export function shellThroughTheDefaultImport(completion: OpenAI.Chat.ChatCompletion) {
  return cpDefaultNode.spawn('sh', ['-c', completion.choices[0].message.content ?? '']); // BUG: sh -c through the default import
}

export function bashThroughAnAlias(completion: OpenAI.Chat.ChatCompletion) {
  return aliasedFileNode('bash', ['-c', completion.choices[0].message.content ?? '']); // BUG: bash -c through an aliased import
}

// ------------------------------------------------------------- promisified

const viaPromisify = promisify(cpDefaultNode.exec);
const viaUtil = util.promisify(cpNamespaceNode.execFile);
const viaAliased = promisify(aliasedNode);

export async function promisified(completion: OpenAI.Chat.ChatCompletion) {
  const t = completion.choices[0].message.content ?? '';
  await viaPromisify(t); // BUG: promisify (node:util) of the default import's exec
  await viaUtil('bash', ['-c', t]); // BUG: util.promisify (node:util) of the namespace's execFile, of bash
  await viaAliased(t); // BUG: promisify of an aliased import
}
