import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/hooks/folderProbe.ts
var folderProbe_exports = {};
__export(folderProbe_exports, {
  probeFolders: () => probeFolders
});
import { spawnSync } from "node:child_process";
import { dirname } from "node:path";
var CHILD_SCRIPT = [
  "const fs = require('node:fs');",
  "process.argv.slice(1).forEach((path, index) => {",
  "  fs.promises.stat(path).then(() => fs.writeSync(1, index + ' there\\n'), () => fs.writeSync(1, index + ' absent\\n'));",
  "});"
].join("\n");
function answersOf(output, count) {
  const answers = /* @__PURE__ */ new Map();
  for (const line of output.split("\n")) {
    const space = line.indexOf(" ");
    if (space < 1) continue;
    const index = Number(line.slice(0, space));
    const word = line.slice(space + 1).trim();
    if (!Number.isInteger(index) || index < 0 || index >= count) continue;
    if (word === "there" || word === "absent") answers.set(index, word);
  }
  return answers;
}
async function probeFolders(paths, deadlineMs, child = { command: process.execPath, args: ["-e", CHILD_SCRIPT, "--"] }) {
  const result = new Map(paths.map((path) => [path, "silent"]));
  if (paths.length === 0) return result;
  let output = "";
  try {
    const run = spawnSync(child.command, [...child.args, ...paths], {
      timeout: deadlineMs,
      windowsHide: true,
      encoding: "utf8",
      cwd: dirname(process.execPath),
      stdio: ["ignore", "pipe", "ignore"]
    });
    output = typeof run.stdout === "string" ? run.stdout : "";
  } catch {
    return result;
  }
  for (const [index, answer] of answersOf(output, paths.length)) {
    const path = paths[index];
    if (path !== void 0) result.set(path, answer);
  }
  return result;
}
export {
  folderProbe_exports as folderProbe
};
