import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/hooks/bashGuard.ts
var bashGuard_exports = {};
__export(bashGuard_exports, {
  BASH_RULES: () => BASH_RULES,
  assessBashCommand: () => assessBashCommand,
  commandWordIndex: () => commandWordIndex,
  splitShell: () => splitShell
});
import { homedir as homedir3 } from "node:os";

// src/hooks/dataRegistry.ts
import { homedir as homedir2 } from "node:os";

// src/hooks/configFile.ts
import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync } from "node:fs";
var MAX_HOOK_CONFIG_BYTES = 64 * 1024;
var OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);

// src/hooks/guardedPath.ts
function windowsSegment(segment, trim) {
  if (segment === "" || segment === "." || segment === "..") return segment;
  const colon = segment.indexOf(":");
  let named = colon < 0 ? segment : segment.slice(0, colon);
  if (trim) {
    const trimmed = named.replace(/[. ]+$/, "");
    if (trimmed !== "") named = trimmed;
  }
  return named === "" ? segment : named;
}
function windowsName(path) {
  if (!/[:. ]/.test(path)) return path;
  const device = /^[\\/]{2}[?.][\\/]/.test(path);
  const prefix = /^(?:[\\/]{2}[?.][\\/])?(?:[A-Za-z]:)?/.exec(path)?.[0] ?? "";
  const parts = path.slice(prefix.length).split(/([\\/]+)/);
  return prefix + parts.map((part, i) => i % 2 === 1 ? part : windowsSegment(part, !device)).join("");
}

// src/hooks/userDataDir.ts
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
function userDataDir(ctx = {}) {
  const env = ctx.env ?? process.env;
  const override = env["GUARDIAN_DATA_DIR"]?.trim();
  if (override !== void 0 && override !== "") return resolve(override);
  const home = () => ctx.home ?? homedir();
  if ((ctx.platform ?? process.platform) === "win32") {
    const local = env["LOCALAPPDATA"]?.trim();
    return join(local !== void 0 && isAbsolute(local) ? local : join(home(), "AppData", "Local"), "dev-guardian");
  }
  const xdg = env["XDG_DATA_HOME"]?.trim();
  return join(xdg !== void 0 && isAbsolute(xdg) ? xdg : join(home(), ".local", "share"), "dev-guardian");
}

// src/hooks/dataRegistry.ts
function safeHome() {
  try {
    return homedir2();
  } catch {
    return "";
  }
}
function userDataDir2(ctx = {}) {
  return userDataDir({ ...ctx, home: ctx.home ?? safeHome() });
}

// src/hooks/powershellText.ts
var UNICODE_SPACE = /[\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\f\v]/;
var SINGLE_QUOTES = "'\u2018\u2019\u201A\u201B";
var DOUBLE_QUOTES = '"\u201C\u201D\u201E';
var TOKEN_BOUNDARY = /[\s;|&(){},]/;
var HERE_STRING_BOUNDARY = /[\s;|&(){},=]/;
function posixSingle(text) {
  return `'${text.replace(/'/g, "'\\''")}'`;
}
function hereStrings() {
  return { single: Number.POSITIVE_INFINITY, double: Number.POSITIVE_INFINITY };
}
function hereString(text, at, seen) {
  const quote = text.charAt(at + 1);
  const single = SINGLE_QUOTES.includes(quote);
  if (text.charAt(at) !== "@" || quote === "" || !single && !DOUBLE_QUOTES.includes(quote)) return null;
  const eol = /^[ \t]*\r?\n/.exec(text.slice(at + 2, at + 2 + 256));
  if (eol === null) return null;
  const start = at + 2 + eol[0].length;
  const kind = single ? "single" : "double";
  if (start >= seen[kind]) return null;
  const closers = single ? SINGLE_QUOTES : DOUBLE_QUOTES;
  for (let line = start; line < text.length; ) {
    if (closers.includes(text.charAt(line)) && text.charAt(line + 1) === "@") {
      return { body: text.slice(start, line).replace(/\r?\n$/, ""), next: line + 2 };
    }
    const nl = text.indexOf("\n", line);
    if (nl < 0) break;
    line = nl + 1;
  }
  seen[kind] = start;
  return null;
}
function atBoundary(text, i, boundary = TOKEN_BOUNDARY) {
  return i === 0 || boundary.test(text.charAt(i - 1));
}
function blockCommentEnd(text, i) {
  const end = text.indexOf("#>", i + 2);
  return end < 0 ? text.length : end + 2;
}
function powershellOpaque(text) {
  if (!text.includes("@") && !text.includes("<#")) return text;
  const seen = hereStrings();
  let out = "";
  let i = 0;
  while (i < text.length) {
    if (atBoundary(text, i) && text.startsWith("<#", i)) {
      i = blockCommentEnd(text, i);
      out += " ";
      continue;
    }
    if (atBoundary(text, i, HERE_STRING_BOUNDARY) && text.charAt(i) === "@") {
      const here = hereString(text, i, seen);
      if (here !== null) {
        out += posixSingle(here.body);
        i = here.next;
        continue;
      }
    }
    out += text.charAt(i);
    i += 1;
  }
  return out;
}
function powershellAsPosix(text) {
  const seen = hereStrings();
  const braces = [];
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text.charAt(i);
    const boundary = atBoundary(text, i);
    if (boundary && text.startsWith("<#", i)) {
      i = blockCommentEnd(text, i);
      out += " ";
      continue;
    }
    if (boundary && ch === "#") {
      while (i < text.length && text.charAt(i) !== "\n" && text.charAt(i) !== "\r") i += 1;
      continue;
    }
    if (boundary && text.startsWith("--%", i) && /^(?:\s|$)/.test(text.charAt(i + 3))) {
      let end = i + 3;
      while (end < text.length && !"\n\r|".includes(text.charAt(end))) end += 1;
      const words = text.slice(i + 3, end).split(/[ \t]+/).filter((w) => w !== "");
      out += words.map(posixSingle).join(" ");
      i = end;
      continue;
    }
    if (ch === "@" && atBoundary(text, i, HERE_STRING_BOUNDARY)) {
      const here = hereString(text, i, seen);
      if (here !== null) {
        out += posixSingle(here.body);
        i = here.next;
        continue;
      }
    }
    if (SINGLE_QUOTES.includes(ch) || DOUBLE_QUOTES.includes(ch)) {
      const quotes = SINGLE_QUOTES.includes(ch) ? SINGLE_QUOTES : DOUBLE_QUOTES;
      const double = quotes === DOUBLE_QUOTES;
      let lit = "";
      let j = i + 1;
      while (j < text.length) {
        const c = text.charAt(j);
        if (double && c === "`" && j + 1 < text.length) {
          lit += text.charAt(j + 1);
          j += 2;
          continue;
        }
        if (quotes.includes(c)) {
          if (quotes.includes(text.charAt(j + 1)) && text.charAt(j + 1) !== "") {
            lit += c;
            j += 2;
            continue;
          }
          break;
        }
        lit += c;
        j += 1;
      }
      out += posixSingle(lit);
      i = j + 1;
      continue;
    }
    if (ch === "`") {
      const next = text.charAt(i + 1);
      if (next === "\n") i += 2;
      else if (next === "\r" && text.charAt(i + 2) === "\n") i += 3;
      else {
        if (next !== "") out += /[A-Za-z0-9_]/.test(next) ? next : posixSingle(next);
        i += 2;
        continue;
      }
      out += " ";
      continue;
    }
    if (ch === "{") {
      const literal = /[$@]/.test(text.charAt(i - 1));
      braces.push(literal);
      out += literal ? "{" : " ; ";
      i += 1;
      continue;
    }
    if (ch === "}") {
      out += braces.pop() === true ? "}" : " ; ";
      i += 1;
      continue;
    }
    if (ch === "\\") out += "\\\\";
    else if (ch === "," || UNICODE_SPACE.test(ch)) out += " ";
    else out += ch;
    i += 1;
  }
  return out;
}

// src/hooks/shell/arrays.ts
function pushAll(into, from) {
  for (const x of from) into.push(x);
}

// src/hooks/shell/command.ts
function basename(value) {
  const parts = value.split(/[\\/]/);
  const last = parts[parts.length - 1];
  return last === void 0 || last.length === 0 ? value : last;
}
var RUNNERS = /* @__PURE__ */ new Set([
  "sudo",
  "doas",
  "env",
  "command",
  "exec",
  "builtin",
  "nohup",
  "nice",
  "time",
  "timeout",
  "setsid",
  "stdbuf",
  "xargs",
  "watch",
  // More wrappers that run the command after their own options (review of
  // 3.6.0, finding 7): BusyBox's applet, `ionice -c3 CMD`, `unbuffer CMD`,
  // GNU `parallel CMD ::: args`.
  "busybox",
  "ionice",
  "unbuffer",
  "parallel",
  // cmd's `start [/b] ["title"] PROGRAM` (fix round 2).
  "start"
]);
var RUNNER_VALUED = {
  sudo: {
    short: "CDgpRrTtUu",
    long: /* @__PURE__ */ new Set(["user", "group", "host", "prompt", "close-from", "chdir", "chroot", "role", "type", "other-user", "command-timeout"])
  },
  doas: { short: "uC", long: /* @__PURE__ */ new Set() },
  env: { short: "uCSa", long: /* @__PURE__ */ new Set(["unset", "chdir", "split-string", "argv0"]) },
  exec: { short: "a", long: /* @__PURE__ */ new Set() },
  nice: { short: "n", long: /* @__PURE__ */ new Set(["adjustment"]) },
  time: { short: "fo", long: /* @__PURE__ */ new Set(["format", "output"]) },
  timeout: { short: "sk", long: /* @__PURE__ */ new Set(["signal", "kill-after"]) },
  stdbuf: { short: "ioe", long: /* @__PURE__ */ new Set(["input", "output", "error"]) },
  xargs: {
    // `J` is BSD's `-J replstr`.
    short: "adEIJLnPs",
    long: /* @__PURE__ */ new Set(["arg-file", "delimiter", "max-args", "max-procs", "max-chars", "process-slot-var"])
  },
  watch: { short: "nq", long: /* @__PURE__ */ new Set(["interval", "equexit"]) },
  // `ionice -c class -n num -p pid CMD` (review of 3.6.0, finding 7).
  ionice: { short: "cnp", long: /* @__PURE__ */ new Set(["class", "classdata", "pid"]) },
  // GNU `parallel`'s commonest valued options; its command template follows them.
  parallel: { short: "jPNnLSX", long: /* @__PURE__ */ new Set(["jobs", "max-args", "max-replace-args", "max-lines", "sshlogin", "results", "colsep", "retries"]) }
};
function runnerOptionWords(runner, option) {
  const valued = RUNNER_VALUED[runner];
  if (valued === void 0) return 1;
  if (option.startsWith("--")) {
    return !option.includes("=") && valued.long.has(option.slice(2)) ? 2 : 1;
  }
  for (let k = 1; k < option.length; k += 1) {
    if (valued.short.includes(option.charAt(k))) return k === option.length - 1 ? 2 : 1;
  }
  return 1;
}
var ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
function resolveCommand(words, through) {
  let i = 0;
  let elevated = false;
  while (i < words.length) {
    const word = words[i];
    if (word === void 0) break;
    if (ASSIGNMENT.test(word.value)) {
      i += 1;
      continue;
    }
    const redirect = parseRedirect(word);
    if (redirect !== null && /^(?:\d*|&|\{[A-Za-z_]\w*\})$/.test(redirect.prefix)) {
      i += redirect.inline === "" ? 2 : 1;
      continue;
    }
    const name = basename(word.value);
    if (!RUNNERS.has(name) || through !== void 0 && !through.has(name)) break;
    if (name === "sudo" || name === "doas") elevated = true;
    i += 1;
    if (name === "start") {
      let titled = false;
      while (i < words.length) {
        const arg = words[i];
        if (arg === void 0) break;
        if (!titled && arg.quoted) {
          titled = true;
          i += 1;
        } else if (/^\/[A-Za-z]+$/.test(cmdSwitch(arg.value))) i += /^\/d$/i.test(cmdSwitch(arg.value)) ? 2 : 1;
        else break;
      }
      continue;
    }
    while (i < words.length) {
      const arg = words[i];
      if (arg === void 0) break;
      if (ASSIGNMENT.test(arg.value)) {
        i += 1;
        continue;
      }
      if (arg.value === "--") {
        i += 1;
        break;
      }
      if (arg.value.startsWith("-") && arg.value.length > 1) {
        i += runnerOptionWords(name, arg.value);
        continue;
      }
      if (name === "env" && arg.value === "-") {
        i += 1;
        continue;
      }
      if ((name === "timeout" || name === "watch") && /^\d+(?:\.\d+)?[smhd]?$/.test(arg.value)) {
        i += 1;
        continue;
      }
      break;
    }
  }
  return { index: i, elevated };
}
function commandWordIndex(words) {
  return resolveCommand(words).index;
}
function cmdSwitch(word) {
  return /^\/\/[A-Za-z?]/.test(word) ? word.slice(1) : word;
}
function cmdSwitches(word) {
  const w = cmdSwitch(word);
  if (!/^(?:\/[A-Za-z?](?::[^/\s]*)?)+$/.test(w)) return void 0;
  return w.split("/").filter((s) => s !== "").map((s) => s.toLowerCase());
}
function parseRedirect(word) {
  const at = word.redirectAt?.[0];
  if (at === void 0) return null;
  const tail2 = word.value.slice(at);
  const op = /^[<>]+[|&]?/.exec(tail2)?.[0] ?? tail2.charAt(0);
  return { prefix: word.value.slice(0, at), op, inline: tail2.slice(op.length) };
}
function psParam(args, names) {
  for (let i = 0; i < args.length; i += 1) {
    const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(args[i] ?? "");
    if (m === null || !names.includes((m[1] ?? "").toLowerCase())) continue;
    return m[2] !== void 0 ? m[2] : args[i + 1];
  }
  return void 0;
}
function commandName(word) {
  return basename(word).toLowerCase().replace(/\.exe$/, "");
}

// src/hooks/shell/cmd.ts
function splitCmdLine(line) {
  const commands = [];
  let words = [];
  let redirects = [];
  let cur = "";
  let inQuote = false;
  let has = false;
  let role = "arg";
  const endWord = () => {
    if (has) {
      if (role === "write") redirects.push(cur);
      else if (role === "arg") words.push(cur);
      role = "arg";
    }
    cur = "";
    has = false;
  };
  const endCommand = () => {
    endWord();
    role = "arg";
    if (words.length > 0 || redirects.length > 0) commands.push({ words, redirects });
    words = [];
    redirects = [];
  };
  for (let i = 0; i < line.length; i += 1) {
    const ch = line.charAt(i);
    if (ch === '"') {
      inQuote = !inQuote;
      has = true;
    } else if (!inQuote && ch === "^" && i + 1 < line.length) {
      i += 1;
      cur += line.charAt(i);
      has = true;
    } else if (!inQuote && (ch === "&" || ch === "|")) {
      endCommand();
      if (line.charAt(i + 1) === ch) i += 1;
    } else if (!inQuote && (ch === ">" || ch === "<")) {
      if (has && /^\d$/.test(cur)) {
        cur = "";
        has = false;
      } else endWord();
      if (ch === ">" && line.charAt(i + 1) === ">") i += 1;
      if (line.charAt(i + 1) === "&") {
        i += 1;
        while (/\d/.test(line.charAt(i + 1))) i += 1;
        continue;
      }
      role = ch === ">" ? "write" : "read";
    } else if (!inQuote && /\s/.test(ch)) {
      if (has) endWord();
    } else {
      cur += ch;
      has = true;
    }
  }
  endCommand();
  return commands;
}
function cmdCommandWords(words) {
  const out = [...words];
  const first = out[0];
  if (first !== void 0 && first.startsWith("@")) {
    if (first.length > 1) out[0] = first.slice(1);
    else out.shift();
  }
  while (out.length > 0 && (out[0] ?? "").toLowerCase() === "call") out.shift();
  return out;
}
var MAX_CMD_NESTING = 8;
function posixWord(word) {
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(word) ? word : `'${word.replace(/'/g, "'\\''")}'`;
}
function cmdLineText(rawArgs) {
  const args = rawArgs.map(cmdSwitch);
  const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
  if (at < 0) return void 0;
  const [first, ...more] = args.slice(at + 1);
  if (first === void 0) return void 0;
  const head = /[\s&|^<>]/.test(first.trim()) ? cmdTextAsPosix(first) : posixWord(first);
  return [head, ...more.map(posixWord)].join(" ");
}
function cmdTextAsPosix(line) {
  let out = "";
  let inQuote = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line.charAt(i);
    if (ch === '"') inQuote = !inQuote;
    if (ch === "\\") out += "\\\\";
    else if (ch === "^" && !inQuote && i + 1 < line.length) {
      i += 1;
      out += `\\${line.charAt(i)}`;
    } else out += ch;
  }
  return out;
}
function cmdLine(rawArgs) {
  const args = rawArgs.map(cmdSwitch);
  const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
  if (at < 0) return [];
  const first = args[at + 1];
  if (first === void 0) return [];
  const head = first.trim();
  const commands = /[\s&|^<>]/.test(head) ? splitCmdLine(head) : [{ words: [head], redirects: [] }];
  const last = commands[commands.length - 1];
  if (last !== void 0) pushAll(last.words, args.slice(at + 2));
  return commands;
}
function cmdInnerCommands(args, depth = 0) {
  if (depth > MAX_CMD_NESTING) return [];
  const out = [];
  for (const command of cmdLine(args)) {
    const words = cmdCommandWords(command.words);
    const name = (words[0] ?? "").toLowerCase().replace(/\.exe$/, "");
    if (name === "cmd") pushAll(out, cmdInnerCommands(words.slice(1), depth + 1));
    else out.push(words.map((value) => ({ value, quoted: false })));
  }
  return out;
}

// src/hooks/shell/paths.ts
function normalizedPath(path) {
  return path.replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/\/+$/, "").toLowerCase();
}
function isAbsolutePath(path) {
  return /^(?:[\\/~$%]|[A-Za-z]:)/.test(path);
}
function resolveFrom(cwd, target) {
  const joined = cwd === "" || isAbsolutePath(target) ? target : `${cwd.replace(/[\\/]+$/, "")}/${target}`;
  const parts = joined.replace(/\\/g, "/").split("/");
  const out = [];
  parts.forEach((part, i) => {
    if (part === "." || part === "" && i > 0 && i < parts.length - 1) return;
    const prev = out[out.length - 1];
    if (part === ".." && prev !== void 0 && prev !== ".." && prev !== "") {
      out.pop();
      return;
    }
    out.push(part);
  });
  return out.join("/");
}
function dirOf(path) {
  const cut = path.lastIndexOf("/");
  return cut < 0 ? "" : path.slice(0, cut);
}
var MAX_CWD = 320;
var CD_COMMANDS = /* @__PURE__ */ new Set(["cd", "chdir", "pushd", "set-location", "sl", "push-location"]);
var CD_RETURNS = /* @__PURE__ */ new Set(["popd", "pop-location"]);
function cdOperand(args) {
  const named = psParam(args, ["path", "literalpath"]);
  if (named !== void 0) return named;
  const operands2 = [];
  let ended = false;
  for (const a of args) {
    if (!ended && a === "--") ended = true;
    else if (!ended && a !== "-" && (/^-[LPe@]+$/.test(a) || /^\/d$/i.test(a))) continue;
    else operands2.push(a);
  }
  return operands2.length > 1 ? null : operands2[0];
}
function cwdAfter(name, args, cwd, dataDir) {
  if (CD_RETURNS.has(name)) return "";
  if (!CD_COMMANDS.has(name)) return void 0;
  const dir = cdOperand(args);
  if (dir === null) return "";
  if (dir === void 0) return "~";
  if (dir === "-") return "";
  const next = resolveFrom(cwd, dir);
  if (next.length > MAX_CWD) return "";
  const tracked = /\.guardian|dev-guardian|\.config|\.claude|registry|guardian_data_dir|localappdata|xdg_data_home|\.local/i.test(next) || dataDir !== void 0 && normalizedPath(next).startsWith(dataDir);
  return tracked ? next : "";
}
function wildcardMatch(pattern, name) {
  const pat = pattern.replace(/\[[^\]]*\]/g, "?");
  let pi = 0;
  let ni = 0;
  let star = -1;
  let mark = 0;
  while (ni < name.length) {
    const c = pat.charAt(pi);
    if (pi < pat.length && (c === "?" || c === name.charAt(ni))) {
      pi += 1;
      ni += 1;
    } else if (pi < pat.length && c === "*") {
      star = pi;
      mark = ni;
      pi += 1;
    } else if (star >= 0) {
      pi = star + 1;
      mark += 1;
      ni = mark;
    } else return false;
  }
  while (pat.charAt(pi) === "*") pi += 1;
  return pi === pat.length;
}

// src/hooks/shell/effects.ts
function noEffects() {
  return { writes: [], removes: [], dirs: [], special: [], links: [], hardLinkSources: [], trees: [], aliases: [] };
}
function mergeEffects(into, from) {
  pushAll(into.writes, from.writes);
  pushAll(into.removes, from.removes);
  pushAll(into.dirs, from.dirs);
  pushAll(into.special, from.special);
  pushAll(into.links, from.links);
  pushAll(into.hardLinkSources, from.hardLinkSources);
  pushAll(into.trees, from.trees);
  pushAll(into.aliases, from.aliases);
}
function lastSegment(path) {
  return path.split(/[\\/]/).filter((s) => s.length > 0).pop() ?? path;
}
function operands(args, valued) {
  const out = [];
  let optionsDone = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (!optionsDone && a === "--") {
      optionsDone = true;
      continue;
    }
    if (!optionsDone && a.startsWith("-") && a.length > 1) {
      if (valued.has(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}
function lnOperands(args) {
  let dir;
  let hasDir = false;
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    const long = /^--target-directory=(.*)$/.exec(a);
    if (long !== null) {
      hasDir = true;
      if (long[1] !== "") dir = long[1];
    } else if (a === "--target-directory" || /^-[a-zA-Z]*t$/.test(a)) {
      hasDir = true;
      dir = args[++i];
    } else if (/^-t./.test(a)) {
      hasDir = true;
      dir = a.slice(2);
    } else if (a === "-S" || a === "--suffix") i++;
    else rest.push(a);
  }
  return { names: operands(rest, /* @__PURE__ */ new Set()), dir, hasDir };
}
function lnDestinations(args) {
  const { names: targets, dir } = lnOperands(args);
  if (dir !== void 0) return targets.map((t) => `${dir}/${lastSegment(t)}`);
  if (targets.length >= 2) return [targets[targets.length - 1] ?? ""];
  return targets.length === 1 ? [lastSegment(targets[0] ?? "")] : [];
}
function lnSymbolic(args) {
  return args.some((a) => a === "--symbolic" || /^-[a-zA-Z]*s[a-zA-Z]*$/.test(a));
}
function lnHardSources(args) {
  if (lnSymbolic(args)) return [];
  const { names, hasDir } = lnOperands(args);
  return hasDir || names.length < 2 ? names : names.slice(0, -1);
}
function lnAliases(args) {
  if (!lnSymbolic(args)) return [];
  const { names, dir } = lnOperands(args);
  if (dir !== void 0) return names.map((t) => [`${dir}/${lastSegment(t)}`, t]);
  if (names.length === 1) return [[lastSegment(names[0] ?? ""), names[0] ?? ""]];
  const link = names[names.length - 1] ?? "";
  const sources = names.slice(0, -1);
  return sources.flatMap(
    (t) => sources.length === 1 ? [[link, t], [`${link}/${lastSegment(t)}`, t]] : [[`${link}/${lastSegment(t)}`, t]]
  );
}
function fromLink(link, target) {
  return resolveFrom(dirOf(link.replace(/\\/g, "/")), target);
}
var NEW_ITEM_VALUED = [
  ["type", ["itemtype", "type"]],
  ["path", ["path", "literalpath", "pspath", "lp"]],
  ["name", ["name"]],
  ["target", ["value", "target"]],
  ["credential", ["credential"]]
];
function newItemParam(spelled) {
  const exact = NEW_ITEM_VALUED.find(([, names]) => names.includes(spelled));
  if (exact !== void 0) return exact[0];
  const matches = NEW_ITEM_VALUED.filter(([, names]) => names.some((n) => n.startsWith(spelled)));
  return matches.length === 1 ? matches[0]?.[0] : void 0;
}
function itemTypeOf(value) {
  if (value === "") return "file";
  const pattern = `${value.toLowerCase()}*`;
  if (wildcardMatch(pattern, "directory") || wildcardMatch(pattern, "container")) return "directory";
  return ["file", "symboliclink", "junction", "hardlink"].find((t) => wildcardMatch(pattern, t)) ?? "unknown";
}
function newItemArgs(args) {
  let spelledType = "";
  let target;
  const paths = [];
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    const param = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    if (param === null) {
      positional.push(a);
      continue;
    }
    const name = newItemParam((param[1] ?? "").toLowerCase());
    const inline = param[2];
    const value = inline !== void 0 ? inline : name !== void 0 ? args[++i] ?? "" : void 0;
    if (value === void 0) continue;
    if (name === "type") spelledType = value;
    else if (name === "path" || name === "name") paths.push(value);
    else if (name === "target") target = value;
  }
  if (paths.length === 0 && positional.length > 0) paths.push(positional[0] ?? "");
  const itemType = itemTypeOf(spelledType);
  return target === void 0 ? { itemType, paths } : { itemType, paths, target };
}
function mklinkDestinations(args) {
  const link = args.find((a) => !a.startsWith("/"));
  return link === void 0 ? [] : [link];
}
function cmdEffects(args, cwd, depth = 0) {
  const e = noEffects();
  if (depth > MAX_CMD_NESTING) return e;
  const commands = cmdLine(args);
  let dir = cwd;
  for (const command of commands) {
    const [raw, ...rest] = cmdCommandWords(command.words);
    const name = (raw ?? "").toLowerCase().replace(/\.exe$/, "");
    pushAll(e.writes, command.redirects.map((r) => resolveFrom(dir, r)));
    mergeEffects(e, effectsOf(name, rest, dir, depth + 1));
    dir = cwdAfter(name, rest, dir) ?? dir;
  }
  return e;
}
function redirectTargets(words) {
  const out = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    const r = word === void 0 ? null : parseRedirect(word);
    if (r === null || !r.op.startsWith(">")) continue;
    const next = words[i + 1]?.value;
    if (r.op.endsWith("&")) {
      const fd = r.inline !== "" ? r.inline : next ?? "";
      if (/^\d*-?$/.test(fd)) continue;
    }
    const target = r.inline !== "" ? r.inline : next;
    if (target !== void 0) out.push(target);
  }
  return out;
}
function withoutRedirections(words) {
  const out = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === void 0) continue;
    const r = parseRedirect(word);
    if (r === null) {
      out.push(word.value);
      continue;
    }
    if (!/^(?:\d*|&)$/.test(r.prefix)) out.push(r.prefix);
    if (r.inline === "") i += 1;
  }
  return out;
}
function intoDir(dir, src) {
  return `${dir.replace(/[\\/]+$/, "")}/${lastSegment(src)}`;
}
function optionValues(args, short, long) {
  const out = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (a === short || a === long) {
      const v = args[i + 1];
      if (v !== void 0) out.push(v);
    } else if (a.startsWith(`${long}=`)) out.push(a.slice(long.length + 1));
    else if (a.startsWith(short) && a.length > short.length && !a.startsWith("--")) out.push(a.slice(short.length));
  }
  return out;
}
var COPY_VALUED = /* @__PURE__ */ new Set(["-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group"]);
var PS_PATH_PARAMS = ["path", "literalpath", "destination"];
var PS_VALUE_PARAMS = ["filter", "include", "exclude", "credential", "fromsession", "tosession"];
var PS_SWITCHES = ["recurse", "force", "container", "passthru", "whatif", "confirm"];
function psName(spelled) {
  const lower = spelled.toLowerCase();
  const all = [...PS_PATH_PARAMS, ...PS_VALUE_PARAMS, ...PS_SWITCHES];
  if (all.includes(lower)) return lower;
  return lower.length >= 3 ? all.find((n) => n.startsWith(lower)) : void 0;
}
function parseTransfer(args, slashSwitches) {
  const named = [];
  const positional = [];
  let dest;
  let into = false;
  let recursive = false;
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (slashSwitches && /^\/[A-Za-z]/.test(a)) continue;
    if (optionsDone || a === "-" || !a.startsWith("-")) {
      positional.push(a);
      continue;
    }
    if (a === "--") {
      optionsDone = true;
      continue;
    }
    const target = /^--target-directory(?:=(.*))?$/.exec(a);
    if (target !== null) {
      dest = target[1] ?? args[++i];
      into = true;
      continue;
    }
    if (a === "--recursive" || a === "--archive") {
      recursive = true;
      continue;
    }
    const ps = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    const param = ps === null ? void 0 : psName(ps[1] ?? "");
    if (ps !== null && param !== void 0) {
      const value = PS_PATH_PARAMS.includes(param) || PS_VALUE_PARAMS.includes(param) ? ps[2] ?? args[++i] : void 0;
      if (param === "recurse") recursive = true;
      else if (param === "destination") dest = value;
      else if ((param === "path" || param === "literalpath") && value !== void 0) named.push(value);
      continue;
    }
    if (COPY_VALUED.has(a)) {
      i += 1;
      continue;
    }
    if (/^-[a-zA-Z]*t$/.test(a)) {
      dest = args[++i];
      into = true;
    } else if (/^-t./.test(a)) {
      dest = a.slice(2);
      into = true;
    }
    if (!a.startsWith("--") && /[rRa]/.test(a.slice(1))) recursive = true;
  }
  const sources = [...named, ...positional];
  if (dest === void 0 && sources.length >= 2) dest = sources.pop();
  return dest === void 0 ? { sources, into, recursive } : { sources, dest, into, recursive };
}
var RSYNC_VALUED = /* @__PURE__ */ new Set([
  "-e",
  "--rsh",
  "-f",
  "--filter",
  "--exclude",
  "--include",
  "--exclude-from",
  "--include-from",
  "--files-from",
  "-T",
  "--temp-dir",
  "-B",
  "--block-size",
  "--chmod",
  "--chown",
  "--log-file",
  "--password-file",
  "--partial-dir",
  "--backup-dir",
  "--suffix",
  "--compare-dest",
  "--copy-dest",
  "--link-dest",
  "--rsync-path",
  "-M",
  "--remote-option",
  "--port",
  "--timeout",
  "--contimeout",
  "--bwlimit",
  "--max-size",
  "--min-size",
  "--out-format",
  "--info",
  "--debug",
  "--iconv",
  "--usermap",
  "--groupmap",
  "--address",
  "--sockopts",
  "--max-delete"
]);
function perlLike(args, codeLetters, valueLetters) {
  const code = [];
  const operandsSeen = [];
  let inPlace = false;
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (!optionsDone && a === "--") {
      optionsDone = true;
      continue;
    }
    if (optionsDone || !a.startsWith("-") || a.length === 1 || a.startsWith("--")) {
      if (optionsDone || !a.startsWith("--")) operandsSeen.push(a);
      continue;
    }
    for (let k = 1; k < a.length; k += 1) {
      const c = a.charAt(k);
      if (codeLetters.includes(c)) {
        const rest = a.slice(k + 1);
        code.push(rest !== "" ? rest : args[++i] ?? "");
        break;
      }
      if (c === "i") {
        inPlace = true;
        break;
      }
      if (valueLetters.includes(c)) {
        if (k === a.length - 1) i += 1;
        break;
      }
      if (c === "0") while (/[0-9a-fA-Fx]/.test(a.charAt(k + 1))) k += 1;
      if (c === "l") while (/[0-9]/.test(a.charAt(k + 1))) k += 1;
    }
  }
  const files = code.length > 0 ? operandsSeen : operandsSeen.slice(1);
  return { code, inPlace, files };
}
var SED_IN_PLACE = /^(?:-[a-zA-Z]*i.*|--in-place(?:=.*)?)$/;
var EDITOR_VALUED_LETTERS = "cSuUiTwWtq";
function editorFiles(args) {
  const out = [];
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (!optionsDone && a === "--") {
      optionsDone = true;
      continue;
    }
    if (!optionsDone && a === "--cmd") {
      i += 1;
      continue;
    }
    if (!optionsDone && /^-[A-Za-z]+$/.test(a)) {
      if (EDITOR_VALUED_LETTERS.includes(a.charAt(a.length - 1))) i += 1;
      continue;
    }
    if (!optionsDone && (a.startsWith("-") || a.startsWith("+"))) continue;
    out.push(a);
  }
  return out;
}
function commandWriteDestinations(name, args) {
  switch (name) {
    case "tee":
    case "sponge":
      return operands(args, /* @__PURE__ */ new Set());
    case "sed":
      return args.some((a) => SED_IN_PLACE.test(a)) ? operands(args, /* @__PURE__ */ new Set(["-e", "-f", "--expression", "--file", "-l", "--line-length"])) : [];
    case "dd":
      return args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3));
    case "curl":
      return optionValues(args, "-o", "--output");
    case "wget":
      return optionValues(args, "-O", "--output-document");
    case "sort":
      return optionValues(args, "-o", "--output");
    case "truncate":
      return operands(args, /* @__PURE__ */ new Set(["-s", "--size", "-r", "--reference"]));
    case "shred":
      return operands(args, /* @__PURE__ */ new Set(["-n", "--iterations", "-s", "--size", "--random-source"]));
    case "perl": {
      const p = perlLike(args, "eE", "IMm");
      return p.inPlace ? p.files : [];
    }
    case "ruby": {
      const p = perlLike(args, "e", "IrCEFx");
      return p.inPlace ? p.files : [];
    }
    // In-place editors, scripted (review 8, item 15): `ed f`, `ex -sc '…|x' f`,
    // `vim -es -c '…' -c wq f` write the files they open.
    case "ed":
    case "red":
      return operands(args, /* @__PURE__ */ new Set(["-p", "--prompt"]));
    case "ex":
    case "vi":
    case "vim":
    case "nvim":
    case "gvim":
      return editorFiles(args);
    // `sc` is Windows PowerShell 5.1's alias of Set-Content (review 8, item 15).
    case "sc":
    case "set-content":
    case "add-content":
    case "ac":
    case "clear-content":
    case "clc":
    case "out-file":
    case "tee-object":
      return args.map((a) => a.replace(/^-[A-Za-z]+:/, ""));
    default:
      return [];
  }
}
var REMOVERS = /* @__PURE__ */ new Set(["rm", "unlink", "ri", "remove-item", "del", "erase", "rd", "rmdir"]);
var CMD_SWITCHED = /* @__PURE__ */ new Set(["copy", "move", "xcopy", "robocopy", "mklink", "del", "erase", "rd", "rmdir", "ren", "rename"]);
function effectsOf(name, rawArgs, cwd, depth = 0) {
  if (name === "cmd") return cmdEffects(rawArgs, cwd, depth);
  const args = CMD_SWITCHED.has(name) ? rawArgs.map(cmdSwitch) : rawArgs;
  const at = (p) => resolveFrom(cwd, p);
  const e = noEffects();
  switch (name) {
    case "mkfifo":
      pushAll(e.special, operands(args, /* @__PURE__ */ new Set(["-m", "--mode"])).map(at));
      return e;
    case "mknod":
      pushAll(e.special, operands(args, /* @__PURE__ */ new Set(["-m", "--mode"])).slice(0, 1).map(at));
      return e;
    case "ln":
      pushAll(e.links, lnDestinations(args).map(at));
      pushAll(e.hardLinkSources, lnHardSources(args).map(at));
      for (const [link, target] of lnAliases(args)) e.aliases.push([at(link), at(fromLink(link, target))]);
      return e;
    case "link":
      pushAll(e.hardLinkSources, operands(args, /* @__PURE__ */ new Set()).slice(0, 1).map(at));
      return e;
    case "fsutil":
      if (/^hardlink$/i.test(args[0] ?? "") && /^create$/i.test(args[1] ?? "")) {
        if (args[2] !== void 0) e.links.push(at(args[2]));
        if (args[3] !== void 0) e.hardLinkSources.push(at(args[3]));
      }
      return e;
    case "mklink": {
      pushAll(e.links, mklinkDestinations(args).map(at));
      const names = args.filter((a) => !a.startsWith("/"));
      const [link, target] = names;
      if (args.some((a) => /^\/h$/i.test(a))) {
        if (target !== void 0) e.hardLinkSources.push(at(target));
      } else if (link !== void 0 && target !== void 0) {
        e.aliases.push([at(link), at(args.some((a) => /^\/j$/i.test(a)) ? target : fromLink(link, target))]);
      }
      return e;
    }
    case "new-item":
    case "ni": {
      const item = newItemArgs(args);
      if (["symboliclink", "hardlink", "junction"].includes(item.itemType)) pushAll(e.links, item.paths.map(at));
      if (item.itemType === "hardlink" && item.target !== void 0) e.hardLinkSources.push(at(item.target));
      else if (item.itemType === "file") pushAll(e.writes, item.paths.map(at));
      const target = item.target;
      if (target !== void 0 && (item.itemType === "symboliclink" || item.itemType === "junction")) {
        for (const p of item.paths) e.aliases.push([at(p), at(item.itemType === "junction" ? target : fromLink(p, target))]);
      }
      return e;
    }
    case "cp":
    case "install":
    case "copy-item":
    case "cpi":
    case "copy":
    case "mv":
    case "move-item":
    case "mi":
    case "move": {
      const t = parseTransfer(args, name === "copy" || name === "move");
      const moves = name === "mv" || name === "move-item" || name === "mi" || name === "move";
      if (moves) pushAll(e.removes, t.sources.map(at));
      if (name === "cp" && args.some((a) => a === "--link" || /^-[a-zA-Z]*l[a-zA-Z]*$/.test(a))) pushAll(e.hardLinkSources, t.sources.map(at));
      if (t.dest === void 0) return e;
      const dest = t.dest;
      if (!t.into) e.writes.push(at(dest));
      pushAll(e.writes, t.sources.map((s) => at(intoDir(dest, s))));
      if (!t.into && (moves || t.recursive)) e.dirs.push(at(dest));
      return e;
    }
    case "xcopy":
    case "robocopy": {
      const [, dest, ...files] = args.filter((a) => !/^\/[A-Za-z]/.test(a));
      if (dest !== void 0) {
        e.dirs.push(at(dest));
        e.writes.push(at(dest));
        pushAll(e.writes, files.map((f) => at(intoDir(dest, f))));
        if (name === "robocopy" && args.some((a) => /^\/(?:mir|purge)$/i.test(a))) e.trees.push(at(dest));
      }
      return e;
    }
    case "rsync": {
      const paths = operands(args, RSYNC_VALUED);
      const dest = paths.pop();
      if (dest === void 0 || paths.length === 0) return e;
      e.writes.push(at(dest));
      pushAll(e.writes, paths.map((s) => at(intoDir(dest, s))));
      if (args.some((a) => a === "--recursive" || a === "--archive" || /^-[a-zA-Z]*[ra]/.test(a))) e.dirs.push(at(dest));
      if (args.some((a) => /^--del(?:ete(?:-[a-z]+)?)?$/.test(a))) e.trees.push(at(dest));
      return e;
    }
    case "ren":
    case "rename":
    case "rename-item":
    case "rni": {
      const positional = args.filter((a) => !a.startsWith("-") && !/^\/[A-Za-z]$/.test(a));
      const src = psParam(args, ["path", "literalpath"]) ?? positional.shift();
      const newName = psParam(args, ["newname"]) ?? positional.shift();
      if (src === void 0) return e;
      e.removes.push(at(src));
      if (newName !== void 0) {
        const dest = /[\\/]/.test(newName) ? newName : `${dirOf(src.replace(/\\/g, "/")) || "."}/${newName}`;
        e.writes.push(at(dest));
        e.dirs.push(at(dest));
      }
      return e;
    }
    default:
      break;
  }
  if (REMOVERS.has(name)) pushAll(e.removes, operands(args, /* @__PURE__ */ new Set()).filter((a) => !/^\/[A-Za-z]$/.test(a)).map(at));
  const written = commandWriteDestinations(name, args).map(at);
  pushAll(e.writes, written);
  if (name === "shred" && args.some((a) => a === "--remove" || a.startsWith("--remove=") || /^-[a-zA-Z]*u/.test(a))) {
    pushAll(e.removes, written);
  }
  return e;
}
function withoutRedirectWords(words) {
  const out = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === void 0) continue;
    const r = parseRedirect(word);
    if (r === null) out.push(word);
    else if (r.inline === "") i += 1;
  }
  return out;
}

// src/hooks/shell/interpreters.ts
var PYTHON = /^(?:python[0-9.]*|py|pypy[0-9.]*)$/;
var INTERPRETERS = /* @__PURE__ */ new Set(["node", "nodejs", "bun", "deno", "tsx", "ts-node", "perl", "ruby", "php", "pwsh", "powershell"]);
var RUN_WRAPPERS = /* @__PURE__ */ new Set(["uv", "poetry", "pipenv", "pdm", "rye", "hatch", "conda", "mamba", "micromamba", "pixi"]);
function isInterpreter(name) {
  return PYTHON.test(name) || INTERPRETERS.has(name);
}
var LAUNCHERS = /* @__PURE__ */ new Set(["npx", "bunx", "pnpx", "start"]);
var LAUNCHER_SUBCOMMANDS = {
  npm: /* @__PURE__ */ new Set(["exec", "x"]),
  pnpm: /* @__PURE__ */ new Set(["dlx", "exec"]),
  yarn: /* @__PURE__ */ new Set(["dlx", "exec"]),
  bun: /* @__PURE__ */ new Set(["x"])
};
var LAUNCHER_VALUED = /* @__PURE__ */ new Set(["-p", "--package", "-c", "--call", "/d"]);
function firstNonFlag(words, from) {
  let k = from;
  while (k < words.length && (words[k]?.value ?? "").startsWith("-")) k += 1;
  return k;
}
function interpreterName(word) {
  return commandName(word).replace(/@[\w.^~<>=-]*$/, "");
}
function interpreterIndex(words, start) {
  let i = start;
  while (i < words.length) {
    const name = interpreterName(words[i]?.value ?? "");
    const sub = LAUNCHER_SUBCOMMANDS[name] === void 0 ? -1 : firstNonFlag(words, i + 1);
    const launches = sub >= 0 && LAUNCHER_SUBCOMMANDS[name]?.has(words[sub]?.value ?? "") === true;
    if (isInterpreter(name) && !launches) return i;
    if (RUN_WRAPPERS.has(name) && words[i + 1]?.value === "run") {
      for (let k = i + 2; k < Math.min(words.length, i + 10); k += 1) {
        if (isInterpreter(interpreterName(words[k]?.value ?? ""))) return k;
      }
      return -1;
    }
    if (launches) i = sub + 1;
    else if (LAUNCHERS.has(name)) i += 1;
    else return -1;
    while (i < words.length) {
      const w = words[i]?.value ?? "";
      if (w !== "" && !/^(?:-|\/[A-Za-z])/.test(w)) break;
      i += LAUNCHER_VALUED.has(w.toLowerCase()) ? 2 : 1;
    }
  }
  return -1;
}
var NODE_VALUED = /* @__PURE__ */ new Set([
  "-r",
  "--require",
  "--import",
  "--loader",
  "--experimental-loader",
  "-C",
  "--conditions",
  "--input-type",
  "--env-file",
  "--title",
  "--cwd",
  "--config",
  "--preload"
]);
function nodeCode(args) {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    const eq = /^--(?:eval|print)=([\s\S]*)$/.exec(a);
    if (eq !== null) return [eq[1] ?? ""];
    if (/^-(?:e|p|pe|ep)$/.test(a) || a === "--eval" || a === "--print") return [args[i + 1] ?? ""];
    if (NODE_VALUED.has(a)) {
      i += 1;
      continue;
    }
    if (!a.startsWith("-")) return [];
  }
  return [];
}
function pythonCode(args) {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (a === "-" || !a.startsWith("-")) return [];
    if (a.startsWith("--")) continue;
    for (let k = 1; k < a.length; k += 1) {
      const c = a.charAt(k);
      if (c === "c") {
        const rest = a.slice(k + 1);
        return [rest !== "" ? rest : args[i + 1] ?? ""];
      }
      if (c === "m") return [];
      if (c === "W" || c === "X") {
        if (k === a.length - 1) i += 1;
        break;
      }
    }
  }
  return [];
}
function phpCode(args) {
  const code = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (/^-[rBRE]$/.test(a)) {
      code.push(args[i + 1] ?? "");
      i += 1;
    } else if (/^-r./.test(a)) code.push(a.slice(2));
    else if (a === "-f" || a === "-F" || !a.startsWith("-")) return code;
    else if (/^-[dcz]$/.test(a)) i += 1;
  }
  return code;
}
function decodeUtf16Base64(text) {
  if (!/^[A-Za-z0-9+/=]+$/.test(text)) return "";
  return Buffer.from(text, "base64").toString("utf16le");
}
var PS_HOST_VALUED = /* @__PURE__ */ new Set([
  "ex",
  "ep",
  "executionpolicy",
  "w",
  "windowstyle",
  "wd",
  "workingdirectory",
  "configurationname",
  "o",
  "of",
  "outputformat",
  "if",
  "inputformat",
  "v",
  "version",
  "psconsolefile",
  "settings",
  "settingsfile",
  "custompipename",
  "configurationfile"
]);
function powershellCommand(args, name) {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    const m = /^[-/]([A-Za-z]+)$/.exec(a);
    if (m === null) return name === "powershell" ? [args.slice(i).join(" ")] : [];
    const p = (m[1] ?? "").toLowerCase();
    if (p === "c" || p.length >= 3 && "command".startsWith(p)) {
      const rest = args.slice(i + 1);
      return rest.length === 0 || rest[0] === "-" ? [] : [rest.join(" ")];
    }
    if (p === "e" || p.length >= 2 && "encodedcommand".startsWith(p)) return [decodeUtf16Base64(args[i + 1] ?? "")];
    if (p === "f" || p === "file") return [];
    if (PS_HOST_VALUED.has(p)) i += 1;
  }
  return [];
}
function powershellReadsStdin(args) {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (a === "-") return true;
    const m = /^[-/]([A-Za-z]+)$/.exec(a);
    if (m === null) return false;
    const p = (m[1] ?? "").toLowerCase();
    if (p === "c" || p.length >= 3 && "command".startsWith(p) || p === "f" || p === "file") return args[i + 1] === void 0 || args[i + 1] === "-";
    if (p === "e" || p.length >= 2 && "encodedcommand".startsWith(p)) return false;
    if (PS_HOST_VALUED.has(p)) i += 1;
  }
  return true;
}
function inlineCode(words, start) {
  const at = interpreterIndex(words, start);
  if (at < 0) return [];
  const name = interpreterName(words[at]?.value ?? "");
  const args = words.slice(at + 1).map((w) => w.value);
  if (PYTHON.test(name)) return pythonCode(args);
  switch (name) {
    case "node":
    case "nodejs":
    case "bun":
    case "tsx":
    case "ts-node":
      return nodeCode(args);
    case "deno":
      return args[0] === "eval" ? args.slice(1).filter((a) => !a.startsWith("-")).slice(0, 1) : [];
    case "perl":
      return perlLike(args, "eE", "IMm").code;
    case "ruby":
      return perlLike(args, "e", "IrCEFx").code;
    case "php":
      return phpCode(args);
    case "pwsh":
    case "powershell":
      return powershellCommand(args, name);
    default:
      return [];
  }
}
function isBareInterpreterStdin(words) {
  const program = interpreterProgram(withoutRedirectWords(words), 0);
  return program.kind === "dash" || program.kind === "none" && program.readsStdin;
}
var NODE_OPTION_VALUED = /* @__PURE__ */ new Set([
  ...NODE_VALUED,
  "--max-old-space-size",
  "--max-semi-space-size",
  "--stack-size",
  "--max-http-header-size",
  "--inspect-port",
  "--debug-port",
  "--openssl-config",
  "--icu-data-dir",
  "--redirect-warnings",
  "--report-dir",
  "--report-directory",
  "--report-filename",
  "--report-signal",
  "--diagnostic-dir",
  "--heapsnapshot-signal",
  "--heapsnapshot-near-heap-limit",
  "--dns-result-order",
  "--unhandled-rejections",
  "--disable-warning",
  "--watch-path",
  "--test-reporter",
  "--test-reporter-destination",
  "--test-name-pattern",
  "--test-concurrency",
  "--experimental-policy",
  "--policy-integrity",
  "--secure-heap",
  "--secure-heap-min",
  "--cpu-prof-dir",
  "--cpu-prof-name",
  "--cpu-prof-interval",
  "--heap-prof-dir",
  "--heap-prof-name",
  "--heap-prof-interval",
  "--trace-event-categories",
  "--trace-event-file-pattern",
  "--use-largepages",
  "--tls-cipher-list",
  "--tls-keylog",
  "--localstorage-file",
  "--env-file-if-exists",
  "--experimental-sea-config"
]);
var DENO_RUN_VALUED = /* @__PURE__ */ new Set(["-c", "--config", "--import-map", "--lock", "--cert", "--location", "--seed", "--env-file", "--ext"]);
var BUN_RUN_VALUED = /* @__PURE__ */ new Set([
  "--cwd",
  "-c",
  "--config",
  "--env-file",
  "-r",
  "--preload",
  "--tsconfig-override",
  "-d",
  "--define",
  "-l",
  "--loader",
  "--main-fields",
  "--conditions",
  "--filter",
  "-F",
  "--elide-lines",
  "--shell"
]);
function operandAt(words, i, readsStdin) {
  const w = words[i];
  if (w === void 0) return { kind: "none", readsStdin };
  return w.value === "-" ? { kind: "dash" } : { kind: "file", index: i };
}
function clusterWords(word, inline, valued) {
  for (let k = 1; k < word.length; k += 1) {
    const c = word.charAt(k);
    if (inline.includes(c)) return "inline";
    if (valued.includes(c)) return k === word.length - 1 ? 2 : 1;
  }
  return 1;
}
function interpreterProgram(words, at) {
  const name = interpreterName(words[at]?.value ?? "");
  const python = PYTHON.test(name);
  const nodeLike = ["node", "nodejs", "tsx", "ts-node"].includes(name);
  if (!python && !nodeLike && !["perl", "ruby", "php", "deno", "bun"].includes(name)) return { kind: "unknown" };
  let i = at + 1;
  if (name === "deno" || name === "bun") {
    const sub = words[i]?.value ?? "";
    if (sub === "eval" || name === "bun" && /^(?:-e|-p|--eval|--print)$/.test(sub)) return { kind: "inline" };
    if (sub === "run") i += 1;
    else if (name === "deno" || sub !== "-") return { kind: "unknown" };
  }
  const readsStdin = !["deno", "bun", "tsx", "ts-node"].includes(name);
  for (; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v === "--") return operandAt(words, i + 1, readsStdin);
    if (v === "-" || !v.startsWith("-")) return operandAt(words, i, readsStdin);
    if (python) {
      if (v.startsWith("--")) {
        if (v === "--check-hash-based-pycs") i += 1;
        continue;
      }
      const used = clusterWords(v, "cm", "WXQ");
      if (used === "inline") return { kind: "inline" };
      i += used - 1;
    } else if (nodeLike) {
      if (/^-(?:e|p|pe|ep)$/.test(v) || /^--(?:eval|print)(?:=|$)/.test(v)) return { kind: "inline" };
      if (!v.includes("=") && NODE_OPTION_VALUED.has(v)) i += 1;
    } else if (name === "deno" || name === "bun") {
      if (!v.includes("=") && (name === "deno" ? DENO_RUN_VALUED : BUN_RUN_VALUED).has(v)) i += 1;
    } else if (name === "php") {
      if (/^-[rBRE]/.test(v)) return { kind: "inline" };
      if (v === "-f" || v === "-F") return operandAt(words, i + 1, readsStdin);
      if (/^-[dcz]$/.test(v)) i += 1;
    } else {
      if (v.startsWith("--")) continue;
      const used = clusterWords(v, name === "perl" ? "eE" : "e", name === "perl" ? "IMm" : "IrCEFx");
      if (used === "inline") return { kind: "inline" };
      i += used - 1;
    }
  }
  return { kind: "none", readsStdin };
}
function codeLang(interpreter) {
  if (PYTHON.test(interpreter)) return "python";
  return ["node", "nodejs", "bun", "deno", "tsx", "ts-node"].includes(interpreter) ? "js" : "other";
}
function codeLiterals(code, lang) {
  const quotes = lang === "js" ? ['"', "'", "`"] : ['"', "'"];
  const out = [];
  let i = 0;
  while (i < code.length) {
    const ch = code.charAt(i);
    const atWordStart = i === 0 || /\s/.test(code.charAt(i - 1));
    const comment = atWordStart && (ch === "#" && lang !== "js" || lang !== "python" && code.startsWith("// ", i));
    if (comment) {
      const nl = code.indexOf("\n", i);
      i = nl < 0 ? code.length : nl + 1;
      continue;
    }
    if (!quotes.includes(ch)) {
      i += 1;
      continue;
    }
    const close = lang === "python" && code.startsWith(ch.repeat(3), i) ? ch.repeat(3) : ch;
    let lit = "";
    let j = i + close.length;
    while (j < code.length) {
      const c = code.charAt(j);
      const next = code.charAt(j + 1);
      if (c === "\\" && (next === "\\" || next === ch)) {
        lit += next;
        j += 2;
        continue;
      }
      if (code.startsWith(close, j)) break;
      lit += c;
      j += 1;
    }
    out.push(lit);
    i = j + close.length;
  }
  return out;
}
function literalPaths(literals) {
  return asWindowsOpens(literals.map((l) => tail(l.trim()).replace(/\\+/g, "/")));
}
function tail(path) {
  return path.length > 1024 ? path.slice(-1024) : path;
}
function asWindowsOpens(paths) {
  const out = [...paths];
  for (const p of paths) {
    const named = windowsName(p);
    if (named !== p) out.push(named);
  }
  return out;
}

// src/hooks/shell/split.ts
var MASK = " ";
var ANSI_C_SIMPLE = {
  a: "\x07",
  b: "\b",
  e: "\x1B",
  E: "\x1B",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "	",
  v: "\v",
  "\\": "\\",
  "'": "'",
  '"': '"',
  "?": "?"
};
function decodeAnsiC(body) {
  if (!body.includes("\\")) return body;
  return body.replace(/\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|.)/g, (all, seq) => {
    const head = seq.charAt(0);
    if (head === "x" || head === "u" || head === "U") return codePoint(parseInt(seq.slice(1), 16), all);
    if (head >= "0" && head <= "7") return codePoint(parseInt(seq, 8), all);
    return ANSI_C_SIMPLE[seq] ?? all;
  });
}
function codePoint(code, fallback) {
  return Number.isFinite(code) && code >= 0 && code <= 1114111 ? String.fromCodePoint(code) : fallback;
}
function scanQuote(source, start) {
  const quote = source.charAt(start);
  let inner = "";
  let i = start + 1;
  while (i < source.length) {
    const ch = source.charAt(i);
    if (quote === '"' && ch === "\\") {
      const next = source.charAt(i + 1);
      if (next === '"' || next === "\\" || next === "$" || next === "`") {
        inner += next;
        i += 2;
        continue;
      }
      if (next === "\n") {
        i += 2;
        continue;
      }
      inner += ch;
      i += 1;
      continue;
    }
    if (ch === quote) return { inner, next: i + 1 };
    inner += ch;
    i += 1;
  }
  return { inner, next: source.length };
}
var INTERPOLATION = /\$\{[^}\n]{0,128}\}|\$[\w:]+|\$\(|[()]/g;
function interpolatedVariables(inner) {
  if (!inner.includes("$")) return [];
  const out = [];
  let depth = 0;
  for (const m of inner.matchAll(INTERPOLATION)) {
    const t = m[0];
    if (t === "$(") depth += 1;
    else if (t === "(") depth += depth > 0 ? 1 : 0;
    else if (t === ")") depth -= depth > 0 ? 1 : 0;
    else {
      const next = inner.charAt(m.index + t.length);
      if (depth === 0 || next !== "." && next !== "[") out.push(t);
    }
  }
  return out;
}
var NAME_POSITION = /(?:(?:^|[\s;|&(])-(?:ov|outv[a-z]*|v[a-z]*|n[a-z]*)[ \t]*:?[ \t]*|(?:^|[\s;|&(])(?:set-variable|new-variable|get-variable|sv|nv|gv)[ \t]+)$/i;
var QUOTED_NAME = /^(?:(?:global|script|local|private|using|variable):)?[A-Za-z_]\w{0,63}$/i;
var TOKEN_WORD = /^(?:iex|invoke-expression|irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|set-variable|new-variable|get-variable|sv|nv|gv|tee|tee-object)$/i;
function quotedName(maskedBefore, inner) {
  if (!QUOTED_NAME.test(inner) || TOKEN_WORD.test(inner)) return void 0;
  return NAME_POSITION.test(maskedBefore.slice(-48)) ? inner : void 0;
}
function withInterpolations(masked, interpolations) {
  if (interpolations.length === 0) return masked;
  let out = "";
  let from = 0;
  for (const { at, vars } of interpolations) {
    out += `${masked.slice(from, at)}${vars} `;
    from = at;
  }
  return out + masked.slice(from);
}
var HEREDOC_WORD = /^[A-Za-z_][A-Za-z0-9_]*$/;
function readHeredocOperator(source, start) {
  let i = start + 2;
  if (source.charAt(i) === "-") i += 1;
  while (source.charAt(i) === " " || source.charAt(i) === "	") i += 1;
  const quote = source.charAt(i);
  let word = "";
  if (quote === "'" || quote === '"') {
    const scanned = scanQuote(source, i);
    word = scanned.inner;
    i = scanned.next;
  } else {
    while (i < source.length && /[A-Za-z0-9_]/.test(source.charAt(i))) {
      word += source.charAt(i);
      i += 1;
    }
  }
  if (!HEREDOC_WORD.test(word)) return null;
  return { word, next: i };
}
function attachHeredocBody(heredoc, body) {
  const target = heredoc.statement;
  if (target.heredocBodies === void 0) target.heredocBodies = [];
  target.heredocBodies.push(body);
}
function skipHeredocBodies(source, from, pending) {
  let pos = from;
  while (pending.length > 0) {
    const heredoc = pending.shift();
    if (heredoc === void 0) break;
    const lines = [];
    for (; ; ) {
      if (pos >= source.length) {
        attachHeredocBody(heredoc, lines.join("\n"));
        return source.length;
      }
      const newline = source.indexOf("\n", pos);
      const line = newline === -1 ? source.slice(pos) : source.slice(pos, newline);
      pos = newline === -1 ? source.length : newline + 1;
      if (line.trim() === heredoc.word) break;
      lines.push(line);
      if (newline === -1) {
        attachHeredocBody(heredoc, lines.join("\n"));
        return source.length;
      }
    }
    attachHeredocBody(heredoc, lines.join("\n"));
  }
  return pos;
}
var COMPOUND_RESERVED = /* @__PURE__ */ new Set(["if", "then", "elif", "else", "fi", "while", "until", "do", "done", "esac", "{", "}", "!", "coproc"]);
function splitShell(command) {
  const statements = [];
  let maskedCommand = "";
  const interpolations = [];
  let masked = "";
  let commands = [];
  let words = [];
  let buf = "";
  let bufQuoted = false;
  let bufRedirects = [];
  let hasWord = false;
  let dashTail = true;
  let lastCode = "";
  const heredocs = [];
  const parens = [];
  let closedWord = false;
  let inBacktick = false;
  let currentStatement = { masked: "", commands: [] };
  const endWord = () => {
    const reserved = hasWord && !bufQuoted && words.length === 0 && COMPOUND_RESERVED.has(buf);
    if (hasWord && !bufQuoted && words.length === 0) {
      if (buf === "case") parens.push("case");
      else if (buf === "esac" && parens[parens.length - 1] === "case") parens.pop();
    }
    const opensBody = hasWord && !bufQuoted && buf === "{";
    const first = words[0];
    const unquotedHead = first !== void 0 && !first.quoted ? first.value : "";
    if (opensBody && unquotedHead === "function" && words.length === 2) {
      words = [];
      dashTail = true;
      buf = "";
      bufQuoted = false;
      bufRedirects = [];
      hasWord = false;
      return;
    }
    const afterTime = opensBody && unquotedHead === "time" && dashTail;
    if (hasWord && !reserved && !afterTime) {
      if (words.length >= 1 && (bufQuoted || !buf.startsWith("-"))) dashTail = false;
      words.push(
        bufRedirects.length > 0 ? { value: buf, quoted: bufQuoted, redirectAt: bufRedirects } : { value: buf, quoted: bufQuoted }
      );
    }
    buf = "";
    bufQuoted = false;
    bufRedirects = [];
    hasWord = false;
  };
  const endCommand = () => {
    endWord();
    if (words.length > 0) commands.push(words);
    words = [];
    dashTail = true;
  };
  let pendingOpens = 0;
  const endStatement = (end, group) => {
    endCommand();
    const text = masked.trim();
    if (text.length > 0 || commands.length > 0) {
      currentStatement.masked = text;
      currentStatement.commands = commands;
      if (end !== void 0) currentStatement.end = end;
      if (pendingOpens > 0) currentStatement.opens = pendingOpens;
      if (group === "case") currentStatement.casePattern = true;
      pendingOpens = 0;
      statements.push(currentStatement);
    } else if (group === "open") pendingOpens += 1;
    else if (group === "close") {
      const last = statements[statements.length - 1];
      if (pendingOpens > 0) pendingOpens -= 1;
      else if (last !== void 0) last.closes = (last.closes ?? 0) + 1;
    }
    masked = "";
    commands = [];
    lastCode = "";
    currentStatement = { masked: "", commands: [] };
  };
  const emitCode = (ch) => {
    if (ch === ">" || ch === "<") bufRedirects.push(buf.length);
    buf += ch;
    hasWord = true;
    masked += ch;
    maskedCommand += ch;
    lastCode = ch;
  };
  let i = 0;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (ch === "\\") {
      const next = command.charAt(i + 1);
      if (next === "") {
        emitCode("\\");
        i += 1;
        continue;
      }
      if (next === "\n") {
        i += 2;
        continue;
      }
      buf += next;
      hasWord = true;
      masked += next;
      maskedCommand += next;
      lastCode = "";
      i += 2;
      continue;
    }
    if (ch === "#" && !hasWord && !(closedWord && /[)`]/.test(command.charAt(i - 1)))) {
      while (i < command.length && command.charAt(i) !== "\n" && command.charAt(i) !== "\r") i += 1;
      continue;
    }
    if (ch === "$" && (command.charAt(i + 1) === "'" || command.charAt(i + 1) === '"') && !/[\w}]/.test(command.charAt(i - 1))) {
      const q = command.charAt(i + 1);
      const scanned = scanQuote(command, i + 1);
      buf += q === "'" ? decodeAnsiC(scanned.inner) : scanned.inner;
      bufQuoted = true;
      hasWord = true;
      masked += MASK;
      maskedCommand += MASK;
      const vars = q === '"' ? interpolatedVariables(scanned.inner) : [];
      if (vars.length > 0) interpolations.push({ at: maskedCommand.length, vars: vars.join(" ") });
      lastCode = MASK;
      i = scanned.next;
      continue;
    }
    if (ch === "'" || ch === '"') {
      const scanned = scanQuote(command, i);
      buf += scanned.inner;
      bufQuoted = true;
      hasWord = true;
      const name = quotedName(maskedCommand, scanned.inner);
      masked += MASK;
      maskedCommand += MASK;
      const vars = ch === '"' ? interpolatedVariables(scanned.inner) : [];
      if (name !== void 0) vars.push(name);
      if (vars.length > 0) interpolations.push({ at: maskedCommand.length, vars: vars.join(" ") });
      lastCode = MASK;
      i = scanned.next;
      continue;
    }
    if (ch === "\n") {
      endStatement("\n");
      maskedCommand += "\n";
      i = heredocs.length > 0 ? skipHeredocBodies(command, i + 1, heredocs) : i + 1;
      continue;
    }
    if (ch === ";") {
      endStatement(";");
      maskedCommand += ";";
      i += 1;
      continue;
    }
    if (ch === "\r" && command.charAt(i + 1) !== "\n") {
      endStatement("\n");
      maskedCommand += "\n";
      i += 1;
      continue;
    }
    if (ch === "(" || ch === ")" || ch === "`") {
      let group;
      if (ch === "(") {
        const kind = /[$<>=@(]/.test(command.charAt(i - 1)) ? "word" : "group";
        parens.push(kind);
        if (kind === "group") group = "open";
      } else if (ch === ")") {
        if (buf === "esac" && !bufQuoted && words.length === 0 && parens[parens.length - 1] === "case") parens.pop();
        if (parens[parens.length - 1] === "case") {
          closedWord = false;
          group = "case";
        } else {
          const closed = parens.pop();
          closedWord = closed === "word";
          if (closed === "group") group = "close";
        }
      } else {
        closedWord = inBacktick;
        inBacktick = !inBacktick;
      }
      endStatement(ch === "(" ? "(" : ch === ")" ? ")" : "`", group);
      maskedCommand += ch;
      i += 1;
      continue;
    }
    if (ch === "&") {
      const next = command.charAt(i + 1);
      if (next === "&") {
        endStatement("&&");
        maskedCommand += "&&";
        i += 2;
        continue;
      }
      if (next === ">" || lastCode === ">" || lastCode === "<" || lastCode === "|") {
        emitCode("&");
        i += 1;
        continue;
      }
      endStatement("&");
      maskedCommand += "&";
      i += 1;
      continue;
    }
    if (ch === "|") {
      if (lastCode === ">") {
        emitCode("|");
        i += 1;
        continue;
      }
      const next = command.charAt(i + 1);
      if (next === "|") {
        endStatement("||");
        maskedCommand += "||";
        i += 2;
        continue;
      }
      if (next === "&") {
        endCommand();
        masked += "|";
        maskedCommand += "|";
        lastCode = "|";
        i += 2;
        continue;
      }
      endCommand();
      masked += "|";
      maskedCommand += "|";
      lastCode = "|";
      i += 1;
      continue;
    }
    if (ch === "<" && command.charAt(i + 1) === "<" && command.charAt(i + 2) !== "<" && command.charAt(i - 1) !== "<") {
      const heredoc = readHeredocOperator(command, i);
      if (heredoc !== null) {
        heredocs.push({ word: heredoc.word, statement: currentStatement });
        endWord();
        masked += " ";
        maskedCommand += " ";
        lastCode = "";
        i = heredoc.next;
        continue;
      }
    }
    if (ch === " " || ch === "	" || ch === "\r") {
      endWord();
      masked += " ";
      maskedCommand += ch;
      i += 1;
      continue;
    }
    emitCode(ch);
    i += 1;
  }
  endStatement();
  return { maskedCommand, interpolatedCommand: withInterpolations(maskedCommand, interpolations), statements };
}

// src/hooks/shell/workdir.ts
var UNREAD_TARGET = /[$`%*?[\]{}]|^~[^\\/]/;
var VARIABLE_TARGET = /^(?:\$\{(?:env:)?\w+\}|\$(?:env:)?\w+|%\w+%)(?:[\\/][^$`%*?[\]{}]*)?$/i;
var MAX_EVAL_DEPTH = 3;
function cdMove(words, evalDepth = 0) {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? "");
  if (name === "eval" && evalDepth < MAX_EVAL_DEPTH) {
    const text = words.slice(at + 1).map((w) => w.value).join(" ");
    if (text.length > 4096) return void 0;
    const inner = splitShell(text).statements;
    const only = inner.length === 1 && inner[0]?.commands.length === 1 ? inner[0]?.commands[0] : void 0;
    return only === void 0 ? void 0 : cdMove(only, evalDepth + 1);
  }
  if (name === "cd..") return { kind: "cd", target: "..", push: false };
  if (CD_RETURNS.has(name)) return { kind: "pop" };
  if (!CD_COMMANDS.has(name)) return void 0;
  const target = cdOperand(words.slice(at + 1).map((w) => w.value));
  if (target === null) return { kind: "unknown" };
  return { kind: "cd", target, push: name === "pushd" || name === "push-location" };
}
function setsCdpath(words) {
  return words.some((w) => /^CDPATH=/.test(w.value));
}
var OPENERS = /* @__PURE__ */ new Set(["if", "while", "until", "for", "select", "case", "{", "function"]);
var CLOSERS = /* @__PURE__ */ new Set(["fi", "done", "esac", "}"]);
var INSIDE = /* @__PURE__ */ new Set(["then", "else", "elif", "do", "!", "time", "-p"]);
function depthDelta(masked) {
  let delta = 0;
  for (const word of masked.trim().split(/\s+/)) {
    if (OPENERS.has(word)) delta += 1;
    else if (CLOSERS.has(word)) delta -= 1;
    else if (!INSIDE.has(word)) break;
  }
  return delta;
}
var MAX_STEPS = 64;
function moved(steps, target) {
  const t = target ?? "~";
  if (/^(?:[\\/]|~(?:[\\/]|$)|[A-Za-z]:[\\/])/.test(t)) return [t];
  return steps === null || steps.length >= MAX_STEPS ? null : [...steps, t];
}
function workdirs(statements, opts = {}) {
  const listEnd = new Array(statements.length);
  for (let k = statements.length - 1; k >= 0; k -= 1) {
    const end = statements[k]?.end;
    listEnd[k] = end === "&&" || end === "||" ? listEnd[k + 1] : end;
  }
  let here = { may: [], sure: [], prevMay: null, prevSure: null, stack: [] };
  let listStart = here;
  let trusted = true;
  let orElse = false;
  let cdpath = opts.cdpath === true;
  let depth = 0;
  const outer = [];
  let inBacktick = false;
  const out = [];
  for (let k = 0; k < statements.length; k += 1) {
    const statement = statements[k];
    if (statement === void 0) {
      out.push([]);
      continue;
    }
    for (let o = 0; o < (statement.opens ?? 0); o += 1) outer.push(here);
    const before = (statement.opens ?? 0) > 0 ? "(" : statements[k - 1]?.end;
    if (before === "&&" || before === "||") {
      if (before === "||") {
        trusted = false;
        orElse = true;
      }
    } else {
      listStart = here;
      trusted = before !== ")" && !(before === "`" && !inBacktick);
      orElse = false;
    }
    const delta = depthDelta(statement.masked);
    if (delta > 0) depth += delta;
    const lone = statement.commands.length === 1;
    const continued = statement.end === "(" || statement.end === "`" && !inBacktick;
    const row = [];
    statement.commands.forEach((words, c) => {
      row.push({ may: here.may, sure: orElse ? null : here.sure });
      const at = resolveCommand(words).index;
      const prefixCdpath = setsCdpath(words.slice(0, at));
      if (at >= words.length && prefixCdpath || commandName(words[at]?.value ?? "") === "export" && setsCdpath(words.slice(at + 1))) cdpath = true;
      const found = cdMove(words);
      const move = found !== void 0 && continued && c === statement.commands.length - 1 ? { kind: "unknown" } : found;
      if (move === void 0) {
        trusted = false;
        return;
      }
      const surely = trusted && lone && depth === 0 && listEnd[k] !== "&";
      if (move.kind === "unknown") {
        here = { ...here, may: null, sure: null, prevMay: here.may, prevSure: here.sure };
      } else if (move.kind === "pop") {
        const top = here.stack[here.stack.length - 1];
        here = {
          may: top?.may ?? null,
          sure: surely ? top?.sure ?? null : null,
          prevMay: here.may,
          prevSure: here.sure,
          stack: here.stack.slice(0, -1)
        };
      } else {
        const back = move.target === "-" || move.target !== void 0 && /^\$\{?OLDPWD\}?$/.test(move.target);
        const unread = !back && move.target !== void 0 && UNREAD_TARGET.test(move.target);
        const lookedUp2 = (cdpath || prefixCdpath) && move.target !== void 0 && !/^(?:\.\.?(?:[\\/]|$)|[\\/~]|[A-Za-z]:)/.test(move.target);
        const variable = unread && move.target !== void 0 && VARIABLE_TARGET.test(move.target);
        const nextMay = back ? here.prevMay : unread && !variable ? null : moved(here.may, move.target);
        const nextSure = !surely || unread || lookedUp2 || move.target === void 0 ? null : back ? here.prevSure : moved(here.sure, move.target);
        here = {
          may: nextMay,
          sure: nextSure,
          prevMay: here.may,
          prevSure: here.sure,
          stack: !move.push ? here.stack : here.stack.length >= MAX_STEPS ? [] : [...here.stack, { may: here.may, sure: here.sure }]
        };
      }
      if (!lone) here = { ...here, sure: null };
    });
    out.push(row);
    if (delta < 0) depth = Math.max(0, depth + delta);
    const end = statement.end;
    if (end === "&") here = { ...listStart, may: here.may, prevMay: here.prevMay };
    if (end === "(") outer.push(here);
    else if (end === "`") {
      if (!inBacktick) outer.push(here);
      else here = outer.pop() ?? { ...here, may: null, sure: null };
      inBacktick = !inBacktick;
    } else if (end === ")" && statement.casePattern !== true) {
      here = outer.pop() ?? { ...here, sure: null };
    }
    for (let c = 0; c < (statement.closes ?? 0); c += 1) here = outer.pop() ?? { ...here, sure: null };
  }
  return out;
}

// src/hooks/bashGuard.ts
var BASH_RULES = [
  // ── Catastrophic: block by default ───────────────────────────────────────
  {
    id: "no-preserve-root",
    level: "block",
    reason: "Uses --no-preserve-root, defeating the root-deletion safeguard",
    pattern: /--no-preserve-root/i
  },
  {
    id: "remote-pipe-to-shell",
    level: "block",
    reason: "Pipes a downloaded script directly into a shell (curl|wget \u2026 | sh/bash)",
    // `sudo -E bash`, `sudo -H -E bash` etc. — flags between `sudo` and the
    // shell name — used to fall through this pattern, which only allowed
    // `sudo` directly followed by the shell.
    // A flag never contains `|`: `-\S+` spanned pipes and made `| sudo -x|sudo
    // -x|…` quadratic (fix round 3).
    pattern: /\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+(?:-[^\s|]+\s+)*)?(?:ba|z|da)?sh\b/i,
    test: after(/\b(?:curl|wget)\b/i, /\|\s*(?:sudo\s+(?:-[^\s|]+\s+)*)?(?:ba|z|da)?sh\b/i)
  },
  {
    id: "powershell-iex-download",
    level: "block",
    reason: "Downloads and executes remote code via Invoke-Expression",
    // `irm`/`iwr` are PowerShell's own built-in aliases for
    // Invoke-RestMethod/Invoke-WebRequest — as common in the wild as the
    // full names, and the piped-download shape is identical either way.
    pattern: /(?:iwr|irm|invoke-webrequest|invoke-restmethod|wget|curl)[^\n]*\|\s*(?:iex|invoke-expression)/i,
    test: after(/(?:iwr|irm|invoke-webrequest|invoke-restmethod|wget|curl)/i, /\|\s*(?:iex|invoke-expression)/i)
  },
  {
    id: "powershell-iex-nested",
    level: "block",
    reason: "Downloads and executes remote code via Invoke-Expression",
    // `iex (irm …)` / `Invoke-Expression (Invoke-RestMethod …)` is the same
    // hazard as the piped form above, spelled with the download as a nested
    // call instead of a pipe. `(` is a statement boundary everywhere else in
    // this file (subshells, command substitution), so this must be
    // scope:'command' to see across it — narrow enough (iex/Invoke-Expression
    // immediately opening a paren around a download cmdlet) that it does not
    // reopen the cross-separator false positives scope:'command' otherwise
    // reintroduces the download and the pipe are never split across `&&`/`;`
    // for the same reason the fork-bomb signature needs scope:'command'.
    pattern: /\b(?:iex|invoke-expression)\s*\(\s*(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b/i,
    scope: "command"
  },
  {
    id: "powershell-disk-format",
    level: "block",
    reason: "Formats or clears an entire disk/volume",
    pattern: /\b(?:Format-Volume|Clear-Disk)\b/i
  },
  {
    id: "process-substitution-remote-fetch",
    level: "block",
    reason: "Executes a downloaded script via process substitution (bash <(curl \u2026))",
    // `bash <(curl …)` hands bash a fake file whose content is curl's stdout
    // — the same hazard as `curl … | sh`, spelled with process substitution
    // instead of a pipe. `<(` is not a statement separator anywhere else in
    // this file, so scope:'command' (which sees the un-split text) is enough
    // here and no tokenizer change is needed — unlike `sh -c "$(curl …)"`,
    // where the whole thing sits inside quotes and is handled separately, by
    // `isBareRemoteFetch` on the extracted `-c` script text. `source <(curl
    // …)` and `. <(wget …)` run the download in the current shell — the same
    // hazard (review I1); `.` counts only where a command starts.
    pattern: /(?:\b(?:sh|bash|zsh|dash|ksh|ash|mksh|source)\b|(?:^|[;&|(){}])[ \t]*\.(?=\s))[^\n]*<\(\s*(?:curl|wget)\b/im,
    scope: "command",
    test: processSubstitutionFetch
  },
  {
    id: "disk-overwrite",
    level: "block",
    reason: "Writes raw bytes to a block device (dd/mkfs/wipefs/shred on /dev/\u2026)",
    // The `\b` used to sit in front of the whole group, and a leading `\b`
    // before `>` demands a word character immediately to its left — so the
    // redirect alternative matched `cat x>/dev/sda` and never the
    // `cat x > /dev/sda` anybody actually writes. Each alternative anchors
    // itself now.
    //
    // `dd … of=` is deliberately narrower than the rest: it only blocks a
    // handful of real block-device name families (`sd`/`hd`/`vd`/`xvd`/
    // `nvme`/`mmcblk`/`disk`/`md`/`dm-`, plus the Windows `\\.\PhysicalDriveN`
    // spelling) — `dd … of=/dev/null`, `of=/dev/stdout`, `of=/dev/zero` and
    // an ordinary regular-file target are all common, harmless uses of dd
    // that this used to block outright by matching any `/dev/` path.
    // `mkfs`/`wipefs`/`shred` keep matching any `/dev/…` target: unlike dd,
    // there is no ordinary reason to run any of them against something that
    // is not a device, so narrowing them has no false positive to fix.
    // `mkfs`'s target used to have to sit immediately after the command
    // (`mkfs\s+\/dev\/`), so `mkfs -t ext4 /dev/sdb` — flags between the
    // command and its target — never matched; `[^\n]*` between them (already
    // safe here: this rule runs per masked *statement*, so it cannot cross a
    // `&&`/`;`/newline) fixes that the same way the rest of this alternation
    // already tolerates flags before its target.
    pattern: /(?:\bdd\b[^\n]*\bof=(?:\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)[\w-]*|\\\\\.\\PhysicalDrive\d*)|\bmkfs(?:\.\w+)?\b[^\n]*\/dev\/|\bwipefs\b[^\n]*\/dev\/|\bshred\b[^\n]*\/dev\/|>\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-))/i,
    test: anyOf(
      after(/\bdd\b/i, /\bof=(?:\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)[\w-]*|\\\\\.\\PhysicalDrive\d*)/i),
      after(/\bmkfs(?:\.\w+)?\b/i, /\/dev\//i),
      after(/\bwipefs\b/i, /\/dev\//i),
      after(/\bshred\b/i, /\/dev\//i),
      (t) => />\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)/i.test(t)
    )
  },
  {
    id: "fork-bomb",
    level: "block",
    reason: "Shell fork bomb",
    // Scoped to the whole command: `(`, `)`, `|`, `&` and `;` are the very
    // characters splitShell() separates on, so this signature only exists
    // before segmentation. Quoted spans are still masked, so
    // `echo ':(){ :|:& };:'` stays inert. Any function name, not only `:`
    // (review 8, item 9: `f(){ f|f& };f` was ok); the backreference is the
    // specification, `forkBomb` the linear reading of it.
    pattern: /(?<![\w:.-])([\w:.-]{1,64})\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1(?![\w:.-])/,
    scope: "command",
    test: forkBomb
  },
  {
    id: "chmod-777-root",
    level: "block",
    reason: "Recursively makes the filesystem root world-writable",
    // `chmod 777 -R /` is the same hazard as `chmod -R 777 /` with the flag
    // and the mode swapped — both orders are real, so both are matched.
    pattern: /\bchmod\b[^\n]*(?:-[a-z]*R[a-z]*\s+0?777\s+\/(?:\s|$)|0?777\s+-[a-z]*R[a-z]*\s+\/(?:\s|$))/i,
    // `-[a-z]*R[a-z]*` backtracked quadratically over a run of R's; a lookahead
    // for the R and one greedy run cannot.
    test: after(
      /\bchmod\b/i,
      /(?:-(?=[a-z]*R)[a-z]*\s+0?777\s+\/(?:\s|$)|0?777\s+-(?=[a-z]*R)[a-z]*\s+\/(?:\s|$))/i
    )
  },
  // ── Risky: warn only ─────────────────────────────────────────────────────
  {
    id: "git-force-push",
    level: "warn",
    reason: "Force-push can overwrite remote history",
    // `+main`/`+master` is git's own shorthand for a forced update of that
    // ref (a `+` prefix on a push refspec), and `--mirror` force-overwrites
    // every ref on the remote — same hazard as `--force`, different spelling.
    pattern: /\bgit\s+push\b[^\n]*?(?:--force\b|--force-with-lease\b|\s-f\b|\s\+\S|--mirror\b)/i,
    test: after(/\bgit\s+push\b/i, /(?:--force\b|--force-with-lease\b|\s-f\b|\s\+\S|--mirror\b)/i)
  },
  {
    id: "git-hard-reset",
    level: "warn",
    reason: "git reset --hard discards uncommitted work",
    pattern: /\bgit\s+reset\b[^\n]*--hard\b/i,
    test: after(/\bgit\s+reset\b/i, /--hard\b/i)
  },
  {
    id: "git-clean-force",
    level: "warn",
    reason: "git clean -fd permanently removes untracked files",
    pattern: /\bgit\s+clean\b[^\n]*-[a-z]*f/i,
    test: after(/\bgit\s+clean\b/i, /-[a-z]*f/i)
  },
  {
    id: "chmod-777",
    level: "warn",
    reason: "chmod 777 grants world-write \u2014 overly permissive",
    pattern: /\bchmod\b[^\n]*\b0?777\b/i,
    test: after(/\bchmod\b/i, /\b0?777\b/i)
  },
  {
    id: "history-wipe",
    level: "warn",
    reason: "Clears shell history",
    pattern: /\bhistory\s+-c\b|>\s*~?\/?\.(?:bash|zsh)_history\b/i
  }
];
function after(keyword, tail2) {
  const kw = new RegExp(keyword.source, keyword.flags.replace(/[gy]/g, ""));
  const tl = new RegExp(tail2.source, `${tail2.flags.replace(/[gy]/g, "")}g`);
  return (text) => {
    const m = kw.exec(text);
    if (m === null) return false;
    tl.lastIndex = m.index + m[0].length;
    return tl.test(text);
  };
}
function anyOf(...tests) {
  return (text) => tests.some((t) => t(text));
}
function processSubstitutionFetch(text) {
  for (const line of text.split("\n")) {
    const shell = /\b(?:sh|bash|zsh|dash|ksh|ash|mksh|source)\b|(?:^|[;&|(){}])[ \t]*\.(?=\s)/i.exec(line);
    if (shell === null) continue;
    const shellEnd = shell.index + shell[0].length;
    for (const fetch of line.matchAll(/<\(\s*(?:curl|wget)\b/gi)) {
      if (fetch.index >= shellEnd) return true;
    }
  }
  return false;
}
var FORK_NAME_CHAR = /[\w:.-]/;
function forkBomb(text) {
  for (const m of text.matchAll(/\(\s*\)\s*\{\s*/g)) {
    let end = m.index;
    for (let k = 0; end > 0 && k < 64 && /\s/.test(text.charAt(end - 1)); k += 1) end -= 1;
    let start = end;
    while (start > 0 && end - start < 64 && FORK_NAME_CHAR.test(text.charAt(start - 1))) start -= 1;
    if (start === end || start > 0 && FORK_NAME_CHAR.test(text.charAt(start - 1))) continue;
    const name = text.slice(start, end).replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");
    const body = new RegExp(`${name}\\s*\\|\\s*${name}\\s*&\\s*\\}\\s*;\\s*${name}(?![\\w:.-])`, "y");
    body.lastIndex = m.index + m[0].length;
    if (body.test(text)) return true;
  }
  return false;
}
var SUDO_RULE = {
  id: "sudo",
  level: "warn",
  reason: "Runs with elevated privileges (sudo)"
};
var LEVEL_RANK = { ok: 0, warn: 1, block: 2 };
function stripQuotes(token) {
  const q = (c) => c === "'" || c === '"' || c === "`";
  let a = 0;
  let b = token.length;
  while (a < b && q(token.charAt(a))) a += 1;
  while (b > a && q(token.charAt(b - 1))) b -= 1;
  return token.slice(a, b);
}
var SYSTEM_DIRS = ["etc", "usr", "bin", "sbin", "var", "lib", "lib64", "boot", "sys", "proc", "root", "home", "opt", "dev", "Users", "System"];
var WINDOWS_DIR = /^(?:[A-Za-z]:[\\/]?|\/(?:mnt\/)?[A-Za-z]\/)(?:Windows(?:[\\/]?(?:System32|SysWOW64))?|Users|Program Files(?: \(x86\))?|ProgramData|PROGRA~\d)(?:[\\/]\*?)?$/i;
var WINDOWS_DIR_NAMES = ["windows", "users", "program files", "program files (x86)", "programdata"];
function normalizeParamModifier(t) {
  const m = /^\$\{((?:env:)?[A-Za-z_]\w*)(?::?[-=?])[^{}]*\}/.exec(t);
  return m === null ? t : `\${${m[1] ?? ""}}${t.slice(m[0].length)}`;
}
function catastrophicKind(raw, tildeUsers = true) {
  const stripped = normalizeParamModifier(stripQuotes(raw));
  return spelledKind(stripped, tildeUsers) ?? plainKind(raw, tildeUsers);
}
function spelledKind(t, tildeUsers) {
  if (t === "/" || /^\/\*+$/.test(t)) return "root";
  if (/^\\\*?$/.test(t)) return "root";
  if (/^~(?:[\\/]\*?)?$/.test(t)) return "home";
  if (tildeUsers && /^~[A-Za-z_][\w.-]*(?:[\\/]\*?)?$/.test(t)) return "home";
  if (/^\$\{?HOME\}?(?:[\\/]\*?)?$/i.test(t)) return "home";
  if (/^(?:\$\{?USERPROFILE\}?|\$\{?HOMEDRIVE\}?\$\{?HOMEPATH\}?|\$\{?env:HOMEDRIVE\}?\$\{?env:HOMEPATH\}?)(?:[\\/]\*?)?$/i.test(t)) {
    return "home";
  }
  if (/^\/[a-z](?:\/\*?)?$/i.test(t)) return "root";
  if (/^\/mnt\/[a-z](?:\/\*?)?$/i.test(t)) return "root";
  if (/^[A-Za-z]:[\\/]\*?$/.test(t)) return "root";
  if (/^(?:%(?:USERPROFILE|HOMEDRIVE%%HOMEPATH|HOMEPATH)%|\$\{?env:(?:USERPROFILE|HOMEPATH)\}?)(?:[\\/]\*?)?$/i.test(t)) {
    return "home";
  }
  if (/^(?:%(?:HOMEDRIVE|SystemDrive|SystemRoot|windir|ProgramFiles|ProgramFiles\(x86\)|ProgramData|ALLUSERSPROFILE|PUBLIC)%|\$\{?env:(?:HOMEDRIVE|SystemDrive|SystemRoot|windir|ProgramFiles|ProgramData|ALLUSERSPROFILE|PUBLIC)\}?)(?:[\\/]\*?)?$/i.test(t)) {
    return "root";
  }
  if (WINDOWS_DIR.test(t)) return "root";
  if (/^\/(?:etc|usr|bin|sbin|var|lib|lib64|boot|sys|proc|root|home|opt|dev|Users|System)(?:\/\*?)?$/.test(t)) {
    return "root";
  }
  return globNamesCatastrophic(t) ? "root" : null;
}
var MAX_PLAIN_TARGET = 4096;
var ROOT_VARIABLES = {
  windir: "C:/Windows",
  systemroot: "C:/Windows",
  programfiles: "C:/Program Files",
  "programfiles(x86)": "C:/Program Files (x86)",
  programw6432: "C:/Program Files",
  programdata: "C:/ProgramData",
  allusersprofile: "C:/ProgramData",
  systemdrive: "C:/",
  homedrive: "C:/"
};
var HOME_VARIABLES = /* @__PURE__ */ new Set(["home", "userprofile"]);
function leadingVariable(t) {
  const m = /^(?:\$\{(?:env:)?([A-Za-z_][\w()]*)\}|\$(?:env:)?([A-Za-z_]\w*(?:\(x86\))?)|%([A-Za-z_][\w()]*)%)/i.exec(t);
  if (m === null) return void 0;
  const name = (m[1] ?? m[2] ?? m[3] ?? "").toLowerCase();
  return { name, rest: t.slice((m[0] ?? "").length) };
}
function plainTarget(raw, variables = true) {
  let t = stripQuotes(raw.trim());
  if (t.length === 0 || t.length > MAX_PLAIN_TARGET) return void 0;
  t = t.replace(/^(?:Microsoft\.PowerShell\.Core\\)?FileSystem::/i, "");
  const unc = /^[\\/]{2}[?.][\\/]UNC[\\/]/i.exec(t);
  if (unc !== null) t = `//${t.slice(unc[0].length)}`;
  else t = t.replace(/^[\\/]{2}[?.][\\/](?=[A-Za-z]:)/, "");
  const share = /^[\\/]{2}[^\\/]+[\\/]([A-Za-z])\$(?=[\\/]|$)/.exec(t);
  if (share !== null) t = `${share[1] ?? ""}:/${t.slice(share[0].length)}`;
  let home = false;
  const homePair = /^(?:\$\{?(?:env:)?HOMEDRIVE\}?\$\{?(?:env:)?HOMEPATH\}?|%HOMEDRIVE%%HOMEPATH%)/i.exec(t);
  if (/^~(?=[\\/]|$)/.test(t)) home = true;
  else if (variables && homePair !== null) {
    home = true;
    t = `~${t.slice(homePair[0].length)}`;
  } else if (variables) {
    const v = leadingVariable(t);
    if (v !== void 0 && HOME_VARIABLES.has(v.name)) {
      home = true;
      t = `~${v.rest}`;
    } else if (v !== void 0 && ROOT_VARIABLES[v.name] !== void 0) t = `${ROOT_VARIABLES[v.name] ?? ""}${v.rest}`;
  }
  const drive = /^[A-Za-z]:/.exec(t)?.[0] ?? "";
  const body = t.slice(drive.length);
  if (!home && !/^[\\/]/.test(body)) return void 0;
  const windows = drive !== "" || /^[\\/](?:mnt[\\/])?[A-Za-z](?:[\\/]|$)/.test(body);
  const segments = [];
  let up = 0;
  for (const raw0 of (home ? body.slice(1) : body).split(/[\\/]+/)) {
    const seg = windows && raw0 !== "." && raw0 !== ".." ? raw0.replace(/[. ]+$/, "") : raw0;
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (segments.length > 0) segments.pop();
      else if (home) up += 1;
      continue;
    }
    segments.push(seg);
  }
  if (home) return { path: ["~", ...segments].join("/"), home, up };
  return { path: `${drive}/${segments.join("/")}`, home, up: 0 };
}
function plainKind(raw, tildeUsers) {
  const plain = plainTarget(raw);
  if (plain === void 0) return null;
  if (plain.home) {
    const below = plain.path === "~" ? 0 : plain.path.split("/").length - 1;
    if (plain.up === 0) return below === 0 ? "home" : null;
    return below < plain.up ? "root" : below === plain.up ? "home" : null;
  }
  return plain.path === stripQuotes(raw) ? null : spelledKind(plain.path, tildeUsers);
}
function isCatastrophicTarget(raw, tildeUsers = true) {
  return catastrophicKind(raw, tildeUsers) !== null;
}
function segmentMatches(seg, names) {
  const pattern = seg.toLowerCase();
  return names.some((n) => wildcardMatch(pattern, n.toLowerCase()));
}
var DRIVE_LETTERS = Array.from({ length: 26 }, (_, k) => String.fromCharCode(97 + k));
function globNamesCatastrophic(t) {
  if (t.length > 256 || !GLOB.test(t)) return false;
  const path = t.replace(/\\/g, "/").replace(/\/+(?:\*)?$/, "");
  const drive = /^([^/]*):(?:\/|$)/.exec(path);
  let segs;
  if (drive !== null) {
    if (!segmentMatches(drive[1] ?? "", DRIVE_LETTERS)) return false;
    segs = path.slice((drive[0] ?? "").length).split("/").filter((s) => s !== "");
    return segs.length === 0 || segs.length === 1 && segmentMatches(segs[0] ?? "", WINDOWS_DIR_NAMES);
  }
  if (!path.startsWith("/")) return false;
  segs = path.slice(1).split("/").filter((s) => s !== "");
  const [a = "", b = "", c = ""] = segs;
  if (segs.length === 1) return segmentMatches(a, SYSTEM_DIRS) || segmentMatches(a, DRIVE_LETTERS);
  const letter = (s) => segmentMatches(s, DRIVE_LETTERS);
  if (segs.length === 2) return letter(a) && segmentMatches(b, WINDOWS_DIR_NAMES) || segmentMatches(a, ["mnt"]) && letter(b);
  return segs.length === 3 && segmentMatches(a, ["mnt"]) && letter(b) && segmentMatches(c, WINDOWS_DIR_NAMES);
}
function targetKey(raw, fold) {
  const plain = plainTarget(raw, false);
  const t = stripQuotes((plain !== void 0 && !plain.home ? plain.path : raw).trim()).replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/\/+\*?$/, "");
  return fold ? t.replace(/^(?:\/mnt)?\/([a-z])(?=\/|$)/i, "$1:").toLowerCase() : t;
}
function homeDirFor(home, platform) {
  if (home === void 0) return void 0;
  const fold = platform === "win32";
  const key = targetKey(home, fold);
  return key === "" || /^[a-z]:$/i.test(key) ? void 0 : { key, fold };
}
function isHomeTarget(raw, home) {
  if (home === void 0) return false;
  const key = targetKey(raw, home.fold);
  if (key === home.key) return true;
  if (!home.fold) return false;
  const cut = key.lastIndexOf("/");
  const homeCut = home.key.lastIndexOf("/");
  if (cut < 0 || key.slice(0, cut) !== home.key.slice(0, homeCut)) return false;
  const short = /^([^~/]{1,6})~\d+$/.exec(key.slice(cut + 1));
  return short !== null && home.key.slice(homeCut + 1).replace(/[\s.]/g, "").startsWith(short[1] ?? "");
}
var PWD_PREFIX = /^(?:\$\(\s*pwd\s*\)|`\s*pwd\s*`|\$\{?PWD\}?|\$env:PWD)(?=[\\/]|$)/i;
function resolvedTarget(raw, ctx) {
  const t = normalizeParamModifier(stripQuotes(raw.trim()));
  if (t === "" || t.length > MAX_PLAIN_TARGET || t.includes("::")) return void 0;
  const pwd = PWD_PREFIX.exec(t);
  if (pwd !== null) return ctx.dir === void 0 ? void 0 : `${ctx.dir}${t.slice(pwd[0].length)}`;
  const v = leadingVariable(t);
  if (v !== void 0) {
    const value = ctx.vars?.[v.name];
    return value === void 0 || value === "" ? void 0 : `${value.replace(/\\/g, "/")}${v.rest.replace(/\\/g, "/")}`;
  }
  if (/^(?:[\\/~$%]|[A-Za-z]:)/.test(t) || ctx.dir === void 0) return void 0;
  return `${ctx.dir}/${t}`;
}
function judgedTargets(targets, ctx) {
  return targets.flatMap((t) => {
    const resolved = resolvedTarget(t, ctx);
    return resolved === void 0 ? [t] : [t, resolved];
  });
}
function isBareDrive(raw) {
  return /^[A-Za-z]:\.{0,2}$/.test(stripQuotes(raw.trim()));
}
var PS_PATH_PARAM = /^(?:pa(?:t|th)?|l(?:i(?:t(?:e(?:r(?:a(?:l(?:p(?:a(?:t(?:h)?)?)?)?)?)?)?)?)?)?|lp|pspath)$/;
var DASH_DELETE_HEADS = /* @__PURE__ */ new Set(["rm", "ri", "remove-item"]);
var SLASH_DELETE_HEADS = /* @__PURE__ */ new Set(["rd", "rmdir", "del", "erase"]);
var RM_LONG_OPTIONS = ["force", "interactive", "one-file-system", "no-preserve-root", "preserve-root", "recursive", "dir", "verbose", "help", "version"];
function rmLongOption(token) {
  const name = (token.slice(2).split("=")[0] ?? "").toLowerCase();
  if (name === "") return void 0;
  if (RM_LONG_OPTIONS.includes(name)) return name;
  const named = RM_LONG_OPTIONS.filter((o) => o.startsWith(name));
  return named.length === 1 ? named[0] : void 0;
}
var RM_SHORT_CLUSTER = /^[dfiIPrRvWx]+$/;
function assessRecursiveDelete(words, start, home, tildeUsers = true, ctx = {}) {
  const head = words[start];
  if (head === void 0) return null;
  const name = basename(head.value).toLowerCase();
  const dashStyle = DASH_DELETE_HEADS.has(name);
  const slashStyle = !dashStyle && SLASH_DELETE_HEADS.has(name);
  if (!dashStyle && !slashStyle) return null;
  let recursive = false;
  let noPreserve = false;
  const targets = [];
  const rest = words.slice(start + 1);
  for (let k = 0; k < rest.length; k += 1) {
    const token = (rest[k]?.value ?? "").replace(/^[\u2013\u2014\u2015]/, "-");
    if (slashStyle && token.startsWith("/")) {
      if (cmdSwitches(token)?.includes("s") === true) recursive = true;
      continue;
    }
    if (token.startsWith("--")) {
      const option = rmLongOption(token);
      if (option === "no-preserve-root") noPreserve = true;
      else if (option === "recursive") recursive = true;
      continue;
    }
    if (token.startsWith("-") && token.length > 1) {
      const colon = token.indexOf(":");
      const flags = colon < 0 ? token.slice(1) : token.slice(1, colon);
      let value = colon < 0 ? void 0 : token.slice(colon + 1);
      const lower = flags.toLowerCase();
      const recurseParam = lower !== "" && "recurse".startsWith(lower);
      const isSwitch = recurseParam || lower.length >= 2 && "force".startsWith(lower);
      if (value === "" && isSwitch) {
        value = rest[k + 1]?.value ?? "";
        k += 1;
      }
      if (value !== void 0 && value !== "" && PS_PATH_PARAM.test(lower)) targets.push(value);
      const on = value === void 0 || !/^\$?(?:false|0)$/i.test(value);
      if (recurseParam) recursive ||= on;
      else if (!isSwitch && value === void 0 && /r/i.test(flags) && (RM_SHORT_CLUSTER.test(flags) || flags.length <= 3)) recursive = true;
    } else targets.push(token);
  }
  const fromPipe = targets.length === 0 && ctx.piped !== void 0;
  if (!(recursive || noPreserve || fromPipe && ctx.pipedRecursive === true)) return null;
  if (fromPipe && ctx.piped !== void 0) targets.push(ctx.piped);
  if (noPreserve || ctx.bareDriveRoot === true && targets.some(isBareDrive) || judgedTargets(targets, ctx).some((t) => isCatastrophicTarget(t, tildeUsers) || isHomeTarget(t, home))) {
    return { ...RULE_RM_ROOT };
  }
  return { ...RULE_RM_BROAD };
}
var LISTERS = /* @__PURE__ */ new Set(["get-childitem", "gci", "ls", "dir", "get-item", "gi"]);
var LIST_NARROWING = /^-(?:fi(?:l(?:t(?:er?)?)?)?|inc(?:l(?:u(?:de?)?)?)?|ex(?:c(?:l(?:u(?:de?)?)?)?)?|at(?:t(?:r(?:i(?:b(?:u(?:t(?:es?)?)?)?)?)?)?)?|name)$/i;
var LIST_VALUED = /^-(?:de(?:p(?:th?)?)?|fi(?:l(?:t(?:er?)?)?)?|inc(?:l(?:u(?:de?)?)?)?|ex(?:c(?:l(?:u(?:de?)?)?)?)?|at(?:t(?:r(?:i(?:b(?:u(?:t(?:es?)?)?)?)?)?)?)?)$/i;
function pipedItems(words) {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? "");
  if (!LISTERS.has(name)) return void 0;
  const args = withoutRedirections(words.slice(at + 1));
  if (args.some((a) => LIST_NARROWING.test(a.split(":")[0] ?? a))) return void 0;
  let path = psParam(args, ["path", "literalpath", "lp", "pspath"]);
  for (let i = 0; path === void 0 && i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (a.startsWith("-")) i += LIST_VALUED.test(a) ? 1 : 0;
    else path = a;
  }
  if (name === "get-item" || name === "gi") return path ?? ".";
  return `${(path ?? ".").replace(/[\\/]+$/, "")}/*`;
}
function listsRecursively(words) {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? "");
  if (!LISTERS.has(name) || name === "get-item" || name === "gi") return false;
  return withoutRedirections(words.slice(at + 1)).some((a) => {
    const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    if (m === null) return false;
    const p = (m[1] ?? "").toLowerCase();
    const off = m[2] !== void 0 && /^\$?(?:false|0)$/i.test(m[2]);
    return !off && (p.length >= 3 && "recurse".startsWith(p) || p.length >= 2 && "depth".startsWith(p));
  });
}
var RULE_RM_ROOT = {
  id: "rm-rf-root",
  level: "block",
  reason: "Recursive delete of the filesystem root, a drive root, a system directory or a home directory"
};
var RULE_RM_BROAD = {
  id: "rm-rf-broad",
  level: "warn",
  reason: "Recursive delete \u2014 confirm the target path is intended"
};
var FIND_FILTERS = /* @__PURE__ */ new Set([
  "-name",
  "-iname",
  "-path",
  "-ipath",
  "-wholename",
  "-iwholename",
  "-regex",
  "-iregex",
  "-lname",
  "-ilname",
  "-newer",
  "-anewer",
  "-cnewer",
  "-newerxy",
  "-mtime",
  "-mmin",
  "-atime",
  "-amin",
  "-ctime",
  "-cmin",
  "-used",
  "-size",
  "-empty",
  "-perm",
  "-user",
  "-group",
  "-uid",
  "-gid",
  "-nouser",
  "-nogroup",
  "-inum",
  "-samefile",
  "-links",
  "-readable",
  "-writable",
  "-executable",
  "-context"
]);
var FIND_DELETERS = /* @__PURE__ */ new Set(["rm", "unlink", "rmdir", "shred", "remove-item", "ri", "del", "erase", "rd"]);
var RULE_FIND_ROOT = {
  id: "find-delete-root",
  level: "block",
  reason: "find \u2026 -delete (or -exec rm) on the filesystem root, a drive root, a system directory or a home directory deletes everything under it"
};
var RULE_FIND_HOME = {
  id: "find-delete-home",
  level: "warn",
  reason: "find \u2026 -delete targets the home directory \u2014 confirm this is intended"
};
var RULE_FIND_BROAD = {
  id: "find-delete-broad",
  level: "warn",
  reason: "find . -delete with no test to narrow it deletes everything under the working directory \u2014 confirm this is intended"
};
function assessFind(words, start, home, tildeUsers = true, ctx = {}) {
  const head = words[start];
  if (head === void 0 || basename(head.value) !== "find") return null;
  const rest = words.slice(start + 1);
  const execs = findExecCommands(words, start);
  const viaExec = execs.some((cmd) => FIND_DELETERS.has(commandName(cmd[resolveCommand(cmd).index]?.value ?? "")));
  const inner = execs.map((cmd) => assessRecursiveDelete(cmd, resolveCommand(cmd).index, home, tildeUsers, { ...ctx, piped: void 0 })).find((r) => r?.level === "block");
  if (inner !== void 0 && inner !== null) return inner;
  if (!viaExec && !rest.some((w) => w.value === "-delete")) return null;
  let k = 0;
  while (k < rest.length) {
    const v = rest[k]?.value ?? "";
    if (/^-(?:[HLP]|O\d*)$/.test(v)) k += 1;
    else if (v === "-D") k += 2;
    else break;
  }
  const targets = [];
  for (; k < rest.length; k += 1) {
    const v = rest[k]?.value ?? "";
    if (v.startsWith("-") || v === "(" || v === "!" || v === ")" || v === ",") break;
    targets.push(stripQuotes(v));
  }
  if (targets.length === 0) targets.push(".");
  const filtered = rest.some((w) => FIND_FILTERS.has(w.value));
  const judged = judgedTargets(targets, ctx);
  if (judged.some((t) => catastrophicKind(t, tildeUsers) === "root")) return { ...RULE_FIND_ROOT };
  if (judged.some((t) => catastrophicKind(t, tildeUsers) === "home" || isHomeTarget(t, home))) {
    return filtered ? { ...RULE_FIND_HOME } : { ...RULE_FIND_ROOT };
  }
  if (!filtered && targets.some((t) => /^\.[\\/]?$/.test(t))) return { ...RULE_FIND_BROAD };
  return null;
}
function findPipedIntoDeleter(commands, c, home, tildeUsers, ctx) {
  const words = commands[c];
  if (words === void 0 || c === 0) return null;
  const at = resolveCommand(words).index;
  if (!words.slice(0, at).some((w) => commandName(w.value) === "xargs")) return null;
  if (!FIND_DELETERS.has(commandName(words[at]?.value ?? ""))) return null;
  for (let p = c - 1; p >= 0; p -= 1) {
    const prev = commands[p] ?? [];
    const f = resolveCommand(prev).index;
    if (commandName(prev[f]?.value ?? "") === "find") {
      return assessFind([...prev, { value: "-delete", quoted: false }], f, home, tildeUsers, { ...ctx, piped: void 0, pipedRecursive: void 0 });
    }
  }
  return null;
}
var HOOK_CONFIG_PATH = /(?:\.guardian\/?hooks[^/]*\.json|\.config\/?dev-guardian\/?hooks\.json)$/i;
function isHookConfigPath(arg) {
  return HOOK_CONFIG_PATH.test(arg.replace(/\\/g, "/"));
}
var HOOK_CONFIG_DIR = /(?:\.guardian|\.config\/?dev-guardian)\/?$/i;
function isHookConfigDir(arg) {
  return HOOK_CONFIG_DIR.test(arg.replace(/\\/g, "/"));
}
var USER_CONFIG_DIR = /\.config\/?dev-guardian\/?$/i;
var CLAUDE_SETTINGS_PATH = /\.claude\/?settings(?:\.local)?\.json$/i;
var MANAGED_SETTINGS_PATH = /(?:ClaudeCode|claude-code)\/?managed-settings\.json$/i;
var CONFIG_DIR_VARIABLE_SETTINGS = /(?:\$\{?(?:env:)?CLAUDE_CONFIG_DIR\}?|%CLAUDE_CONFIG_DIR%)\/?settings(?:\.local)?\.json$/i;
function isSettingsPath(path, configDirName) {
  if (CLAUDE_SETTINGS_PATH.test(path) || CONFIG_DIR_VARIABLE_SETTINGS.test(path) || MANAGED_SETTINGS_PATH.test(path)) return true;
  if (configDirName === void 0) return false;
  const lower = path.toLowerCase();
  for (const file of ["settings.json", "settings.local.json"]) {
    if (lower.endsWith(`${configDirName}/${file}`) || lower.endsWith(`${configDirName}${file}`)) return true;
  }
  return false;
}
var DATA_DIR_SPELLED = /(?:(?:\$\{?(?:env:)?(?:localappdata|xdg_data_home)\}?|%(?:localappdata|xdg_data_home)%|appdata\/local|\.local\/share)\/dev-guardian|\$\{?(?:env:)?guardian_data_dir\}?|%guardian_data_dir%)$/;
function isDataDirPath(path, dataDir) {
  const p = normalizedPath(path);
  return dataDir !== void 0 && p === dataDir || DATA_DIR_SPELLED.test(p);
}
function isRegistryPath(path, dataDir) {
  const p = normalizedPath(path);
  for (let at = p.indexOf("/registry"); at >= 0; at = p.indexOf("/registry", at + 1)) {
    const next = p.charAt(at + "/registry".length);
    if (next !== "" && next !== "/") continue;
    const parent = p.slice(0, at);
    if (dataDir !== void 0 && parent === dataDir || DATA_DIR_SPELLED.test(parent)) return true;
  }
  return false;
}
function configDirNameOf(dir) {
  const last = (dir ?? "").trim().replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";
  return last === "" ? void 0 : last.toLowerCase();
}
function namesLooseningKey(text) {
  return /\bdisableAllHooks\b|\bGUARDIAN_HOOKS(?:_BASH_BLOCK)?\b|\bGUARDIAN_PKG_VET(?:_DEADLINE_MS)?\b|\bNODE_OPTIONS\b/i.test(text) || /enabledPlugins/i.test(text) && /dev-guardian/i.test(text);
}
function loosens(scope) {
  if (scope.notes.loosens === void 0) {
    const raw = scope.raw;
    scope.notes.loosens = namesLooseningKey(raw) || raw.includes("\\") && namesLooseningKey(unescapeText(raw)) || base64Literals(raw).some((text) => namesLooseningKey(text) || namesLooseningKey(unescapeText(text)));
  }
  return scope.notes.loosens;
}
function unescapeText(text) {
  return text.replace(/\\(?:x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|([0-7]{1,3}))/g, (all, x, u1, u2, o) => {
    const code = x !== void 0 ? parseInt(x, 16) : u1 !== void 0 ? parseInt(u1, 16) : u2 !== void 0 ? parseInt(u2, 16) : parseInt(o ?? "", 8);
    return Number.isFinite(code) && code <= 1114111 ? String.fromCodePoint(code) : all;
  });
}
var MAX_BASE64_LITERALS = 64;
function base64Literals(text) {
  const out = [];
  let tried = 0;
  for (const m of text.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g)) {
    if ((tried += 1) > MAX_BASE64_LITERALS) break;
    const decoded = decodeBase64(m[0]);
    if (decoded !== void 0 && !decoded.includes("\uFFFD")) out.push(decoded);
  }
  return out;
}
var GLOB = /[*?[]/;
var USER_CONFIG_TAIL = [".config", "dev-guardian", "hooks.json"];
var CONFIG_TAILS = [
  [".guardian", "hooks.config.json"],
  [".guardian", "hooks-allowlist.json"],
  USER_CONFIG_TAIL
];
function globNamesConfig(path, tails = CONFIG_TAILS) {
  const t = tail(path);
  if (!GLOB.test(t)) return false;
  const segs = t.split("/").filter((s) => s !== "");
  return tails.some(
    (names) => names.length <= segs.length && names.every((name, k) => wildcardMatch((segs[segs.length - names.length + k] ?? "").toLowerCase(), name))
  );
}
var MAX_BRACE_WORDS = 64;
var MAX_BRACE_WORD = 1024;
function braceAt(word) {
  for (let i = word.indexOf("{"); i >= 0; i = word.indexOf("{", i + 1)) {
    if (word.charAt(i - 1) === "$") continue;
    let depth = 0;
    const commas = [];
    let close = -1;
    for (let j = i + 1; j < word.length; j += 1) {
      const c = word.charAt(j);
      if (c === "{") depth += 1;
      else if (c === "}") {
        if (depth === 0) {
          close = j;
          break;
        }
        depth -= 1;
      } else if (c === "," && depth === 0) commas.push(j);
    }
    if (close < 0) return void 0;
    const pre = word.slice(0, i);
    const post = word.slice(close + 1);
    if (commas.length > 0) {
      const alts = [];
      let from = i + 1;
      for (const c of [...commas, close]) {
        alts.push(word.slice(from, c));
        from = c + 1;
      }
      return { pre, alts, post };
    }
    const seq = /^(-?\d{1,6}|[A-Za-z])\.\.(-?\d{1,6}|[A-Za-z])$/.exec(word.slice(i + 1, close));
    if (seq !== null) {
      const [a = "", b = ""] = [seq[1], seq[2]];
      const numeric = /\d/.test(a) && /\d/.test(b);
      if (!numeric && (/\d/.test(a) || /\d/.test(b))) continue;
      const lo = numeric ? Number(a) : a.charCodeAt(0);
      const hi = numeric ? Number(b) : b.charCodeAt(0);
      if (Math.abs(hi - lo) + 1 > MAX_BRACE_WORDS) return "too-many";
      const step = lo <= hi ? 1 : -1;
      const alts = [];
      for (let v = lo; ; v += step) {
        alts.push(numeric ? String(v) : String.fromCharCode(v));
        if (v === hi) break;
      }
      return { pre, alts, post };
    }
  }
  return void 0;
}
function expandBraces(word) {
  if (word.length > MAX_BRACE_WORD || !word.includes("{") || !word.includes("}")) return void 0;
  const out = [];
  const stack = [word];
  let expanded = false;
  for (let steps = 0; stack.length > 0; steps += 1) {
    if (steps > 8 * MAX_BRACE_WORDS) return void 0;
    const w = stack.pop() ?? "";
    const at = braceAt(w);
    if (at === "too-many") return void 0;
    if (at === void 0) {
      if (w !== "") out.push(w);
      if (out.length > MAX_BRACE_WORDS) return void 0;
      continue;
    }
    expanded = true;
    for (let k = at.alts.length - 1; k >= 0; k -= 1) stack.push(`${at.pre}${at.alts[k] ?? ""}${at.post}`);
    if (stack.length > 8 * MAX_BRACE_WORDS) return void 0;
  }
  return expanded ? out : void 0;
}
function expandWords(words) {
  if (!words.some((w) => !w.quoted && w.value.includes("{"))) return words;
  let out;
  for (const [k, w] of words.entries()) {
    const expanded = w.quoted || w.redirectAt !== void 0 ? void 0 : expandBraces(w.value);
    if (expanded === void 0) {
      out?.push(w);
      continue;
    }
    out ??= words.slice(0, k);
    for (const value of expanded) out.push({ value, quoted: false });
  }
  return out ?? words;
}
function literalsNameHookConfig(literals, scope) {
  const paths = literalPaths(literals);
  const named = locate(paths, (p) => HOOK_CONFIG_PATH.test(p) || USER_CONFIG_DIR.test(p), scope);
  if (named === "inside") return named;
  const has = (re) => paths.some((p) => re.test(p));
  if (has(/(?:^|\/)dev-guardian\/?$/i) && has(/(?:^|\/)hooks\.json$/i)) return "inside";
  if (has(/(?:^|\/)\.guardian\/?$/i) && has(/(?:^|\/)hooks[.-][^/]*\.json$/i)) return "inside";
  return named;
}
function literalsNameClaudeSettings(literals, scope) {
  const configDirName = scope.configDirName;
  const paths = literalPaths(literals);
  const named = locate(paths, (p) => isSettingsPath(p, configDirName), scope);
  if (named === "inside") return named;
  const has = (re) => paths.some((p) => re.test(p));
  const inDir = has(/(?:^|\/)\.claude\/?$/i) || configDirName !== void 0 && paths.some((p) => p.toLowerCase().replace(/\/+$/, "").endsWith(configDirName));
  return inDir && has(/^settings(?:\.local)?\.json$/i) ? "inside" : named;
}
function quoteTracker(text) {
  let quote = "";
  let i = 0;
  return (index) => {
    for (; i < index; i += 1) {
      const ch = text.charAt(i);
      if (quote === "") {
        if (ch === "\\") i += 1;
        else if (ch === "'" || ch === '"') quote = ch;
      } else if (quote === '"' && ch === "\\") i += 1;
      else if (ch === quote) quote = "";
    }
    return quote === "";
  };
}
var MAX_CALL_ARGS = 512;
function callArgs(text, from) {
  const args = [];
  let depth = 0;
  let cur = "";
  let quote = "";
  const end = Math.min(text.length, from + MAX_CALL_ARGS);
  let closed = false;
  for (let i = from; i < end; i += 1) {
    const ch = text.charAt(i);
    if (quote !== "") {
      cur += ch;
      if (ch === quote) quote = "";
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === ")" && depth === 0) {
      closed = true;
      break;
    }
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === "," && depth === 0) {
      args.push(cur.trim());
      cur = "";
      if (args.length === 2) return { args, cut: false };
      continue;
    }
    cur += ch;
  }
  args.push(cur.trim());
  return { args, cut: !closed && end < text.length };
}
function argPath(arg) {
  const q = /^(['"])([\s\S]*)\1$/.exec(arg);
  if (q !== null) return (q[2] ?? "").replace(q[1] === "'" ? /''/g : /`"/g, q[1] ?? "");
  const literals = codeLiterals(arg, "other");
  return literals[literals.length - 1] ?? arg;
}
var DOTNET_CALL = /\[\s*(?:System\s*\.\s*)?IO\s*\.\s*(File|Directory)\s*\]\s*::\s*([A-Za-z]+)\s*\(/gi;
function dotNetEffects(text, cwd, notes) {
  const e = noEffects();
  const newObject = /new-object/i.test(text);
  if (!text.includes("::") && !newObject) return e;
  const unquotedAt = quoteTracker(text);
  for (const m of text.matchAll(DOTNET_CALL)) {
    if (!unquotedAt(m.index)) continue;
    const kind = (m[1] ?? "").toLowerCase();
    const method = (m[2] ?? "").toLowerCase();
    const call = callArgs(text, m.index + m[0].length);
    if (call.cut && notes !== void 0) notes.calls = true;
    const paths = call.args.map((a) => resolveFrom(cwd, argPath(a)));
    const [first, second] = paths;
    if (first === void 0) continue;
    if (method === "delete") {
      e.removes.push(first);
      if (kind === "directory" && /^\$?true$/i.test(call.args[1] ?? "")) e.trees.push(first);
    } else if (method === "createsymboliclink") {
      e.links.push(first);
      if (second !== void 0) e.aliases.push([first, second]);
    } else if (method === "move" || method === "replace") {
      e.removes.push(first);
      if (second !== void 0) (kind === "directory" ? e.dirs : e.writes).push(second);
    } else if (kind === "file" && method === "copy") {
      if (second !== void 0) e.writes.push(second);
    } else if (kind === "file" && /^(?:write|append|create|open)/.test(method) && !/^open(?:read|text)$/.test(method)) {
      e.writes.push(first);
    }
  }
  if (!/streamwriter|filestream/i.test(text)) return e;
  const unquotedWriterAt = quoteTracker(text);
  for (const m of text.matchAll(DOTNET_WRITER)) {
    if (!unquotedWriterAt(m.index)) continue;
    const kind = (m[1] ?? m[2] ?? "").toLowerCase();
    const after2 = m.index + m[0].length;
    const open = /^\s*@?\(/.exec(text.slice(after2, after2 + 64));
    let args;
    if (open !== null) {
      const call = callArgs(text, after2 + open[0].length);
      if (call.cut && notes !== void 0) notes.calls = true;
      args = call.args;
    } else {
      const word = /^\s*('(?:[^']|'')*'|"(?:[^"`]|`.)*"|[^\s;|,)]+)/.exec(text.slice(after2, after2 + MAX_CALL_ARGS));
      args = word === null ? [] : [word[1] ?? ""];
    }
    const first = args[0];
    if (first === void 0 || first === "") continue;
    const all = text.slice(after2, after2 + MAX_CALL_ARGS).split(")")[0] ?? "";
    if (kind === "filestream" && /\bRead\b/i.test(all) && !/Write|Create|Append|Truncate/i.test(all)) continue;
    e.writes.push(resolveFrom(cwd, argPath(first)));
  }
  return e;
}
var DOTNET_WRITER = /\[\s*(?:System\s*\.\s*)?IO\s*\.\s*(StreamWriter|FileStream)\s*\]\s*::\s*new\b|\bNew-Object\s+(?:-TypeName\s+)?(?:System\s*\.\s*)?IO\s*\.\s*(StreamWriter|FileStream)\b(?:\s+-ArgumentList\b|\s+-Args?\b)?/gi;
var RULE_HARD_LINK = {
  id: "guard-config-hard-link",
  level: "block",
  reason: "Makes a hard link to the guardrail hooks' own configuration or to Claude Code's settings \u2014 a second name through which it can be rewritten"
};
var CLAUDE_DIR = /\.claude\/?$/i;
var MANAGED_SETTINGS_DIR = /(?:^|\/)(?:etc\/?claude-code|ClaudeCode)\/?$/i;
var RULE_LINK = {
  id: "guard-config-link",
  level: "block",
  reason: "Makes a symbolic link or a junction to the guardrail hooks' own configuration, to Claude Code's settings or to the directory that holds them \u2014 a second name through which a later command rewrites them without naming them"
};
var RULE_REGISTRY = {
  id: "guardian-registry-write",
  level: "block",
  reason: "Writes dev-guardian's registry of trusted databases (<data dir>/registry) \u2014 which database to trust is the user's decision: they run the dev-guardian CLI's `db adopt` themselves, in a terminal"
};
function literalsNameRegistry(literals, dataDir) {
  const paths = literalPaths(literals);
  if (paths.some((p) => isRegistryPath(p, dataDir))) return true;
  const has = (re) => paths.some((p) => re.test(p));
  return has(/(?:^|\/)dev-guardian\/?$/i) && has(/^registry\/?$/i);
}
var RULE_SPECIAL = {
  id: "guard-config-special-file",
  level: "block",
  reason: "Replaces the guardrail hooks' own configuration with a FIFO, a device node or a link"
};
var RULE_WRITE = {
  id: "guard-config-shell-write",
  level: "block",
  reason: "Writes the guardrail hooks' own configuration from the shell"
};
var RULE_REMOVE = {
  id: "guard-config-remove",
  level: "block",
  reason: "Removes or moves away the guardrail hooks' own configuration"
};
var RULE_DIR = {
  id: "guard-config-dir-replace",
  level: "block",
  reason: "Moves or copies a directory onto the guardrail hooks' configuration directory"
};
var RULE_INLINE = {
  id: "guard-config-inline-code",
  level: "block",
  reason: "Runs program code that names the guardrail hooks' own configuration"
};
var RULE_SETTINGS = {
  id: "claude-settings-loosen",
  level: "block",
  reason: "Writes Claude Code's settings with a key that switches the guardrail hooks off"
};
function worst(placements) {
  if (placements.includes("inside")) return "inside";
  return placements.includes("outside") ? "outside" : null;
}
function keyAtOrBelow(dir, key) {
  return dir !== void 0 && dir !== "" && (key === dir || key.startsWith(`${dir}/`));
}
function locate(paths, pred, scope) {
  let found = null;
  for (const p of paths) {
    if (!pred(p)) continue;
    if (placeOf(p, scope) === "inside") return "inside";
    found = "outside";
  }
  return found;
}
function placeOf(raw, scope) {
  const places = scope.places;
  if (places === void 0) return "inside";
  let t = stripQuotes(raw).replace(/\\/g, "/");
  const homeSpelled = /^(?:~|\$\{?HOME\}?|\$\{?USERPROFILE\}?|\$\{?env:USERPROFILE\}?|%USERPROFILE%)(?=\/|$)/i.exec(t);
  if (homeSpelled !== null) {
    if (places.home === void 0) return "inside";
    t = `${places.home}${t.slice(homeSpelled[0].length)}`;
  } else if (/^~[A-Za-z_]/.test(t)) {
    return "outside";
  } else if (!/^(?:\/|[A-Za-z]:\/)/.test(t)) {
    return "inside";
  }
  if (GLOB.test(t)) return "inside";
  const key = targetKey(t, places.fold);
  if (/(?:^|\/)\.config\/dev-guardian(?:\/|$)/i.test(key)) {
    if (places.home === void 0) return "inside";
    return keyAtOrBelow(`${places.home}/.config/dev-guardian`, key) ? "inside" : "outside";
  }
  if (MANAGED_SETTINGS_PATH.test(key)) return "inside";
  if (isSettingsPath(key, scope.configDirName) || CLAUDE_DIR.test(key)) {
    return [places.project, places.cwd, places.home, places.configDir].some((d) => keyAtOrBelow(d, key)) ? "inside" : "outside";
  }
  return [places.project, places.cwd].some((d) => keyAtOrBelow(d, key)) ? "inside" : "outside";
}
var RULE_ELSEWHERE = {
  id: "guard-config-elsewhere",
  level: "warn",
  reason: "Writes a file named like the guardrail hooks' configuration or Claude Code's settings outside this project, the working directory and the home directory \u2014 not the one this session reads; confirm the target"
};
var BLOCK_DEVICE = /^\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)|PhysicalDrive\d/i;
var RULE_DISK_WRITE = {
  id: "disk-overwrite",
  level: "block",
  reason: "Writes raw bytes to a block device (dd/mkfs/wipefs/shred on /dev/\u2026)"
};
var MAX_ALIASES = 64;
var MAX_LOOKUPS = 64;
function absoluteOf(raw, scope) {
  const t = stripQuotes(raw).replace(/\\/g, "/");
  if (/^~(?=\/|$)/.test(t)) return scope.homePath === void 0 ? void 0 : `${scope.homePath.replace(/\/+$/, "")}${t.slice(1)}`;
  if (/^[~$%]/.test(t)) return void 0;
  if (scope.windows === true) {
    const msys = /^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/.exec(t);
    if (msys !== null) return `${(msys[1] ?? "").toUpperCase()}:${t.slice(msys[0].length) || "/"}`;
    if (/^[A-Za-z]:(?!\/)/.test(t)) return void 0;
  }
  if (/^(?:\/|[A-Za-z]:\/)/.test(t)) return t;
  return scope.dir === void 0 ? void 0 : resolveFrom(scope.dir, t);
}
function aliasKey(raw, scope) {
  const k = (absoluteOf(raw, scope) ?? stripQuotes(raw).replace(/\\/g, "/")).replace(/\/+$/, "");
  return scope.windows === true ? k.toLowerCase() : k;
}
function realPathOf(raw, scope, lookup) {
  const realPath = scope.realPath;
  if (realPath === void 0) return void 0;
  const whole = absoluteOf(raw, scope)?.replace(/(?<=.)\/+$/, "");
  if (whole === void 0 || GLOB.test(whole) || /^\/dev\//.test(whole)) return void 0;
  const cut = whole.lastIndexOf("/");
  if (lookup === "path" || lookup === "name" && /\.json|~\d/i.test(whole.slice(cut + 1))) return lookedUp(whole, realPath, scope);
  if (cut <= 0 || /^[A-Za-z]:$/.test(whole.slice(0, cut))) return void 0;
  const dir = lookedUp(whole.slice(0, cut), realPath, scope);
  return dir === void 0 ? void 0 : `${dir.replace(/\/+$/, "")}${whole.slice(cut)}`;
}
function lookedUp(abs, realPath, scope) {
  const notes = scope.notes;
  if (notes.realPaths.has(abs)) return notes.realPaths.get(abs);
  if (notes.realPaths.size >= MAX_LOOKUPS) {
    notes.links = true;
    return void 0;
  }
  if (notes.now() > notes.deadline) {
    notes.budget = true;
    return void 0;
  }
  let real;
  try {
    real = realPath(abs)?.replace(/\\/g, "/");
  } catch {
    real = void 0;
  }
  const differs = real !== void 0 && (scope.windows === true ? real.toLowerCase() !== abs.toLowerCase() : real !== abs);
  const found = differs ? real : void 0;
  notes.realPaths.set(abs, found);
  return found;
}
function throughLinks(effects, scope) {
  const notes = scope.notes;
  const expand = (paths, lookup) => {
    const out = [...paths];
    for (const p of paths) {
      if (notes.aliases.length > 0) {
        const key = aliasKey(p, scope);
        for (const [link, target] of notes.aliases) {
          if (lookup !== "parent" && key === link || key.startsWith(`${link}/`)) out.push(`${target}${key.slice(link.length)}`);
        }
      }
      const real = realPathOf(p, scope, lookup);
      if (real !== void 0) out.push(real);
    }
    return out;
  };
  const targets = expand(
    effects.aliases.map(([, target]) => target),
    "path"
  );
  const links = expand(effects.links, "parent");
  for (const [link, target] of effects.aliases) {
    if (notes.aliases.length >= MAX_ALIASES) {
      notes.links = true;
      break;
    }
    notes.aliases.push([aliasKey(link, scope), aliasKey(target, scope)]);
  }
  return {
    effects: {
      writes: expand(effects.writes, "name"),
      removes: expand(effects.removes, "parent"),
      dirs: expand(effects.dirs, "path"),
      special: expand(effects.special, "parent"),
      links,
      hardLinkSources: expand(effects.hardLinkSources, "parent"),
      trees: expand(effects.trees, "path"),
      aliases: effects.aliases
    },
    targets
  };
}
function judgeEffects(effects, scope) {
  const { effects: named, targets: linkTargets } = throughLinks(effects, scope);
  const e = {
    writes: asWindowsOpens(named.writes.map(tail)),
    removes: asWindowsOpens(named.removes.map(tail)),
    dirs: asWindowsOpens(named.dirs.map(tail)),
    special: asWindowsOpens(named.special.map(tail)),
    links: asWindowsOpens(named.links.map(tail)),
    hardLinkSources: asWindowsOpens(named.hardLinkSources.map(tail)),
    trees: named.trees.map(tail),
    aliases: []
  };
  const targets = asWindowsOpens(linkTargets.map(tail));
  const out = [];
  const judged = (rule, where) => {
    if (where === "inside") out.push({ ...rule });
    else if (where === "outside") out.push({ ...RULE_ELSEWHERE });
  };
  const configAt = (p) => isHookConfigPath(p) || globNamesConfig(p);
  judged(RULE_SPECIAL, worst([locate(e.special, isHookConfigPath, scope), locate(e.links, (p) => isHookConfigPath(p) || isHookConfigDir(p), scope)]));
  judged(RULE_WRITE, locate(e.writes, configAt, scope));
  const removesConfig = (p) => isHookConfigPath(p) || USER_CONFIG_DIR.test(p) || globNamesConfig(p, [USER_CONFIG_TAIL]);
  judged(RULE_REMOVE, locate(e.removes, removesConfig, scope));
  judged(RULE_DIR, locate(e.dirs, isHookConfigDir, scope));
  const linksGuarded = (p) => isHookConfigPath(p) || isHookConfigDir(p) || isSettingsPath(p, scope.configDirName) || CLAUDE_DIR.test(p);
  judged(RULE_HARD_LINK, locate(e.hardLinkSources, linksGuarded, scope));
  judged(RULE_LINK, locate(targets, (p) => linksGuarded(p) || MANAGED_SETTINGS_DIR.test(p), scope));
  if (e.trees.some((p) => isCatastrophicTarget(p, scope.tildeUsers) || isHomeTarget(p, scope.home))) out.push({ ...RULE_RM_ROOT });
  if (e.writes.some((p) => BLOCK_DEVICE.test(p))) out.push({ ...RULE_DISK_WRITE });
  const inRegistry = (p) => isRegistryPath(p, scope.dataDir);
  const registryOrData = (p) => inRegistry(p) || isDataDirPath(p, scope.dataDir);
  if (e.writes.some(inRegistry) || e.special.some(inRegistry) || e.hardLinkSources.some(inRegistry) || e.links.some(registryOrData) || e.dirs.some(registryOrData) || targets.some(registryOrData)) {
    out.push({ ...RULE_REGISTRY });
  }
  const settings = locate(e.writes, (p) => isSettingsPath(p, scope.configDirName), scope);
  if (settings !== null && loosens(scope)) judged(RULE_SETTINGS, settings);
  return out;
}
var RULE_PLUGIN_OFF = {
  id: "claude-plugin-disable",
  level: "block",
  reason: "Switches the guardrail hooks off through Claude Code's plugin command"
};
function turnsPluginOff(words, start) {
  let i = start;
  const head = words[i]?.value ?? "";
  if (commandName(head) === "npx" && /(?:^|\/)claude-code(?:@|$)/.test(words[i + 1]?.value ?? "")) i += 1;
  else if (commandName(head) !== "claude") return false;
  const rest = words.slice(i + 1).map((w) => w.value);
  if (rest[0] !== "plugin" && rest[0] !== "plugins") return false;
  const verbs = rest[1] === "marketplace" ? rest.slice(2, 3) : rest.slice(1, 2);
  if (!verbs.some((v) => /^(?:disable|uninstall|remove|rm)$/.test(v))) return false;
  return rest.some((a) => /dev-guardian/i.test(a));
}
var RULE_DB_ADOPT = {
  id: "db-adopt-yes",
  level: "block",
  reason: "db adopt --yes marks a database as trusted; run it yourself in a terminal after reading `db adopt` without --yes"
};
var CLI_NAME = /^(?:dev-guardian(?:@[\w.^~<>=-]*)?(?:\.(?:mjs|cjs|js|cmd|ps1|exe))?|guardian\.cjs)$/i;
var CLI_HOSTS = /* @__PURE__ */ new Set(["node", "nodejs", "bun", "deno", "tsx", "ts-node", "npx", "pnpx", "bunx", "npm", "pnpm", "yarn"]);
var CLI_HOST_SUBCOMMANDS = /* @__PURE__ */ new Set(["dlx", "exec", "x", "run"]);
function cliArgs(words, at) {
  const head = words[at];
  if (head === void 0) return void 0;
  if (CLI_NAME.test(basename(head.value))) return words.slice(at + 1).map((w) => w.value);
  if (!CLI_HOSTS.has(interpreterName(head.value))) return void 0;
  let subcommand = false;
  for (let i = at + 1; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v.startsWith("-")) {
      i += !v.includes("=") && (NODE_OPTION_VALUED.has(v) || LAUNCHER_VALUED.has(v)) ? 1 : 0;
      continue;
    }
    if (!subcommand && CLI_HOST_SUBCOMMANDS.has(v)) {
      subcommand = true;
      continue;
    }
    return CLI_NAME.test(basename(v)) ? words.slice(i + 1).map((w) => w.value) : void 0;
  }
  return void 0;
}
function adoptsDatabase(words, at) {
  const args = cliArgs(words, at);
  if (args === void 0) return false;
  const db = args.findIndex((a) => !a.startsWith("-"));
  if (args[db] !== "db" || !args.slice(db + 1).includes("adopt")) return false;
  return args.some((a) => a === "--yes" || a.startsWith("--yes="));
}
function adoptsDatabaseThroughLauncher(words, at) {
  return throughLauncher(words, at, adoptsDatabase);
}
function throughLauncher(words, at, runs) {
  const started = startProcessArgv(words, at);
  if (started !== void 0 && runs(started, 0)) return true;
  return findExecCommands(words, at).some((cmd) => runs(cmd, resolveCommand(cmd).index));
}
function updatesBaseline(words, at) {
  const args = cliArgs(words, at);
  if (args === void 0) return false;
  const plain = args.filter((a) => !a.startsWith("-"));
  return plain[0] === "baseline" && plain[1] === "update";
}
var RULE_BASELINE_UPDATE = {
  id: "baseline-update",
  level: "warn",
  reason: "dev-guardian baseline update accepts EVERY current finding into .guardian/baseline.json, new ones included, and the gate stops reporting them \u2014 the user decides. To accept one reviewed finding, suppress it inline with a reason (`nosemgrep: <rule> -- <reason>`, `# nosec`), or rebuild the baseline on the base commit"
};
var START_PROCESS = /* @__PURE__ */ new Set(["start-process", "saps", "start"]);
function plainWords(values) {
  return values.map((value) => ({ value, quoted: false }));
}
function startProcessArgv(words, at) {
  const sp = words.findIndex((w, i) => i <= at && START_PROCESS.has(commandName(w.value)));
  if (sp < 0) return void 0;
  let file;
  const list = [];
  const positional = [];
  let inList = false;
  for (let i = sp + 1; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    const param = /^-([A-Za-z]+)(?::([\s\S]*))?$/.exec(v);
    if (param !== null) {
      inList = false;
      const name = `-${param[1] ?? ""}`;
      const inline = param[2];
      if (PS_FILE_PATH.test(name)) file = inline ?? words[i += 1]?.value;
      else if (PS_ARGUMENT_LIST.test(name)) {
        inList = true;
        if (inline !== void 0) list.push(inline);
      } else if (inline === void 0 && /^-(?:verb|wo\w*|windowstyle|w|redirect\w*|credential|cred|environment)$/i.test(name)) i += 1;
      continue;
    }
    if (inList) list.push(v);
    else positional.push(v);
  }
  file ??= positional.shift();
  if (list.length === 0 && positional[0] !== void 0) list.push(positional[0]);
  if (file === void 0) return void 0;
  return plainWords([file, ...list.flatMap((a) => a.split(/\s+/).filter((s) => s !== ""))]);
}
function findExecCommands(words, at) {
  if (commandName(words[at]?.value ?? "") !== "find") return [];
  const out = [];
  let cmd;
  for (let i = at + 1; i < words.length; i += 1) {
    const w = words[i];
    if (w === void 0) continue;
    if (cmd === void 0) {
      if (/^-(?:exec|execdir|ok|okdir)$/.test(w.value)) cmd = [];
      continue;
    }
    if (w.value === ";" || w.value === "+" && words[i - 1]?.value === "{}") {
      out.push(cmd);
      cmd = void 0;
    } else cmd.push(w);
  }
  if (cmd !== void 0 && cmd.length > 0) out.push(cmd);
  return out;
}
function envSplitScript(words, end) {
  for (let i = 0; i < Math.min(end, words.length); i += 1) {
    if (commandName(words[i]?.value ?? "") !== "env") continue;
    for (let j = i + 1; j < words.length; j += 1) {
      const a = words[j]?.value ?? "";
      let value;
      let next = j + 1;
      const long = /^--split-string(?:=([\s\S]*))?$/.exec(a);
      const valued = /^-[^-]/.test(a) ? /[uCSa]/.exec(a.slice(1)) : null;
      if (long !== null) {
        if (long[1] !== void 0) value = long[1];
        else {
          value = words[j + 1]?.value;
          next = j + 2;
        }
      } else if (valued !== null && valued[0] === "S") {
        const rest = a.slice(valued.index + 2);
        if (rest !== "") value = rest;
        else {
          value = words[j + 1]?.value;
          next = j + 2;
        }
      } else if (/^-[^-]/.test(a) || a.startsWith("--")) {
        j += runnerOptionWords("env", a) - 1;
        continue;
      } else if (ASSIGNMENT.test(a) || a === "-") {
        continue;
      } else return void 0;
      if (value === void 0) return void 0;
      return [value, ...words.slice(next).map((w) => w.value)].join(" ");
    }
    return void 0;
  }
  return void 0;
}
function judgeCode(code, lang, scope) {
  const literals = codeLiterals(code, lang);
  const out = [];
  const placed = (rule, where) => {
    if (where === "inside") out.push({ ...rule });
    else if (where === "outside") out.push({ ...RULE_ELSEWHERE });
  };
  placed(RULE_INLINE, literalsNameHookConfig(literals, scope));
  const settings = literalsNameClaudeSettings(literals, scope);
  if (settings !== null && loosens(scope)) placed(RULE_SETTINGS, settings);
  if (literalsNameRegistry(literals, scope.dataDir)) out.push({ ...RULE_REGISTRY });
  return out;
}
function assessGuardConfig(words, start, scope) {
  const head = words[start];
  if (head === void 0) return [];
  const e = effectsOf(commandName(head.value), withoutRedirections(words.slice(start + 1)), scope.cwd);
  pushAll(e.writes, redirectTargets(words).map((t) => resolveFrom(scope.cwd, t)));
  const out = judgeEffects(e, scope);
  const commands = commandName(head.value) === "cmd" ? cmdInnerCommands(words.slice(start + 1).map((w) => w.value)) : [];
  for (const [cmdWords, at] of [[words, start], ...commands.map((c) => [c, 0])]) {
    if (turnsPluginOff(cmdWords, at)) out.push({ ...RULE_PLUGIN_OFF });
    const lang = codeLang(interpreterName(cmdWords[interpreterIndex(cmdWords, at)]?.value ?? ""));
    for (const code of inlineCode(cmdWords, at)) pushAll(out, judgeCode(code, lang, scope));
  }
  return out;
}
function isBareRemoteFetch(script) {
  const s = script.trim();
  const unwrapped = s.startsWith("$(") && s.endsWith(")") ? s.slice(2, -1).trim() : s.startsWith("`") && s.endsWith("`") ? s.slice(1, -1).trim() : s;
  return /^(?:curl|wget)\b/i.test(unwrapped);
}
var SHELLS = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "su", "pwsh", "powershell"]);
function shellScript(text) {
  return { text, powershell: false };
}
var DASH_C = /^-[A-Za-z]*c$/;
var FLOCK_VALUED = /^-[wE]$|^--(?:timeout|conflict-exit-code)$/;
function carrierScript(name, words, start) {
  const rest = words.slice(start + 1);
  const dashC = (w, nextWord) => {
    if (w === void 0) return void 0;
    if (w.value.startsWith("--command=")) return w.value.slice("--command=".length);
    return !w.quoted && (DASH_C.test(w.value) || w.value === "--command") ? nextWord?.value ?? "" : void 0;
  };
  const argv = (from) => rest.slice(from).map((x) => x.value).join(" ") || void 0;
  if (name === "trap") {
    let i = 0;
    while (i < rest.length && (rest[i]?.value ?? "").startsWith("-") && rest[i]?.value !== "--") i += 1;
    if (rest[i]?.value === "--") i += 1;
    const arg = rest[i]?.value;
    return arg !== void 0 && arg !== "-" && arg !== "" && rest.length > i + 1 ? arg : void 0;
  }
  if (name === "script") {
    for (let i = 0; i < rest.length; i += 1) {
      const c = dashC(rest[i], rest[i + 1]);
      if (c !== void 0) return c;
    }
    return void 0;
  }
  if (name === "runuser") {
    for (let i = 0; i < rest.length; i += 1) {
      const c = dashC(rest[i], rest[i + 1]);
      if (c !== void 0) return c;
      if (rest[i]?.value === "--") return argv(i + 1);
    }
    return void 0;
  }
  if (name === "flock") {
    let i = 0;
    while (i < rest.length && (rest[i]?.value ?? "").startsWith("-")) {
      const c2 = dashC(rest[i], rest[i + 1]);
      if (c2 !== void 0) return c2;
      i += FLOCK_VALUED.test(rest[i]?.value ?? "") ? 2 : 1;
    }
    const c = dashC(rest[i + 1], rest[i + 2]);
    return c !== void 0 ? c : argv(i + 1);
  }
  return null;
}
function nestedScripts(words, start) {
  const head = words[start];
  const name = head === void 0 ? "" : basename(head.value).toLowerCase();
  const carried = carrierScript(name, words, start);
  if (carried !== null) return carried === void 0 ? [] : [shellScript(carried)];
  const launcher = head === void 0 ? "" : commandName(head.value);
  if (launcher === "npx" || launcher === "pnpx" || launcher === "npm" && words[firstNonFlag(words, start + 1)]?.value === "exec") {
    for (let i = start + 1; i < words.length; i += 1) {
      const v = words[i]?.value ?? "";
      if (v === "-c" || v === "--call") return words[i + 1] === void 0 ? [] : [shellScript(words[i + 1]?.value ?? "")];
      if (v.startsWith("--call=")) return [shellScript(v.slice("--call=".length))];
      if (v === "--") break;
    }
  }
  if (head !== void 0 && basename(head.value) === "eval") {
    const script = words.slice(start + 1).map((w) => w.value).join(" ").trim();
    return script.length > 0 ? [shellScript(script)] : [];
  }
  if (launcher === "wsl") {
    const script = wslScript(words, start);
    return script === void 0 || script.trim() === "" ? [] : [shellScript(script)];
  }
  if (launcher === "iex" || launcher === "invoke-expression") {
    const args = words.slice(start + 1).filter((w, k) => !(k === 0 && !w.quoted && /^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i.test(w.value)));
    const script = args.map((w) => w.value).join(" ").trim();
    if (args.length > 0 && args.every((w) => !w.quoted && /^\$(?:\{[^}]*\}|[\w:?]+)$/.test(w.value))) {
      return [{ text: script, powershell: true, iex: true, unread: true }];
    }
    return script.length > 0 ? [{ text: script, powershell: true, iex: true }] : [];
  }
  let sawShell = false;
  for (let i = start; i < words.length; i += 1) {
    const word = words[i];
    if (word === void 0) continue;
    const name2 = commandName(word.value);
    if (!word.quoted && (name2 === "pwsh" || name2 === "powershell")) {
      return powershellCommand(
        words.slice(i + 1).map((w) => w.value),
        name2
      ).filter((s) => s.trim().length > 0).map((text) => ({ text, powershell: true }));
    }
    if (!word.quoted && DASH_C.test(word.value) && sawShell) {
      const script = scriptAfterDashC(words, i + 1);
      return script === void 0 ? [] : [shellScript(script)];
    }
    if (SHELLS.has(basename(word.value))) sawShell = true;
  }
  return [];
}
function scriptAfterDashC(words, from) {
  for (let j = from; j < words.length; j += 1) {
    const w = words[j];
    if (w === void 0) return void 0;
    if (!w.quoted && w.value === "--") return words[j + 1]?.value;
    if (!w.quoted && /^[-+][oO]$/.test(w.value)) {
      j += 1;
      continue;
    }
    if (!w.quoted && /^[-+][A-Za-z]+$/.test(w.value)) continue;
    return w.value;
  }
  return void 0;
}
var SHELL_VALUED = /^(?:[-+][oO]|--rcfile|--init-file)$/;
function scriptReader(words) {
  const plain = withoutRedirectWords(words);
  let at = resolveCommand(plain, PIPE_RUNNERS).index;
  if (commandName(plain[at]?.value ?? "") === "busybox") at += 1;
  const name = commandName(plain[at]?.value ?? "");
  const args = plain.slice(at + 1);
  if (name === "iex" || name === "invoke-expression") return args.length === 0 ? "powershell" : void 0;
  if (name === "pwsh" || name === "powershell") return powershellReadsStdin(args.map((w) => w.value)) ? "powershell" : void 0;
  if (name === "cmd") {
    const run = args.findIndex((a) => /^\/[ck]$/i.test(cmdSwitch(a.value)));
    if (run >= 0 && run < args.length - 1) return void 0;
    return args.every((a) => /^\/[A-Za-z]+$/.test(cmdSwitch(a.value))) ? "cmd" : void 0;
  }
  if (name === "source" || name === ".") return STDIN_PATHS.has(args[0]?.value ?? "") ? "shell" : void 0;
  if (name === "xargs") {
    const rest = plain.slice(at);
    const p = resolveCommand(rest).index;
    const program = commandName(rest[p]?.value ?? "");
    if (!SCRIPT_SHELLS.has(program) && program !== "su") return void 0;
    const c = rest.findIndex((w, k) => k > p && !w.quoted && DASH_C.test(w.value));
    if (c < 0) return void 0;
    const script = rest[c + 1]?.value;
    const replace = xargsReplacement(rest.slice(1, p).map((w) => w.value));
    return script === void 0 || replace !== void 0 && script.trim() === replace ? "shell" : void 0;
  }
  if (name === "script") {
    const c = args.findIndex((a) => /^(?:-[A-Za-z]*c|--command)$/.test(a.value) || a.value.startsWith("--command="));
    if (c < 0) return "shell";
    const program = args[c]?.value.startsWith("--command=") ? args[c]?.value.slice("--command=".length) : args[c + 1]?.value;
    const inner = program === void 0 ? void 0 : splitShell(program).statements;
    const only = inner?.length === 1 && inner[0]?.commands.length === 1 ? inner[0]?.commands[0] : void 0;
    return only === void 0 ? void 0 : scriptReader(only);
  }
  if (!STDIN_SHELLS.has(name)) return void 0;
  if (name === "su") return args.some((a) => /^(?:-[A-Za-z]*c|--command|--session-command)(?:=|$)/.test(a.value)) ? void 0 : "shell";
  for (let i = 0; i < args.length; i += 1) {
    const w = args[i];
    if (w === void 0) break;
    const v = w.value;
    if (w.quoted) return STDIN_PATHS.has(v) ? "shell" : void 0;
    if (v === "-") return "shell";
    if (v === "--") return args[i + 1] === void 0 || STDIN_PATHS.has(args[i + 1]?.value ?? "") ? "shell" : void 0;
    if (SHELL_VALUED.test(v)) {
      i += 1;
      continue;
    }
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(v)) return void 0;
    if (/^-[A-Za-z]*s[A-Za-z]*$/.test(v)) return "shell";
    if (/^[-+]/.test(v)) continue;
    return STDIN_PATHS.has(v) ? "shell" : void 0;
  }
  return "shell";
}
function readsScript(words) {
  return scriptReader(words) !== void 0;
}
function downloads(words) {
  return DOWNLOADERS.has(commandName(words[resolveCommand(words).index]?.value ?? ""));
}
function fedScripts(statement, reads, powershell = false) {
  const scripts = [];
  const first = statement.commands[0];
  if (statement.heredocBodies && first !== void 0 && reads(first)) {
    pushAll(scripts, statement.heredocBodies.map((text) => ({ text, reader: first })));
  }
  let downloaded = false;
  for (let c = 1; c < statement.commands.length; c += 1) {
    downloaded ||= downloads(statement.commands[c - 1] ?? []);
    const reader = statement.commands[c];
    if (reader === void 0 || !reads(reader)) continue;
    const fed = textOutputOf(statement.commands, { heredocs: statement.heredocBodies, powershell }, c);
    if (fed === "opaque") scripts.push({ text: "", reader, opaque: true });
    else if (fed === void 0) {
      if (!downloaded) scripts.push({ text: "", reader, unread: true });
    } else if (fed.trim().length > 0) scripts.push({ text: fed.trim(), reader });
  }
  return scripts;
}
var RULE_UNREAD_SCRIPT = {
  id: "unread-script",
  level: "warn",
  reason: "Runs text it could not read as a script (\u2026 | bash, gc x | iex, iex (\u2026), [scriptblock]::Create($x), \u2026 | cmd) \u2014 what it runs was not assessed"
};
var GROUP_CLOSERS = /^(\}|done|fi|esac)\s*\|/;
function groupFedScripts(statements, powershell) {
  const out = [];
  let afterOpen = 0;
  let brace = 0;
  let read = 0;
  for (let k = 0; k < statements.length; k += 1) {
    const statement = statements[k];
    if (statement === void 0) continue;
    const reader = statement.commands[0];
    const closer = GROUP_CLOSERS.exec(statement.masked)?.[1];
    const paren = /^\|/.test(statement.masked) && k > 0 && statements[k - 1]?.end === ")";
    if (reader !== void 0 && (closer !== void 0 || paren) && readsScript(reader)) {
      if (closer !== void 0 && closer !== "}") out.push({ text: "", reader, unread: true });
      else {
        const texts = [];
        let unread = false;
        for (let j = Math.max(paren ? afterOpen : brace, read); j < k; j += 1) {
          const text = textOutputOf(statements[j]?.commands ?? [], { heredocs: statements[j]?.heredocBodies, powershell });
          if (typeof text === "string") texts.push(text);
          else unread = true;
        }
        if (unread) out.push({ text: "", reader, unread: true });
        else if (texts.join("").trim() !== "") out.push({ text: texts.join("\n").trim(), reader });
      }
      read = k + 1;
    }
    if (/^\{/.test(statement.masked)) brace = k;
    if (statement.end === "(") afterOpen = k + 1;
  }
  return out;
}
function outputSubstitutionScripts(statements, powershell) {
  const out = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === void 0 || statement.end !== "(" || !statement.masked.endsWith(">")) continue;
    const reader = statements[k + 1]?.commands[0];
    if (reader === void 0 || !readsScript(reader)) continue;
    const members = statement.commands.map((words, c) => {
      if (c < statement.commands.length - 1) return words;
      let end = words.length;
      while (end > 0 && words[end - 1]?.value === ">") end -= 1;
      return words.slice(0, end);
    });
    const text = textOutputOf(members, { heredocs: statement.heredocBodies, powershell });
    if (text === "opaque") out.push({ text: "", reader, opaque: true });
    else if (text === void 0) out.push({ text: "", reader, unread: true });
    else if (text.trim() !== "") out.push({ text: text.trim(), reader });
  }
  return out;
}
function iexSubexpressionScripts(statements) {
  const out = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    const words = statement?.commands[statement.commands.length - 1];
    if (statement === void 0 || words === void 0 || statement.end !== "(") continue;
    const at = resolveCommand(words).index;
    const name = commandName(words[at]?.value ?? "");
    if (name !== "iex" && name !== "invoke-expression") continue;
    if (!words.slice(at + 1).every((w) => w.value === "$" || /^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i.test(w.value))) continue;
    const body = statements[k + 1];
    const text = body?.end === ")" ? textOutputOf(body.commands, { heredocs: body.heredocBodies, powershell: true }) : void 0;
    if (typeof text === "string") {
      if (text.trim() !== "") out.push({ text: text.trim(), reader: words, kind: "powershell" });
    } else out.push({ text: "", reader: words, unread: true });
  }
  return out;
}
var SCRIPT_BLOCK_CALL = /\[\s*(?:System\s*\.\s*Management\s*\.\s*Automation\s*\.\s*)?scriptblock\s*\]\s*::\s*Create\s*\(|\$ExecutionContext\s*\.\s*(?:SessionState\s*\.\s*)?InvokeCommand\s*\.\s*(?:InvokeScript|NewScriptBlock)\s*\(|\.\s*AddScript\s*\(/gi;
var MAX_SCRIPT_BLOCK_CALLS = 32;
var MAX_SCRIPT_BLOCK_ARG = 16 * 1024;
function scriptBlockScripts(text) {
  const out = [];
  let calls = 0;
  for (const m of text.matchAll(SCRIPT_BLOCK_CALL)) {
    if ((calls += 1) > MAX_SCRIPT_BLOCK_CALLS) {
      out.push("unread");
      break;
    }
    const from = m.index + m[0].length;
    const window = text.slice(from, from + MAX_SCRIPT_BLOCK_ARG);
    const literal = /^\s*(?:'((?:[^']|'')*)'|"((?:[^"`]|`.)*)")\s*\)/.exec(window);
    if (literal === null) out.push("unread");
    else out.push(literal[1] !== void 0 ? literal[1].replace(/''/g, "'") : (literal[2] ?? "").replace(/`(.)/g, "$1"));
  }
  return out;
}
var MAX_DECODED = 64 * 1024;
var RULE_DECODED_SCRIPT = {
  id: "decoded-script",
  level: "warn",
  reason: "Runs decoded text as a script (base64 -d, xxd -r, gunzip, openssl \u2026 fed to a shell or an interpreter) \u2014 what it runs could not be assessed"
};
function decoderOf(words) {
  const at = resolveCommand(words).index;
  const name = commandName(words[at]?.value ?? "");
  const args = withoutRedirections(words.slice(at + 1));
  if (name === "base64" || name === "base32" || name === "basenc") {
    if (!args.some((a) => /^(?:--decode|-[A-Za-z]*[dD][A-Za-z]*)$/.test(a))) return void 0;
    return name === "base64" ? "base64" : "other";
  }
  if (name === "openssl") {
    if (!args.includes("-d")) return void 0;
    return args.some((a) => a === "base64" || a === "-base64" || a === "-a") && !args.some((a) => /^-(?:aes|des|chacha|bf|camellia|in$)/.test(a)) ? "base64" : "other";
  }
  if (name === "xxd") return args.some((a) => /^-[A-Za-z]*r/.test(a)) ? "other" : void 0;
  if (name === "gzip" || name === "bzip2" || name === "xz" || name === "zstd" || name === "lz4") {
    return args.some((a) => a === "--decompress" || /^-[A-Za-z]*d/.test(a)) ? "other" : void 0;
  }
  return ["gunzip", "zcat", "bunzip2", "bzcat", "unxz", "xzcat", "unzstd", "zstdcat", "uudecode", "rev"].includes(name) ? "other" : void 0;
}
function decodeBase64(text) {
  const compact = text.replace(/\s+/g, "");
  if (compact.length === 0 || compact.length > MAX_DECODED || !/^[A-Za-z0-9+/=_-]+$/.test(compact)) return void 0;
  return Buffer.from(compact.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}
function hereStringText(words) {
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    if (w === void 0 || !w.value.startsWith("<<<") || w.redirectAt?.[0] !== 0) continue;
    const inline = w.value.slice(3);
    return inline.length > 0 ? inline : words[i + 1]?.value;
  }
  return void 0;
}
function textOutputOf(members, feed = {}, end = members.length) {
  let decodes = 0;
  const decoded = (text) => {
    let t = text;
    for (let k = 0; k < decodes; k += 1) {
      const d = decodeBase64(t);
      if (d === void 0) return "opaque";
      t = d;
    }
    return t;
  };
  for (let i = end - 1; i >= 0; i -= 1) {
    const last = members[i];
    if (last === void 0) return void 0;
    const lone = last.length === 1 ? last[0] : void 0;
    if (feed.powershell === true && i === 0 && lone !== void 0 && lone.quoted) return decoded(lone.value);
    const at = resolveCommand(last).index;
    const name = commandName(last[at]?.value ?? "");
    const args = withoutRedirections(last.slice(at + 1));
    if (name === "echo") return decoded(args.filter((a, k) => !(k === 0 && /^-[neE]+$/.test(a))).join(" "));
    if (name === "printf") return decoded(args[args.length - 1] ?? "");
    if (!(name === "cat" && args.every((a) => a === "-") || name === "tee")) {
      const decoder = decoderOf(last);
      if (decoder === void 0) return decodes > 0 ? "opaque" : void 0;
      if (decoder === "other") return "opaque";
      decodes += 1;
    }
    const here = hereStringText(last);
    if (here !== void 0) return decoded(here);
    if (feed.heredocs !== void 0 && feed.heredocs.length > 0) return decoded(feed.heredocs.join("\n"));
  }
  return decodes > 0 ? "opaque" : void 0;
}
function substitutionOutput(script) {
  const s = script.trim();
  const inner = s.startsWith("$(") && s.endsWith(")") ? s.slice(2, -1) : s.startsWith("`") && s.endsWith("`") ? s.slice(1, -1) : void 0;
  if (inner === void 0 || inner.length > MAX_DECODED) return void 0;
  const statements = splitShell(inner).statements;
  const only = statements.length === 1 ? statements[0] : void 0;
  return only === void 0 ? void 0 : textOutputOf(only.commands.map(expandWords));
}
function processSubstitutionScripts(statements) {
  const out = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === void 0 || statement.end !== "(" || !statement.masked.endsWith("<")) continue;
    const words = statement.commands[statement.commands.length - 1];
    const lastWord = words?.[words.length - 1];
    if (words === void 0 || lastWord === void 0 || lastWord.value !== "<" || lastWord.redirectAt?.[0] !== 0) continue;
    const head = words.slice(0, -1);
    const at = resolveCommand(head).index;
    const name = commandName(head[at]?.value ?? "");
    const shell = STDIN_SHELLS.has(name) && scriptOperand(head, at, name) === void 0 && !head.some((w) => !w.quoted && DASH_C.test(w.value));
    if (!shell && name !== "source" && name !== ".") continue;
    const texts = [];
    let opaque = false;
    for (let j = k + 1; j < statements.length; j += 1) {
      const body = statements[j];
      if (body === void 0) break;
      const text = textOutputOf(body.commands.map(expandWords), { heredocs: body.heredocBodies });
      if (text === "opaque") opaque = true;
      else if (text !== void 0) texts.push(text);
      if (body.end === ")") break;
    }
    if (opaque) out.push("opaque");
    if (texts.length > 0) out.push(texts.join("\n"));
  }
  return out;
}
function scanSubstitutionBody(command, from) {
  let depth = 1;
  let quote = "";
  for (let i = from; i < command.length; i += 1) {
    const ch = command.charAt(i);
    if (quote !== "") {
      if (quote === '"' && ch === "\\") i += 1;
      else if (ch === quote) quote = "";
      continue;
    }
    if (ch === "\\") i += 1;
    else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return { body: command.slice(from, i), next: i + 1 };
    }
  }
  return { body: command.slice(from), next: command.length };
}
function scanDoubleQuotedSubstitutions(command, from, out) {
  let i = from;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (ch === "\\") {
      i += 2;
      continue;
    }
    if (ch === '"') return i + 1;
    if (ch === "`") {
      let end = i + 1;
      while (end < command.length && !(command.charAt(end) === "`" && command.charAt(end - 1) !== "\\")) end += 1;
      out.push(command.slice(i + 1, end));
      i = end + 1;
      continue;
    }
    if (ch === "$" && command.charAt(i + 1) === "(" && command.charAt(i + 2) !== "(") {
      const sub = scanSubstitutionBody(command, i + 2);
      out.push(sub.body);
      i = sub.next;
      continue;
    }
    i += 1;
  }
  return command.length;
}
function quotedSubstitutions(command) {
  const out = [];
  let i = 0;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (ch === "\\") i += 2;
    else if (ch === "'") {
      const end = command.indexOf("'", i + 1);
      i = end < 0 ? command.length : end + 1;
    } else if (ch === '"') i = scanDoubleQuotedSubstitutions(command, i + 1, out);
    else i += 1;
  }
  return out;
}
var DOWNLOADERS = /* @__PURE__ */ new Set(["curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"]);
var PIPE_RUNNERS = /* @__PURE__ */ new Set(["sudo", "doas", "env", "command", "exec", "builtin", "nohup", "nice", "time", "timeout", "setsid", "stdbuf"]);
var STDIN_SHELLS = /* @__PURE__ */ new Set([...SHELLS, "fish", "csh", "tcsh"]);
var STDIN_PATHS = /* @__PURE__ */ new Set(["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"]);
var RULE_PIPE_TO_SHELL = {
  id: "remote-pipe-to-shell",
  level: "block",
  reason: "Pipes a downloaded script directly into a shell (curl|wget \u2026 | sh/bash)"
};
var RULE_FETCH_EXEC = {
  id: "remote-pipe-to-shell",
  level: "block",
  reason: "Executes the output of a remote download (curl/wget via $(\u2026) or `\u2026`)"
};
var RULE_IEX_DOWNLOAD = {
  id: "powershell-iex-download",
  level: "block",
  reason: "Downloads and executes remote code via Invoke-Expression"
};
var RULE_DOWNLOAD_RUN = {
  id: "download-then-run",
  level: "block",
  reason: "Downloads a file and runs it in the same command (DownloadFile / -OutFile, then &, ., Start-Process, \u2026)"
};
var RULE_POSIX_DOWNLOAD_RUN = {
  id: "download-then-run",
  level: "block",
  reason: "Downloads a file (curl -o / -O, wget, > file) and runs it in the same command (sh f, ./f, source f, python3 f, \u2026) with no checksum or signature check of that file in between"
};
function readsStdinAsScript(words, at) {
  const name = commandName(words[at]?.value ?? "");
  if (STDIN_SHELLS.has(name)) return true;
  if ((name === "source" || name === ".") && STDIN_PATHS.has(words[at + 1]?.value ?? "")) return true;
  if (name === "xargs") return xargsRunsStdin(words, at);
  const plain = withoutRedirectWords(words.slice(at));
  if (RUN_WRAPPERS.has(name) && words[at + 1]?.value === "run") return runWrapperReadsStdin(plain, 2, name === "uv");
  if (name === "uvx") return runWrapperReadsStdin(plain, 1, false);
  if (name === "uv" && words[at + 1]?.value === "tool" && words[at + 2]?.value === "run") return runWrapperReadsStdin(plain, 3, false);
  return isInterpreter(name) && isBareInterpreterStdin(plain);
}
var RUN_WRAPPER_VALUED = /* @__PURE__ */ new Set([
  "--with",
  "--with-editable",
  "--with-requirements",
  "-p",
  "--python",
  "--project",
  "--directory",
  "--env-file",
  "--extra",
  "--group",
  "--only-group",
  "--no-group",
  "--package",
  "--index",
  "--default-index",
  "-i",
  "--index-url",
  "--extra-index-url",
  "-f",
  "--find-links",
  "--config-file",
  "--cache-dir",
  "-C",
  "--config-setting",
  "-n",
  "--name",
  "--prefix",
  "--cwd",
  "-e",
  "--environment",
  "--from",
  "--manifest-path"
]);
function runWrapperReadsStdin(words, from, dashIsProgram) {
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v === "-") return dashIsProgram;
    if (v === "--") continue;
    if (v.startsWith("-")) {
      i += !v.includes("=") && RUN_WRAPPER_VALUED.has(v) ? 1 : 0;
      continue;
    }
    return isInterpreter(interpreterName(v)) && isBareInterpreterStdin(words.slice(i));
  }
  return false;
}
function xargsRunsStdin(words, at) {
  return xargsProgram(words, at) !== void 0;
}
function xargsProgram(words, at) {
  const rest = withoutRedirectWords(words.slice(at));
  const i = resolveCommand(rest).index;
  const name = commandName(rest[i]?.value ?? "");
  const last = rest[rest.length - 1]?.value ?? "";
  if (i >= rest.length - 1) return void 0;
  const replace = xargsReplacement(rest.slice(1, i).map((w) => w.value));
  if (SCRIPT_SHELLS.has(name) || name === "su") {
    if (DASH_C.test(last)) return "appended";
    const c = rest.findIndex((w, k) => k > i && !w.quoted && DASH_C.test(w.value));
    const script = c < 0 ? void 0 : rest[c + 1]?.value;
    if (script === void 0) return void 0;
    if (replace !== void 0 && script.includes(replace)) return "replaced";
    return runsItsArguments(script) ? "appended" : void 0;
  }
  if (!isInterpreter(name)) return void 0;
  if (/^(?:-[A-Za-z]*[ceE]|-r|--eval|--print|-p)$/.test(last)) return "appended";
  return replace !== void 0 && inlineCode(rest, i).some((code) => code.includes(replace)) ? "replaced" : void 0;
}
var POSITIONAL = /\$(?:[0-9@*]|\{[0-9@*]\})/;
function runsItsArguments(script) {
  if (!POSITIONAL.test(script)) return false;
  return splitShell(script).statements.some(
    (st) => st.commands.some((words) => {
      const at = resolveCommand(words).index;
      const head = words[at]?.value ?? "";
      if (POSITIONAL.test(head) && head.replace(POSITIONAL, "") === "") return true;
      return basename(head) === "eval" && words.slice(at + 1).some((w) => POSITIONAL.test(w.value));
    })
  );
}
function xargsReplacement(options) {
  let replace;
  for (let k = 0; k < options.length; k += 1) {
    const o = options[k] ?? "";
    if (o === "--replace") replace = "{}";
    else if (o.startsWith("--replace=")) replace = o.slice("--replace=".length) || "{}";
    else if (/^-[^-]/.test(o)) {
      for (let c = 1; c < o.length; c += 1) {
        const letter = o.charAt(c);
        const attached = o.slice(c + 1);
        if (letter === "I" || letter === "J") {
          replace = attached !== "" ? attached : options[k += 1];
          break;
        }
        if (letter === "i") {
          replace = attached !== "" ? attached : "{}";
          break;
        }
        if ("adELnPs".includes(letter)) {
          if (attached === "") k += 1;
          break;
        }
      }
    }
  }
  return replace === "" ? void 0 : replace;
}
function interpreterRunsFetch(statements, k) {
  const statement = statements[k];
  if (statement === void 0 || !statement.masked.endsWith("<")) return false;
  const words = statement.commands[statement.commands.length - 1];
  const lastWord = words?.[words.length - 1];
  if (words === void 0 || lastWord === void 0 || lastWord.value !== "<" || lastWord.redirectAt?.[0] !== 0) return false;
  const next = statements[k + 1]?.commands[0];
  if (next === void 0 || !["curl", "wget"].includes(commandName(next[resolveCommand(next).index]?.value ?? ""))) return false;
  const head = words.slice(0, -1);
  const at = resolveCommand(head).index;
  return interpreterProgram(head, at).kind === "none";
}
var RULE_PROCESS_FETCH = {
  id: "process-substitution-remote-fetch",
  level: "block",
  reason: "Executes a downloaded script via process substitution (bash <(curl \u2026))"
};
function pipesDownloadIntoShell(statement) {
  let downloaded = false;
  for (const words of statement.commands) {
    const at = resolveCommand(words, PIPE_RUNNERS).index;
    if (downloaded && readsStdinAsScript(words, at)) {
      const xargs = commandName(words[at]?.value ?? "") === "xargs" ? xargsProgram(words, at) : void 0;
      return xargs === "replaced" ? RULE_XARGS_REPLACED : RULE_PIPE_TO_SHELL;
    }
    if (DOWNLOADERS.has(commandName(words[at]?.value ?? ""))) downloaded = true;
  }
  return null;
}
function pipesDownloadIntoSubshell(statements) {
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === void 0 || statement.end !== "(" || !statement.masked.endsWith("|")) continue;
    if (!statement.commands.some((words) => DOWNLOADERS.has(commandName(words[resolveCommand(words, PIPE_RUNNERS).index]?.value ?? "")))) continue;
    let depth = 1;
    for (let j = k + 1; j < statements.length && depth > 0; j += 1) {
      const body = statements[j];
      if (body === void 0) break;
      const first = body.commands[0];
      if (first !== void 0 && readsStdinAsScript(first, resolveCommand(first, PIPE_RUNNERS).index)) return RULE_PIPE_TO_SHELL;
      if (body.end === "(") depth += 1;
      else if (body.end === ")") depth -= 1;
    }
  }
  return null;
}
function evalSubstitutionBodies(statements) {
  const out = [];
  for (let k = 0; k < statements.length - 1; k += 1) {
    const statement = statements[k];
    if (statement === void 0) continue;
    const words = statement.commands[statement.commands.length - 1];
    if (words === void 0 || basename(words[resolveCommand(words).index]?.value ?? "") !== "eval") continue;
    const backtick = statement.end === "`";
    const dollarParen = statement.end === "(" && words[words.length - 1]?.value === "$";
    if (!backtick && !dollarParen) continue;
    const body = [];
    let depth = 1;
    for (let j = k + 1; j < statements.length; j += 1) {
      const b = statements[j];
      if (b === void 0) break;
      body.push(b);
      if (backtick) {
        if (b.end === "`") break;
      } else if (b.end === "(") depth += 1;
      else if (b.end === ")") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    if (body.length > 0) out.push(body);
  }
  return out;
}
var RULE_XARGS_REPLACED = {
  id: "xargs-download-program",
  level: "block",
  reason: `Writes downloaded text into a program through xargs's replacement string (xargs -I{} sh -c '\u2026 {} \u2026'), where it runs as code; hand each line over as an argument instead: xargs -I{} sh -c '\u2026 "$1"' _ {} (sys.argv / process.argv for an interpreter)`
};
function hereStringFetchIntoShell(words, at) {
  if (!readsStdinAsScript(words, at) && !["source", "."].includes(commandName(words[at]?.value ?? ""))) return false;
  for (let i = at + 1; i < words.length; i += 1) {
    const w = words[i];
    if (w === void 0 || !w.value.startsWith("<<<") || w.redirectAt?.[0] !== 0) continue;
    const inline = w.value.slice(3);
    if (isBareRemoteFetch(inline.length > 0 ? inline : words[i + 1]?.value ?? "")) return true;
  }
  return false;
}
var PS_DOWNLOAD = /(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|start-bitstransfer)(?![\w-])|\.\s*(?:downloadstring|downloaddata|downloadfile|openread|getstringasync|getbytearrayasync|getstreamasync)\s*\(/i;
var PS_EXEC_TOKENS = /(?<run>(?<![\w$.\\/-])(?:iex|invoke-expression)(?![\w.-])|\[\s*(?:(?:system\s*\.\s*)?management\s*\.\s*automation\s*\.\s*)?scriptblock\s*\]\s*::\s*create\b|\.\s*(?:invokescript|newscriptblock)\b|(?<![\w-])-scriptblock\b)|(?<dl>(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)(?![\w-])|\.\s*(?:downloadstring|downloaddata|openread|getstringasync|getbytearrayasync|getstreamasync)\b)|(?<ref>\$(?:\{[^}\n]{0,128}\}|[\w:]+))(?<assign>\s*\+?=(?!=))?|(?<setvar>(?<![\w$.\\/-])(?:set-variable|new-variable|sv|nv)(?![\w.-]))|(?<getvar>(?<![\w$.\\/-])(?:get-variable|gv)(?![\w.-]))|(?<tee>(?<![\w$.\\/-])(?:tee-object|tee)(?![\w.-]))|(?<outvar>(?<![\w-])-(?:ov|outv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)\+?(?<outname>[A-Za-z_][\w:]*))?)|(?<teevar>(?<![\w-])-v(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)(?<teename>[A-Za-z_][\w:]*))?)|&&|\|\||[()|;\n]/gi;
function psVariable(spelled) {
  let v = spelled.toLowerCase();
  if (v.startsWith("$")) v = v.slice(1);
  if (v.startsWith("{") && v.endsWith("}")) v = v.slice(1, -1);
  return `$${v.replace(/^(?:global|script|local|private|using|variable):/, "")}`;
}
var VARIABLE_VALUED = ["value", "scope", "option", "description", "include", "exclude", "visibility"];
var VARIABLE_NAME_WINDOW = 256;
var MAX_VARIABLE_NAMES = 256;
function variableNamed(text, from) {
  const end = Math.min(text.length, from + VARIABLE_NAME_WINDOW);
  let named;
  let positional;
  let wantName = false;
  let skipValue = false;
  let i = from;
  while (i < end) {
    const c = text.charAt(i);
    if (c === " " || c === "	") {
      i += 1;
      continue;
    }
    if (c === ";" || c === "|" || c === "\n" || c === "&" || c === ")") break;
    let j = i + 1;
    if (c === "(") {
      for (let depth = 1; j < end && depth > 0; j += 1) {
        const d = text.charAt(j);
        if (d === "(") depth += 1;
        else if (d === ")") depth -= 1;
      }
    } else {
      while (j < end && !" 	;|&()\n".includes(text.charAt(j))) j += 1;
    }
    const word = text.slice(i, j);
    i = j;
    if (wantName) {
      wantName = false;
      named = /^[$\w{}:]+$/.test(word) ? psVariable(word) : "*";
      continue;
    }
    if (skipValue) {
      skipValue = false;
      continue;
    }
    const param = /^-([A-Za-z]+)(?::(.*))?$/.exec(word);
    if (param !== null) {
      const p = (param[1] ?? "").toLowerCase();
      const inline = param[2];
      if ("name".startsWith(p)) {
        if (inline === void 0) wantName = true;
        else named = /^[$\w{}:]+$/.test(inline) ? psVariable(inline) : "*";
      } else if (inline === void 0 && p.length >= 2 && VARIABLE_VALUED.some((v) => v.startsWith(p))) skipValue = true;
      continue;
    }
    positional ??= /^[\w{}:]+$/.test(word) ? psVariable(word) : "*";
  }
  return named ?? positional ?? "*";
}
function powershellDownloadExecution(text) {
  if (!/iex|invoke-expression|scriptblock|invokescript/i.test(text)) return false;
  const opens = [];
  let inIex = 0;
  let pendingIex = false;
  let downloaded = false;
  let piped = false;
  let assigning = [];
  const tainted = /* @__PURE__ */ new Set();
  let inTee = false;
  let afterIexParen = false;
  let names = 0;
  const holdsDownload = (v) => tainted.has(v) || tainted.has("*") || v === "*" && tainted.size > 0;
  const download = () => {
    if (inIex > 0 || pendingIex) return true;
    downloaded = true;
    for (const v of assigning) tainted.add(v);
    return false;
  };
  const fills = (v) => {
    assigning.push(v);
    if (downloaded) tainted.add(v);
  };
  const nameAfter = (at) => ++names > MAX_VARIABLE_NAMES ? "*" : variableNamed(text, at);
  for (const m of text.matchAll(PS_EXEC_TOKENS)) {
    const t = m[0].toLowerCase();
    const g = m.groups ?? {};
    const afterParen = afterIexParen;
    afterIexParen = false;
    if (g["run"] !== void 0) {
      if (piped) return true;
      pendingIex = true;
    } else if (g["dl"] !== void 0) {
      if (download()) return true;
      if (afterParen && t.startsWith(".")) return true;
    } else if (g["ref"] !== void 0) {
      const v = psVariable(g["ref"]);
      if (g["assign"] !== void 0) assigning = [v];
      else if (holdsDownload(v) && download()) return true;
    } else if (g["setvar"] !== void 0) {
      fills(nameAfter(m.index + m[0].length));
    } else if (g["getvar"] !== void 0) {
      if (holdsDownload(nameAfter(m.index + m[0].length)) && download()) return true;
    } else if (g["tee"] !== void 0) {
      inTee = true;
    } else if (g["outvar"] !== void 0) {
      fills(g["outname"] === void 0 ? "*" : psVariable(g["outname"]));
    } else if (g["teevar"] !== void 0) {
      if (inTee) fills(g["teename"] === void 0 ? "*" : psVariable(g["teename"]));
    } else if (t === "(") {
      opens.push(pendingIex);
      if (pendingIex) inIex += 1;
      pendingIex = false;
    } else if (t === ")") {
      if (opens.pop() === true) {
        inIex -= 1;
        afterIexParen = true;
      }
      pendingIex = false;
    } else if (t === "|") {
      if (downloaded) piped = true;
      pendingIex = false;
      inTee = false;
    } else {
      downloaded = false;
      piped = false;
      pendingIex = false;
      assigning = [];
      inTee = false;
    }
  }
  return false;
}
function runKey(path) {
  return stripQuotes(path.trim()).replace(/\\/g, "/").replace(/^(?:\.\/)+/, "").replace(/\/{2,}/g, "/").toLowerCase();
}
var DOWNLOAD_FILE_CALL = /\.\s*DownloadFile(?:Async|TaskAsync)?\s*\(/gi;
var SAVING_CMDLETS = /* @__PURE__ */ new Set(["iwr", "irm", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer", "curl", "wget"]);
var SAVE_PARAM = /^-(?:outf(?:i(?:le?)?)?|dest(?:i(?:n(?:a(?:t(?:i(?:on?)?)?)?)?)?)?)(?::(.*))?$/i;
var CURL_SHORT_VALUED = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
var WGET_SHORT_VALUED = "OoPtTwUeiaBQlDIXRA";
var URL_ARG = /^[a-z][a-z0-9+.-]*:\/\//i;
function remoteName(url, fallback) {
  const path = url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, "").replace(/[?#].*$/, "");
  const last = path.split("/").pop() ?? "";
  return last !== "" ? last : fallback;
}
function posixSaves(name, words, at) {
  if (name !== "curl" && name !== "wget") return [];
  const wget = name === "wget";
  const valued = wget ? WGET_SHORT_VALUED : CURL_SHORT_VALUED;
  const saved = [...redirectTargets(words.slice(at + 1))];
  const urls = [];
  let named = false;
  let remote = false;
  let dir = "";
  const save = (f) => {
    if (f === void 0 || f === "" || f === "-") {
      if (f === "-") named = true;
      return;
    }
    named = true;
    saved.push(f);
  };
  const args = words.slice(at + 1).map((w) => w.value);
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    const long = /^--([a-z-]+)(?:=(.*))?$/i.exec(a);
    if (long !== null) {
      const flag = (long[1] ?? "").toLowerCase();
      const value = () => long[2] !== void 0 ? long[2] : args[i += 1];
      if (!wget && flag === "output") save(value());
      else if (wget && flag === "output-document") save(value());
      else if (!wget && (flag === "remote-name" || flag === "remote-name-all")) remote = true;
      else if (!wget && flag === "output-dir" || wget && flag === "directory-prefix") dir = value() ?? "";
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      for (let k = 1; k < a.length; k += 1) {
        const c = a.charAt(k);
        if (!wget && c === "O") remote = true;
        if (!valued.includes(c)) continue;
        const v = k < a.length - 1 ? a.slice(k + 1) : args[i += 1];
        if (wget && c === "O" || !wget && c === "o") save(v);
        else if (wget && c === "P") dir = v ?? "";
        break;
      }
      continue;
    }
    if (URL_ARG.test(a)) urls.push(a);
  }
  if (wget && !named || !wget && remote && !named) {
    for (const url of urls) {
      const file = remoteName(url, wget ? "index.html" : void 0);
      if (file !== void 0) saved.push(dir === "" ? file : `${dir.replace(/[\\/]+$/, "")}/${file}`);
    }
  } else if (dir !== "") {
    return saved.map((f) => isAbsolutePath(f) ? f : `${dir.replace(/[\\/]+$/, "")}/${f}`);
  }
  return saved;
}
function pipedSaves(name, words, at) {
  const out = redirectTargets(words.slice(at + 1));
  pushAll(out, commandWriteDestinations(name, withoutRedirections(words.slice(at + 1))).filter((f) => !f.startsWith("-")));
  return out;
}
function powershellSaves(name, words, at) {
  if (!SAVING_CMDLETS.has(name)) return [];
  const out = [];
  for (let i = at + 1; i < words.length; i += 1) {
    const m = SAVE_PARAM.exec(words[i]?.value ?? "");
    if (m === null) continue;
    const dest = m[1] !== void 0 && m[1] !== "" ? m[1] : words[i + 1]?.value;
    if (dest !== void 0 && dest.trim() !== "") out.push(dest);
  }
  return out;
}
function downloadFileCalls(text) {
  if (!/downloadfile/i.test(text)) return [];
  const out = [];
  const unquotedAt = quoteTracker(text);
  for (const m of text.matchAll(DOWNLOAD_FILE_CALL)) {
    if (!unquotedAt(m.index)) continue;
    const { args } = callArgs(text, m.index + m[0].length);
    const second = args[1];
    const literals = codeLiterals(args[0] ?? "", "other");
    const dest = second !== void 0 ? argPath(second) : literals.length >= 2 ? literals[literals.length - 1] : void 0;
    if (dest !== void 0 && dest.trim() !== "") out.push(dest);
  }
  return out;
}
var SCRIPT_SHELLS = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish", "csh", "tcsh"]);
var OPENERS2 = /* @__PURE__ */ new Set(["start", "start-process", "saps", "invoke-item", "ii"]);
var RUNS_ARGUMENT = /* @__PURE__ */ new Set(["msiexec", "cscript", "wscript", "rundll32", "iex", "invoke-expression"]);
var READERS = /* @__PURE__ */ new Set(["get-content", "gc", "cat", "type"]);
var RUNNABLE_EXTENSIONS = /* @__PURE__ */ new Set([
  "exe",
  "com",
  "bat",
  "cmd",
  "msi",
  "msp",
  "msix",
  "msixbundle",
  "appx",
  "appxbundle",
  "ps1",
  "psm1",
  "vbs",
  "vbe",
  "js",
  "jse",
  "wsf",
  "wsh",
  "hta",
  "scr",
  "cpl",
  "jar",
  "reg",
  "lnk",
  "application",
  "appref-ms",
  "sh",
  "bash",
  "command",
  "py",
  "pyw",
  "pl",
  "rb",
  "php",
  "app",
  "pkg"
]);
function isRunnableName(path) {
  const last = stripQuotes(path).split(/[\\/]/).pop() ?? "";
  const ext = /\.([A-Za-z0-9-]+)$/.exec(last)?.[1];
  return ext === void 0 || RUNNABLE_EXTENSIONS.has(ext.toLowerCase());
}
var PS_ARGUMENT_LIST = /^-(?:args|a(?:r(?:g(?:u(?:m(?:e(?:n(?:t(?:l(?:i(?:st?)?)?)?)?)?)?)?)?)?)?)$/i;
var PS_FILE_PATH = /^-(?:f(?:i(?:l(?:e(?:p(?:a(?:th?)?)?)?)?)?)?|path|pspath|lp)$/i;
function scriptOperand(words, at, name) {
  const rest = words.slice(at + 1);
  if (SCRIPT_SHELLS.has(name)) {
    if (rest.some((w) => !w.quoted && DASH_C.test(w.value))) return void 0;
    return withoutRedirections(rest).find((v) => !v.startsWith("-"));
  }
  const plain = withoutRedirectWords(words.slice(at));
  const program = interpreterProgram(plain, 0);
  if (program.kind === "file") return plain[program.index]?.value;
  if (program.kind !== "unknown") return void 0;
  if (inlineCode(words, at).length > 0 || rest.some((w) => /^-[A-Za-z]*m$/.test(w.value))) return void 0;
  return withoutRedirections(rest).find((v) => !v.startsWith("-"));
}
function runsStdin(words, at) {
  return readsStdinAsScript(words, at);
}
function commandRuns(statement, c, heads, pipedIntoRunner) {
  const words = statement.commands[c];
  const at = heads[c] ?? 0;
  const head = words?.[at];
  if (words === void 0 || head === void 0) return [];
  const name = commandName(head.value);
  const out = [];
  const rest = withoutRedirections(words.slice(at + 1));
  const operands2 = rest.filter((v) => v !== "" && !v.startsWith("-") && !/^\/[A-Za-z]+$/.test(v));
  if (name === "." || name === "source") {
    if (rest[0] !== void 0) out.push(rest[0]);
  } else if (name === "powershell" || name === "pwsh") {
    const file = rest.findIndex((v) => /^-f(?:i(?:le?)?)?$/i.test(v));
    if (file >= 0) out.push(rest[file + 1] ?? "");
    else out.push(...operands2);
  } else if (name === "cmd") {
    const run = rest.findIndex((v) => /^\/[ck]$/i.test(cmdSwitch(v)));
    if (run >= 0) out.push(rest[run + 1] ?? "");
  } else if (SCRIPT_SHELLS.has(name) || isInterpreter(name)) {
    const script = scriptOperand(words, at, name);
    if (script !== void 0) out.push(script);
  } else if (OPENERS2.has(name)) {
    const files = [];
    for (let i = 0; i < rest.length; i += 1) {
      const v = rest[i] ?? "";
      if (PS_ARGUMENT_LIST.test(v)) files.push(...(rest[i += 1] ?? "").split(/[\s,]+/));
      else if (PS_FILE_PATH.test(v)) files.push(rest[i += 1] ?? "");
      else if (v.startsWith("-")) i += /^-(?:verb|wo\w*|windowstyle|w|redirect\w*|credential|cred)$/i.test(v) ? 1 : 0;
      else files.push(v);
    }
    out.push(...files.filter((f) => f !== "" && !/^\/[A-Za-z]+$/.test(f) && isRunnableName(f)));
  } else if (RUNS_ARGUMENT.has(name)) {
    out.push(...operands2);
  } else if (READERS.has(name) && pipedIntoRunner) {
    out.push(...operands2);
  }
  return out.filter((f) => f !== "");
}
function pipedIntoRunners(statement, heads) {
  const out = new Array(statement.commands.length).fill(false);
  let later = false;
  for (let c = statement.commands.length - 1; c >= 0; c -= 1) {
    out[c] = later;
    const words = statement.commands[c] ?? [];
    const i = heads[c] ?? 0;
    const n = commandName(words[i]?.value ?? "");
    if (n === "iex" || n === "invoke-expression" || runsStdin(words, i)) later = true;
  }
  return out;
}
var MAY_DOWNLOAD = /curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadfile/i;
function isIntegrityCheck(words, at) {
  const name = commandName(words[at]?.value ?? "");
  const args = words.slice(at + 1).map((w) => w.value);
  if (/^(?:sha(?:1|224|256|384|512)sum|b2sum|shasum)$/.test(name)) {
    return args.some((a) => a === "--check" || /^-[A-Za-z]*c[A-Za-z]*$/.test(a));
  }
  if (name === "gpg" || name === "gpg2") return args.includes("--verify");
  if (name === "gpgv") return true;
  if (name === "minisign" || name === "signify") return args.some((a) => /^-[A-Za-z]*V/.test(a));
  if (name === "cosign") return args.includes("verify-blob");
  if (name === "openssl") return args.some((a) => a === "-verify" || a === "-prverify");
  return false;
}
function cwdFor(name, args, cwd) {
  if (CD_RETURNS.has(name)) return "";
  if (!CD_COMMANDS.has(name)) return cwd;
  const dir = psParam(args, ["path", "literalpath"]) ?? args.find((a) => !(a.startsWith("-") || /^\/d$/i.test(a)));
  if (dir === void 0) return "~";
  const next = resolveFrom(cwd, dir);
  return next.length > MAX_CWD ? "" : next;
}
var TRANSFERS = /* @__PURE__ */ new Set(["mv", "cp", "install", "copy-item", "cpi", "copy", "move-item", "mi", "move"]);
var PATH_DIRS = /^(?:\/usr\/local\/s?bin|\/usr\/s?bin|\/s?bin|\/opt\/homebrew\/bin|\/opt\/local\/bin|(?:~|\$\{?home\}?)\/(?:\.local\/)?bin)$/i;
function transfersOf(name, words, at) {
  if (!TRANSFERS.has(name)) return [];
  const args = withoutRedirections(words.slice(at + 1));
  if (name === "install" && args.some((a) => a === "-d" || a === "--directory")) return [];
  const t = parseTransfer(args, name === "copy" || name === "move");
  const dest = t.dest;
  if (dest === void 0) return [];
  return t.sources.map((from) => {
    const inside = `${dest.replace(/[\\/]+$/, "")}/${lastSegment(from)}`;
    return { from, to: t.into ? [inside] : [dest, inside] };
  });
}
var GPG_VALUED = /* @__PURE__ */ new Set([
  "--keyring",
  "--primary-keyring",
  "--secret-keyring",
  "--homedir",
  "--trustdb-name",
  "--options",
  "--status-fd",
  "--logger-fd",
  "--attribute-fd",
  "--passphrase-fd",
  "--command-fd",
  "--status-file",
  "--logger-file",
  "--default-key",
  "-u",
  "--local-user",
  "-r",
  "--recipient",
  "-o",
  "--output",
  "--trusted-key",
  "--trust-model",
  "--verify-options",
  "--assert-signer",
  "--weak-digest",
  "--auto-key-locate",
  "--keyserver",
  "--keyserver-options",
  "--compress-algo",
  "--cipher-algo",
  "--digest-algo",
  "--display-charset",
  "--charset"
]);
function gpgOperands(args, gpgv) {
  const out = [];
  let verifying = gpgv;
  let optionsDone = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (!optionsDone && a === "--verify") verifying = true;
    else if (!optionsDone && a === "--") optionsDone = true;
    else if (!optionsDone && a.startsWith("-") && a !== "-") i += !a.includes("=") && GPG_VALUED.has(a) ? 1 : 0;
    else if (verifying) out.push(a);
  }
  return out;
}
var SIDECAR = /^(.+)\.(?:sha(?:1|224|256|384|512)(?:sum)?|asc|sig|minisig)$/;
function integrityCheckOf(statement, heads, cwd) {
  const last = statement.commands.length - 1;
  const words = statement.commands[last];
  const at = heads[last] ?? 0;
  if (words === void 0 || !isIntegrityCheck(words, at)) return void 0;
  const key = (token) => runKey(resolveFrom(cwd, token));
  const names = [];
  statement.commands.forEach((member, c) => {
    for (const w of member.slice((heads[c] ?? 0) + 1)) {
      for (const token of w.value.split(/\s+/)) if (token !== "" && !token.startsWith("-")) names.push(key(token));
    }
  });
  const tool = commandName(words[at]?.value ?? "");
  const args = withoutRedirections(words.slice(at + 1));
  const sumTool = /^(?:sha(?:1|224|256|384|512)sum|b2sum|shasum)$/.test(tool);
  const lists = sumTool ? args.filter((v) => !v.startsWith("-") && !/^\d+$/.test(v)).map(key) : [];
  const implying = sumTool ? names.slice() : [];
  if (tool === "gpg" || tool === "gpg2" || tool === "gpgv") {
    const operands2 = gpgOperands(args, tool === "gpgv");
    const signature = operands2[0];
    if (operands2.length === 1 && signature !== void 0) implying.push(key(signature));
  }
  const implied = implying.flatMap((name) => SIDECAR.exec(name)?.[1] ?? []);
  return { names, lists, implied };
}
function archiveExtraction(name, words, at) {
  const args = withoutRedirections(words.slice(at + 1));
  const out = {};
  if (name === "unzip") {
    for (let i = 0; i < args.length; i += 1) {
      const a = args[i] ?? "";
      if (a === "-d") out.dir = args[i += 1];
      else if (a.startsWith("-d") && a.length > 2) out.dir = a.slice(2);
      else if (!a.startsWith("-") && out.archive === void 0) out.archive = a;
    }
    return out.archive === void 0 ? void 0 : out;
  }
  if (name !== "tar" && name !== "bsdtar" && name !== "gtar") return void 0;
  let extract = false;
  const pending = [];
  const take = (letter, value) => {
    if (letter === "f") out.archive = value;
    else out.dir = value;
  };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    if (a === "--extract" || a === "--get") {
      extract = true;
      continue;
    }
    const long = /^--(directory|file)(?:=(.*))?$/.exec(a);
    if (long !== null) {
      take(long[1] === "file" ? "f" : "C", long[2] ?? args[i += 1]);
      continue;
    }
    if (a.startsWith("--")) continue;
    const option = a.startsWith("-") && a !== "-";
    if (!option && i > 0) {
      const letter = pending.shift();
      if (letter !== void 0) take(letter, a);
      continue;
    }
    const cluster = option ? a.slice(1) : a;
    for (let c = 0; c < cluster.length; c += 1) {
      const letter = cluster.charAt(c);
      if (letter === "x") extract = true;
      if (letter !== "f" && letter !== "C") continue;
      const rest = cluster.slice(c + 1);
      if (option && rest !== "") {
        take(letter, rest);
        break;
      }
      pending.push(letter);
      if (option) break;
    }
  }
  return extract ? out : void 0;
}
var NOT_FROM_ARCHIVE = /* @__PURE__ */ new Set([
  "echo",
  "printf",
  "cd",
  "pwd",
  "export",
  "unset",
  "set",
  "true",
  "false",
  "test",
  "[",
  "[[",
  "command",
  "type",
  "hash",
  "which",
  "whereis",
  "ls",
  "chmod",
  "chown",
  "chgrp",
  "rm",
  "rmdir",
  "mv",
  "cp",
  "ln",
  "mkdir",
  "touch",
  "cat",
  "head",
  "tail",
  "grep",
  "sed",
  "awk",
  "sort",
  "wc",
  "file",
  "stat",
  "du",
  "df",
  "tar",
  "bsdtar",
  "gzip",
  "gunzip",
  "xz",
  "unzip",
  "curl",
  "wget",
  "install",
  "sleep",
  "date",
  "uname",
  "id",
  "whoami",
  "exit",
  "sha256sum",
  "sha512sum",
  "shasum",
  "gpg",
  "readlink",
  "realpath",
  "basename",
  "dirname",
  "tee",
  "find",
  "source",
  ".",
  "popd",
  "pushd"
]);
function downloadsThenRuns(text, statements, bareRunsCwd) {
  if (!MAY_DOWNLOAD.test(text)) return null;
  const downloads2 = /* @__PURE__ */ new Map();
  for (const dest of downloadFileCalls(text)) downloads2.set(runKey(resolveFrom("", dest)), { at: -1, kind: "powershell" });
  const pathBins = /* @__PURE__ */ new Map();
  const verified = /* @__PURE__ */ new Map();
  let listAt = -2;
  let errexit = false;
  let errexitHolds = true;
  let cwd = "";
  const extracted = /* @__PURE__ */ new Map();
  for (let k = 0; k < statements.length; k += 1) {
    const statement = statements[k];
    if (statement === void 0) continue;
    const heads = statement.commands.map((words) => resolveCommand(words).index);
    const ran = [];
    const saved = [];
    const reading = downloads2.size > 0 || extracted.size > 0;
    const piped = reading ? pipedIntoRunners(statement, heads) : [];
    let streaming;
    let fromArchive;
    const downloadedArchive = (archive) => {
      if (archive === void 0 || archive === "-") return streaming;
      const key = runKey(resolveFrom(cwd, archive));
      const d = downloads2.get(key);
      return d !== void 0 && !((verified.get(key) ?? -3) > d.at) && !(listAt > d.at) ? d.kind : void 0;
    };
    statement.commands.forEach((words, c) => {
      const at = heads[c] ?? 0;
      const head = words[at]?.value ?? "";
      const name = commandName(head);
      const posix = posixSaves(name, words, at);
      const ps = powershellSaves(name, words, at);
      for (const dest of posix) saved.push({ key: runKey(resolveFrom(cwd, dest)), kind: "posix" });
      for (const dest of ps) saved.push({ key: runKey(resolveFrom(cwd, dest)), kind: "powershell" });
      if (streaming !== void 0) {
        const kind = streaming;
        for (const dest of pipedSaves(name, words, at)) saved.push({ key: runKey(resolveFrom(cwd, dest)), kind });
      }
      const extraction = archiveExtraction(name, words, at);
      if (extraction !== void 0) {
        const dir = runKey(resolveFrom(cwd, extraction.dir ?? ".")).replace(/\/+$/, "");
        const kind = downloadedArchive(extraction.archive);
        if (kind !== void 0 && PATH_DIRS.test(dir) && !extracted.has(dir)) extracted.set(dir, { at: k, kind });
      }
      if (DOWNLOADERS.has(name) && posix.length === 0 && ps.length === 0) {
        streaming = name === "curl" || name === "wget" ? "posix" : "powershell";
      }
      if (reading) {
        for (const file of commandRuns(statement, c, heads, piped[c] === true)) ran.push(runKey(resolveFrom(cwd, file)));
        if (/[\\/]/.test(head)) ran.push(runKey(resolveFrom(cwd, head)));
        else if (head !== "") {
          const onPath = pathBins.get(head.toLowerCase());
          if (onPath !== void 0) ran.push(onPath);
          if (!NOT_FROM_ARCHIVE.has(head.toLowerCase())) {
            for (const e of extracted.values()) if (e.at < k) fromArchive ??= e.kind;
          }
          if (bareRunsCwd) {
            for (const ext of /\.[A-Za-z0-9]+$/.test(head) ? [""] : ["", ".exe", ".cmd", ".bat", ".com"]) {
              ran.push(runKey(resolveFrom(cwd, `${head}${ext}`)));
            }
          }
        }
        for (const { from, to } of transfersOf(name, words, at)) {
          const src = runKey(resolveFrom(cwd, from));
          const mark = downloads2.get(src);
          if (mark === void 0) continue;
          for (const dest of to) {
            const key = runKey(resolveFrom(cwd, dest));
            downloads2.set(key, mark);
            const check2 = verified.get(src);
            if (check2 !== void 0) verified.set(key, check2);
            const bin = lastSegment(key);
            if (PATH_DIRS.test(dirOf(key)) && bin !== "") pathBins.set(bin, key);
          }
        }
      }
      cwd = cwdFor(name, withoutRedirections(words.slice(at + 1)), cwd);
    });
    const only = statement.commands.length === 1 ? statement.commands[0] : void 0;
    const lone = only !== void 0 && only.length === 1 ? commandName(only[0]?.value ?? "") : "";
    const next = statements[k + 1]?.commands[0];
    if (reading && (lone === "iex" || lone === "invoke-expression") && next !== void 0 && READERS.has(commandName(next[0]?.value ?? ""))) {
      for (const w of next.slice(1)) if (!w.value.startsWith("-")) ran.push(runKey(resolveFrom(cwd, w.value)));
    }
    for (const file of ran) {
      const d = downloads2.get(file);
      if (d !== void 0 && d.at < k && !((verified.get(file) ?? -3) > d.at) && !(listAt > d.at)) return d.kind;
      const e = extracted.get(dirOf(file));
      if (e !== void 0 && e.at < k) return e.kind;
    }
    if (fromArchive !== void 0) return fromArchive;
    for (const { key, kind } of saved) {
      downloads2.set(key, { at: k, kind });
      verified.delete(key);
      const bin = lastSegment(key);
      if (PATH_DIRS.test(dirOf(key)) && bin !== "") pathBins.set(bin, key);
    }
    const lead = /^\s*(\S+)/.exec(statement.masked)?.[1] ?? "";
    if (COMPOUND_WORDS.has(lead) || statement.end === "(" || statement.end === ")" || statement.end === "`") errexitHolds = false;
    const setting = statement.end !== "&" ? errexitSetting(statement) : void 0;
    if (setting !== void 0) errexit = setting;
    const check = statements[k - 1]?.end === "||" ? void 0 : integrityCheckOf(statement, heads, cwd);
    if (check !== void 0) {
      for (const name of check.names) if (downloads2.has(name)) verified.set(name, k);
      for (const name of check.implied) verified.set(name, k);
      if (check.lists.some((list) => downloads2.has(list))) listAt = k;
    }
    const carried = statement.end === "&&" || errexit && errexitHolds && (statement.end === ";" || statement.end === "\n");
    if (!carried) {
      verified.clear();
      listAt = -2;
    }
  }
  return null;
}
var COMPOUND_WORDS = /* @__PURE__ */ new Set([
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "for",
  "while",
  "until",
  "do",
  "done",
  "case",
  "esac",
  "select",
  "function",
  "{",
  "}",
  "!",
  "[[",
  "]]",
  "coproc"
]);
function errexitSetting(statement) {
  if (statement.commands.length !== 1) return void 0;
  const words = statement.commands[0] ?? [];
  if (words[0]?.value !== "set") return void 0;
  let out;
  for (let i = 1; i < words.length; i += 1) {
    const m = /^([-+])([A-Za-z]+)$/.exec(words[i]?.value ?? "");
    if (m === null) break;
    const on = m[1] === "-";
    const letters = m[2] ?? "";
    if (letters.includes("e")) out = on;
    if (letters.endsWith("o")) {
      if (words[i + 1]?.value === "errexit") out = on;
      i += 1;
    }
  }
  return out;
}
function cdpathValue(word) {
  const m = /^CDPATH=(.*)$/.exec(word);
  return m === null ? void 0 : (m[1] ?? "").split(":").filter((d) => d !== "");
}
function moveCwd(scope, words, at) {
  const head = words[at];
  const exported = head !== void 0 && commandName(head.value) === "export";
  for (const w of exported ? words.slice(at + 1) : head === void 0 ? words : []) {
    const dirs = cdpathValue(w.value);
    if (dirs !== void 0) scope.cdpath = dirs;
  }
  if (head === void 0) return;
  const name = commandName(head.value);
  const args = withoutRedirections(words.slice(at + 1));
  const prefix = words.slice(0, at).map((w) => cdpathValue(w.value)).find((d) => d !== void 0);
  const cdpath = prefix ?? scope.cdpath ?? [];
  const here = scope.cwd;
  if (name === "popd" || name === "pop-location") {
    const stack = scope.dirStack ?? [];
    scope.prevCwd = here;
    scope.cwd = stack[stack.length - 1] ?? "";
    scope.dirStack = stack.slice(0, -1);
    return;
  }
  if (!CD_COMMANDS.has(name)) return;
  const target = psParam(args, ["path", "literalpath"]) ?? args.find((a) => a === "-" || !(a.startsWith("-") || /^\/d$/i.test(a)));
  const pushes = name === "pushd" || name === "push-location";
  let next;
  if (target === "-" || target !== void 0 && /^\$\{?OLDPWD\}?$/.test(target)) next = scope.prevCwd ?? "";
  else if (pushes && target === void 0) {
    const stack = scope.dirStack ?? [];
    next = stack[stack.length - 1] ?? "";
    scope.dirStack = [...stack.slice(0, -1), here];
    scope.prevCwd = here;
    scope.cwd = next;
    return;
  } else {
    next = cwdAfter(name, args, here, scope.dataDir) ?? here;
    if (target !== void 0 && !isAbsolutePath(target) && !/^\.\.?(?:[\\/]|$)/.test(target)) {
      for (const dir of cdpath) {
        const via = cwdAfter("cd", [resolveFrom(dir, target)], "", scope.dataDir);
        if (via !== void 0 && via !== "") {
          next = via;
          break;
        }
      }
    }
  }
  if (pushes) scope.dirStack = [...scope.dirStack ?? [], here];
  scope.prevCwd = here;
  scope.cwd = next;
}
var ROOT_ITSELF = /^(?:\/\*?|\\\*?|[A-Za-z]:[\\/]?\*?|\/(?:mnt\/)?[A-Za-z]\/?\*?)$/i;
function recursivePermsOnRoot(words, at, tildeUsers = true) {
  const name = commandName(words[at]?.value ?? "");
  if (name !== "chmod" && name !== "chown" && name !== "chgrp") return null;
  const args = withoutRedirections(words.slice(at + 1));
  if (!args.some((a) => a === "--recursive" || /^-[A-Za-z]*R[A-Za-z]*$/.test(a))) return null;
  const operandWords = args.filter((a) => !a.startsWith("-") || /^-[rwxXst]+$/.test(a));
  const targets = args.some((a) => a.startsWith("--reference")) ? operandWords : operandWords.slice(1);
  const roots = targets.filter((t) => catastrophicKind(t, tildeUsers) === "root");
  if (roots.length === 0) return null;
  return roots.some((t) => ROOT_ITSELF.test(stripQuotes(t))) ? { id: "recursive-perms-root", level: "block", reason: "Recursively changes the permissions or the owner of the filesystem root" } : { id: "recursive-perms-system", level: "warn", reason: "Recursively changes the permissions or the owner of a system directory \u2014 confirm this is intended" };
}
function destructiveCommand(words, at) {
  const name = commandName(words[at]?.value ?? "");
  const args = withoutRedirections(words.slice(at + 1));
  const plain = args.filter((a) => !a.startsWith("-") && !/^\/[A-Za-z]/.test(a)).map((a) => a.toLowerCase());
  if (name === "vssadmin" && plain[0] === "delete" && plain[1] === "shadows" || name === "wmic" && plain[0] === "shadowcopy" && plain.includes("delete")) {
    return { id: "shadow-copy-delete", level: "warn", reason: "Deletes Windows' volume shadow copies (restore points)" };
  }
  if (name === "reg" && plain[0] === "delete" && /^(?:hklm|hkey_local_machine)/i.test(plain[1] ?? "")) {
    return { id: "registry-delete", level: "warn", reason: "Deletes a machine-wide registry key (HKLM)" };
  }
  if ((name === "terraform" || name === "tofu" || name === "terragrunt") && (plain[0] === "destroy" || plain[0] === "apply" && args.includes("-destroy"))) {
    return { id: "terraform-destroy", level: "warn", reason: "Destroys the infrastructure Terraform manages" };
  }
  if (name === "aws" && plain[0] === "s3" && (plain[1] === "rm" && args.includes("--recursive") || plain[1] === "rb" && args.includes("--force"))) {
    return { id: "s3-recursive-delete", level: "warn", reason: "Deletes an S3 bucket's objects recursively" };
  }
  if (name === "gh" && plain[0] === "repo" && plain[1] === "delete") {
    return { id: "gh-repo-delete", level: "warn", reason: "Deletes a GitHub repository" };
  }
  return null;
}
function startedCommandLine(words, at) {
  const name = commandName(words[at]?.value ?? "");
  if (name !== "start-process" && name !== "saps") return void 0;
  const argv = startProcessArgv(words, at);
  return argv === void 0 ? void 0 : argv.map((w) => posixWord(w.value)).join(" ");
}
var WSL_VALUED = /* @__PURE__ */ new Set(["-d", "--distribution", "-u", "--user", "--cd", "--shell-type", "--distribution-id"]);
function wslScript(words, start) {
  for (let i = start + 1; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v === "--") return words.slice(i + 1).map((w) => w.value).join(" ");
    if (v === "-e" || v === "--exec") return words.slice(i + 1).map((w) => posixWord(w.value)).join(" ");
    if (WSL_VALUED.has(v)) {
      i += 1;
      continue;
    }
    if (v === "--system" || v === "-s") continue;
    if (v.startsWith("-")) return void 0;
    return words.slice(i).map((w) => w.value).join(" ");
  }
  return void 0;
}
var MAX_NESTING = 3;
var MAX_DIR = 4096;
function foldDots(path) {
  const drive = /^[A-Za-z]:/.exec(path)?.[0] ?? "";
  const parts = [];
  for (const seg of path.slice(drive.length).split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return `${drive}/${parts.join("/")}`;
}
function dirAfter(start, steps, ctx) {
  if (steps === null) return void 0;
  let cur = start;
  for (const step of steps) {
    let target = step.replace(/\\/g, "/");
    if (target === "~" || target.startsWith("~/")) {
      if (ctx.homePath === void 0) return void 0;
      target = `${ctx.homePath}${target.slice(1)}`;
    } else if (/^[$%]/.test(target)) {
      const v = leadingVariable(target);
      const value = v === void 0 ? void 0 : HOME_VARIABLES.has(v.name) ? ctx.homePath : v.name === "pwd" ? cur : ctx.vars?.[v.name];
      if (v === void 0 || value === void 0) return void 0;
      target = `${value.replace(/\\/g, "/")}${v.rest.replace(/\\/g, "/")}`;
    } else if (/^[A-Za-z]:\.?$/.test(target)) {
      if (ctx.bareDriveRoot !== true) return void 0;
      target = `${target.charAt(0)}:/`;
    }
    if (/^(?:\/|[A-Za-z]:\/)/.test(target)) cur = foldDots(target);
    else if (cur === void 0) return void 0;
    else cur = foldDots(`${cur}/${target}`);
    if (cur.length > MAX_DIR) return void 0;
  }
  return cur;
}
function targetVariables(env) {
  const get = (...names) => {
    for (const name of names) {
      const key = Object.keys(env).find((k) => k.toUpperCase() === name);
      const value = key === void 0 ? void 0 : env[key]?.trim();
      if (value !== void 0 && value !== "") return value;
    }
    return void 0;
  };
  const out = {};
  for (const [name, from] of [
    ["temp", ["TEMP", "TMP"]],
    ["tmp", ["TMP", "TEMP"]],
    ["tmpdir", ["TMPDIR"]],
    ["localappdata", ["LOCALAPPDATA"]],
    ["appdata", ["APPDATA"]]
  ]) {
    const value = get(...from);
    if (value !== void 0) out[name] = value;
  }
  return out;
}
function collect(command, depth, out, scope) {
  const cmd = command.trim();
  if (cmd.length === 0) return;
  if (scope.notes.now() > scope.notes.deadline) {
    scope.notes.budget = true;
    return;
  }
  const { maskedCommand, interpolatedCommand, statements } = splitShell(cmd);
  const commandText = collapseBlanks(maskedCommand);
  for (const rule of BASH_RULES) {
    if (rule.scope === "command" && (rule.test ?? ((t) => rule.pattern.test(t)))(commandText)) {
      out.push({ id: rule.id, level: rule.level, reason: rule.reason });
    }
  }
  pushAll(out, judgeEffects(dotNetEffects(cmd, scope.cwd, scope.notes), scope));
  const flowText = interpolatedCommand === maskedCommand ? commandText : collapseBlanks(interpolatedCommand);
  if (powershellDownloadExecution(flowText)) out.push(RULE_IEX_DOWNLOAD);
  const ranDownload = downloadsThenRuns(cmd, statements, scope.cmdLine === true);
  if (ranDownload !== null) out.push(ranDownload === "posix" ? RULE_POSIX_DOWNLOAD_RUN : RULE_DOWNLOAD_RUN);
  if (/<\(\s*(?:curl|wget)/i.test(commandText) && statements.some((_s, k) => interpreterRunsFetch(statements, k))) {
    out.push(RULE_PROCESS_FETCH);
  }
  if (commandText.includes("<(")) collectGenerated(processSubstitutionScripts(statements), depth, out, scope);
  const subshell = pipesDownloadIntoSubshell(statements);
  if (subshell !== null) out.push(subshell);
  for (const body of evalSubstitutionBodies(statements)) {
    if (body.some((b) => b.commands.some((words) => DOWNLOADERS.has(commandName(words[resolveCommand(words, PIPE_RUNNERS).index]?.value ?? ""))))) {
      out.push({ ...RULE_FETCH_EXEC });
    } else {
      collectGenerated(body.map((b) => textOutputOf(b.commands.map(expandWords), { heredocs: b.heredocBodies })), depth, out, scope);
    }
  }
  if (cmd.includes("$(") || cmd.includes("`")) {
    for (const body of quotedSubstitutions(cmd)) {
      if (body.trim() === "") continue;
      if (depth >= MAX_NESTING) {
        scope.notes.depth = true;
        continue;
      }
      noteScript(scope, body, scope.powershell === true);
      collect(body, depth + 1, out, { ...scope, cmdLine: false });
    }
  }
  const dirs = workdirs(statements);
  const startDir = scope.dir;
  let memoSteps;
  let memoDir;
  const dirOf2 = (steps) => {
    if (steps !== memoSteps) {
      memoSteps = steps;
      memoDir = dirAfter(startDir, steps, { homePath: scope.homePath, vars: scope.vars, bareDriveRoot: scope.bareDriveRoot === true && scope.powershell !== true && scope.cmdLine !== true });
    }
    return memoDir;
  };
  const powershellScope = scope.powershell === true;
  collectFed(
    [
      ...commandText.includes(">(") ? outputSubstitutionScripts(statements, powershellScope) : [],
      ...groupFedScripts(statements, powershellScope),
      ...iexSubexpressionScripts(statements),
      ...powershellScope && /scriptblock|InvokeCommand|AddScript/i.test(cmd) ? scriptBlockScripts(cmd).map((text) => text === "unread" ? { text: "", reader: [], unread: true } : { text, reader: [], kind: "powershell" }) : []
    ],
    depth,
    out,
    scope
  );
  for (const [s, written] of statements.entries()) {
    if (scope.notes.now() > scope.notes.deadline) {
      scope.notes.budget = true;
      return;
    }
    const commands = written.commands.map(expandWords);
    const expanded = commands.some((c, k) => c !== written.commands[k]);
    const statement = expanded ? { ...written, commands } : written;
    const masked = capText(collapseBlanks(statement.masked), scope.notes);
    const expandedText = expanded ? capText(collapseBlanks(commands.map((ws) => ws.map((w) => w.quoted ? MASK : w.value).join(" ")).join(" | ")), scope.notes) : void 0;
    for (const rule of BASH_RULES) {
      if (rule.scope === "command") continue;
      const test = rule.test ?? ((t) => rule.pattern.test(t));
      if (test(masked) || expandedText !== void 0 && test(expandedText)) {
        out.push({ id: rule.id, level: rule.level, reason: rule.reason });
      }
    }
    const piped = pipesDownloadIntoShell(statement);
    if (piped !== null) out.push(piped);
    for (const [c, words] of statement.commands.entries()) {
      if (scope.notes.now() > scope.notes.deadline) {
        scope.notes.budget = true;
        return;
      }
      const resolved = resolveCommand(words);
      if (resolved.elevated) out.push({ ...SUDO_RULE });
      const here = dirOf2(dirs[s]?.[c]?.may ?? null);
      const deleting = {
        dir: here,
        vars: scope.vars,
        bareDriveRoot: scope.bareDriveRoot === true && scope.powershell !== true && scope.cmdLine !== true,
        piped: scope.powershell === true && c > 0 ? pipedItems(statement.commands[c - 1] ?? []) : void 0,
        pipedRecursive: scope.powershell === true && c > 0 ? listsRecursively(statement.commands[c - 1] ?? []) : void 0
      };
      const del = assessRecursiveDelete(words, resolved.index, scope.home, scope.tildeUsers, deleting);
      if (del !== null) out.push(del);
      const find = assessFind(words, resolved.index, scope.home, scope.tildeUsers, deleting);
      if (find !== null) out.push(find);
      const findXargs = findPipedIntoDeleter(statement.commands, c, scope.home, scope.tildeUsers !== false, deleting);
      if (findXargs !== null) out.push(findXargs);
      if (hereStringFetchIntoShell(words, resolved.index)) out.push(RULE_FETCH_EXEC);
      const hereText = hereStringText(words);
      const hereReader = hereText === void 0 ? void 0 : scriptReader(words);
      if (hereText !== void 0 && hereReader !== void 0) {
        const generated = substitutionOutput(hereText) ?? hereText;
        collectFed([generated === "opaque" ? { text: "", reader: words, opaque: true } : { text: generated, reader: words, kind: hereReader }], depth, out, { ...scope, dir: here });
      }
      if (inlineCode(words, resolved.index).some(isBareRemoteFetch)) out.push(RULE_FETCH_EXEC);
      pushAll(out, assessGuardConfig(words, resolved.index, scope));
      if (adoptsDatabase(words, resolved.index) || adoptsDatabaseThroughLauncher(words, resolved.index)) out.push({ ...RULE_DB_ADOPT });
      if (updatesBaseline(words, resolved.index) || throughLauncher(words, resolved.index, updatesBaseline)) {
        out.push({ ...RULE_BASELINE_UPDATE });
      }
      const perms = recursivePermsOnRoot(words, resolved.index, scope.tildeUsers);
      if (perms !== null) out.push(perms);
      const destructive = destructiveCommand(words, resolved.index);
      if (destructive !== null) out.push(destructive);
      const scripts = nestedScripts(words, resolved.index);
      const split = envSplitScript(words, resolved.index);
      if (split !== void 0) scripts.push(shellScript(split));
      const started = startedCommandLine(words, resolved.index);
      if (started !== void 0) scripts.push(shellScript(started));
      const cmdHead = words[resolved.index];
      const line = cmdHead !== void 0 && commandName(cmdHead.value) === "cmd" ? cmdLineText(withoutRedirections(words.slice(resolved.index + 1))) : void 0;
      if (depth >= MAX_NESTING && (scripts.length > 0 || line !== void 0)) scope.notes.depth = true;
      if (depth < MAX_NESTING) {
        for (const { text: script, powershell, iex, unread } of scripts) {
          if (unread === true) {
            out.push({ ...RULE_UNREAD_SCRIPT });
            continue;
          }
          if (isBareRemoteFetch(script)) out.push(RULE_FETCH_EXEC);
          if (!powershell) collectGenerated([substitutionOutput(script)], depth, out, scope);
          if (iex === true && PS_DOWNLOAD.test(script)) out.push(RULE_IEX_DOWNLOAD);
          noteScript(scope, script, powershell);
          collect(script, depth + 1, out, { ...scope, cmdLine: false, powershell, dir: here });
          const asPowerShell = powershell ? powershellAsPosix(script) : script;
          if (asPowerShell !== script) collect(asPowerShell, depth + 1, out, { ...scope, cmdLine: false, powershell, dir: here });
        }
        if (line !== void 0) {
          noteScript(scope, line, false);
          collect(line, depth + 1, out, { ...scope, cmdLine: true, powershell: false, dir: here });
        }
      }
      moveCwd(scope, words, resolved.index);
    }
    const fed = fedScripts(statement, readsScript, scope.powershell === true);
    if (fed.length > 0) collectFed(fed, depth, out, { ...scope, dir: dirOf2(dirs[s]?.[0]?.may ?? null) });
    for (const { text, reader, opaque, unread } of fedScripts(statement, isBareInterpreterStdin, scope.powershell === true)) {
      if (unread === true) continue;
      if (opaque === true) out.push({ ...RULE_DECODED_SCRIPT });
      else pushAll(out, judgeCode(text, codeLang(commandName(reader[0]?.value ?? "")), scope));
    }
  }
}
function collectFed(fed, depth, out, scope) {
  if (fed.length === 0) return;
  if (fed.some((f) => f.opaque === true)) out.push({ ...RULE_DECODED_SCRIPT });
  if (fed.some((f) => f.unread === true)) out.push({ ...RULE_UNREAD_SCRIPT });
  const readable = fed.filter((f) => f.opaque !== true && f.unread !== true);
  if (readable.length === 0) return;
  if (depth >= MAX_NESTING) {
    scope.notes.depth = true;
    return;
  }
  for (const f of readable) {
    const kind = f.kind ?? scriptReader(f.reader) ?? "shell";
    const powershell = kind === "powershell";
    noteScript(scope, f.text, powershell);
    collect(f.text, depth + 1, out, { ...scope, cmdLine: kind === "cmd", powershell });
    const asPosix = powershell ? powershellAsPosix(f.text) : f.text;
    if (asPosix !== f.text) collect(asPosix, depth + 1, out, { ...scope, cmdLine: false, powershell });
  }
}
function collectGenerated(texts, depth, out, scope) {
  for (const text of texts) {
    if (text === void 0) continue;
    if (text === "opaque") out.push({ ...RULE_DECODED_SCRIPT });
    else if (depth >= MAX_NESTING) scope.notes.depth = true;
    else {
      noteScript(scope, text, false);
      collect(text, depth + 1, out, { ...scope, cmdLine: false, powershell: false });
    }
  }
}
var MAX_STATEMENT_LENGTH = 16 * 1024;
var MAX_COMMAND_LENGTH = 512 * 1024;
var DEFAULT_BUDGET_MS = 2500;
function safeHomedir() {
  try {
    return homedir3();
  } catch {
    return void 0;
  }
}
function partialRule(notes) {
  const causes = [
    ...notes.statement ? ["over 16 KB"] : [],
    ...notes.command ? ["over 512 KB"] : [],
    ...notes.budget ? ["assessment time budget exhausted"] : [],
    ...notes.depth ? [`nested more than ${MAX_NESTING} levels deep`] : [],
    ...notes.calls ? [`an [IO.File] call's arguments over ${MAX_CALL_ARGS} characters`] : [],
    ...notes.failed ? ["the assessment failed"] : [],
    ...notes.links ? [`more than ${MAX_ALIASES} links made, or ${MAX_LOOKUPS} paths looked up through links`] : []
  ];
  return causes.length === 0 ? null : { id: "partially-assessed", level: "warn", reason: `part of this command was not assessed (${causes.join("; ")})` };
}
function capQuestion(notes) {
  const causes = [
    ...notes.command ? ["over 512 KB"] : [],
    ...notes.statement ? ["a statement over 16 KB"] : [],
    ...notes.budget ? ["the assessment time budget ran out"] : [],
    ...notes.depth ? [`nested more than ${MAX_NESTING} levels deep`] : []
  ];
  return causes.length === 0 ? void 0 : `this command is too large or too deeply nested to assess in full (${causes.join("; ")}), so what it runs past that point was not checked \u2014 the user decides whether to run it`;
}
function collapseBlanks(text) {
  return text.replace(/[ \t]{2,}/g, " ");
}
var MAX_NOTED_SCRIPTS = 64;
function noteScript(scope, text, powershell) {
  const scripts = scope.notes.scripts;
  const shell = powershell ? "powershell" : "bash";
  const t = text.trim();
  if (t === "" || scripts.size >= MAX_NOTED_SCRIPTS) return;
  const key = `${shell}\0${t}`;
  if (!scripts.has(key)) scripts.set(key, { text: t, shell });
}
function capText(text, notes) {
  if (text.length <= MAX_STATEMENT_LENGTH) return text;
  notes.statement = true;
  return text.slice(0, MAX_STATEMENT_LENGTH);
}
function assessBashCommand(command, opts = {}) {
  const whole = (command ?? "").trim();
  if (!whole) return { level: "ok", reasons: [], rules: [] };
  const now = opts.now ?? (() => performance.now());
  const deadline = now() + (opts.budgetMs ?? DEFAULT_BUDGET_MS);
  const cut = whole.length > MAX_COMMAND_LENGTH;
  const text = cut ? whole.slice(0, MAX_COMMAND_LENGTH) : whole;
  const homeRaw = opts.homeDir ?? safeHomedir();
  const platform = opts.platform ?? process.platform;
  const home = homeDirFor(homeRaw, platform);
  const dataDir = normalizedPath(opts.dataDir ?? safeUserDataDir());
  const configDir = opts.claudeConfigDir ?? process.env["CLAUDE_CONFIG_DIR"];
  const fold = platform === "win32";
  const placeKey = (p) => p === void 0 || p.trim() === "" ? void 0 : targetKey(p, fold);
  const where = {
    home,
    configDirName: configDirNameOf(configDir),
    dataDir: dataDir === "" ? void 0 : dataDir,
    tildeUsers: opts.shell !== "powershell",
    powershell: opts.shell === "powershell",
    places: opts.cwd === void 0 && opts.projectDir === void 0 ? void 0 : { fold, home: placeKey(homeRaw), cwd: placeKey(opts.cwd), project: placeKey(opts.projectDir), configDir: placeKey(configDir) },
    dir: opts.cwd === void 0 || opts.cwd.trim() === "" ? void 0 : foldDots(opts.cwd.replace(/\\/g, "/")),
    homePath: homeRaw === void 0 ? void 0 : homeRaw.replace(/\\/g, "/"),
    vars: targetVariables(opts.env ?? process.env),
    bareDriveRoot: platform === "win32" && opts.shell !== "powershell",
    windows: platform === "win32",
    realPath: opts.realPath
  };
  if (opts.shell !== "powershell") return assessReadings([text], cut, now, deadline, where);
  return assessReadings([powershellAsPosix(text), powershellOpaque(text)], cut, now, deadline, where);
}
function safeUserDataDir() {
  try {
    return userDataDir2();
  } catch {
    return "";
  }
}
function assessReadings(readings, cut, now, deadline, where) {
  const notes = {
    statement: false,
    command: cut,
    budget: false,
    depth: false,
    loosens: void 0,
    failed: false,
    calls: false,
    deadline,
    now,
    scripts: /* @__PURE__ */ new Map(),
    aliases: [],
    realPaths: /* @__PURE__ */ new Map(),
    links: false
  };
  const matched = [];
  for (const [n, cmd] of readings.entries()) {
    if (n > 0 && (cmd === readings[n - 1] || matched.some((m) => m.level === "block"))) continue;
    notes.loosens = void 0;
    try {
      collect(cmd, 0, matched, { raw: cmd, cwd: "", notes, ...where });
    } catch {
      notes.failed = true;
    }
  }
  const partial = partialRule(notes);
  if (partial !== null) matched.push(partial);
  const scripts = notes.scripts.size > 0 ? { scripts: [...notes.scripts.values()] } : {};
  if (matched.length === 0) return { level: "ok", reasons: [], rules: [], ...scripts };
  const byId = /* @__PURE__ */ new Map();
  for (const m of matched) if (!byId.has(m.id)) byId.set(m.id, m);
  if (byId.has("rm-rf-root")) byId.delete("rm-rf-broad");
  const effective = [...byId.values()].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
  const blocks = effective.filter((r) => r.level === "block");
  const only = blocks.length === 1 ? blocks[0] : void 0;
  const own = only?.id === RULE_DB_ADOPT.id ? only.reason : void 0;
  const questions = [byId.get(RULE_BASELINE_UPDATE.id)?.reason, capQuestion(notes)].filter((q) => q !== void 0);
  const ask = blocks.length === 0 && questions.length > 0 ? questions.join("; and ") : void 0;
  return {
    level: effective[0]?.level ?? "ok",
    reasons: effective.map((r) => r.reason),
    rules: effective.map((r) => r.id),
    ...own === void 0 ? {} : { denyMessage: own },
    ...ask === void 0 ? {} : { ask },
    ...scripts
  };
}

// src/pkgvet/mayInstall.ts
var mayInstall_exports = {};
__export(mayInstall_exports, {
  mayInstall: () => mayInstall
});
var INSTALLER_WORD = /(?:^|[^\w.-])(?:npm|pnpm|pnpx|npx|yarn|bunx?|pipx?|pip\d[\d.]*|uvx?|poetry|composer|dotnet)(?:$|[^\w-])/i;
function mayInstall(command) {
  const unquoted = command.replace(/['"`]/g, "");
  return INSTALLER_WORD.test(unquoted.replace(/\\/g, "")) || INSTALLER_WORD.test(unquoted.replace(/\\/g, "/"));
}
export {
  bashGuard_exports as bashGuard,
  mayInstall_exports as installGate
};
