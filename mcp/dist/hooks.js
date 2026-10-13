import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/hooks/configFile.ts
var configFile_exports = {};
__export(configFile_exports, {
  MAX_HOOK_CONFIG_BYTES: () => MAX_HOOK_CONFIG_BYTES,
  isNetworkPath: () => isNetworkPath,
  isRemoteOrDeviceTarget: () => isRemoteOrDeviceTarget,
  localShareAsLocal: () => localShareAsLocal,
  readBoundedBytes: () => readBoundedBytes,
  readSmallJsonFile: () => readSmallJsonFile,
  readSmallText: () => readSmallText,
  readSmallTextFile: () => readSmallTextFile,
  textOf: () => textOf,
  walkLinksUnder: () => walkLinksUnder
});
import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync } from "node:fs";
import { isAbsolute, join, parse, relative, resolve } from "node:path";
function isRemoteOrDeviceTarget(target) {
  return /^(?:[\\/]{2}|\\\?\?\\)/.test(target);
}
function isNetworkPath(path) {
  if (!/^(?:[\\/]{2}|\\\?\?\\)/.test(path)) return false;
  return !/^(?:[\\/]{2}[?.]|\\\?\?)[\\/][A-Za-z]:(?:[\\/]|$)/.test(path);
}
function localShareAsLocal(path, hostname2 = "") {
  const m = /^[\\/]{2}(?:\?[\\/]UNC[\\/])?([^\\/]+)[\\/]([A-Za-z])\$(?=[\\/]|$)(.*)$/i.exec(path);
  if (m === null) return void 0;
  const host = (m[1] ?? "").toLowerCase().replace(/^\[|\]$/g, "");
  const local = ["localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"].includes(host) || hostname2 !== "" && host === hostname2.toLowerCase();
  if (!local) return void 0;
  const rest = m[3] ?? "";
  return `${(m[2] ?? "").toUpperCase()}:${rest === "" ? "\\" : rest}`;
}
function walkLinksUnder(under, path) {
  const rel = relative(resolve(under), resolve(path));
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return { ok: true };
  let current = resolve(under);
  const queue = rel.split(/[\\/]+/).filter((p) => p.length > 0);
  let hops = 0;
  for (let part = queue.shift(); part !== void 0; part = queue.shift()) {
    if (part === ".") continue;
    if (part === "..") {
      current = resolve(current, "..");
      continue;
    }
    const next = join(current, part);
    let isLink;
    try {
      isLink = lstatSync(next).isSymbolicLink();
    } catch {
      return { ok: true };
    }
    if (!isLink) {
      current = next;
      continue;
    }
    hops += 1;
    if (hops > MAX_LINK_HOPS) return { ok: false, reason: "unreadable", at: next };
    let target;
    try {
      target = readlinkSync(next);
    } catch {
      return { ok: false, reason: "unreadable", at: next };
    }
    if (isRemoteOrDeviceTarget(target)) return { ok: false, reason: "remote-link", at: next };
    const resolved = resolve(current, target);
    const root = parse(resolved).root;
    queue.unshift(...resolved.slice(root.length).split(/[\\/]+/).filter((p) => p.length > 0));
    current = root;
  }
  return { ok: true };
}
function readBoundedBytes(path, maxBytes, opts = {}) {
  let fd;
  try {
    fd = openSync(path, OPEN_FLAGS);
  } catch (e) {
    const code = e.code;
    if (code === "ENOENT" || code === "ENOTDIR") return { status: "absent" };
    if (code === "EISDIR") return { status: "refused", reason: "not-a-regular-file" };
    return { status: "refused", reason: "unreadable" };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { status: "refused", reason: "not-a-regular-file" };
    if (opts.head === true) {
      const buf2 = Buffer.allocUnsafe(Math.max(0, Math.min(maxBytes, st.size)));
      let total2 = 0;
      while (total2 < buf2.length) {
        const n = readSync(fd, buf2, total2, buf2.length - total2, null);
        if (n === 0) break;
        total2 += n;
      }
      return { status: "ok", bytes: buf2.subarray(0, total2) };
    }
    if (st.size > maxBytes) return { status: "refused", reason: "too-large" };
    let buf = Buffer.allocUnsafe(st.size + 1);
    let total = 0;
    for (; ; ) {
      if (total === buf.length) {
        if (buf.length > maxBytes) break;
        const bigger = Buffer.allocUnsafe(Math.min(buf.length * 2, maxBytes + 1));
        buf.copy(bigger, 0, 0, total);
        buf = bigger;
      }
      const n = readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
    }
    if (total > maxBytes) return { status: "refused", reason: "too-large" };
    return { status: "ok", bytes: buf.subarray(0, total) };
  } catch {
    return { status: "refused", reason: "unreadable" };
  } finally {
    try {
      closeSync(fd);
    } catch {
    }
  }
}
function textOf(bytes) {
  const text = bytes.toString("utf8");
  return text.charCodeAt(0) === 65279 ? text.slice(1) : text;
}
function readText(path, maxBytes) {
  const r = readBoundedBytes(path, maxBytes);
  return r.status === "ok" ? { status: "ok", text: textOf(r.bytes) } : r;
}
function readSmallJsonFile(path, maxBytes = MAX_HOOK_CONFIG_BYTES, under) {
  if (under !== void 0) {
    const walk2 = walkLinksUnder(under, path);
    if (!walk2.ok) return { status: "refused", reason: walk2.reason };
  }
  const r = readText(path, maxBytes);
  if (r.status !== "ok") return r;
  try {
    return { status: "ok", value: JSON.parse(r.text) };
  } catch {
    return { status: "invalid" };
  }
}
function readSmallText(path, maxBytes, under) {
  if (under !== void 0) {
    const walk2 = walkLinksUnder(under, path);
    if (!walk2.ok) return { status: "refused", reason: walk2.reason };
  }
  return readText(path, maxBytes);
}
function readSmallTextFile(path, maxBytes, under) {
  const r = readSmallText(path, maxBytes, under);
  return r.status === "ok" ? r.text : void 0;
}
var MAX_HOOK_CONFIG_BYTES, OPEN_FLAGS, MAX_LINK_HOPS;
var init_configFile = __esm({
  "src/hooks/configFile.ts"() {
    "use strict";
    MAX_HOOK_CONFIG_BYTES = 64 * 1024;
    OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);
    MAX_LINK_HOPS = 32;
  }
});

// src/hooks/guardedPath.ts
var guardedPath_exports = {};
__export(guardedPath_exports, {
  fileIdentity: () => fileIdentity,
  guardedPath: () => guardedPath,
  hardLinkedTo: () => hardLinkedTo,
  windowsName: () => windowsName
});
import { realpathSync, statSync } from "node:fs";
import { hostname } from "node:os";
import { basename, dirname, join as join2, parse as parse2 } from "node:path";
function safeHostname() {
  try {
    return hostname();
  } catch {
    return "";
  }
}
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
function resolveExisting(abs, realpath) {
  const root = parse2(abs).root;
  if (root === "" || !walkLinksUnder(root, abs).ok) return abs;
  const rest = [];
  let head = abs;
  for (let i = 0; i < 512; i += 1) {
    try {
      const real = realpath(head);
      return rest.length === 0 ? real : join2(real, ...rest.reverse());
    } catch {
      const parent = dirname(head);
      if (parent === head) return abs;
      rest.push(basename(head));
      head = parent;
    }
  }
  return abs;
}
function fileIdentity(abs) {
  if (isNetworkPath(abs)) return void 0;
  try {
    const root = parse2(abs).root;
    if (root === "" || !walkLinksUnder(root, abs).ok) return void 0;
    const s = statSync(abs, { bigint: true });
    return s.isFile() ? { dev: s.dev, ino: s.ino, nlink: s.nlink } : void 0;
  } catch {
    return void 0;
  }
}
function hardLinkedTo(abs, guarded) {
  const id = fileIdentity(abs);
  if (id === void 0 || id.nlink < 2n) return void 0;
  return guarded.find((g) => {
    const other = fileIdentity(g);
    return other !== void 0 && other.dev === id.dev && other.ino === id.ino;
  });
}
function guardedPath(abs, opts = {}) {
  const win = (opts.platform ?? process.platform) === "win32";
  let named = win ? windowsName(abs) : abs;
  if (win && isNetworkPath(named)) {
    const local = localShareAsLocal(named, opts.hostname ?? safeHostname());
    if (local === void 0) return named;
    named = windowsName(local);
  }
  try {
    return resolveExisting(named, opts.realpath ?? realpathSync.native);
  } catch {
    return named;
  }
}
var init_guardedPath = __esm({
  "src/hooks/guardedPath.ts"() {
    "use strict";
    init_configFile();
  }
});

// src/hooks/userDataDir.ts
import { homedir } from "node:os";
import { isAbsolute as isAbsolute2, join as join3, resolve as resolve2 } from "node:path";
function userDataDir(ctx = {}) {
  const env = ctx.env ?? process.env;
  const override = env["GUARDIAN_DATA_DIR"]?.trim();
  if (override !== void 0 && override !== "") return resolve2(override);
  const home = () => ctx.home ?? homedir();
  if ((ctx.platform ?? process.platform) === "win32") {
    const local = env["LOCALAPPDATA"]?.trim();
    return join3(local !== void 0 && isAbsolute2(local) ? local : join3(home(), "AppData", "Local"), "dev-guardian");
  }
  const xdg = env["XDG_DATA_HOME"]?.trim();
  return join3(xdg !== void 0 && isAbsolute2(xdg) ? xdg : join3(home(), ".local", "share"), "dev-guardian");
}
var init_userDataDir = __esm({
  "src/hooks/userDataDir.ts"() {
    "use strict";
  }
});

// src/hooks/dataRegistry.ts
var dataRegistry_exports = {};
__export(dataRegistry_exports, {
  registryDir: () => registryDir,
  userDataDir: () => userDataDir2,
  writesRegistry: () => writesRegistry
});
import { readdirSync } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { isAbsolute as isAbsolute3, join as join4, parse as parse3, relative as relative2, resolve as resolve3 } from "node:path";
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
function registryDir(ctx = {}) {
  return join4(userDataDir2(ctx), "registry");
}
function atOrBelow(dir, path) {
  const rel = relative2(dir, path);
  return rel === "" || !rel.startsWith("..") && !isAbsolute3(rel);
}
function filesIn(dir) {
  try {
    const root = parse3(dir).root;
    if (root === "" || !walkLinksUnder(root, dir).ok) return [];
    return readdirSync(dir).slice(0, MAX_ENTRIES).map((name) => join4(dir, name));
  } catch {
    return [];
  }
}
function writesRegistry(abs, ctx = {}) {
  const opts = ctx.platform === void 0 ? {} : { platform: ctx.platform };
  const registry = guardedPath(resolve3(registryDir(ctx)), opts);
  const target = guardedPath(resolve3(abs), opts);
  if (atOrBelow(registry, target)) return true;
  if (isNetworkPath(target)) return /(?:appdata[\\/]local|\.local[\\/]share)[\\/]dev-guardian[\\/]registry(?:[\\/]|$)/i.test(target);
  const id = fileIdentity(target);
  if (id === void 0 || id.nlink < 2n) return false;
  return hardLinkedTo(target, filesIn(registry)) !== void 0;
}
var MAX_ENTRIES;
var init_dataRegistry = __esm({
  "src/hooks/dataRegistry.ts"() {
    "use strict";
    init_configFile();
    init_guardedPath();
    init_userDataDir();
    MAX_ENTRIES = 1024;
  }
});

// src/hooks/powershellText.ts
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
        if (next !== "") out += posixSingle(next);
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
var UNICODE_SPACE, SINGLE_QUOTES, DOUBLE_QUOTES, TOKEN_BOUNDARY, HERE_STRING_BOUNDARY;
var init_powershellText = __esm({
  "src/hooks/powershellText.ts"() {
    "use strict";
    UNICODE_SPACE = /[\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\f\v]/;
    SINGLE_QUOTES = "'\u2018\u2019\u201A\u201B";
    DOUBLE_QUOTES = '"\u201C\u201D\u201E';
    TOKEN_BOUNDARY = /[\s;|&(){},]/;
    HERE_STRING_BOUNDARY = /[\s;|&(){},=]/;
  }
});

// src/hooks/shell/command.ts
function basename2(value) {
  const parts = value.split(/[\\/]/);
  const last = parts[parts.length - 1];
  return last === void 0 || last.length === 0 ? value : last;
}
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
    const name = basename2(word.value);
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
function parseRedirect(word) {
  const at = word.redirectAt?.[0];
  if (at === void 0) return null;
  const tail2 = word.value.slice(at);
  const op = /^[<>]+[|&]?/.exec(tail2)?.[0] ?? tail2.charAt(0);
  return { prefix: word.value.slice(0, at), op, inline: tail2.slice(op.length) };
}
var RUNNERS, RUNNER_VALUED, ASSIGNMENT;
var init_command = __esm({
  "src/hooks/shell/command.ts"() {
    "use strict";
    RUNNERS = /* @__PURE__ */ new Set([
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
      // cmd's `start [/b] ["title"] PROGRAM` (fix round 2).
      "start"
    ]);
    RUNNER_VALUED = {
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
      watch: { short: "nq", long: /* @__PURE__ */ new Set(["interval", "equexit"]) }
    };
    ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
  }
});

// src/hooks/shell/split.ts
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
  const endStatement = (end) => {
    endCommand();
    const text = masked.trim();
    if (text.length > 0 || commands.length > 0) {
      currentStatement.masked = text;
      currentStatement.commands = commands;
      if (end !== void 0) currentStatement.end = end;
      statements.push(currentStatement);
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
      if (ch === "(") parens.push(/[$<>=@(]/.test(command.charAt(i - 1)) ? "word" : "group");
      else if (ch === ")") {
        if (buf === "esac" && !bufQuoted && words.length === 0 && parens[parens.length - 1] === "case") parens.pop();
        closedWord = parens[parens.length - 1] === "case" ? false : parens.pop() === "word";
      } else {
        closedWord = inBacktick;
        inBacktick = !inBacktick;
      }
      endStatement(ch === "(" ? "(" : ch === ")" ? ")" : "`");
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
var MASK, INTERPOLATION, NAME_POSITION, QUOTED_NAME, TOKEN_WORD, HEREDOC_WORD, COMPOUND_RESERVED;
var init_split = __esm({
  "src/hooks/shell/split.ts"() {
    "use strict";
    MASK = " ";
    INTERPOLATION = /\$\{[^}\n]{0,128}\}|\$[\w:]+|\$\(|[()]/g;
    NAME_POSITION = /(?:(?:^|[\s;|&(])-(?:ov|outv[a-z]*|v[a-z]*|n[a-z]*)[ \t]*:?[ \t]*|(?:^|[\s;|&(])(?:set-variable|new-variable|get-variable|sv|nv|gv)[ \t]+)$/i;
    QUOTED_NAME = /^(?:(?:global|script|local|private|using|variable):)?[A-Za-z_]\w{0,63}$/i;
    TOKEN_WORD = /^(?:iex|invoke-expression|irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|set-variable|new-variable|get-variable|sv|nv|gv|tee|tee-object)$/i;
    HEREDOC_WORD = /^[A-Za-z_][A-Za-z0-9_]*$/;
    COMPOUND_RESERVED = /* @__PURE__ */ new Set(["if", "then", "elif", "else", "fi", "while", "until", "do", "done", "esac", "{", "}", "!"]);
  }
});

// src/hooks/bashGuard.ts
var bashGuard_exports = {};
__export(bashGuard_exports, {
  BASH_RULES: () => BASH_RULES,
  assessBashCommand: () => assessBashCommand,
  commandWordIndex: () => commandWordIndex,
  splitShell: () => splitShell
});
import { homedir as homedir3 } from "node:os";
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
    for (const fetch2 of line.matchAll(/<\(\s*(?:curl|wget)\b/gi)) {
      if (fetch2.index >= shellEnd) return true;
    }
  }
  return false;
}
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
function stripQuotes(token) {
  const q = (c) => c === "'" || c === '"' || c === "`";
  let a = 0;
  let b = token.length;
  while (a < b && q(token.charAt(a))) a += 1;
  while (b > a && q(token.charAt(b - 1))) b -= 1;
  return token.slice(a, b);
}
function catastrophicKind(raw, tildeUsers = true) {
  const t = stripQuotes(raw);
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
function isCatastrophicTarget(raw, tildeUsers = true) {
  return catastrophicKind(raw, tildeUsers) !== null;
}
function segmentMatches(seg, names) {
  const pattern = seg.toLowerCase();
  return names.some((n) => wildcardMatch(pattern, n.toLowerCase()));
}
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
  const t = stripQuotes(raw.trim()).replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/\/+\*?$/, "");
  return fold ? t.replace(/^(?:\/mnt)?\/([a-z])(?=\/|$)/i, "$1:").toLowerCase() : t;
}
function homeDirFor(home, platform) {
  if (home === void 0) return void 0;
  const fold = platform === "win32";
  const key = targetKey(home, fold);
  return key === "" || /^[a-z]:$/i.test(key) ? void 0 : { key, fold };
}
function isHomeTarget(raw, home) {
  return home !== void 0 && targetKey(raw, home.fold) === home.key;
}
function assessRecursiveDelete(words, start, home, tildeUsers = true) {
  const head = words[start];
  if (head === void 0) return null;
  const name = basename2(head.value).toLowerCase();
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
      if (cmdSwitch(token).toLowerCase() === "/s") recursive = true;
      continue;
    }
    if (token === "--no-preserve-root") noPreserve = true;
    else if (token === "--recursive") recursive = true;
    else if (token.startsWith("--")) continue;
    else if (token.startsWith("-") && token.length > 1) {
      const colon = token.indexOf(":");
      const flags = colon < 0 ? token.slice(1) : token.slice(1, colon);
      let value = colon < 0 ? void 0 : token.slice(colon + 1);
      const lower = flags.toLowerCase();
      const isSwitch = lower === "recurse" || lower === "rec" || lower === "force" || lower === "fo";
      if (value === "" && isSwitch) {
        value = rest[k + 1]?.value ?? "";
        k += 1;
      }
      if (value !== void 0 && value !== "" && PS_PATH_PARAM.test(lower)) targets.push(value);
      const on = value === void 0 || !/^\$?(?:false|0)$/i.test(value);
      if (lower === "recurse" || lower === "rec") recursive ||= on;
      else if (!isSwitch && value === void 0 && flags.length <= 3 && /r/i.test(flags)) recursive = true;
    } else targets.push(token);
  }
  if (!(recursive || noPreserve)) return null;
  if (noPreserve || targets.some((t) => isCatastrophicTarget(t, tildeUsers) || isHomeTarget(t, home))) return { ...RULE_RM_ROOT };
  return { ...RULE_RM_BROAD };
}
function assessFind(words, start, home, tildeUsers = true) {
  const head = words[start];
  if (head === void 0 || basename2(head.value) !== "find") return null;
  const rest = words.slice(start + 1);
  const execs = findExecCommands(words, start);
  const viaExec = execs.some((cmd) => FIND_DELETERS.has(commandName(cmd[resolveCommand(cmd).index]?.value ?? "")));
  const inner = execs.map((cmd) => assessRecursiveDelete(cmd, resolveCommand(cmd).index, home, tildeUsers)).find((r) => r?.level === "block");
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
  if (targets.some((t) => catastrophicKind(t, tildeUsers) === "root")) return { ...RULE_FIND_ROOT };
  if (targets.some((t) => catastrophicKind(t, tildeUsers) === "home" || isHomeTarget(t, home))) {
    return filtered ? { ...RULE_FIND_HOME } : { ...RULE_FIND_ROOT };
  }
  if (!filtered && targets.some((t) => /^\.[\\/]?$/.test(t))) return { ...RULE_FIND_BROAD };
  return null;
}
function isHookConfigPath(arg) {
  return HOOK_CONFIG_PATH.test(arg.replace(/\\/g, "/"));
}
function isHookConfigDir(arg) {
  return HOOK_CONFIG_DIR.test(arg.replace(/\\/g, "/"));
}
function isSettingsPath(path, configDirName) {
  if (CLAUDE_SETTINGS_PATH.test(path) || CONFIG_DIR_VARIABLE_SETTINGS.test(path)) return true;
  if (configDirName === void 0) return false;
  const lower = path.toLowerCase();
  for (const file of ["settings.json", "settings.local.json"]) {
    if (lower.endsWith(`${configDirName}/${file}`) || lower.endsWith(`${configDirName}${file}`)) return true;
  }
  return false;
}
function normalizedPath(path) {
  return path.replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/\/+$/, "").toLowerCase();
}
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
  return /\bdisableAllHooks\b|\bGUARDIAN_HOOKS(?:_BASH_BLOCK)?\b|\bGUARDIAN_PKG_VET\b/i.test(text) || /enabledPlugins/i.test(text) && /dev-guardian/i.test(text);
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
function commandName(word) {
  return basename2(word).toLowerCase().replace(/\.exe$/, "");
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
function cwdAfter(name, args, cwd, dataDir) {
  if (CD_RETURNS.has(name)) return "";
  if (!CD_COMMANDS.has(name)) return void 0;
  const dir = psParam(args, ["path", "literalpath"]) ?? args.find((a) => a === "-" || !(a.startsWith("-") || /^\/d$/i.test(a)));
  if (dir === void 0) return "~";
  if (dir === "-") return "";
  const next = resolveFrom(cwd, dir);
  if (next.length > MAX_CWD) return "";
  const tracked = /\.guardian|dev-guardian|\.config|\.claude|registry|guardian_data_dir|localappdata|xdg_data_home|\.local/i.test(next) || dataDir !== void 0 && normalizedPath(next).startsWith(dataDir);
  return tracked ? next : "";
}
function globNamesConfig(path, tails = CONFIG_TAILS) {
  const t = tail(path);
  if (!GLOB.test(t)) return false;
  const segs = t.split("/").filter((s) => s !== "");
  return tails.some(
    (names) => names.length <= segs.length && names.every((name, k) => wildcardMatch((segs[segs.length - names.length + k] ?? "").toLowerCase(), name))
  );
}
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
function noEffects() {
  return { writes: [], removes: [], dirs: [], special: [], links: [], hardLinkSources: [], trees: [] };
}
function pushAll(into, from) {
  for (const x of from) into.push(x);
}
function mergeEffects(into, from) {
  pushAll(into.writes, from.writes);
  pushAll(into.removes, from.removes);
  pushAll(into.dirs, from.dirs);
  pushAll(into.special, from.special);
  pushAll(into.links, from.links);
  pushAll(into.hardLinkSources, from.hardLinkSources);
  pushAll(into.trees, from.trees);
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
function lnDestinations(args) {
  let dir;
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    const long = /^--target-directory=(.+)$/.exec(a);
    if (long !== null) dir = long[1];
    else if (a === "--target-directory" || /^-[a-zA-Z]*t$/.test(a)) dir = args[++i];
    else if (/^-t./.test(a)) dir = a.slice(2);
    else if (a === "-S" || a === "--suffix") i++;
    else rest.push(a);
  }
  const targets = operands(rest, /* @__PURE__ */ new Set());
  if (dir !== void 0) return targets.map((t) => `${dir}/${lastSegment(t)}`);
  if (targets.length >= 2) return [targets[targets.length - 1] ?? ""];
  return targets.length === 1 ? [lastSegment(targets[0] ?? "")] : [];
}
function lnHardSources(args) {
  if (args.some((a) => a === "--symbolic" || /^-[a-zA-Z]*s[a-zA-Z]*$/.test(a))) return [];
  let dir = false;
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (/^--target-directory=/.test(a)) dir = true;
    else if (a === "--target-directory" || /^-[a-zA-Z]*t$/.test(a)) {
      dir = true;
      i += 1;
    } else if (/^-t./.test(a)) dir = true;
    else if (a === "-S" || a === "--suffix") i += 1;
    else rest.push(a);
  }
  const names = operands(rest, /* @__PURE__ */ new Set());
  return dir || names.length < 2 ? names : names.slice(0, -1);
}
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
function psParam(args, names) {
  for (let i = 0; i < args.length; i += 1) {
    const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(args[i] ?? "");
    if (m === null || !names.includes((m[1] ?? "").toLowerCase())) continue;
    return m[2] !== void 0 ? m[2] : args[i + 1];
  }
  return void 0;
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
      if (args.some((a) => /^\/h$/i.test(a)) && names[1] !== void 0) e.hardLinkSources.push(at(names[1]));
      return e;
    }
    case "new-item":
    case "ni": {
      const item = newItemArgs(args);
      if (["symboliclink", "hardlink", "junction"].includes(item.itemType)) pushAll(e.links, item.paths.map(at));
      if (item.itemType === "hardlink" && item.target !== void 0) e.hardLinkSources.push(at(item.target));
      else if (item.itemType === "file") pushAll(e.writes, item.paths.map(at));
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
function isInterpreter(name) {
  return PYTHON.test(name) || INTERPRETERS.has(name);
}
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
function nodeCode(args) {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? "";
    const eq2 = /^--(?:eval|print)=([\s\S]*)$/.exec(a);
    if (eq2 !== null) return [eq2[1] ?? ""];
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
    } else if (method === "createsymboliclink") e.links.push(first);
    else if (method === "move" || method === "replace") {
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
function literalsNameRegistry(literals, dataDir) {
  const paths = literalPaths(literals);
  if (paths.some((p) => isRegistryPath(p, dataDir))) return true;
  const has = (re) => paths.some((p) => re.test(p));
  return has(/(?:^|\/)dev-guardian\/?$/i) && has(/^registry\/?$/i);
}
function worst(placements) {
  if (placements.includes("inside")) return "inside";
  return placements.includes("outside") ? "outside" : null;
}
function keyAtOrBelow(dir, key) {
  return dir !== void 0 && dir !== "" && (key === dir || key.startsWith(`${dir}/`));
}
function locate(paths, pred, scope) {
  let found2 = null;
  for (const p of paths) {
    if (!pred(p)) continue;
    if (placeOf(p, scope) === "inside") return "inside";
    found2 = "outside";
  }
  return found2;
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
  if (isSettingsPath(key, scope.configDirName) || CLAUDE_DIR.test(key)) {
    return [places.project, places.cwd, places.home, places.configDir].some((d) => keyAtOrBelow(d, key)) ? "inside" : "outside";
  }
  return [places.project, places.cwd].some((d) => keyAtOrBelow(d, key)) ? "inside" : "outside";
}
function judgeEffects(effects, scope) {
  const e = {
    writes: asWindowsOpens(effects.writes.map(tail)),
    removes: asWindowsOpens(effects.removes.map(tail)),
    dirs: asWindowsOpens(effects.dirs.map(tail)),
    special: asWindowsOpens(effects.special.map(tail)),
    links: asWindowsOpens(effects.links.map(tail)),
    hardLinkSources: asWindowsOpens(effects.hardLinkSources.map(tail)),
    trees: effects.trees.map(tail)
  };
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
  if (e.trees.some((p) => isCatastrophicTarget(p, scope.tildeUsers) || isHomeTarget(p, scope.home))) out.push({ ...RULE_RM_ROOT });
  if (e.writes.some((p) => BLOCK_DEVICE.test(p))) out.push({ ...RULE_DISK_WRITE });
  const inRegistry = (p) => isRegistryPath(p, scope.dataDir);
  const registryOrData = (p) => inRegistry(p) || isDataDirPath(p, scope.dataDir);
  if (e.writes.some(inRegistry) || e.special.some(inRegistry) || e.hardLinkSources.some(inRegistry) || e.links.some(registryOrData) || e.dirs.some(registryOrData)) {
    out.push({ ...RULE_REGISTRY });
  }
  const settings = locate(e.writes, (p) => isSettingsPath(p, scope.configDirName), scope);
  if (settings !== null && loosens(scope)) judged(RULE_SETTINGS, settings);
  return out;
}
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
function cliArgs(words, at) {
  const head = words[at];
  if (head === void 0) return void 0;
  if (CLI_NAME.test(basename2(head.value))) return words.slice(at + 1).map((w) => w.value);
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
    return CLI_NAME.test(basename2(v)) ? words.slice(i + 1).map((w) => w.value) : void 0;
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
function shellScript(text) {
  return { text, powershell: false };
}
function nestedScripts(words, start) {
  const head = words[start];
  const launcher2 = head === void 0 ? "" : commandName(head.value);
  if (launcher2 === "npx" || launcher2 === "pnpx" || launcher2 === "npm" && words[firstNonFlag(words, start + 1)]?.value === "exec") {
    for (let i = start + 1; i < words.length; i += 1) {
      const v = words[i]?.value ?? "";
      if (v === "-c" || v === "--call") return words[i + 1] === void 0 ? [] : [shellScript(words[i + 1]?.value ?? "")];
      if (v.startsWith("--call=")) return [shellScript(v.slice("--call=".length))];
      if (v === "--") break;
    }
  }
  if (head !== void 0 && basename2(head.value) === "eval") {
    const script = words.slice(start + 1).map((w) => w.value).join(" ").trim();
    return script.length > 0 ? [shellScript(script)] : [];
  }
  if (launcher2 === "wsl") {
    const script = wslScript(words, start);
    return script === void 0 || script.trim() === "" ? [] : [shellScript(script)];
  }
  if (launcher2 === "iex" || launcher2 === "invoke-expression") {
    const script = words.slice(start + 1).map((w) => w.value).join(" ").trim();
    return script.length > 0 ? [{ text: script, powershell: true, iex: true }] : [];
  }
  let sawShell = false;
  for (let i = start; i < words.length; i += 1) {
    const word = words[i];
    if (word === void 0) continue;
    const name = commandName(word.value);
    if (!word.quoted && (name === "pwsh" || name === "powershell")) {
      return powershellCommand(
        words.slice(i + 1).map((w) => w.value),
        name
      ).filter((s) => s.trim().length > 0).map((text) => ({ text, powershell: true }));
    }
    if (!word.quoted && DASH_C.test(word.value) && sawShell) {
      const script = scriptAfterDashC(words, i + 1);
      return script === void 0 ? [] : [shellScript(script)];
    }
    if (SHELLS.has(basename2(word.value))) sawShell = true;
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
function isBareShellStdin(words) {
  const head = words[0];
  if (head === void 0 || !SHELLS.has(basename2(head.value))) return false;
  return words.slice(1).every((w) => w.value.startsWith("-"));
}
function fedScripts(statement, reads) {
  const scripts = [];
  if (statement.commands.length === 1 && statement.heredocBodies) {
    const only = statement.commands[0];
    if (only !== void 0 && reads(only)) pushAll(scripts, statement.heredocBodies.map((text) => ({ text, reader: only })));
  }
  if (statement.commands.length >= 2) {
    const last = statement.commands[statement.commands.length - 1];
    if (last !== void 0 && reads(last)) {
      const fed = textOutputOf(statement.commands.slice(0, -1));
      if (fed === "opaque") scripts.push({ text: "", reader: last, opaque: true });
      else if (fed !== void 0 && fed.trim().length > 0) scripts.push({ text: fed.trim(), reader: last });
    }
  }
  return scripts;
}
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
function textOutputOf(members) {
  const last = members[members.length - 1];
  if (last === void 0) return void 0;
  const at = resolveCommand(last).index;
  const name = commandName(last[at]?.value ?? "");
  const args = withoutRedirections(last.slice(at + 1));
  if (name === "echo") return args.filter((a, k) => !(k === 0 && /^-[neE]+$/.test(a))).join(" ");
  if (name === "printf") return args[args.length - 1] ?? "";
  const decoder = decoderOf(last);
  if (decoder === void 0) return void 0;
  if (decoder === "other") return "opaque";
  const here = hereStringText(last);
  const input = here ?? (members.length > 1 ? textOutputOf(members.slice(0, -1)) : void 0);
  if (typeof input !== "string") return "opaque";
  return decodeBase64(input) ?? "opaque";
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
      const text = textOutputOf(body.commands.map(expandWords));
      if (text === "opaque") opaque = true;
      else if (text !== void 0) texts.push(text);
      if (body.end === ")") break;
    }
    if (opaque) out.push("opaque");
    if (texts.length > 0) out.push(texts.join("\n"));
  }
  return out;
}
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
function runsItsArguments(script) {
  if (!POSITIONAL.test(script)) return false;
  return splitShell(script).statements.some(
    (st) => st.commands.some((words) => {
      const at = resolveCommand(words).index;
      const head = words[at]?.value ?? "";
      if (POSITIONAL.test(head) && head.replace(POSITIONAL, "") === "") return true;
      return basename2(head) === "eval" && words.slice(at + 1).some((w) => POSITIONAL.test(w.value));
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
function psVariable(spelled) {
  let v = spelled.toLowerCase();
  if (v.startsWith("$")) v = v.slice(1);
  if (v.startsWith("{") && v.endsWith("}")) v = v.slice(1, -1);
  return `$${v.replace(/^(?:global|script|local|private|using|variable):/, "")}`;
}
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
    if (g["run"] !== void 0) {
      if (piped) return true;
      pendingIex = true;
    } else if (g["dl"] !== void 0) {
      if (download()) return true;
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
      if (opens.pop() === true) inIex -= 1;
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
function isRunnableName(path) {
  const last = stripQuotes(path).split(/[\\/]/).pop() ?? "";
  const ext = /\.([A-Za-z0-9-]+)$/.exec(last)?.[1];
  return ext === void 0 || RUNNABLE_EXTENSIONS.has(ext.toLowerCase());
}
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
  } else if (OPENERS.has(name)) {
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
function downloadsThenRuns(text, statements, bareRunsCwd) {
  if (!MAY_DOWNLOAD.test(text)) return null;
  const downloads = /* @__PURE__ */ new Map();
  for (const dest of downloadFileCalls(text)) downloads.set(runKey(resolveFrom("", dest)), { at: -1, kind: "powershell" });
  const pathBins = /* @__PURE__ */ new Map();
  const verified = /* @__PURE__ */ new Map();
  let listAt = -2;
  let cwd = "";
  const extracted = /* @__PURE__ */ new Map();
  for (let k = 0; k < statements.length; k += 1) {
    const statement = statements[k];
    if (statement === void 0) continue;
    const heads = statement.commands.map((words) => resolveCommand(words).index);
    const ran = [];
    const saved = [];
    const reading = downloads.size > 0 || extracted.size > 0;
    const piped = reading ? pipedIntoRunners(statement, heads) : [];
    let streaming;
    let fromArchive;
    const downloadedArchive = (archive) => {
      if (archive === void 0 || archive === "-") return streaming;
      const key = runKey(resolveFrom(cwd, archive));
      const d = downloads.get(key);
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
          const mark = downloads.get(src);
          if (mark === void 0) continue;
          for (const dest of to) {
            const key = runKey(resolveFrom(cwd, dest));
            downloads.set(key, mark);
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
      const d = downloads.get(file);
      if (d !== void 0 && d.at < k && !((verified.get(file) ?? -3) > d.at) && !(listAt > d.at)) return d.kind;
      const e = extracted.get(dirOf(file));
      if (e !== void 0 && e.at < k) return e.kind;
    }
    if (fromArchive !== void 0) return fromArchive;
    for (const { key, kind } of saved) {
      downloads.set(key, { at: k, kind });
      verified.delete(key);
      const bin = lastSegment(key);
      if (PATH_DIRS.test(dirOf(key)) && bin !== "") pathBins.set(bin, key);
    }
    const check = integrityCheckOf(statement, heads, cwd);
    if (check !== void 0) {
      for (const name of check.names) if (downloads.has(name)) verified.set(name, k);
      for (const name of check.implied) verified.set(name, k);
      if (check.lists.some((list) => downloads.has(list))) listAt = k;
    }
    if (statement.end !== "&&") {
      verified.clear();
      listAt = -2;
    }
  }
  return null;
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
  for (const written of statements) {
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
    for (const words of statement.commands) {
      if (scope.notes.now() > scope.notes.deadline) {
        scope.notes.budget = true;
        return;
      }
      const resolved = resolveCommand(words);
      if (resolved.elevated) out.push({ ...SUDO_RULE });
      const del = assessRecursiveDelete(words, resolved.index, scope.home, scope.tildeUsers);
      if (del !== null) out.push(del);
      const find = assessFind(words, resolved.index, scope.home, scope.tildeUsers);
      if (find !== null) out.push(find);
      if (hereStringFetchIntoShell(words, resolved.index)) out.push(RULE_FETCH_EXEC);
      const here = hereStringText(words);
      if (here !== void 0 && isBareShellStdin(withoutRedirectWords(words.slice(resolved.index)))) {
        const generated = substitutionOutput(here);
        collectGenerated([generated ?? here], depth, out, scope);
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
        for (const { text: script, powershell, iex } of scripts) {
          if (isBareRemoteFetch(script)) out.push(RULE_FETCH_EXEC);
          if (!powershell) collectGenerated([substitutionOutput(script)], depth, out, scope);
          if (iex === true && PS_DOWNLOAD.test(script)) out.push(RULE_IEX_DOWNLOAD);
          collect(script, depth + 1, out, { ...scope, cmdLine: false });
          const asPowerShell = powershell ? powershellAsPosix(script) : script;
          if (asPowerShell !== script) collect(asPowerShell, depth + 1, out, { ...scope, cmdLine: false });
        }
        if (line !== void 0) collect(line, depth + 1, out, { ...scope, cmdLine: true });
      }
      moveCwd(scope, words, resolved.index);
    }
    const fed = fedScripts(statement, isBareShellStdin);
    if (fed.some((f) => f.opaque === true)) out.push({ ...RULE_DECODED_SCRIPT });
    if (depth < MAX_NESTING) {
      for (const { text, opaque } of fed) if (opaque !== true) collect(text, depth + 1, out, { ...scope, cmdLine: false });
    } else if (fed.length > 0) scope.notes.depth = true;
    for (const { text, reader, opaque } of fedScripts(statement, isBareInterpreterStdin)) {
      if (opaque === true) out.push({ ...RULE_DECODED_SCRIPT });
      else pushAll(out, judgeCode(text, codeLang(commandName(reader[0]?.value ?? "")), scope));
    }
  }
}
function collectGenerated(texts, depth, out, scope) {
  for (const text of texts) {
    if (text === void 0) continue;
    if (text === "opaque") out.push({ ...RULE_DECODED_SCRIPT });
    else if (depth >= MAX_NESTING) scope.notes.depth = true;
    else collect(text, depth + 1, out, { ...scope, cmdLine: false });
  }
}
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
    ...notes.failed ? ["the assessment failed"] : []
  ];
  return causes.length === 0 ? null : { id: "partially-assessed", level: "warn", reason: `part of this command was not assessed (${causes.join("; ")})` };
}
function collapseBlanks(text) {
  return text.replace(/[ \t]{2,}/g, " ");
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
    places: opts.cwd === void 0 && opts.projectDir === void 0 ? void 0 : { fold, home: placeKey(homeRaw), cwd: placeKey(opts.cwd), project: placeKey(opts.projectDir), configDir: placeKey(configDir) }
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
    now
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
  const partial2 = partialRule(notes);
  if (partial2 !== null) matched.push(partial2);
  if (matched.length === 0) return { level: "ok", reasons: [], rules: [] };
  const byId = /* @__PURE__ */ new Map();
  for (const m of matched) if (!byId.has(m.id)) byId.set(m.id, m);
  if (byId.has("rm-rf-root")) byId.delete("rm-rf-broad");
  const effective = [...byId.values()].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
  const blocks = effective.filter((r) => r.level === "block");
  const only = blocks.length === 1 ? blocks[0] : void 0;
  const own = only?.id === RULE_DB_ADOPT.id ? only.reason : void 0;
  const ask = blocks.length === 0 ? byId.get(RULE_BASELINE_UPDATE.id)?.reason : void 0;
  return {
    level: effective[0]?.level ?? "ok",
    reasons: effective.map((r) => r.reason),
    rules: effective.map((r) => r.id),
    ...own === void 0 ? {} : { denyMessage: own },
    ...ask === void 0 ? {} : { ask }
  };
}
var BASH_RULES, FORK_NAME_CHAR, SUDO_RULE, LEVEL_RANK, SYSTEM_DIRS, WINDOWS_DIR, WINDOWS_DIR_NAMES, DRIVE_LETTERS, PS_PATH_PARAM, DASH_DELETE_HEADS, SLASH_DELETE_HEADS, RULE_RM_ROOT, RULE_RM_BROAD, FIND_FILTERS, FIND_DELETERS, RULE_FIND_ROOT, RULE_FIND_HOME, RULE_FIND_BROAD, HOOK_CONFIG_PATH, HOOK_CONFIG_DIR, USER_CONFIG_DIR, CLAUDE_SETTINGS_PATH, CONFIG_DIR_VARIABLE_SETTINGS, DATA_DIR_SPELLED, MAX_BASE64_LITERALS, MAX_CWD, CD_COMMANDS, CD_RETURNS, GLOB, USER_CONFIG_TAIL, CONFIG_TAILS, MAX_BRACE_WORDS, MAX_BRACE_WORD, NEW_ITEM_VALUED, MAX_CMD_NESTING, COPY_VALUED, PS_PATH_PARAMS, PS_VALUE_PARAMS, PS_SWITCHES, RSYNC_VALUED, SED_IN_PLACE, EDITOR_VALUED_LETTERS, REMOVERS, CMD_SWITCHED, PYTHON, INTERPRETERS, RUN_WRAPPERS, LAUNCHERS, LAUNCHER_SUBCOMMANDS, LAUNCHER_VALUED, NODE_VALUED, PS_HOST_VALUED, NODE_OPTION_VALUED, DENO_RUN_VALUED, BUN_RUN_VALUED, MAX_CALL_ARGS, DOTNET_CALL, DOTNET_WRITER, RULE_HARD_LINK, CLAUDE_DIR, RULE_REGISTRY, RULE_SPECIAL, RULE_WRITE, RULE_REMOVE, RULE_DIR, RULE_INLINE, RULE_SETTINGS, RULE_ELSEWHERE, BLOCK_DEVICE, RULE_DISK_WRITE, RULE_PLUGIN_OFF, RULE_DB_ADOPT, CLI_NAME, CLI_HOSTS, CLI_HOST_SUBCOMMANDS, RULE_BASELINE_UPDATE, START_PROCESS, SHELLS, DASH_C, MAX_DECODED, RULE_DECODED_SCRIPT, DOWNLOADERS, PIPE_RUNNERS, STDIN_SHELLS, STDIN_PATHS, RULE_PIPE_TO_SHELL, RULE_FETCH_EXEC, RULE_IEX_DOWNLOAD, RULE_DOWNLOAD_RUN, RULE_POSIX_DOWNLOAD_RUN, RUN_WRAPPER_VALUED, POSITIONAL, RULE_PROCESS_FETCH, RULE_XARGS_REPLACED, PS_DOWNLOAD, PS_EXEC_TOKENS, VARIABLE_VALUED, VARIABLE_NAME_WINDOW, MAX_VARIABLE_NAMES, DOWNLOAD_FILE_CALL, SAVING_CMDLETS, SAVE_PARAM, CURL_SHORT_VALUED, WGET_SHORT_VALUED, URL_ARG, SCRIPT_SHELLS, OPENERS, RUNS_ARGUMENT, READERS, RUNNABLE_EXTENSIONS, PS_ARGUMENT_LIST, PS_FILE_PATH, MAY_DOWNLOAD, TRANSFERS, PATH_DIRS, GPG_VALUED, SIDECAR, NOT_FROM_ARCHIVE, ROOT_ITSELF, WSL_VALUED, MAX_NESTING, MAX_STATEMENT_LENGTH, MAX_COMMAND_LENGTH, DEFAULT_BUDGET_MS;
var init_bashGuard = __esm({
  "src/hooks/bashGuard.ts"() {
    "use strict";
    init_dataRegistry();
    init_guardedPath();
    init_powershellText();
    init_command();
    init_split();
    init_command();
    init_split();
    BASH_RULES = [
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
    FORK_NAME_CHAR = /[\w:.-]/;
    SUDO_RULE = {
      id: "sudo",
      level: "warn",
      reason: "Runs with elevated privileges (sudo)"
    };
    LEVEL_RANK = { ok: 0, warn: 1, block: 2 };
    SYSTEM_DIRS = ["etc", "usr", "bin", "sbin", "var", "lib", "lib64", "boot", "sys", "proc", "root", "home", "opt", "dev", "Users", "System"];
    WINDOWS_DIR = /^(?:[A-Za-z]:[\\/]?|\/(?:mnt\/)?[A-Za-z]\/)(?:Windows(?:[\\/]?(?:System32|SysWOW64))?|Users|Program Files(?: \(x86\))?|ProgramData|PROGRA~\d)(?:[\\/]\*?)?$/i;
    WINDOWS_DIR_NAMES = ["windows", "users", "program files", "program files (x86)", "programdata"];
    DRIVE_LETTERS = Array.from({ length: 26 }, (_, k) => String.fromCharCode(97 + k));
    PS_PATH_PARAM = /^(?:pa(?:t|th)?|l(?:i(?:t(?:e(?:r(?:a(?:l(?:p(?:a(?:t(?:h)?)?)?)?)?)?)?)?)?)?|lp|pspath)$/;
    DASH_DELETE_HEADS = /* @__PURE__ */ new Set(["rm", "ri", "remove-item"]);
    SLASH_DELETE_HEADS = /* @__PURE__ */ new Set(["rd", "rmdir", "del", "erase"]);
    RULE_RM_ROOT = {
      id: "rm-rf-root",
      level: "block",
      reason: "Recursive delete of the filesystem root, a drive root, a system directory or a home directory"
    };
    RULE_RM_BROAD = {
      id: "rm-rf-broad",
      level: "warn",
      reason: "Recursive delete \u2014 confirm the target path is intended"
    };
    FIND_FILTERS = /* @__PURE__ */ new Set([
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
    FIND_DELETERS = /* @__PURE__ */ new Set(["rm", "unlink", "rmdir", "shred", "remove-item", "ri", "del", "erase", "rd"]);
    RULE_FIND_ROOT = {
      id: "find-delete-root",
      level: "block",
      reason: "find \u2026 -delete (or -exec rm) on the filesystem root, a drive root, a system directory or a home directory deletes everything under it"
    };
    RULE_FIND_HOME = {
      id: "find-delete-home",
      level: "warn",
      reason: "find \u2026 -delete targets the home directory \u2014 confirm this is intended"
    };
    RULE_FIND_BROAD = {
      id: "find-delete-broad",
      level: "warn",
      reason: "find . -delete with no test to narrow it deletes everything under the working directory \u2014 confirm this is intended"
    };
    HOOK_CONFIG_PATH = /(?:\.guardian\/?hooks[^/]*\.json|\.config\/?dev-guardian\/?hooks\.json)$/i;
    HOOK_CONFIG_DIR = /(?:\.guardian|\.config\/?dev-guardian)\/?$/i;
    USER_CONFIG_DIR = /\.config\/?dev-guardian\/?$/i;
    CLAUDE_SETTINGS_PATH = /\.claude\/?settings(?:\.local)?\.json$/i;
    CONFIG_DIR_VARIABLE_SETTINGS = /(?:\$\{?(?:env:)?CLAUDE_CONFIG_DIR\}?|%CLAUDE_CONFIG_DIR%)\/?settings(?:\.local)?\.json$/i;
    DATA_DIR_SPELLED = /(?:(?:\$\{?(?:env:)?(?:localappdata|xdg_data_home)\}?|%(?:localappdata|xdg_data_home)%|appdata\/local|\.local\/share)\/dev-guardian|\$\{?(?:env:)?guardian_data_dir\}?|%guardian_data_dir%)$/;
    MAX_BASE64_LITERALS = 64;
    MAX_CWD = 320;
    CD_COMMANDS = /* @__PURE__ */ new Set(["cd", "chdir", "pushd", "set-location", "sl", "push-location"]);
    CD_RETURNS = /* @__PURE__ */ new Set(["popd", "pop-location"]);
    GLOB = /[*?[]/;
    USER_CONFIG_TAIL = [".config", "dev-guardian", "hooks.json"];
    CONFIG_TAILS = [
      [".guardian", "hooks.config.json"],
      [".guardian", "hooks-allowlist.json"],
      USER_CONFIG_TAIL
    ];
    MAX_BRACE_WORDS = 64;
    MAX_BRACE_WORD = 1024;
    NEW_ITEM_VALUED = [
      ["type", ["itemtype", "type"]],
      ["path", ["path", "literalpath", "pspath", "lp"]],
      ["name", ["name"]],
      ["target", ["value", "target"]],
      ["credential", ["credential"]]
    ];
    MAX_CMD_NESTING = 8;
    COPY_VALUED = /* @__PURE__ */ new Set(["-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group"]);
    PS_PATH_PARAMS = ["path", "literalpath", "destination"];
    PS_VALUE_PARAMS = ["filter", "include", "exclude", "credential", "fromsession", "tosession"];
    PS_SWITCHES = ["recurse", "force", "container", "passthru", "whatif", "confirm"];
    RSYNC_VALUED = /* @__PURE__ */ new Set([
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
    SED_IN_PLACE = /^(?:-[a-zA-Z]*i.*|--in-place(?:=.*)?)$/;
    EDITOR_VALUED_LETTERS = "cSuUiTwWtq";
    REMOVERS = /* @__PURE__ */ new Set(["rm", "unlink", "ri", "remove-item", "del", "erase", "rd", "rmdir"]);
    CMD_SWITCHED = /* @__PURE__ */ new Set(["copy", "move", "xcopy", "robocopy", "mklink", "del", "erase", "rd", "rmdir", "ren", "rename"]);
    PYTHON = /^(?:python[0-9.]*|py|pypy[0-9.]*)$/;
    INTERPRETERS = /* @__PURE__ */ new Set(["node", "nodejs", "bun", "deno", "tsx", "ts-node", "perl", "ruby", "php", "pwsh", "powershell"]);
    RUN_WRAPPERS = /* @__PURE__ */ new Set(["uv", "poetry", "pipenv", "pdm", "rye", "hatch", "conda", "mamba", "micromamba", "pixi"]);
    LAUNCHERS = /* @__PURE__ */ new Set(["npx", "bunx", "pnpx", "start"]);
    LAUNCHER_SUBCOMMANDS = {
      npm: /* @__PURE__ */ new Set(["exec", "x"]),
      pnpm: /* @__PURE__ */ new Set(["dlx", "exec"]),
      yarn: /* @__PURE__ */ new Set(["dlx", "exec"]),
      bun: /* @__PURE__ */ new Set(["x"])
    };
    LAUNCHER_VALUED = /* @__PURE__ */ new Set(["-p", "--package", "-c", "--call", "/d"]);
    NODE_VALUED = /* @__PURE__ */ new Set([
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
    PS_HOST_VALUED = /* @__PURE__ */ new Set([
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
    NODE_OPTION_VALUED = /* @__PURE__ */ new Set([
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
    DENO_RUN_VALUED = /* @__PURE__ */ new Set(["-c", "--config", "--import-map", "--lock", "--cert", "--location", "--seed", "--env-file", "--ext"]);
    BUN_RUN_VALUED = /* @__PURE__ */ new Set([
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
    MAX_CALL_ARGS = 512;
    DOTNET_CALL = /\[\s*(?:System\s*\.\s*)?IO\s*\.\s*(File|Directory)\s*\]\s*::\s*([A-Za-z]+)\s*\(/gi;
    DOTNET_WRITER = /\[\s*(?:System\s*\.\s*)?IO\s*\.\s*(StreamWriter|FileStream)\s*\]\s*::\s*new\b|\bNew-Object\s+(?:-TypeName\s+)?(?:System\s*\.\s*)?IO\s*\.\s*(StreamWriter|FileStream)\b(?:\s+-ArgumentList\b|\s+-Args?\b)?/gi;
    RULE_HARD_LINK = {
      id: "guard-config-hard-link",
      level: "block",
      reason: "Makes a hard link to the guardrail hooks' own configuration or to Claude Code's settings \u2014 a second name through which it can be rewritten"
    };
    CLAUDE_DIR = /\.claude\/?$/i;
    RULE_REGISTRY = {
      id: "guardian-registry-write",
      level: "block",
      reason: "Writes dev-guardian's registry of trusted databases (<data dir>/registry) \u2014 which database to trust is the user's decision: they run the dev-guardian CLI's `db adopt` themselves, in a terminal"
    };
    RULE_SPECIAL = {
      id: "guard-config-special-file",
      level: "block",
      reason: "Replaces the guardrail hooks' own configuration with a FIFO, a device node or a link"
    };
    RULE_WRITE = {
      id: "guard-config-shell-write",
      level: "block",
      reason: "Writes the guardrail hooks' own configuration from the shell"
    };
    RULE_REMOVE = {
      id: "guard-config-remove",
      level: "block",
      reason: "Removes or moves away the guardrail hooks' own configuration"
    };
    RULE_DIR = {
      id: "guard-config-dir-replace",
      level: "block",
      reason: "Moves or copies a directory onto the guardrail hooks' configuration directory"
    };
    RULE_INLINE = {
      id: "guard-config-inline-code",
      level: "block",
      reason: "Runs program code that names the guardrail hooks' own configuration"
    };
    RULE_SETTINGS = {
      id: "claude-settings-loosen",
      level: "block",
      reason: "Writes Claude Code's settings with a key that switches the guardrail hooks off"
    };
    RULE_ELSEWHERE = {
      id: "guard-config-elsewhere",
      level: "warn",
      reason: "Writes a file named like the guardrail hooks' configuration or Claude Code's settings outside this project, the working directory and the home directory \u2014 not the one this session reads; confirm the target"
    };
    BLOCK_DEVICE = /^\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-)|PhysicalDrive\d/i;
    RULE_DISK_WRITE = {
      id: "disk-overwrite",
      level: "block",
      reason: "Writes raw bytes to a block device (dd/mkfs/wipefs/shred on /dev/\u2026)"
    };
    RULE_PLUGIN_OFF = {
      id: "claude-plugin-disable",
      level: "block",
      reason: "Switches the guardrail hooks off through Claude Code's plugin command"
    };
    RULE_DB_ADOPT = {
      id: "db-adopt-yes",
      level: "block",
      reason: "db adopt --yes marks a database as trusted; run it yourself in a terminal after reading `db adopt` without --yes"
    };
    CLI_NAME = /^(?:dev-guardian(?:@[\w.^~<>=-]*)?(?:\.(?:mjs|cjs|js|cmd|ps1|exe))?|guardian\.cjs)$/i;
    CLI_HOSTS = /* @__PURE__ */ new Set(["node", "nodejs", "bun", "deno", "tsx", "ts-node", "npx", "pnpx", "bunx", "npm", "pnpm", "yarn"]);
    CLI_HOST_SUBCOMMANDS = /* @__PURE__ */ new Set(["dlx", "exec", "x", "run"]);
    RULE_BASELINE_UPDATE = {
      id: "baseline-update",
      level: "warn",
      reason: "dev-guardian baseline update accepts EVERY current finding into .guardian/baseline.json, new ones included, and the gate stops reporting them \u2014 the user decides. To accept one reviewed finding, suppress it inline with a reason (`nosemgrep: <rule> -- <reason>`, `# nosec`), or rebuild the baseline on the base commit"
    };
    START_PROCESS = /* @__PURE__ */ new Set(["start-process", "saps", "start"]);
    SHELLS = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "su", "pwsh", "powershell"]);
    DASH_C = /^-[A-Za-z]*c$/;
    MAX_DECODED = 64 * 1024;
    RULE_DECODED_SCRIPT = {
      id: "decoded-script",
      level: "warn",
      reason: "Runs decoded text as a script (base64 -d, xxd -r, gunzip, openssl \u2026 fed to a shell or an interpreter) \u2014 what it runs could not be assessed"
    };
    DOWNLOADERS = /* @__PURE__ */ new Set(["curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"]);
    PIPE_RUNNERS = /* @__PURE__ */ new Set(["sudo", "doas", "env", "command", "exec", "builtin", "nohup", "nice", "time", "timeout", "setsid", "stdbuf"]);
    STDIN_SHELLS = /* @__PURE__ */ new Set([...SHELLS, "fish", "csh", "tcsh"]);
    STDIN_PATHS = /* @__PURE__ */ new Set(["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"]);
    RULE_PIPE_TO_SHELL = {
      id: "remote-pipe-to-shell",
      level: "block",
      reason: "Pipes a downloaded script directly into a shell (curl|wget \u2026 | sh/bash)"
    };
    RULE_FETCH_EXEC = {
      id: "remote-pipe-to-shell",
      level: "block",
      reason: "Executes the output of a remote download (curl/wget via $(\u2026) or `\u2026`)"
    };
    RULE_IEX_DOWNLOAD = {
      id: "powershell-iex-download",
      level: "block",
      reason: "Downloads and executes remote code via Invoke-Expression"
    };
    RULE_DOWNLOAD_RUN = {
      id: "download-then-run",
      level: "block",
      reason: "Downloads a file and runs it in the same command (DownloadFile / -OutFile, then &, ., Start-Process, \u2026)"
    };
    RULE_POSIX_DOWNLOAD_RUN = {
      id: "download-then-run",
      level: "block",
      reason: "Downloads a file (curl -o / -O, wget, > file) and runs it in the same command (sh f, ./f, source f, python3 f, \u2026) with no checksum or signature check of that file in between"
    };
    RUN_WRAPPER_VALUED = /* @__PURE__ */ new Set([
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
    POSITIONAL = /\$(?:[0-9@*]|\{[0-9@*]\})/;
    RULE_PROCESS_FETCH = {
      id: "process-substitution-remote-fetch",
      level: "block",
      reason: "Executes a downloaded script via process substitution (bash <(curl \u2026))"
    };
    RULE_XARGS_REPLACED = {
      id: "xargs-download-program",
      level: "block",
      reason: `Writes downloaded text into a program through xargs's replacement string (xargs -I{} sh -c '\u2026 {} \u2026'), where it runs as code; hand each line over as an argument instead: xargs -I{} sh -c '\u2026 "$1"' _ {} (sys.argv / process.argv for an interpreter)`
    };
    PS_DOWNLOAD = /(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget|start-bitstransfer)(?![\w-])|\.\s*(?:downloadstring|downloaddata|downloadfile|openread|getstringasync|getbytearrayasync|getstreamasync)\s*\(/i;
    PS_EXEC_TOKENS = /(?<run>(?<![\w$.\\/-])(?:iex|invoke-expression)(?![\w.-])|\[\s*(?:(?:system\s*\.\s*)?management\s*\.\s*automation\s*\.\s*)?scriptblock\s*\]\s*::\s*create\b|\.\s*(?:invokescript|newscriptblock)\b|(?<![\w-])-scriptblock\b)|(?<dl>(?<![\w$-])(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)(?![\w-])|\.\s*(?:downloadstring|downloaddata|openread|getstringasync|getbytearrayasync|getstreamasync)\b)|(?<ref>\$(?:\{[^}\n]{0,128}\}|[\w:]+))(?<assign>\s*\+?=(?!=))?|(?<setvar>(?<![\w$.\\/-])(?:set-variable|new-variable|sv|nv)(?![\w.-]))|(?<getvar>(?<![\w$.\\/-])(?:get-variable|gv)(?![\w.-]))|(?<tee>(?<![\w$.\\/-])(?:tee-object|tee)(?![\w.-]))|(?<outvar>(?<![\w-])-(?:ov|outv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)\+?(?<outname>[A-Za-z_][\w:]*))?)|(?<teevar>(?<![\w-])-v(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?(?![\w-])(?:(?:[ \t]*:[ \t]*|[ \t]+)(?<teename>[A-Za-z_][\w:]*))?)|&&|\|\||[()|;\n]/gi;
    VARIABLE_VALUED = ["value", "scope", "option", "description", "include", "exclude", "visibility"];
    VARIABLE_NAME_WINDOW = 256;
    MAX_VARIABLE_NAMES = 256;
    DOWNLOAD_FILE_CALL = /\.\s*DownloadFile(?:Async|TaskAsync)?\s*\(/gi;
    SAVING_CMDLETS = /* @__PURE__ */ new Set(["iwr", "irm", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer", "curl", "wget"]);
    SAVE_PARAM = /^-(?:outf(?:i(?:le?)?)?|dest(?:i(?:n(?:a(?:t(?:i(?:on?)?)?)?)?)?)?)(?::(.*))?$/i;
    CURL_SHORT_VALUED = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
    WGET_SHORT_VALUED = "OoPtTwUeiaBQlDIXRA";
    URL_ARG = /^[a-z][a-z0-9+.-]*:\/\//i;
    SCRIPT_SHELLS = /* @__PURE__ */ new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish", "csh", "tcsh"]);
    OPENERS = /* @__PURE__ */ new Set(["start", "start-process", "saps", "invoke-item", "ii"]);
    RUNS_ARGUMENT = /* @__PURE__ */ new Set(["msiexec", "cscript", "wscript", "rundll32", "iex", "invoke-expression"]);
    READERS = /* @__PURE__ */ new Set(["get-content", "gc", "cat", "type"]);
    RUNNABLE_EXTENSIONS = /* @__PURE__ */ new Set([
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
    PS_ARGUMENT_LIST = /^-(?:args|a(?:r(?:g(?:u(?:m(?:e(?:n(?:t(?:l(?:i(?:st?)?)?)?)?)?)?)?)?)?)?)$/i;
    PS_FILE_PATH = /^-(?:f(?:i(?:l(?:e(?:p(?:a(?:th?)?)?)?)?)?)?|path|pspath|lp)$/i;
    MAY_DOWNLOAD = /curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadfile/i;
    TRANSFERS = /* @__PURE__ */ new Set(["mv", "cp", "install", "copy-item", "cpi", "copy", "move-item", "mi", "move"]);
    PATH_DIRS = /^(?:\/usr\/local\/s?bin|\/usr\/s?bin|\/s?bin|\/opt\/homebrew\/bin|\/opt\/local\/bin|(?:~|\$\{?home\}?)\/(?:\.local\/)?bin)$/i;
    GPG_VALUED = /* @__PURE__ */ new Set([
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
    SIDECAR = /^(.+)\.(?:sha(?:1|224|256|384|512)(?:sum)?|asc|sig|minisig)$/;
    NOT_FROM_ARCHIVE = /* @__PURE__ */ new Set([
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
    ROOT_ITSELF = /^(?:\/\*?|\\\*?|[A-Za-z]:[\\/]?\*?|\/(?:mnt\/)?[A-Za-z]\/?\*?)$/i;
    WSL_VALUED = /* @__PURE__ */ new Set(["-d", "--distribution", "-u", "--user", "--cd", "--shell-type", "--distribution-id"]);
    MAX_NESTING = 3;
    MAX_STATEMENT_LENGTH = 16 * 1024;
    MAX_COMMAND_LENGTH = 512 * 1024;
    DEFAULT_BUDGET_MS = 2500;
  }
});

// src/pkgvet/mayInstall.ts
var mayInstall_exports = {};
__export(mayInstall_exports, {
  mayInstall: () => mayInstall
});
function mayInstall(command) {
  const unquoted = command.replace(/['"`]/g, "");
  return INSTALLER_WORD.test(unquoted.replace(/\\/g, "")) || INSTALLER_WORD.test(unquoted.replace(/\\/g, "/"));
}
var INSTALLER_WORD;
var init_mayInstall = __esm({
  "src/pkgvet/mayInstall.ts"() {
    "use strict";
    INSTALLER_WORD = /(?:^|[^\w.-])(?:npm|pnpm|pnpx|npx|yarn|bunx?|pipx?|pip\d[\d.]*|uvx?|poetry|composer|dotnet)(?:$|[^\w-])/i;
  }
});

// src/pkgvet/parseCommand.ts
function isPathLike(word) {
  return word === "." || word === ".." || word.startsWith("./") || word.startsWith("../") || word.startsWith(".\\") || word.startsWith("..\\") || word.startsWith("/") || word.startsWith("~") || word.startsWith("\\") || /^[A-Za-z]:[\\/]/.test(word);
}
function notAPackage(word) {
  if (word.length === 0) return "empty";
  if (SCP_GIT.test(word)) return "SSH git spec (user@host:path) \u2014 not looked up";
  if (isPathLike(word)) return "local path \u2014 not looked up";
  if (URL_OR_VCS.test(word)) return "URL / VCS / protocol spec \u2014 not looked up";
  if (ARCHIVE.test(word)) return "archive file \u2014 not looked up";
  return null;
}
function skip(raw, reason) {
  return { raw, reason };
}
function checkName(ecosystem, name, raw) {
  if (SHELL_EXPANSION.test(name)) return skip(raw, "not a literal package name (shell expansion or glob)");
  if (!NAME_RE[ecosystem].test(name)) return skip(raw, `not a valid ${ecosystem} package name`);
  return { ecosystem, name, raw };
}
function withRange(spec, range) {
  if (!("name" in spec)) return spec;
  const r = range?.trim();
  return r !== void 0 && r !== "" ? { ...spec, range: r } : spec;
}
function parseNpm(raw) {
  if (/[$`]/.test(raw)) return skip(raw, "not a literal package name (shell expansion)");
  const bad = notAPackage(raw);
  if (bad !== null) return skip(raw, bad);
  const scoped = raw.startsWith("@");
  const at = raw.indexOf("@", scoped ? 1 : 0);
  const name = at > 0 ? raw.slice(0, at) : raw;
  let range = at > 0 ? raw.slice(at + 1) : void 0;
  if (!scoped && name.includes("/")) return skip(raw, "GitHub shorthand (user/repo) \u2014 not looked up");
  if (range !== void 0) {
    if (range.startsWith("npm:")) {
      const real = parseNpm(range.slice(4));
      return "name" in real ? { ...real, raw } : skip(raw, real.reason);
    }
    const rangeBad = notAPackage(range);
    if (rangeBad !== null || URL_OR_VCS.test(range)) return skip(raw, rangeBad ?? "URL / VCS / protocol spec \u2014 not looked up");
    if (range === "latest") range = void 0;
  }
  return withRange(checkName("npm", name, raw), range);
}
function parsePython(raw, poetryAt) {
  let text = raw.trim();
  const semi = text.indexOf(";");
  if (semi >= 0) text = text.slice(0, semi).trim();
  if (/[$`]/.test(text)) return skip(raw, "not a literal package name (shell expansion)");
  if (/\s@\s|@\s*(?:[a-z][a-z0-9+.-]*:\/\/|git\+|file:)/i.test(text)) return skip(raw, "direct URL reference \u2014 not looked up");
  const bad = notAPackage(text);
  if (bad !== null) return skip(raw, bad);
  if (/[\\/]/.test(text)) return skip(raw, "local path \u2014 not looked up");
  let name = text;
  let range;
  const at = text.indexOf("@");
  if (at > 0 && (poetryAt || !PEP440_OP.test(text))) {
    name = text.slice(0, at);
    range = text.slice(at + 1).trim();
    if (range === "latest") range = void 0;
  } else {
    const m = PEP440_OP.exec(text);
    if (m !== null) {
      name = text.slice(0, m.index);
      range = text.slice(m.index).replace(/\s+/g, "");
    }
  }
  name = name.replace(/\[[^\]]*\]/, "").replace(/\s*\(.*$/, "").trim();
  return withRange(checkName("pypi", name, raw), range);
}
function parseComposer(raw) {
  if (/[$`]/.test(raw)) return skip(raw, "not a literal package name (shell expansion)");
  const bad = notAPackage(raw);
  if (bad !== null) return skip(raw, bad);
  const sep2 = raw.search(/[:=\s]/);
  let name = sep2 > 0 ? raw.slice(0, sep2) : raw;
  let range = sep2 > 0 ? raw.slice(sep2 + 1) : void 0;
  if (sep2 < 0 && raw.includes("@") && !raw.startsWith("@")) {
    const at = raw.indexOf("@");
    name = raw.slice(0, at);
    range = raw.slice(at + 1);
  }
  if (!name.includes("/")) return skip(raw, "platform package or not a vendor/name \u2014 not looked up");
  return withRange(checkName("packagist", name, raw), range);
}
function parseNuget(raw) {
  if (/[$`]/.test(raw)) return skip(raw, "not a literal package name (shell expansion)");
  const bad = notAPackage(raw);
  if (bad !== null) return skip(raw, bad);
  const at = raw.indexOf("@");
  const name = at > 0 ? raw.slice(0, at) : raw;
  const range = at > 0 ? raw.slice(at + 1) : void 0;
  return withRange(checkName("nuget", name, raw), range);
}
function walk(words, table) {
  const positionals = [];
  const skipped = [];
  const uncertain = [];
  let customRegistry;
  const registries = [];
  const flags = [];
  const note = (flag, value) => {
    flags.push(value === void 0 ? { flag } : { flag, value });
    if (table.registry.has(flag) && value !== void 0) {
      registries.push(value);
      customRegistry = customRegistry ?? value;
    }
    if (table.registryBool?.has(flag)) {
      registries.push(flag);
      customRegistry = customRegistry ?? flag;
    }
    const why = table.reported?.get(flag);
    if (why !== void 0 && value !== void 0) skipped.push(skip(value, why));
    if (table.dir?.has(flag)) uncertain.push(`directory changed by ${flag}`);
    if (table.workspace?.has(flag)) uncertain.push(`workspace context (${flag})`);
  };
  const known = (flag) => table.value.has(flag) || table.bool.has(flag);
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    if (w === void 0) break;
    const v = w.value;
    if (v === "--") continue;
    if (!v.startsWith("-") || v.length === 1) {
      positionals.push({ value: v });
      continue;
    }
    const eqAt = v.indexOf("=");
    if (eqAt > 0) {
      const flag = v.slice(0, eqAt);
      if (!known(flag)) uncertain.push(`unknown flag ${flag}`);
      note(flag, v.slice(eqAt + 1));
      continue;
    }
    if (table.value.has(v)) {
      note(v, words[i + 1]?.value);
      i += 1;
      continue;
    }
    if (table.bool.has(v)) {
      note(v, void 0);
      continue;
    }
    if (!v.startsWith("--") && SHORT_CLUSTER.test(v)) {
      for (let k = 1; k < v.length; k += 1) {
        const flag = `-${v.charAt(k)}`;
        if (table.value.has(flag)) {
          const rest = v.slice(k + 1);
          if (rest !== "") note(flag, rest);
          else {
            note(flag, words[i + 1]?.value);
            i += 1;
          }
          break;
        }
        if (!table.bool.has(flag)) uncertain.push(`unknown flag ${flag}`);
        note(flag, void 0);
      }
      continue;
    }
    uncertain.push(`unknown flag ${v}`);
    if (v.startsWith("--") && !v.startsWith("--no-")) i += 1;
  }
  const out = { positionals, skipped, uncertain, registries, flags };
  if (customRegistry !== void 0) out.customRegistry = customRegistry;
  return out;
}
function base(word) {
  const last = word.split(/[\\/]/).pop() ?? word;
  return last.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, "");
}
function commandStart(words) {
  return commandWordIndex(words);
}
function launcher(manager, ecosystem, args, pre, launch) {
  return { manager, ecosystem, args, pre, uncertain: [], launch };
}
function nextPositional(words, from, table) {
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v.startsWith("-") && v.length > 1) {
      if (!v.includes("=") && table.value.has(v)) i += 1;
      continue;
    }
    return i;
  }
  return -1;
}
function detect(words) {
  const start = commandStart(words);
  const headWord = words[start];
  if (headWord === void 0) return null;
  let head = base(headWord.value);
  let i = start + 1;
  if (/^(?:python[0-9.]*|py)$/.test(head)) {
    const m = words.findIndex((w, idx) => idx > start && w.value === "-m");
    const mod = m >= 0 ? words[m + 1]?.value : void 0;
    if (mod === void 0 || !/^(?:pip[0-9.]*|uv)$/.test(mod)) return null;
    head = mod.startsWith("pip") ? "pip" : "uv";
    i = m + 2;
  } else if (head === "php") {
    const script = words[start + 1]?.value ?? "";
    if (!/composer(?:\.phar)?$/i.test(script)) return null;
    head = "composer";
    i = start + 2;
  }
  if (/^pip[0-9.]*$/.test(head)) head = "pip";
  if (head === "composer.phar") head = "composer";
  const rest = words.slice(i);
  if (head === "npx") return launcher("npx", "npm", rest, [], { style: "run", flags: "npx", localFirst: true });
  if (head === "pnpx") return launcher("pnpm", "npm", rest, [], { style: "run", flags: "pnpm-dlx" });
  if (head === "bunx") return launcher("bun", "npm", rest, [], { style: "run", flags: "bunx", localFirst: true });
  if (head === "uvx") return launcher("uv", "pypi", rest, [], { style: "run", flags: "uvx" });
  if (head === "pipx") {
    const sub2 = nextPositional(words, i, LAUNCH_FLAGS["pipx-run"] ?? FLAGS["pip"] ?? { value: set(), bool: set(), registry: set() });
    const subWord2 = sub2 < 0 ? "" : words[sub2]?.value ?? "";
    if (subWord2 === "install") return launcher("pipx", "pypi", words.slice(sub2 + 1), words.slice(i, sub2), { style: "install", flags: "pipx-install" });
    if (subWord2 === "run") return launcher("pipx", "pypi", words.slice(sub2 + 1), words.slice(i, sub2), { style: "run", flags: "pipx-run" });
    return null;
  }
  const table = FLAGS[head];
  if (table === void 0) return null;
  const sub = nextPositional(words, i, table);
  if (sub < 0) return null;
  const subName = words[sub]?.value ?? "";
  const after2 = words.slice(sub + 1);
  const before = words.slice(i, sub);
  if (head === "npm" && (subName === "exec" || subName === "x")) {
    return launcher("npm", "npm", after2, before, { style: "run", flags: "npx", localFirst: true });
  }
  if (head === "pnpm" && subName === "dlx") return launcher("pnpm", "npm", after2, before, { style: "run", flags: "pnpm-dlx" });
  if (head === "yarn" && subName === "dlx") return launcher("yarn", "npm", after2, before, { style: "run", flags: "yarn-dlx" });
  if (head === "bun" && subName === "x") return launcher("bun", "npm", after2, before, { style: "run", flags: "bunx", localFirst: true });
  if (head === "uv" && subName === "tool") {
    const toolTable = LAUNCH_FLAGS["uvx"] ?? table;
    const verb = nextPositional(words, sub + 1, toolTable);
    const verbName = verb < 0 ? "" : words[verb]?.value ?? "";
    const tail2 = words.slice(verb + 1);
    if (verbName === "run") return launcher("uv", "pypi", tail2, before, { style: "run", flags: "uvx" });
    if (verbName === "install") return launcher("uv", "pypi", tail2, before, { style: "install", flags: "uv-tool-install" });
    return null;
  }
  const subWord = words[sub]?.value ?? "";
  const pre = words.slice(i, sub);
  switch (head) {
    case "npm":
      return NPM_INSTALL.has(subWord) ? { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case "pnpm":
      return subWord === "add" ? { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case "bun":
      return BUN_ADD.has(subWord) ? { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case "yarn": {
      let at = sub;
      const uncertain = [];
      if (subWord === "global") at = nextPositional(words, sub + 1, table);
      else if (subWord === "workspace") {
        const ws = nextPositional(words, sub + 1, table);
        at = ws < 0 ? -1 : nextPositional(words, ws + 1, table);
        uncertain.push("workspace context (yarn workspace)");
      }
      if (at < 0 || words[at]?.value !== "add") return null;
      return { manager: head, ecosystem: "npm", args: words.slice(at + 1), pre, uncertain };
    }
    case "pip":
      return subWord === "install" ? { manager: head, ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case "uv": {
      if (subWord === "add") return { manager: "uv", ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [] };
      if (subWord === "pip") {
        const inst = nextPositional(words, sub + 1, table);
        if (inst >= 0 && words[inst]?.value === "install") {
          return { manager: "uv-pip", ecosystem: "pypi", args: words.slice(inst + 1), pre, uncertain: [] };
        }
      }
      return null;
    }
    case "poetry":
      return subWord === "add" ? { manager: head, ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case "composer":
      return COMPOSER_REQUIRE.has(subWord) ? { manager: head, ecosystem: "packagist", args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case "dotnet": {
      if (subWord !== "add") return null;
      let at = nextPositional(words, sub + 1, table);
      const uncertain = [];
      if (at >= 0 && words[at]?.value !== "package") {
        uncertain.push("dotnet project argument (the NuGet configuration next to that project was not read)");
        at = nextPositional(words, at + 1, table);
      }
      if (at < 0 || words[at]?.value !== "package") return null;
      return { manager: head, ecosystem: "nuget", args: words.slice(at + 1), pre, uncertain };
    }
    default:
      return null;
  }
}
function collectLaunch(d, launch, context) {
  const table = LAUNCH_FLAGS[launch.flags] ?? { value: set(), bool: set(), registry: set() };
  const pre = walk(d.pre, table);
  let body = d.args;
  if (launch.style === "run") {
    const at = nextPositional(d.args, 0, table);
    if (at >= 0) body = d.args.slice(0, at + 1);
  }
  const w = walk(body, table);
  const flags = [...pre.flags, ...w.flags];
  const has = (names) => names !== void 0 && flags.some((f) => names.has(f.flag));
  const values = (names) => names === void 0 ? [] : flags.filter((f) => names.has(f.flag)).flatMap((f) => (f.value ?? "").split(",")).map((v) => v.trim()).filter((v) => v !== "");
  const raws = [];
  if (!has(table.noFetchFlags)) {
    const named = values(table.packageFlags);
    if (named.length > 0) raws.push(...named);
    else if (!has(table.shellFlags)) raws.push(...w.positionals.map((p) => p.value));
    raws.push(...values(table.extraPackageFlags));
  }
  const packages = [];
  const skipped = [...pre.skipped, ...w.skipped];
  for (const raw of raws) {
    const spec = d.ecosystem === "npm" ? parseNpm(raw) : parsePython(raw, false);
    if ("name" in spec) packages.push(spec);
    else skipped.push(spec);
  }
  const out = {
    ecosystem: d.ecosystem,
    manager: d.manager,
    packages,
    skipped,
    uncertain: [.../* @__PURE__ */ new Set([...context, ...pre.uncertain, ...w.uncertain])],
    registries: [...pre.registries, ...w.registries]
  };
  const registry = pre.customRegistry ?? w.customRegistry;
  if (registry !== void 0) out.customRegistry = registry;
  if (launch.localFirst === true) out.localFirst = true;
  return out;
}
function collect2(d, context) {
  if (d.launch !== void 0) return collectLaunch(d, d.launch, context);
  const table = FLAGS[d.manager === "uv-pip" ? "pip" : d.manager] ?? FLAGS["npm"];
  const flagTable = table ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, flagTable);
  const { positionals, skipped, customRegistry, uncertain, registries } = walk(d.args, flagTable);
  const packages = [];
  const out = {
    ecosystem: d.ecosystem,
    manager: d.manager,
    packages,
    skipped,
    uncertain: [.../* @__PURE__ */ new Set([...context, ...d.uncertain, ...preWalk.uncertain, ...uncertain])],
    registries: [...preWalk.registries, ...registries]
  };
  const registry = preWalk.customRegistry ?? customRegistry;
  if (registry !== void 0) out.customRegistry = registry;
  let lastComposer;
  for (const p of positionals) {
    let spec;
    switch (d.ecosystem) {
      case "npm":
        spec = parseNpm(p.value);
        break;
      case "pypi":
        spec = parsePython(p.value, d.manager === "poetry");
        break;
      case "packagist":
        if (lastComposer !== void 0 && lastComposer.range === void 0 && !p.value.includes("/") && COMPOSER_CONSTRAINT.test(p.value)) {
          lastComposer.range = p.value;
          continue;
        }
        spec = parseComposer(p.value);
        break;
      case "nuget":
        spec = parseNuget(p.value);
        break;
      default:
        spec = skip(p.value, "unsupported ecosystem");
    }
    if ("name" in spec) {
      packages.push(spec);
      lastComposer = d.ecosystem === "packagist" ? spec : void 0;
    } else {
      skipped.push(spec);
      lastComposer = void 0;
    }
  }
  if (d.ecosystem === "nuget") {
    const extra = packages.splice(1);
    for (const e of extra) skipped.push(skip(e.raw, "unexpected extra argument to dotnet add package"));
    const first = packages[0];
    const version = flagValue(d.args, ["-v", "--version"]);
    if (first !== void 0 && version !== void 0) first.range = version;
  }
  return out;
}
function flagValue(words, names) {
  for (let i = 0; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    for (const n of names) {
      if (v === n) return words[i + 1]?.value;
      if (v.startsWith(`${n}=`)) return v.slice(n.length + 1);
    }
  }
  return void 0;
}
function packageKey(p) {
  return `${p.ecosystem}\0${p.name.toLowerCase()}\0${p.range ?? ""}`;
}
function parseInstallCommands(command, opts = {}) {
  const text = stripComments(command);
  const out = parseReading(text, null);
  if (opts.shell !== "powershell") return out;
  const asPowerShell = powershellAsPosix(text);
  if (asPowerShell === text) return out;
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  for (const c of parseReading(asPowerShell, POWERSHELL_READING)) {
    const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
    if (packages.length === 0) continue;
    for (const p of packages) seen.add(packageKey(p));
    out.push({ ...c, packages, skipped: [] });
  }
  return out;
}
function parseReading(text, forced) {
  const out = [];
  let split;
  try {
    split = splitShell(text);
  } catch {
    return out;
  }
  const notConfident = forced ?? confidentShape(text);
  const envChange = changesEnvironment(text, split.statements);
  let dirChanged = false;
  let workdir;
  for (const statement of split.statements) {
    for (const words of statement.commands) {
      const d = detect(words);
      if (d !== null) {
        const context = [];
        if (envChange) context.push("inline environment assignment in the command (it can redirect the registry)");
        if (dirChanged) context.push("directory change earlier in the command (that directory\u2019s registry configuration was not read)");
        const c = collect2(d, context);
        c.uncertain = notConfident === null ? [] : [.../* @__PURE__ */ new Set([notConfident, ...c.uncertain])];
        if (workdir !== void 0) c.workdir = workdir;
        out.push(c);
      }
      if (changesDirectory(words)) {
        dirChanged = true;
        workdir = directoryAfter(workdir, words);
      }
    }
  }
  return out;
}
function stripComments(command) {
  let out = "";
  let quote = null;
  let i = 0;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (quote === "'") {
      out += ch;
      if (ch === "'") quote = null;
      i += 1;
      continue;
    }
    if (quote === '"') {
      out += ch;
      if ((ch === "\\" || ch === "`") && i + 1 < command.length) {
        out += command.charAt(i + 1);
        i += 2;
        continue;
      }
      if (ch === '"') quote = null;
      i += 1;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === "\\" && i + 1 < command.length) {
      out += ch + command.charAt(i + 1);
      i += 2;
      continue;
    }
    if (ch === "<" && command.charAt(i + 1) === "#") {
      const end = command.indexOf("#>", i + 2);
      i = end < 0 ? command.length : end + 2;
      out += " ";
      continue;
    }
    if (ch === "#" && (out === "" || /[\s;&|(]$/.test(out))) {
      const nl = command.indexOf("\n", i);
      i = nl < 0 ? command.length : nl;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}
function notSingle(why) {
  return `not a single plain install statement (${why})`;
}
function notPlain(why) {
  return `not a plain install command (${why})`;
}
function confidentShape(text) {
  const t = text.trim();
  const words = [];
  let cur = "";
  let has = false;
  let quote = null;
  for (let i = 0; i < t.length; i += 1) {
    const ch = t.charAt(i);
    if (quote === "'") {
      if (ch !== "'") cur += ch;
      else if (t.charAt(i + 1) === "'") return notSingle("adjacent '\u2026' spans (PowerShell reads '' as a quote)");
      else quote = null;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === "$" || ch === "`" || ch === "\\") return notSingle(`'${ch}' inside double quotes`);
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
      continue;
    }
    if (ch === " " || ch === "	") {
      if (has) words.push(cur);
      cur = "";
      has = false;
      continue;
    }
    if (NOT_SIMPLE.test(ch)) return notSingle(`'${ch === "\n" || ch === "\r" ? "newline" : ch}' outside quotes`);
    cur += ch;
    has = true;
  }
  if (quote !== null) return notSingle("unterminated quote");
  if (has) words.push(cur);
  const [tool, ...rest] = words;
  if (tool === void 0) return notSingle("empty");
  const at = (k) => rest[k] ?? "";
  let key;
  let args;
  let launch = false;
  switch (tool) {
    case "npx":
    case "bunx":
    case "uvx":
      [key, args, launch] = [tool, rest, true];
      break;
    case "pnpx":
      [key, args, launch] = ["pnpm-dlx", rest, true];
      break;
    case "pipx":
      if (at(0) === "install") [key, args] = ["pipx-install", rest.slice(1)];
      else if (at(0) === "run") [key, args, launch] = ["pipx-run", rest.slice(1), true];
      else return notPlain(`'pipx ${at(0)}'`);
      break;
    case "npm":
      if (at(0) === "exec" || at(0) === "x") {
        [key, args, launch] = ["npx", rest.slice(1), true];
        break;
      }
      if (!NPM_INSTALL.has(at(0))) return notPlain(`'npm ${at(0)}'`);
      [key, args] = ["npm", rest.slice(1)];
      break;
    case "pnpm":
    case "yarn":
      if (at(0) === "dlx") {
        [key, args, launch] = [`${tool}-dlx`, rest.slice(1), true];
        break;
      }
      if (at(0) !== "add") return notPlain(`'${tool} ${at(0)}'`);
      [key, args] = [tool, rest.slice(1)];
      break;
    case "bun":
      if (at(0) === "x") {
        [key, args, launch] = ["bunx", rest.slice(1), true];
        break;
      }
      if (!BUN_ADD.has(at(0))) return notPlain(`'bun ${at(0)}'`);
      [key, args] = ["bun", rest.slice(1)];
      break;
    case "pip":
    case "pip3":
      if (at(0) !== "install") return notPlain(`'${tool} ${at(0)}'`);
      [key, args] = ["pip", rest.slice(1)];
      break;
    case "python":
    case "python3":
    case "py":
      if (at(0) !== "-m" || at(1) !== "pip" && at(1) !== "pip3" || at(2) !== "install") return notPlain(`'${tool} ${rest.join(" ")}'`);
      [key, args] = ["pip", rest.slice(3)];
      break;
    case "uv":
      if (at(0) === "add") [key, args] = ["uv", rest.slice(1)];
      else if (at(0) === "pip" && at(1) === "install") [key, args] = ["uv-pip", rest.slice(2)];
      else if (at(0) === "tool" && at(1) === "run") [key, args, launch] = ["uvx", rest.slice(2), true];
      else if (at(0) === "tool" && at(1) === "install") [key, args] = ["uv-tool-install", rest.slice(2)];
      else return notPlain(`'uv ${at(0)}'`);
      break;
    case "poetry":
      if (at(0) !== "add") return notPlain(`'poetry ${at(0)}'`);
      [key, args] = ["poetry", rest.slice(1)];
      break;
    case "composer":
      if (at(0) !== "require") return notPlain(`'composer ${at(0)}'`);
      [key, args] = ["composer", rest.slice(1)];
      break;
    case "dotnet":
      if (at(0) !== "add" || at(1) !== "package") return notPlain(`'dotnet ${at(0)} ${at(1)}' (dotnet add <project> package \u2026)`);
      [key, args] = ["dotnet", rest.slice(2)];
      break;
    default:
      return notPlain(`'${tool}' is not a bare package-manager name`);
  }
  const allow = ALLOW[key];
  if (allow === void 0) return notPlain(`no allowlist for ${key}`);
  let positionals = 0;
  for (let k = 0; k < args.length; k += 1) {
    const w = args[k] ?? "";
    if (launch && w === "--") continue;
    if (!w.startsWith("-") || w === "-") {
      if (launch) return null;
      positionals += 1;
      continue;
    }
    const eqAt = w.indexOf("=");
    if (eqAt > 0) {
      const flag = w.slice(0, eqAt);
      if (!allow.value.has(flag)) return `flag ${flag} is not on the confident-shape allowlist`;
      continue;
    }
    if (allow.bool.has(w)) continue;
    if (allow.value.has(w)) {
      if (k + 1 >= args.length) return `flag ${w} has no value`;
      k += 1;
      continue;
    }
    if (!w.startsWith("--") && SHORT_CLUSTER.test(w)) {
      const bad = [...w.slice(1)].map((c) => `-${c}`).find((f) => !allow.bool.has(f));
      if (bad === void 0) continue;
      return `flag ${bad} is not on the confident-shape allowlist`;
    }
    return `flag ${w} is not on the confident-shape allowlist`;
  }
  return positionals > 0 ? null : notPlain("no package named");
}
function changesDirectory(words) {
  const head = words[commandStart(words)];
  return head !== void 0 && DIR_COMMANDS.has(base(head.value));
}
function directoryAfter(prev, words) {
  if (prev === null) return null;
  const at = commandStart(words);
  const name = base(words[at]?.value ?? "");
  if (name === "popd" || name === "pop-location") return null;
  const steps = prev ?? [];
  if (name === "cd..") return [...steps, ".."];
  const operands2 = words.slice(at + 1).map((w) => w.value).filter((v, _, all) => !/^-[LPe@]+$/.test(v) && !/^-(?:path|literalpath)$/i.test(v) && !(all.length > 1 && /^\/d$/i.test(v)));
  const target = operands2[0];
  if (operands2.length !== 1 || target === void 0 || target === "" || target === "-" || UNREAD_TARGET.test(target)) return null;
  return [...steps, target];
}
function powershellSetsEnv(command) {
  if (/\$env:[A-Za-z_][A-Za-z0-9_]*\s*=|SetEnvironmentVariable/i.test(command)) return true;
  for (const segment of command.split(/[;\n]/)) {
    const m = /\b(?:Set-Item|New-Item)\b/i.exec(segment);
    if (m !== null && /\benv:/i.test(segment.slice(m.index + m[0].length))) return true;
  }
  return false;
}
function changesEnvironment(command, statements) {
  if (powershellSetsEnv(command)) return true;
  for (const statement of statements) {
    for (const words of statement.commands) {
      const start = commandStart(words);
      for (let i = 0; i < start; i += 1) {
        const w = words[i];
        if (w !== void 0 && (ASSIGNMENT2.test(w.value) || base(w.value) === "env")) return true;
      }
      const head = words[start];
      if (head === void 0) continue;
      const name = base(head.value);
      if (name === "env") return true;
      if (ENV_COMMANDS.has(name)) {
        const args = words.slice(start + 1);
        if (name === "export" || name === "setx" || args.some((a) => a.value.includes("="))) return true;
      }
    }
  }
  return false;
}
var NAME_RE, SHELL_EXPANSION, URL_OR_VCS, ARCHIVE, SCP_GIT, PEP440_OP, set, NPM_COMMON_BOOL, FLAGS, UV_VALUED, UV_BOOL, UV_REGISTRY, LAUNCH_FLAGS, SHORT_CLUSTER, ASSIGNMENT2, NPM_INSTALL, COMPOSER_REQUIRE, BUN_ADD, COMPOSER_CONSTRAINT, POWERSHELL_READING, NPM_ALLOW_BOOL, ALLOW, NOT_SIMPLE, DIR_COMMANDS, UNREAD_TARGET, ENV_COMMANDS;
var init_parseCommand = __esm({
  "src/pkgvet/parseCommand.ts"() {
    "use strict";
    init_command();
    init_split();
    init_powershellText();
    NAME_RE = {
      npm: /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-zA-Z0-9][a-zA-Z0-9._~-]*$/,
      pypi: /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/,
      packagist: /^[a-z0-9](?:[_.-]?[a-z0-9]+)*\/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]+)*$/i,
      nuget: /^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$/
    };
    SHELL_EXPANSION = /[$`*?{}[\]<>|&;]/;
    URL_OR_VCS = /^(?:[a-z][a-z0-9+.-]*:\/\/|git\+|git:|hg\+|svn\+|bzr\+|github:|gitlab:|bitbucket:|gist:|file:|link:|workspace:|portal:|patch:|exec:)/i;
    ARCHIVE = /\.(?:tgz|tar|tar\.gz|tar\.bz2|tar\.xz|zip|whl|egg|nupkg)$/i;
    SCP_GIT = /^[A-Za-z0-9._-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:/;
    PEP440_OP = /(===|==|~=|!=|<=|>=|<|>)/;
    set = (...xs) => new Set(xs);
    NPM_COMMON_BOOL = [
      "--save",
      "-S",
      "--save-dev",
      "-D",
      "--save-optional",
      "-O",
      "--save-peer",
      "--save-exact",
      "-E",
      "--save-bundle",
      "-B",
      "--no-save",
      "--save-prod",
      "-P",
      "--global",
      "-g",
      "--legacy-peer-deps",
      "--strict-peer-deps",
      "--force",
      "-f",
      "--ignore-scripts",
      "--no-audit",
      "--audit",
      "--no-fund",
      "--fund",
      "--dry-run",
      "--prefer-offline",
      "--prefer-online",
      "--offline",
      "--no-package-lock",
      "--package-lock-only",
      "--foreground-scripts",
      "--install-links",
      "--no-optional",
      "--production",
      "--dev",
      "--no-bin-links",
      "--bin-links",
      "--global-style",
      "--legacy-bundling",
      "--no-shrinkwrap",
      "--silent",
      "--quiet",
      "-q",
      "--verbose",
      "-d",
      "--json",
      "--progress",
      "--no-progress",
      "--color",
      "--no-color",
      "--workspaces",
      "--include-workspace-root",
      "--if-present",
      "--yes",
      "-y",
      "--no-workspaces",
      "--no-update-notifier",
      "--exact",
      "--peer",
      "--optional",
      "--tilde",
      "-T",
      "--frozen-lockfile",
      "--no-frozen-lockfile"
    ];
    FLAGS = {
      npm: {
        // `-C` is npm's short form of `--prefix`.
        value: set(
          "--registry",
          "--prefix",
          "-C",
          "--tag",
          "--workspace",
          "-w",
          "--omit",
          "--include",
          "--install-strategy",
          "--cache",
          "--userconfig",
          "--globalconfig",
          "--before",
          "--loglevel",
          "--save-prefix",
          "--otp",
          "--scope",
          "--cpu",
          "--os",
          "--libc",
          "--location"
        ),
        bool: set(...NPM_COMMON_BOOL),
        registry: set("--registry"),
        dir: set("--prefix", "-C"),
        workspace: set("--workspace", "-w", "--workspaces")
      },
      pnpm: {
        value: set(
          "--registry",
          "--filter",
          "-F",
          "--dir",
          "-C",
          "--reporter",
          "--store-dir",
          "--global-dir",
          "--modules-dir",
          "--virtual-store-dir",
          "--lockfile-dir",
          "--network-concurrency",
          "--config",
          "--loglevel",
          "--allow-build"
        ),
        bool: set(...NPM_COMMON_BOOL, "--workspace", "-w", "--workspace-root", "--recursive", "-r"),
        registry: set("--registry"),
        dir: set("--dir", "-C"),
        workspace: set("--workspace", "--filter", "-F")
      },
      yarn: {
        value: set(
          "--registry",
          "--cwd",
          "--network-timeout",
          "--modules-folder",
          "--cache-folder",
          "--mutex",
          "--scope",
          "--mode"
        ),
        bool: set(
          ...NPM_COMMON_BOOL,
          "--ignore-workspace-root-check",
          "-W",
          "--cached",
          "--interactive",
          "-i",
          "--prefer-dev"
        ),
        registry: set("--registry"),
        dir: set("--cwd")
      },
      bun: {
        value: set(
          "--registry",
          "--cwd",
          "--backend",
          "--cache-dir",
          "--config",
          "-c",
          "--concurrent-scripts",
          "--network-concurrency",
          "--omit",
          "--linker",
          "--ca",
          "--cafile",
          "--filter"
        ),
        bool: set(
          ...NPM_COMMON_BOOL,
          "--trust",
          "--analyze",
          "-a",
          "--only-missing",
          "--save-text-lockfile",
          "--no-cache",
          "-p"
        ),
        registry: set("--registry"),
        dir: set("--cwd"),
        workspace: set("--filter")
      },
      pip: {
        value: set(
          "-r",
          "--requirement",
          "-c",
          "--constraint",
          "-e",
          "--editable",
          "-t",
          "--target",
          "--prefix",
          "--root",
          "-i",
          "--index-url",
          "--extra-index-url",
          "-f",
          "--find-links",
          "--trusted-host",
          "--platform",
          "--python-version",
          "--implementation",
          "--abi",
          "--src",
          "--upgrade-strategy",
          "--progress-bar",
          "--log",
          "--proxy",
          "--retries",
          "--timeout",
          "--exists-action",
          "--cert",
          "--client-cert",
          "--cache-dir",
          "--no-binary",
          "--only-binary",
          "--config-settings",
          "-C",
          "--global-option",
          "--report",
          "--python",
          "--root-user-action",
          "--keyring-provider",
          "--group",
          "--index-strategy",
          "--extra",
          "--override",
          "-p",
          "--prerelease",
          "--resolution"
        ),
        bool: set(
          "-U",
          "--upgrade",
          "--user",
          "--no-deps",
          "--pre",
          "--force-reinstall",
          "-I",
          "--ignore-installed",
          "--no-cache-dir",
          "--no-cache",
          "-q",
          "-v",
          "--quiet",
          "--verbose",
          "--break-system-packages",
          "--dry-run",
          "--no-build-isolation",
          "--require-hashes",
          "--isolated",
          "--disable-pip-version-check",
          "--no-input",
          "--compile",
          "--no-compile",
          "--prefer-binary",
          "--no-warn-script-location",
          "--use-pep517",
          "--no-clean",
          "--check-build-dependencies",
          "--ignore-requires-python",
          "--system",
          "--all-extras",
          "--no-index",
          "--compile-bytecode"
        ),
        registry: set("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index", "--default-index"),
        registryBool: set("--no-index"),
        reported: /* @__PURE__ */ new Map([
          ["-r", "requirements file (-r) \u2014 its contents are not vetted"],
          ["--requirement", "requirements file (-r) \u2014 its contents are not vetted"],
          ["-c", "constraints file (-c) \u2014 not vetted"],
          ["--constraint", "constraints file (-c) \u2014 not vetted"],
          ["-e", "editable install (-e) \u2014 local or VCS source, not looked up"],
          ["--editable", "editable install (-e) \u2014 local or VCS source, not looked up"]
        ])
      },
      uv: {
        value: set(
          "--group",
          "--optional",
          "--index",
          "--index-url",
          "--default-index",
          "--extra-index-url",
          "--extra",
          "--package",
          "--script",
          "-r",
          "--requirements",
          "--constraints",
          "-c",
          "--rev",
          "--tag",
          "--branch",
          "--python",
          "-p",
          "--bounds",
          "--directory",
          "--project",
          "--config-file",
          "--cache-dir",
          "--marker",
          "-m",
          "--find-links",
          "-f",
          "--index-strategy",
          "--keyring-provider",
          "--resolution",
          "--prerelease",
          "--exclude-newer",
          "--link-mode",
          "--no-binary-package",
          "--no-build-package",
          "--upgrade-package",
          "-P",
          "--reinstall-package",
          "--refresh-package",
          "--config-setting",
          "-C"
        ),
        bool: set(
          "--dev",
          "--editable",
          "--no-editable",
          "--raw",
          "--raw-sources",
          "--frozen",
          "--locked",
          "--no-sync",
          "--workspace",
          "--no-workspace",
          "--active",
          "-U",
          "--upgrade",
          "--offline",
          "--no-cache",
          "-n",
          "-q",
          "-v",
          "--quiet",
          "--verbose",
          "--native-tls",
          "--no-index",
          "--no-build-isolation",
          "--refresh",
          "--reinstall",
          "--no-build",
          "--no-binary",
          "--no-config",
          "--no-progress",
          "--compile-bytecode"
        ),
        registry: set("--index", "--index-url", "--default-index", "--extra-index-url", "--find-links", "-f"),
        registryBool: set("--no-index"),
        reported: /* @__PURE__ */ new Map([
          ["-r", "requirements file (-r) \u2014 its contents are not vetted"],
          ["--requirements", "requirements file (-r) \u2014 its contents are not vetted"]
        ]),
        dir: set("--directory", "--project"),
        workspace: set("--package")
      },
      poetry: {
        value: set(
          "--group",
          "-G",
          "--extras",
          "-E",
          "--python",
          "--platform",
          "--source",
          "--markers",
          "--directory",
          "-C",
          "--project",
          "-P",
          "--optional"
        ),
        bool: set(
          "--dev",
          "-D",
          "--editable",
          "-e",
          "--allow-prereleases",
          "--dry-run",
          "--lock",
          "--no-interaction",
          "-n",
          "-q",
          "-v",
          "-vv",
          "-vvv",
          "--quiet",
          "--verbose",
          "--no-ansi",
          "--ansi"
        ),
        registry: set("--source"),
        dir: set("--directory", "-C", "--project", "-P")
      },
      composer: {
        dir: set("--working-dir", "-d"),
        value: set("--working-dir", "-d"),
        bool: set(
          "--dev",
          "--no-dev",
          "--no-update",
          "--no-install",
          "--no-audit",
          "--no-security-blocking",
          "--update-with-dependencies",
          "-w",
          "--update-with-all-dependencies",
          "-W",
          "--with-dependencies",
          "--with-all-dependencies",
          "--prefer-dist",
          "--prefer-source",
          "--prefer-install",
          "--dry-run",
          "--no-progress",
          "--no-scripts",
          "--no-plugins",
          "--update-no-dev",
          "--ignore-platform-reqs",
          "--prefer-stable",
          "--prefer-lowest",
          "--sort-packages",
          "--optimize-autoloader",
          "-o",
          "--classmap-authoritative",
          "-a",
          "--apcu-autoloader",
          "--fixed",
          "-n",
          "--no-interaction",
          "-q",
          "--quiet",
          "-v",
          "-vv",
          "-vvv",
          "--ansi",
          "--no-ansi",
          "--no-cache",
          "--minimal-changes",
          "-m"
        ),
        registry: set()
      },
      dotnet: {
        value: set("-v", "--version", "-f", "--framework", "-s", "--source", "--package-directory"),
        bool: set("-n", "--no-restore", "--interactive", "--prerelease"),
        registry: set("-s", "--source")
      }
    };
    UV_VALUED = [
      "--python",
      "-p",
      "--index",
      "--index-url",
      "--default-index",
      "--extra-index-url",
      "--find-links",
      "-f",
      "--index-strategy",
      "--keyring-provider",
      "--resolution",
      "--prerelease",
      "--exclude-newer",
      "--link-mode",
      "--directory",
      "--project",
      "--config-file",
      "--cache-dir",
      "--constraints",
      "--overrides",
      "--env-file",
      "--with-requirements",
      "--with-editable",
      "--python-preference",
      "--color"
    ];
    UV_BOOL = [
      "--isolated",
      "--offline",
      "-q",
      "--quiet",
      "-v",
      "--verbose",
      "--no-cache",
      "-n",
      "--refresh",
      "--reinstall",
      "--upgrade",
      "-U",
      "--native-tls",
      "--no-config",
      "--no-progress",
      "--no-python-downloads",
      "--force",
      "--no-index",
      "--compile-bytecode"
    ];
    UV_REGISTRY = ["--index", "--index-url", "--default-index", "--extra-index-url", "--find-links", "-f"];
    LAUNCH_FLAGS = {
      npx: {
        value: set(
          "--package",
          "-p",
          "--call",
          "-c",
          "--registry",
          "--cache",
          "--userconfig",
          "--prefix",
          "--workspace",
          "-w",
          "--loglevel",
          "--node-options"
        ),
        bool: set(
          "--yes",
          "-y",
          "--no",
          "--no-install",
          "--ignore-existing",
          "--quiet",
          "-q",
          "--silent",
          "--prefer-offline",
          "--prefer-online",
          "--offline",
          "--workspaces",
          "--include-workspace-root",
          "--verbose"
        ),
        registry: set("--registry"),
        workspace: set("--workspace", "-w", "--workspaces"),
        packageFlags: set("--package", "-p"),
        shellFlags: set("--call", "-c"),
        noFetchFlags: set("--no", "--no-install", "--offline")
      },
      "pnpm-dlx": {
        value: set("--package", "--allow-build", "--registry", "--dir", "-C", "--reporter"),
        bool: set("--silent", "-s", "--shell-mode", "-c"),
        registry: set("--registry"),
        dir: set("--dir", "-C"),
        packageFlags: set("--package"),
        shellFlags: set("--shell-mode", "-c")
      },
      "yarn-dlx": {
        value: set("--package", "-p"),
        bool: set("--quiet", "-q"),
        registry: set(),
        packageFlags: set("--package", "-p")
      },
      bunx: {
        value: set("--package", "-p"),
        bool: set("--bun", "--silent", "--verbose"),
        registry: set(),
        packageFlags: set("--package", "-p")
      },
      uvx: {
        value: set(...UV_VALUED, "--from", "--with", "-w"),
        bool: set(...UV_BOOL),
        registry: set(...UV_REGISTRY),
        registryBool: set("--no-index"),
        dir: set("--directory", "--project"),
        packageFlags: set("--from"),
        extraPackageFlags: set("--with", "-w")
      },
      "uv-tool-install": {
        value: set(...UV_VALUED, "--with", "-w", "--editable", "-e"),
        bool: set(...UV_BOOL),
        registry: set(...UV_REGISTRY),
        registryBool: set("--no-index"),
        dir: set("--directory", "--project"),
        extraPackageFlags: set("--with", "-w"),
        reported: /* @__PURE__ */ new Map([
          ["--editable", "editable install (-e) \u2014 local or VCS source, not looked up"],
          ["-e", "editable install (-e) \u2014 local or VCS source, not looked up"]
        ])
      },
      "pipx-install": {
        value: set("--index-url", "-i", "--suffix", "--python", "--preinstall", "--spec"),
        bool: set(
          "--force",
          "-f",
          "--include-deps",
          "--editable",
          "-e",
          "--system-site-packages",
          "--global",
          "--quiet",
          "-q",
          "--verbose",
          "-v",
          "--fetch-missing-python"
        ),
        registry: set("--index-url", "-i"),
        extraPackageFlags: set("--preinstall", "--spec")
      },
      "pipx-run": {
        value: set("--spec", "--index-url", "-i", "--python", "--path"),
        bool: set("--no-cache", "--quiet", "-q", "--verbose", "-v", "--system-site-packages", "--fetch-missing-python"),
        registry: set("--index-url", "-i"),
        packageFlags: set("--spec")
      }
    };
    SHORT_CLUSTER = /^-[A-Za-z]{2,}/;
    ASSIGNMENT2 = /^[A-Za-z_][A-Za-z0-9_]*=/;
    NPM_INSTALL = /* @__PURE__ */ new Set(["install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"]);
    COMPOSER_REQUIRE = /* @__PURE__ */ new Set(["require", "r", "req", "requ", "requi", "requir"]);
    BUN_ADD = /* @__PURE__ */ new Set(["add", "a", "install", "i"]);
    COMPOSER_CONSTRAINT = /^(?:[\^~<>=!*]|v?\d|dev-|@)/;
    POWERSHELL_READING = "found by reading the command as PowerShell does (a comma list, a backtick escape or continuation, a doubled quote, a Unicode space) \u2014 vetted for malicious versions only";
    NPM_ALLOW_BOOL = ["-D", "--save-dev", "-E", "--save-exact", "-O", "--save-optional", "-P", "--save-prod", "-S", "--save"];
    ALLOW = {
      npm: {
        bool: set(
          ...NPM_ALLOW_BOOL,
          "-B",
          "--save-bundle",
          "-g",
          "--global",
          "--save-peer",
          "--no-save",
          "--ignore-scripts",
          "--no-audit",
          "--no-fund",
          "--silent",
          "--verbose",
          "--legacy-peer-deps"
        ),
        value: set()
      },
      pnpm: {
        bool: set(
          ...NPM_ALLOW_BOOL.filter((f) => f !== "-S" && f !== "--save"),
          "--save-peer",
          "-g",
          "--global",
          "--ignore-scripts",
          "--silent"
        ),
        value: set()
      },
      yarn: {
        bool: set(
          "-D",
          "--dev",
          "-P",
          "--peer",
          "-O",
          "--optional",
          "-E",
          "--exact",
          "-T",
          "--tilde",
          "--silent",
          "--ignore-scripts"
        ),
        value: set()
      },
      bun: {
        bool: set(
          "-d",
          "-D",
          "--dev",
          "--optional",
          "--peer",
          "-E",
          "--exact",
          "-g",
          "--global",
          "--no-save",
          "--silent",
          "--verbose"
        ),
        value: set()
      },
      pip: {
        bool: set(
          "-U",
          "--upgrade",
          "--user",
          "--no-deps",
          "-q",
          "--quiet",
          "-v",
          "--verbose",
          "--pre",
          "--force-reinstall",
          "--no-cache-dir",
          "--break-system-packages",
          "--disable-pip-version-check"
        ),
        value: set()
      },
      uv: { bool: set("--dev", "-q", "--quiet", "-v", "--verbose", "--no-sync"), value: set("--group", "--optional") },
      "uv-pip": { bool: set("-U", "--upgrade", "-q", "--quiet", "-v", "--verbose", "--no-deps", "--system"), value: set() },
      poetry: {
        bool: set(
          "--dev",
          "-D",
          "--allow-prereleases",
          "--dry-run",
          "--lock",
          "-q",
          "--quiet",
          "-v",
          "--verbose",
          "-n",
          "--no-interaction"
        ),
        value: set("--group", "-G", "--optional")
      },
      // Not `--no-update` / `--no-install` (composer) or `--no-restore` / `-n`
      // (dotnet): each defers the lookup the command would make, so a name the
      // public registry lacks is not yet a failed install (follow-up Part Y).
      composer: {
        bool: set(
          "--dev",
          "-W",
          "--with-all-dependencies",
          "-w",
          "--with-dependencies",
          "--update-with-dependencies",
          "--update-with-all-dependencies",
          "--no-scripts",
          "--no-progress",
          "-n",
          "--no-interaction",
          "-q",
          "--quiet",
          "--sort-packages"
        ),
        value: set()
      },
      dotnet: { bool: set("--prerelease"), value: set("-v", "--version", "-f", "--framework") },
      // The launchers (review P1): consent and verbosity only. A package flag
      // (`-p`, `--from`, `--spec`), a registry or `--pip-args` takes the command
      // out of the confident shape.
      npx: { bool: set("-y", "--yes", "-q", "--quiet", "--silent"), value: set() },
      "pnpm-dlx": { bool: set("--silent", "-s"), value: set() },
      "yarn-dlx": { bool: set("-q", "--quiet"), value: set() },
      bunx: { bool: set("--bun", "--silent", "--verbose"), value: set() },
      uvx: { bool: set("-q", "--quiet", "-v", "--verbose", "--isolated"), value: set() },
      "uv-tool-install": { bool: set("-q", "--quiet", "-v", "--verbose", "--force", "--upgrade", "-U"), value: set() },
      "pipx-install": { bool: set("--force", "-f", "-q", "--quiet", "-v", "--verbose", "--include-deps"), value: set() },
      "pipx-run": { bool: set("-q", "--quiet", "-v", "--verbose", "--no-cache"), value: set() }
    };
    NOT_SIMPLE = /[;&|()<>`$\\\n\r{}*?[\],]/;
    DIR_COMMANDS = /* @__PURE__ */ new Set(["cd", "chdir", "pushd", "popd", "set-location", "push-location", "pop-location", "sl", "cd.."]);
    UNREAD_TARGET = /[$`%*?[\]{}]/;
    ENV_COMMANDS = /* @__PURE__ */ new Set(["export", "declare", "typeset", "local", "readonly", "set", "setx"]);
  }
});

// src/platform/configsDir.ts
import { existsSync, readdirSync as readdirSync2 } from "node:fs";
import { dirname as dirname2, join as join5 } from "node:path";
import { fileURLToPath } from "node:url";
function resolveConfigsDir() {
  const here = dirname2(fileURLToPath(import.meta.url));
  const bundled = join5(here, "..", "..", "configs");
  if (existsSync(join5(bundled, ...MARKER_RULES))) return bundled;
  const unbundled = join5(here, "..", "..", "..", "configs");
  if (existsSync(join5(unbundled, ...MARKER_RULES))) return unbundled;
  return unbundled;
}
var MARKER_RULES;
var init_configsDir = __esm({
  "src/platform/configsDir.ts"() {
    "use strict";
    MARKER_RULES = ["semgrep", "base.yml"];
  }
});

// src/pkgvet/typosquat.ts
function damerauLevenshtein(a, b, max) {
  if (a === b) return 0;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > max) return max + 1;
  const INF = max + 1;
  let prev2 = new Array(lb + 1).fill(INF);
  let prev = new Array(lb + 1).fill(INF);
  let cur = new Array(lb + 1).fill(INF);
  for (let j = 0; j <= Math.min(lb, max); j += 1) prev[j] = j;
  for (let i = 1; i <= la; i += 1) {
    cur.fill(INF);
    if (i <= max) cur[0] = i;
    const from = Math.max(1, i - max);
    const to = Math.min(lb, i + max);
    let rowMin = cur[0] ?? INF;
    for (let j = from; j <= to; j += 1) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      let v = Math.min((prev[j] ?? INF) + 1, (cur[j - 1] ?? INF) + 1, (prev[j - 1] ?? INF) + cost);
      if (i > 1 && j > 1 && a.charCodeAt(i - 1) === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
        v = Math.min(v, (prev2[j - 2] ?? INF) + 1);
      }
      if (v > INF) v = INF;
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return INF;
    const recycled = prev2;
    prev2 = prev;
    prev = cur;
    cur = recycled;
  }
  const d = prev[lb] ?? INF;
  return d > max ? INF : d;
}
function typoThreshold(length) {
  if (length < 5) return 0;
  if (length < 8) return 1;
  return 2;
}
function normalizePackageName(ecosystem, name) {
  const lower = name.trim().toLowerCase();
  return ecosystem === "pypi" ? lower.replace(/[-_.]+/g, "-") : lower;
}
function ownerOf(ecosystem, normalized) {
  if (ecosystem === "npm") {
    if (!normalized.startsWith("@")) return null;
    const slash = normalized.indexOf("/");
    return slash > 1 ? normalized.slice(1, slash) : null;
  }
  if (ecosystem === "packagist") {
    const slash = normalized.indexOf("/");
    return slash > 0 ? normalized.slice(0, slash) : null;
  }
  return null;
}
function isSiblingNotTypo(a, b, distance) {
  if (a.replace(DIGIT_RUN, "#") === b.replace(DIGIT_RUN, "#")) return true;
  const sa = a.split(SEGMENT_SPLIT);
  const sb = b.split(SEGMENT_SPLIT);
  if (sa.length < 2 || sa.length !== sb.length) return false;
  let differing = -1;
  for (let i = 0; i < sa.length; i += 1) {
    if (sa[i] === sb[i]) continue;
    if (differing !== -1) return false;
    differing = i;
  }
  if (differing === -1) return false;
  const x = sa[differing] ?? "";
  const y = sb[differing] ?? "";
  const longest = Math.max(x.length, y.length);
  if (longest <= 2) return true;
  if (distance < 2) return false;
  return damerauLevenshtein(x, y, longest) * 5 >= longest * 2;
}
function buildPopularIndex(ecosystem, names) {
  const ordered = [];
  const set2 = /* @__PURE__ */ new Set();
  const byLength = /* @__PURE__ */ new Map();
  for (const raw of names) {
    const n = normalizePackageName(ecosystem, raw);
    if (n.length === 0 || set2.has(n)) continue;
    set2.add(n);
    ordered.push(n);
    const bucket = byLength.get(n.length);
    if (bucket === void 0) byLength.set(n.length, [n]);
    else bucket.push(n);
  }
  return { ecosystem, names: ordered, set: set2, byLength };
}
function findTyposquatTarget(index, name, opts = {}) {
  const eco = index.ecosystem;
  const cand = normalizePackageName(eco, name);
  if (cand.length === 0) return null;
  if ((opts.exemptPopular ?? true) && index.set.has(cand)) return null;
  if (typoThreshold(cand.length) === 0) return null;
  const candOwner = ownerOf(eco, cand);
  const candScoped = eco === "npm" && cand.startsWith("@");
  let best = null;
  let bestRank = Number.POSITIVE_INFINITY;
  for (let len = cand.length - 2; len <= cand.length + 2; len += 1) {
    const bucket = index.byLength.get(len);
    if (bucket === void 0) continue;
    for (const target of bucket) {
      if (target === cand) continue;
      if (eco === "npm") {
        const targetScoped = target.startsWith("@");
        if (candScoped !== targetScoped) continue;
      }
      if (candOwner !== null && candOwner === ownerOf(eco, target)) continue;
      const max = typoThreshold(Math.min(cand.length, target.length));
      if (max === 0) continue;
      const d = damerauLevenshtein(cand, target, max);
      if (d === 0 || d > max) continue;
      if (isSiblingNotTypo(cand, target, d)) continue;
      const rank = index.names.indexOf(target);
      if (best === null || d < best.distance || d === best.distance && rank < bestRank) {
        best = { similar_to: target, distance: d };
        bestRank = rank;
      }
    }
  }
  return best;
}
var SEGMENT_SPLIT, DIGIT_RUN;
var init_typosquat = __esm({
  "src/pkgvet/typosquat.ts"() {
    "use strict";
    SEGMENT_SPLIT = /[-_./@]+/;
    DIGIT_RUN = /[0-9]+/g;
  }
});

// src/pkgvet/popular.ts
import { readFileSync } from "node:fs";
import { join as join6 } from "node:path";
function defaultPopularDir() {
  return join6(resolveConfigsDir(), "popular-packages");
}
function parsePopularList(text) {
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));
}
function loadPopularIndex(ecosystem, dir = defaultPopularDir()) {
  const path = join6(dir, `${ecosystem}.txt`);
  const hit = cache.get(path);
  if (hit !== void 0) return hit;
  let index = null;
  try {
    const names = parsePopularList(readFileSync(path, "utf8"));
    index = names.length > 0 ? buildPopularIndex(ecosystem, names) : null;
  } catch {
    index = null;
  }
  cache.set(path, index);
  return index;
}
var cache;
var init_popular = __esm({
  "src/pkgvet/popular.ts"() {
    "use strict";
    init_configsDir();
    init_typosquat();
    cache = /* @__PURE__ */ new Map();
  }
});

// src/pkgvet/privateRegistry.ts
import { lstatSync as lstatSync2, readdirSync as readdirSync3 } from "node:fs";
import { homedir as homedir4 } from "node:os";
import { dirname as dirname3, isAbsolute as isAbsolute4, join as join7, parse as parse4, relative as relative3, resolve as resolve4 } from "node:path";
function registryCache() {
  return { reads: /* @__PURE__ */ new Map(), workspaces: /* @__PURE__ */ new Map() };
}
function isPublic(ecosystem, url) {
  return PUBLIC_HOSTS[ecosystem].test(url.trim().replace(/^["']|["']$/g, ""));
}
function isPublicRegistryUrl(ecosystem, url) {
  return isPublic(ecosystem, url);
}
function isInside(dir, path) {
  const rel = relative3(dir, path);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute4(rel);
}
function walkRoot(path, ctx, under) {
  const abs = resolve4(path);
  if (isRemoteOrDeviceTarget(abs)) return void 0;
  if (under !== void 0) return under;
  const holds = (dir2, base2) => samePath(dir2, base2) || isInside(dir2, base2);
  const project = ctx.projectDir === void 0 ? void 0 : resolve4(ctx.projectDir);
  const home = resolve4(homeOf(ctx));
  if (project !== void 0 && holds(abs, project) || holds(abs, home)) return void 0;
  if (project !== void 0 && isInside(project, abs)) return project;
  const dir = dirname3(abs);
  if (project !== void 0 && holds(dir, project)) return dir;
  if (isInside(home, abs)) return home;
  return parse4(abs).root;
}
function noteUnread(path, what) {
  firstUnread = firstUnread ?? { path, what };
}
function takeUnread() {
  const unread = firstUnread;
  firstUnread = void 0;
  return unread;
}
function takeUnchecked() {
  const unchecked = firstUnchecked;
  firstUnchecked = void 0;
  return unchecked;
}
function read(path, ctx, under, what = "configuration") {
  const root = walkRoot(path, ctx, under);
  const key = `${path}\0${root ?? ""}`;
  let r = ctx.cache?.reads.get(key);
  if (r === void 0) {
    r = readSmallText(path, MAX_REGISTRY_CONFIG_BYTES, root);
    ctx.cache?.reads.set(key, r);
  }
  if (r.status === "refused") noteUnread(path, what);
  return r.status === "ok" ? r.text : void 0;
}
function present(path) {
  try {
    lstatSync2(path);
    return true;
  } catch {
    return false;
  }
}
function listDir(dir, ctx) {
  const under = walkRoot(dir, ctx);
  if (under !== void 0 && !walkLinksUnder(under, dir).ok) {
    noteUnread(dir, "directory");
    return [];
  }
  try {
    return readdirSync3(dir);
  } catch (e) {
    const code = e.code;
    if (code !== "ENOENT" && code !== "ENOTDIR") noteUnread(dir, "directory");
    return [];
  }
}
function samePath(a, b) {
  const norm = (p) => resolve4(p).replace(/[\\/]+$/, "");
  return process.platform === "win32" ? norm(a).toLowerCase() === norm(b).toLowerCase() : norm(a) === norm(b);
}
function ancestors(ctx) {
  if (ctx.projectDir === void 0) return [];
  const stops = [ctx.homeDir, homedir4()].filter((x) => typeof x === "string");
  const out = [];
  let dir = resolve4(ctx.projectDir);
  for (let i = 0; i < 16; i += 1) {
    if (stops.some((s) => samePath(s, dir))) break;
    out.push(dir);
    if (present(join7(dir, ".git"))) break;
    const parent = dirname3(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return out;
}
function envOf(ctx) {
  return ctx.env ?? process.env;
}
function homeOf(ctx) {
  return ctx.homeDir ?? homedir4();
}
function envValue(env, name) {
  const v = env[name] ?? env[name.toLowerCase()];
  return v !== void 0 && v.trim() !== "" ? v.trim() : void 0;
}
function npmScope(name) {
  const m = /^@([^/]+)\//.exec(name);
  return m?.[1];
}
function fromNpmrc(text, scope) {
  let found2;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^(@[^:=\s]+:)?registry\s*=\s*(.+)$/i.exec(line);
    if (m === null) continue;
    const lineScope = m[1]?.slice(1, -1);
    const url = (m[2] ?? "").trim();
    if (lineScope === void 0) found2 = found2 ?? url;
    else if (scope !== void 0 && lineScope.toLowerCase() === scope.toLowerCase()) return url;
  }
  return found2;
}
function fromYarnrcYml(text, scope) {
  let global;
  let inScopes = false;
  let currentScope;
  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === "" || raw.trim().startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      inScopes = /^npmScopes\s*:/.test(line);
      currentScope = void 0;
      const m = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
      if (m !== null) global = (m[1] ?? "").replace(/^["']|["']$/g, "");
      continue;
    }
    if (!inScopes) continue;
    const scopeKey = /^["']?@?([^"':]+)["']?\s*:\s*$/.exec(line);
    if (scopeKey !== null) {
      currentScope = scopeKey[1];
      continue;
    }
    const server = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
    if (server !== null && scope !== void 0 && currentScope?.toLowerCase() === scope.toLowerCase()) {
      return (server[1] ?? "").replace(/^["']|["']$/g, "");
    }
  }
  return global;
}
function fromYarnrc(text, scope) {
  let found2;
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*["']?(@[^:"']+:)?registry["']?\s+["']?([^"'\s]+)["']?/.exec(raw);
    if (m === null) continue;
    const lineScope = m[1]?.slice(1, -1);
    if (lineScope === void 0) found2 = found2 ?? m[2];
    else if (scope !== void 0 && lineScope.toLowerCase() === scope.toLowerCase()) return m[2];
  }
  return found2;
}
function fromBunfig(text, scope) {
  let section = "";
  let found2;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header !== null) {
      section = (header[1] ?? "").trim();
      continue;
    }
    const url = /https?:\/\/[^"'\s}]+/.exec(line)?.[0] ?? "(configured)";
    if (section === "install" && /^registry\s*=/.test(line)) found2 = found2 ?? url;
    if (section === "install.scopes" && scope !== void 0) {
      const key = /^["']?@?([^"'=\s]+)["']?\s*=/.exec(line)?.[1];
      if (key !== void 0 && key.toLowerCase() === scope.toLowerCase()) return url;
    }
  }
  return found2;
}
function npmConfigFiles(ctx) {
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const files = [];
  const near = ancestors(ctx);
  for (const dir of near) {
    files.push(
      { path: join7(dir, ".npmrc"), parse: fromNpmrc },
      { path: join7(dir, ".yarnrc.yml"), parse: fromYarnrcYml },
      { path: join7(dir, ".yarnrc"), parse: fromYarnrc },
      { path: join7(dir, "bunfig.toml"), parse: fromBunfig }
    );
  }
  const top = near[near.length - 1];
  if (top !== void 0) {
    for (let dir = dirname3(top), i = 0; i < 64; dir = dirname3(dir), i += 1) {
      files.push({ path: join7(dir, ".yarnrc.yml"), parse: fromYarnrcYml });
      if (dirname3(dir) === dir) break;
    }
  }
  const xdg = envValue(env, "XDG_CONFIG_HOME") ?? join7(home, ".config");
  const localAppData = envValue(env, "LOCALAPPDATA") ?? join7(home, "AppData", "Local");
  files.push(
    { path: envValue(env, "NPM_CONFIG_USERCONFIG") ?? join7(home, ".npmrc"), parse: fromNpmrc },
    { path: join7(home, ".yarnrc.yml"), parse: fromYarnrcYml },
    { path: join7(home, ".yarnrc"), parse: fromYarnrc },
    { path: join7(home, ".bunfig.toml"), parse: fromBunfig },
    { path: join7(xdg, ".bunfig.toml"), parse: fromBunfig },
    { path: join7(xdg, "pnpm", "rc"), parse: fromNpmrc },
    { path: join7(localAppData, "pnpm", "config", "rc"), parse: fromNpmrc },
    { path: join7(home, "Library", "Preferences", "pnpm", "rc"), parse: fromNpmrc }
  );
  const globalConfig = envValue(env, "NPM_CONFIG_GLOBALCONFIG");
  if (globalConfig !== void 0) files.push({ path: globalConfig, parse: fromNpmrc });
  const prefix = envValue(env, "NPM_CONFIG_PREFIX") ?? ((ctx.platform ?? process.platform) === "win32" ? join7(envValue(env, "APPDATA") ?? join7(home, "AppData", "Roaming"), "npm") : dirname3(dirname3(ctx.nodeExecPath ?? process.execPath)));
  files.push({ path: join7(prefix, "etc", "npmrc"), parse: fromNpmrc });
  return files;
}
function envRegistry(ecosystem, ctx) {
  for (const [key, raw] of Object.entries(envOf(ctx))) {
    if (raw === void 0 || raw.trim() === "" || !ENV_REGISTRY[ecosystem].test(key)) continue;
    const value = raw.trim();
    if (/NO_INDEX/i.test(key)) {
      if (/^(?:1|true|yes|on)$/i.test(value)) return { kind: "registry", source: key };
      continue;
    }
    if (value.split(/\s+/).some((u) => !isPublic(ecosystem, u.replace(/^[^=]+=(?=https?:)/, "")))) {
      return { kind: "registry", source: key, url: value };
    }
  }
  return null;
}
function npmRegistry(name, ctx) {
  const scope = npmScope(name);
  const fromEnv = envRegistry("npm", ctx);
  if (fromEnv !== null) return fromEnv;
  let authSource;
  for (const { path, parse: parse8 } of npmConfigFiles(ctx)) {
    const text = read(path, ctx);
    if (text === void 0) continue;
    const url = parse8(text, scope);
    if (url !== void 0 && !isPublic("npm", url)) return { kind: "registry", source: path, url };
    if (authSource === void 0 && NPM_AUTH.test(text)) authSource = path;
  }
  if (scope !== void 0 && authSource !== void 0) return { kind: "auth", source: authSource };
  const local = npmWorkspacePackage(name, ctx);
  return local === void 0 ? null : { kind: "workspace", source: local };
}
function workspaceIndex(root, file, nameOf, ctx) {
  const key = `${file}\0${root}`;
  const cached = ctx.cache?.workspaces.get(key);
  if (cached !== void 0) return cached;
  const index = { names: /* @__PURE__ */ new Map() };
  const queue = [{ dir: root, depth: 0 }];
  for (let at = 0; at < queue.length; at += 1) {
    if (at >= MAX_SCAN_DIRS) {
      index.cut = "size";
      break;
    }
    if (ctx.deadlineAt !== void 0 && Date.now() > ctx.deadlineAt) {
      index.cut = "time";
      break;
    }
    const next = queue[at];
    if (next === void 0) break;
    const manifest = join7(next.dir, file);
    const r = readSmallText(manifest, MAX_REGISTRY_CONFIG_BYTES, walkRoot(manifest, ctx, root));
    if (r.status === "refused") index.unread = index.unread ?? { path: manifest, what: "workspace manifest" };
    else if (r.status === "ok") {
      const name = nameOf(r.text);
      if (name !== void 0 && !index.names.has(name)) index.names.set(name, manifest);
    }
    if (next.depth >= MAX_SCAN_DEPTH) continue;
    let entries = [];
    try {
      entries = readdirSync3(next.dir, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.name.startsWith(".") && !SKIP_DIRS.has(e.name)).map((e) => e.name);
    } catch {
      continue;
    }
    for (const e of entries) queue.push({ dir: join7(next.dir, e), depth: next.depth + 1 });
  }
  ctx.cache?.workspaces.set(key, index);
  return index;
}
function findManifest(root, file, nameOf, wanted, ctx) {
  const index = workspaceIndex(root, file, nameOf, ctx);
  const hit = index.names.get(wanted);
  if (hit !== void 0) return hit;
  if (index.unread !== void 0) noteUnread(index.unread.path, index.unread.what);
  if (index.cut !== void 0) firstUnchecked = firstUnchecked ?? { root, cut: index.cut };
  return void 0;
}
function npmManifestName(text) {
  try {
    const name = JSON.parse(text).name;
    return typeof name === "string" ? name : void 0;
  } catch {
    return void 0;
  }
}
function pyprojectName(text) {
  const project = /^\s*\[project\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text)?.[1] ?? "";
  const n = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(project)?.[1];
  return n === void 0 ? void 0 : pep503(n);
}
function hasWorkspaces(packageJson) {
  if (packageJson === void 0) return false;
  try {
    const w = JSON.parse(packageJson).workspaces;
    if (Array.isArray(w)) return w.length > 0;
    return w !== null && typeof w === "object" && Array.isArray(w.packages);
  } catch {
    return false;
  }
}
function npmWorkspacePackage(name, ctx) {
  for (const dir of ancestors(ctx)) {
    const isRoot = hasWorkspaces(read(join7(dir, "package.json"), ctx, void 0, "workspace manifest")) || present(join7(dir, "pnpm-workspace.yaml"));
    if (!isRoot) continue;
    const hit = findManifest(dir, "package.json", npmManifestName, name, ctx);
    if (hit !== void 0) return hit;
  }
  return void 0;
}
function uvWorkspacePackage(name, ctx) {
  const wanted = pep503(name);
  for (const dir of ancestors(ctx)) {
    const path = join7(dir, "pyproject.toml");
    const text = read(path, ctx);
    if (text === void 0) continue;
    const sources = /^\s*\[tool\.uv\.sources\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text)?.[1] ?? "";
    for (const m of sources.matchAll(/^\s*["']?([A-Za-z0-9._-]+)["']?\s*=/gm)) {
      if (pep503(m[1] ?? "") === wanted) return path;
    }
    if (!/^\s*\[tool\.uv\.workspace\]/m.test(text)) continue;
    const hit = findManifest(dir, "pyproject.toml", pyprojectName, wanted, ctx);
    if (hit !== void 0) return hit;
  }
  return void 0;
}
function fromPipConf(text) {
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*(index[-_]url|extra[-_]index[-_]url|find[-_]links)\s*[=:]\s*(\S+)/i.exec(raw);
    if (m !== null && !isPublic("pypi", m[2] ?? "")) return m[2];
    if (/^\s*no[-_]index\s*[=:]\s*(?:true|1|yes|on)\s*$/i.test(raw)) return "no-index";
  }
  return void 0;
}
function fromPyproject(text) {
  if (/^\s*\[\[\s*tool\.(?:uv\.index|poetry\.source|pdm\.source)\s*\]\]/m.test(text)) {
    return /https?:\/\/[^"'\s]+/.exec(text.slice(text.search(/\[\[\s*tool\.(?:uv\.index|poetry\.source|pdm\.source)/)))?.[0] ?? "(configured)";
  }
  const uv = /^\s*\[tool\.uv\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(text);
  if (uv !== null) {
    const m = /^\s*(?:index-url|extra-index-url|find-links)\s*=\s*["']?([^"'\s\]]+)/m.exec(uv[1] ?? "");
    if (m !== null && !isPublic("pypi", m[1] ?? "")) return m[1];
  }
  return void 0;
}
function fromUvToml(text) {
  if (/^\s*\[\[\s*index\s*\]\]/m.test(text)) return /https?:\/\/[^"'\s]+/.exec(text)?.[0] ?? "(configured)";
  const m = /^\s*(?:index-url|extra-index-url|find-links)\s*=\s*["']?([^"'\s\]]+)/m.exec(text);
  if (m !== null && !isPublic("pypi", m[1] ?? "")) return m[1];
  return void 0;
}
function pypiRegistry(name, ctx) {
  const env = envOf(ctx);
  const fromEnv = envRegistry("pypi", ctx);
  if (fromEnv !== null) return fromEnv;
  const home = homeOf(ctx);
  const etc = ctx.etcDir ?? "/etc";
  const confs = [];
  const explicit = envValue(env, "PIP_CONFIG_FILE");
  if (explicit !== void 0) confs.push(explicit);
  const xdg = envValue(env, "XDG_CONFIG_HOME") ?? join7(home, ".config");
  confs.push(
    join7(xdg, "pip", "pip.conf"),
    join7(home, ".pip", "pip.conf"),
    join7(home, "Library", "Application Support", "pip", "pip.conf")
  );
  const appdata = envValue(env, "APPDATA") ?? join7(home, "AppData", "Roaming");
  confs.push(join7(appdata, "pip", "pip.ini"), join7(home, "pip", "pip.ini"));
  for (const prefix of [envValue(env, "VIRTUAL_ENV"), envValue(env, "CONDA_PREFIX")]) {
    if (prefix !== void 0) confs.push(join7(prefix, "pip.conf"), join7(prefix, "pip.ini"));
  }
  confs.push(join7(etc, "pip.conf"), join7(etc, "xdg", "pip", "pip.conf"));
  confs.push(join7(ctx.systemLibraryDir ?? "/Library", "Application Support", "pip", "pip.conf"));
  for (const d of (envValue(env, "XDG_CONFIG_DIRS") ?? "").split(":").filter(Boolean)) confs.push(join7(d, "pip", "pip.conf"));
  const programData = envValue(env, "ProgramData") ?? envValue(env, "PROGRAMDATA");
  if (programData !== void 0) confs.push(join7(programData, "pip", "pip.ini"));
  for (const path of confs) {
    const text = read(path, ctx);
    const url = text === void 0 ? void 0 : fromPipConf(text);
    if (url !== void 0) return { kind: "registry", source: path, url };
  }
  const uvConfs = [];
  const uvExplicit = envValue(env, "UV_CONFIG_FILE");
  if (uvExplicit !== void 0) uvConfs.push(uvExplicit);
  uvConfs.push(join7(xdg, "uv", "uv.toml"), join7(appdata, "uv", "uv.toml"), join7(etc, "uv", "uv.toml"));
  for (const path of uvConfs) {
    const text = read(path, ctx);
    const url = text === void 0 ? void 0 : fromUvToml(text);
    if (url !== void 0) return { kind: "registry", source: path, url };
  }
  for (const dir of ancestors(ctx)) {
    const uvToml = join7(dir, "uv.toml");
    const uvText = read(uvToml, ctx);
    const uvUrl = uvText === void 0 ? void 0 : fromUvToml(uvText);
    if (uvUrl !== void 0) return { kind: "registry", source: uvToml, url: uvUrl };
    const pyproject = join7(dir, "pyproject.toml");
    const text = read(pyproject, ctx);
    if (text === void 0) continue;
    const url = fromPyproject(text);
    if (url !== void 0) return { kind: "registry", source: pyproject, url };
    break;
  }
  const local = uvWorkspacePackage(name, ctx);
  return local === void 0 ? null : { kind: "workspace", source: local };
}
function hasRepositories(text) {
  if (text === void 0) return false;
  try {
    const doc = JSON.parse(text);
    const r = doc.repositories;
    if (Array.isArray(r)) return r.length > 0;
    return r !== null && typeof r === "object" && Object.keys(r).length > 0;
  } catch {
    return false;
  }
}
function composerRegistry(ctx) {
  for (const dir of ancestors(ctx)) {
    const path = join7(dir, "composer.json");
    const text = read(path, ctx);
    if (text === void 0) continue;
    if (hasRepositories(text)) return { kind: "registry", source: path };
    break;
  }
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const composerHome = envValue(env, "COMPOSER_HOME");
  const globals = composerHome !== void 0 ? [join7(composerHome, "config.json")] : [join7(home, ".composer", "config.json"), join7(home, ".config", "composer", "config.json"), join7(envValue(env, "APPDATA") ?? join7(home, "AppData", "Roaming"), "Composer", "config.json")];
  for (const path of globals) if (hasRepositories(read(path, ctx))) return { kind: "registry", source: path };
  return null;
}
function nugetConfigIn(dir, ctx) {
  const hit = listDir(dir, ctx).find((f) => f.toLowerCase() === "nuget.config");
  return hit === void 0 ? void 0 : join7(dir, hit);
}
function customNugetSources(text) {
  const sources = /<packageSources>([\s\S]*?)<\/packageSources>/i.exec(text)?.[1] ?? "";
  const out = [];
  for (const m of sources.matchAll(/<add\b[^>]*\bvalue\s*=\s*"([^"]+)"/gi)) {
    const url = m[1] ?? "";
    if (url !== "" && !isPublic("nuget", url)) out.push(url);
  }
  return out;
}
function isLocalFolderSource(source) {
  return !/^[a-z][a-z0-9+.-]*:\/\//i.test(source) && !/^[\\/]{2}/.test(source);
}
function localFeedHas(folder, configPath, id, ctx) {
  const env = envOf(ctx);
  const expanded = folder.replace(/%([^%]+)%/g, (whole, name) => envValue(env, name) ?? whole);
  const portable = (ctx.platform ?? process.platform) === "win32" ? expanded : expanded.replace(/\\/g, "/");
  const dir = resolve4(dirname3(configPath), portable.replace(/[\\/]+$/, ""));
  const lower = id.toLowerCase();
  return listDir(dir, ctx).some((entry) => {
    const e = entry.toLowerCase();
    return e === lower || nupkgIds(e).includes(lower);
  });
}
function nupkgIds(file) {
  const m = /^(.+)\.nupkg$/i.exec(file);
  if (m === null) return [];
  const parts = (m[1] ?? "").split(".");
  const ids = [];
  for (let i = 1; i < parts.length; i += 1) {
    if (NUGET_VERSION.test(parts.slice(i).join("."))) ids.push(parts.slice(0, i).join("."));
  }
  return ids;
}
function nugetRegistry(name, ctx) {
  const fromEnv = envRegistry("nuget", ctx);
  if (fromEnv !== null) return fromEnv;
  const files = [];
  if (ctx.projectDir !== void 0) {
    let dir = resolve4(ctx.projectDir);
    for (let i = 0; i < 64; i += 1) {
      const f = nugetConfigIn(dir, ctx);
      if (f !== void 0) files.push(f);
      const parent = dirname3(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const appdata = envValue(env, "APPDATA") ?? join7(home, "AppData", "Roaming");
  for (const dir of [join7(appdata, "NuGet"), join7(home, ".nuget", "NuGet"), join7(home, ".config", "NuGet")]) {
    const f = nugetConfigIn(dir, ctx);
    if (f !== void 0) files.push(f);
  }
  const userDirs = [join7(appdata, "NuGet", "config"), join7(home, ".nuget", "config"), join7(home, ".config", "NuGet", "config")];
  const machineDirs = [
    join7(ctx.etcDir ?? "/etc", "opt", "NuGet", "Config"),
    join7(ctx.systemLibraryDir ?? "/Library", "Application Support", "NuGet", "Config")
  ];
  const programFilesX86 = envValue(env, "ProgramFiles(x86)");
  if (programFilesX86 !== void 0) machineDirs.push(join7(programFilesX86, "NuGet", "Config"));
  const machineWide = /* @__PURE__ */ new Set();
  for (const dir of [...userDirs, ...machineDirs]) {
    for (const f of listDir(dir, ctx).filter((e) => /\.config$/i.test(e)).sort()) {
      files.push(join7(dir, f));
      if (machineDirs.includes(dir)) machineWide.add(join7(dir, f));
    }
  }
  for (const path of files) {
    const text = read(path, ctx);
    if (text === void 0) continue;
    for (const url of customNugetSources(text)) {
      if (machineWide.has(path) && isLocalFolderSource(url) && !localFeedHas(url, path, name, ctx)) continue;
      return { kind: "registry", source: path, url };
    }
  }
  return null;
}
function customRegistryFor(ecosystem, name, ctx = {}) {
  firstUnread = void 0;
  firstUnchecked = void 0;
  let found2;
  try {
    switch (ecosystem) {
      case "npm":
        found2 = npmRegistry(name, ctx);
        break;
      case "pypi":
        found2 = pypiRegistry(name, ctx);
        break;
      case "packagist":
        found2 = composerRegistry(ctx);
        break;
      case "nuget":
        found2 = nugetRegistry(name, ctx);
        break;
      default:
        found2 = null;
    }
  } catch {
    found2 = null;
  }
  const unread = takeUnread();
  const unchecked = takeUnchecked();
  if (found2 !== null) return found2;
  if (unchecked !== void 0) return { kind: "unchecked", source: unchecked.root, cut: unchecked.cut };
  return unread !== void 0 ? { kind: "unreadable", source: unread.path, what: unread.what } : null;
}
var MAX_WORKSPACE_DIRS, PUBLIC_HOSTS, MAX_REGISTRY_CONFIG_BYTES, firstUnread, firstUnchecked, NPM_AUTH, ENV_REGISTRY, SKIP_DIRS, MAX_SCAN_DIRS, MAX_SCAN_DEPTH, pep503, NUGET_VERSION;
var init_privateRegistry = __esm({
  "src/pkgvet/privateRegistry.ts"() {
    "use strict";
    init_configFile();
    MAX_WORKSPACE_DIRS = 3e3;
    PUBLIC_HOSTS = {
      npm: /^(?:https?:)?\/\/(?:registry\.npmjs\.(?:org|com)|registry\.yarnpkg\.com)(?:[:/]|$)/i,
      pypi: /^(?:https?:)?\/\/(?:pypi\.org|pypi\.python\.org|files\.pythonhosted\.org)(?:[:/]|$)/i,
      packagist: /^(?:https?:)?\/\/(?:repo\.)?packagist\.org(?:[:/]|$)/i,
      nuget: /^(?:https?:)?\/\/(?:api\.nuget\.org|www\.nuget\.org|nuget\.org)(?:[:/]|$)/i
    };
    MAX_REGISTRY_CONFIG_BYTES = 1024 * 1024;
    NPM_AUTH = /^\s*(?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/:)?_(?:authToken|auth|password)\s*=|^\s*npmAuth(?:Token|Ident)\s*:/m;
    ENV_REGISTRY = {
      npm: /^(?:YARN_NPM_REGISTRY_SERVER|YARN_REGISTRY|BUN_CONFIG_REGISTRY|npm_config_.*registry.*)$/i,
      pypi: /^(?:(?:PIP|UV)_.*INDEX.*|PIP_FIND_LINKS|UV_FIND_LINKS)$/i,
      packagist: /^$/,
      nuget: /^(?:NUGET_\w*(?:SOURCE|FEED|CONFIG)\w*|NUGET_FALLBACK_PACKAGES|NuGetPackageSourceCredentials_.+)$/i
    };
    SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", ".venv", "venv", "__pycache__", "vendor", "dist", "build", "target"]);
    MAX_SCAN_DIRS = MAX_WORKSPACE_DIRS;
    MAX_SCAN_DEPTH = 5;
    pep503 = (n) => n.trim().toLowerCase().replace(/[-_.]+/g, "-");
    NUGET_VERSION = /^\d+(?:\.\d+){0,3}(?:-[0-9a-z-]+(?:\.[0-9a-z-]+)*)?(?:\+[0-9a-z-]+(?:\.[0-9a-z-]+)*)?$/i;
  }
});

// src/runners/osv.ts
async function queryOsv(packages, opts = {}) {
  const queryable = packages.filter((p) => p.name).slice(0, MAX_QUERIES);
  if (queryable.length === 0) {
    return { online: true, queried: 0, vulnerable_packages: [] };
  }
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === "function" ? fetch : void 0);
  if (fetchImpl === void 0) {
    return { online: false, queried: 0, vulnerable_packages: [], error: "no_fetch" };
  }
  const vulnerable = [];
  try {
    for (let i = 0; i < queryable.length; i += CHUNK) {
      const chunk = queryable.slice(i, i + CHUNK);
      const body = {
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          ...p.version ? { version: p.version } : {}
        }))
      };
      const json = await postJson(OSV_BATCH_URL, body, opts, fetchImpl);
      const results = Array.isArray(json.results) ? json.results : [];
      results.forEach((res, idx) => {
        const pkg = chunk[idx];
        if (!pkg) return;
        const vulns = res?.vulns;
        if (Array.isArray(vulns) && vulns.length > 0) {
          const ids = vulns.map((v) => v.id).filter((x) => typeof x === "string");
          const group = {
            ecosystem: pkg.ecosystem,
            name: pkg.name,
            vuln_ids: ids,
            severity: "high"
          };
          if (pkg.version) group.version = pkg.version;
          vulnerable.push(group);
        }
      });
    }
  } catch (e) {
    return {
      online: false,
      queried: queryable.length,
      vulnerable_packages: [],
      error: e instanceof Error ? e.message : "osv_request_failed"
    };
  }
  return { online: true, queried: queryable.length, vulnerable_packages: vulnerable };
}
async function postJson(url, body, opts, fetchImpl) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort();
    else opts.signal.addEventListener("abort", () => controller.abort(), { once: true });
  }
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`osv http ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timeout);
  }
}
var OSV_BATCH_URL, DEFAULT_TIMEOUT_MS, MAX_QUERIES, CHUNK;
var init_osv = __esm({
  "src/runners/osv.ts"() {
    "use strict";
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
    DEFAULT_TIMEOUT_MS = 6e3;
    MAX_QUERIES = 200;
    CHUNK = 100;
  }
});

// src/pkgvet/registry.ts
function describeError(e, signal) {
  if (signal.aborted) return "network budget exhausted before the registry answered";
  if (e instanceof Error) {
    if (e.name === "AbortError" || e.name === "TimeoutError") return "request timed out";
    const cause = e.cause;
    const detail = cause instanceof Error ? cause.message : "";
    return detail !== "" ? `${e.message} (${detail})` : e.message;
  }
  return String(e);
}
async function fetchJson(url, http, headers = {}) {
  try {
    const res = await http.fetchImpl(url, { headers: { accept: "application/json", ...headers }, signal: http.signal });
    if (res.status === 404 || res.status === 410) return { kind: "not_found" };
    if (res.status === 429) return { kind: "error", reason: `rate limited by ${new URL(url).host} (HTTP 429)` };
    if (!res.ok) return { kind: "error", reason: `${new URL(url).host} answered HTTP ${res.status}` };
    return { kind: "ok", json: await res.json() };
  } catch (e) {
    return { kind: "error", reason: describeError(e, http.signal) };
  }
}
function isRecord(x) {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}
function stringRecord(x) {
  const out = {};
  if (!isRecord(x)) return out;
  for (const [k, v] of Object.entries(x)) if (typeof v === "string") out[k] = v;
  return out;
}
function npmDocUrl(name) {
  return `https://registry.npmjs.org/${name.replace("/", "%2F")}`;
}
async function lookupNpm(name, http) {
  const r = await fetchJson(npmDocUrl(name), http, { accept: "application/vnd.npm.install-v1+json" });
  if (r.kind !== "ok") return r;
  if (!isRecord(r.json) || !isRecord(r.json["versions"])) return { kind: "error", reason: "npm registry returned an unexpected document" };
  const versions = Object.keys(r.json["versions"]);
  const installScript = {};
  for (const [v, meta] of Object.entries(r.json["versions"])) {
    if (isRecord(meta) && meta["hasInstallScript"] === true) installScript[v] = true;
  }
  const tags = stringRecord(r.json["dist-tags"]);
  const info = { versions, tags, times: {}, installScript };
  if (tags["latest"] !== void 0) info.latest = tags["latest"];
  if (typeof r.json["modified"] === "string") info.modified = r.json["modified"];
  return { kind: "found", info };
}
async function npmFullDocument(name, http) {
  const r = await fetchJson(npmDocUrl(name), http);
  if (r.kind === "not_found") return { kind: "error", reason: "npm registry no longer has this package" };
  if (r.kind === "error") return r;
  if (!isRecord(r.json)) return { kind: "error", reason: "npm registry returned an unexpected document" };
  const scripts = {};
  const versions = r.json["versions"];
  if (isRecord(versions)) {
    for (const [v, meta] of Object.entries(versions)) {
      if (isRecord(meta)) scripts[v] = stringRecord(meta["scripts"]);
    }
  }
  return { kind: "ok", times: stringRecord(r.json["time"]), scripts };
}
async function npmVersionScripts(name, version, http) {
  const r = await fetchJson(`${npmDocUrl(name)}/${encodeURIComponent(version)}`, http);
  if (r.kind === "not_found") return { kind: "error", reason: "version manifest not found" };
  if (r.kind === "error") return r;
  return { kind: "ok", scripts: isRecord(r.json) ? stringRecord(r.json["scripts"]) : {} };
}
async function lookupPypi(name, http) {
  const r = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, http);
  if (r.kind !== "ok") return r;
  if (!isRecord(r.json) || !isRecord(r.json["info"])) return { kind: "error", reason: "PyPI returned an unexpected document" };
  const releases = isRecord(r.json["releases"]) ? r.json["releases"] : {};
  const times = {};
  const versions = [];
  for (const [v, files] of Object.entries(releases)) {
    if (!Array.isArray(files) || files.length === 0) continue;
    versions.push(v);
    let earliest;
    for (const f of files) {
      const t = isRecord(f) ? f["upload_time_iso_8601"] ?? f["upload_time"] : void 0;
      if (typeof t === "string" && (earliest === void 0 || t < earliest)) earliest = t;
    }
    if (earliest !== void 0) times[v] = earliest;
  }
  const info = { versions, times, installScript: {} };
  const latest = r.json["info"]["version"];
  if (typeof latest === "string") info.latest = latest;
  return { kind: "found", info };
}
async function lookupPackagist(name, http) {
  const lower = name.toLowerCase();
  const r = await fetchJson(`https://repo.packagist.org/p2/${lower}.json`, http);
  if (r.kind !== "ok") return r;
  const pkgs = isRecord(r.json) ? r.json["packages"] : void 0;
  const list = isRecord(pkgs) ? pkgs[lower] : void 0;
  if (!Array.isArray(list)) return { kind: "error", reason: "Packagist returned an unexpected document" };
  let carried = {};
  const versions = [];
  const times = {};
  for (const entry of list) {
    if (!isRecord(entry)) continue;
    const next = { ...carried };
    for (const [k, v] of Object.entries(entry)) {
      if (v === "__unset") delete next[k];
      else next[k] = v;
    }
    carried = next;
    const version = next["version"];
    if (typeof version !== "string") continue;
    versions.push(version);
    const time = next["time"];
    if (typeof time === "string") times[version] = time;
  }
  return { kind: "found", info: { versions, times, installScript: {} } };
}
async function lookupNuget(name, http) {
  const lower = name.toLowerCase();
  const r = await fetchJson(`https://api.nuget.org/v3-flatcontainer/${encodeURIComponent(lower)}/index.json`, http);
  if (r.kind !== "ok") return r;
  const versions = isRecord(r.json) && Array.isArray(r.json["versions"]) ? r.json["versions"].filter((v) => typeof v === "string") : null;
  if (versions === null) return { kind: "error", reason: "NuGet returned an unexpected document" };
  return { kind: "found", info: { versions, times: {}, installScript: {} } };
}
function nugetSearchUrl(id) {
  return `https://azuresearch-usnc.nuget.org/query?q=${encodeURIComponent(`packageid:${id.toLowerCase()}`)}&prerelease=true&semVerLevel=2.0.0&take=1`;
}
async function nugetCanonicalId(id, http) {
  const r = await fetchJson(nugetSearchUrl(id), http);
  if (r.kind !== "ok" || !isRecord(r.json) || !Array.isArray(r.json["data"])) return void 0;
  for (const entry of r.json["data"]) {
    const found2 = isRecord(entry) ? entry["id"] : void 0;
    if (typeof found2 === "string" && found2.toLowerCase() === id.toLowerCase()) return found2;
  }
  return void 0;
}
async function nugetPublished(name, version, http) {
  const url = `https://api.nuget.org/v3/registration5-gz-semver2/${encodeURIComponent(name.toLowerCase())}/${encodeURIComponent(version.toLowerCase())}.json`;
  const r = await fetchJson(url, http);
  if (r.kind === "not_found") return { kind: "error", reason: "NuGet registration leaf not found" };
  if (r.kind === "error") return r;
  const published = isRecord(r.json) ? r.json["published"] : void 0;
  return typeof published === "string" ? { kind: "ok", published } : { kind: "ok" };
}
function lookupRegistry(ecosystem, name, http) {
  switch (ecosystem) {
    case "npm":
      return lookupNpm(name, http);
    case "pypi":
      return lookupPypi(name, http);
    case "packagist":
      return lookupPackagist(name, http);
    case "nuget":
      return lookupNuget(name, http);
    default:
      return Promise.resolve({ kind: "error", reason: "unsupported ecosystem" });
  }
}
var init_registry = __esm({
  "src/pkgvet/registry.ts"() {
    "use strict";
  }
});

// src/pkgvet/types.ts
var OSV_ECOSYSTEM;
var init_types = __esm({
  "src/pkgvet/types.ts"() {
    "use strict";
    OSV_ECOSYSTEM = {
      npm: "npm",
      pypi: "PyPI",
      packagist: "Packagist",
      nuget: "NuGet"
    };
  }
});

// src/pkgvet/versions.ts
function parse5(version) {
  let s = version.trim().replace(/^[vV=]+/, "");
  const plus = s.indexOf("+");
  if (plus >= 0) s = s.slice(0, plus);
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(s);
  if (m === null) return null;
  const releaseText = m[1] ?? "";
  const rest = m[2] ?? "";
  const release = releaseText.split(".").map((x) => Number(x));
  if (release.some((n) => !Number.isFinite(n))) return null;
  let stage = 2;
  if (rest !== "") {
    if (POST_REST.test(rest)) stage = 3;
    else if (DEV_REST.test(rest)) stage = 0;
    else stage = 1;
  }
  return { release, stage, rest };
}
function compareRelease(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}
function compareRest(a, b) {
  const ta = a.split(/[-._]|(?<=\d)(?=\D)|(?<=\D)(?=\d)/).filter(Boolean);
  const tb = b.split(/[-._]|(?<=\d)(?=\D)|(?<=\D)(?=\d)/).filter(Boolean);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i += 1) {
    const x = ta[i];
    const y = tb[i];
    if (x === void 0) return -1;
    if (y === void 0) return 1;
    const nx = Number(x);
    const ny = Number(y);
    if (Number.isFinite(nx) && Number.isFinite(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x.toLowerCase() !== y.toLowerCase()) {
      return x.toLowerCase() < y.toLowerCase() ? -1 : 1;
    }
  }
  return 0;
}
function compareVersions(a, b) {
  const pa = parse5(a);
  const pb = parse5(b);
  if (pa === null || pb === null) return pa === null ? pb === null ? 0 : -1 : 1;
  const r = compareRelease(pa.release, pb.release);
  if (r !== 0) return r;
  if (pa.stage !== pb.stage) return pa.stage - pb.stage;
  return compareRest(pa.rest, pb.rest);
}
function isPrerelease(version) {
  const p = parse5(version);
  return p === null || p.stage < 2;
}
function partial(text) {
  const t = text.trim().replace(/^[vV]/, "");
  if (t === "" || WILD.test(t)) return { nums: [], pre: "" };
  const plus = t.indexOf("+");
  const noBuild = plus >= 0 ? t.slice(0, plus) : t;
  const dash = noBuild.search(/-/);
  const core = dash >= 0 ? noBuild.slice(0, dash) : noBuild;
  const pre = dash >= 0 ? noBuild.slice(dash) : "";
  const nums = [];
  for (const part of core.split(".")) {
    if (WILD.test(part)) break;
    if (!/^\d+$/.test(part)) return null;
    nums.push(Number(part));
  }
  return { nums, pre };
}
function bump(nums) {
  const next = nums.slice();
  const last = next.length - 1;
  next[last] = (next[last] ?? 0) + 1;
  return fmt(next);
}
function comparator(op, text, composerTilde) {
  const p = partial(text);
  if (p === null) return null;
  const { nums, pre } = p;
  const full = nums.length >= 3;
  const exact = full ? fmt(nums) + pre : fmt(nums);
  switch (op) {
    case "":
    case "=":
    case "==":
      if (nums.length === 0) return [ANY];
      if (full) return [eq(exact)];
      return [gte(fmt(nums)), lt(bump(nums))];
    case "^": {
      if (nums.length === 0) return [ANY];
      const [major = 0, minor, patch] = nums;
      if (major > 0 || nums.length === 1) return [gte(exact), lt(bump([major]))];
      if ((minor ?? 0) > 0 || nums.length === 2) return [gte(exact), lt(bump([0, minor ?? 0]))];
      return [gte(exact), lt(bump([0, 0, patch ?? 0]))];
    }
    case "~":
    case "~>": {
      if (nums.length === 0) return [ANY];
      if (nums.length === 1) return [gte(exact), lt(bump(nums))];
      if (composerTilde && nums.length === 2) return [gte(exact), lt(bump(nums.slice(0, 1)))];
      return [gte(exact), lt(bump(nums.slice(0, 2)))];
    }
    case ">=":
      return [gte(exact)];
    case ">":
      return full ? [gt(exact)] : nums.length === 0 ? [() => false] : [gte(bump(nums))];
    case "<":
      return [lt(exact)];
    case "<=":
      return full ? [lte(exact)] : nums.length === 0 ? [ANY] : [lt(bump(nums))];
    case "!=":
      return [(v) => !eq(exact)(v)];
    default:
      return null;
  }
}
function semverishRange(range, composer) {
  const alternatives = range.split(composer ? /\s*\|\|?\s*/ : /\s*\|\|\s*/);
  const out = [];
  for (const alt of alternatives) {
    let text = alt.trim();
    if (composer) text = text.replace(/@[a-zA-Z]+$/, "").trim();
    if (text === "" || text === "*" || WILD.test(text)) {
      out.push([ANY]);
      continue;
    }
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
    if (hyphen !== null) {
      const lo = comparator(">=", hyphen[1] ?? "", composer);
      const hiPartial = partial(hyphen[2] ?? "");
      if (lo === null || hiPartial === null) return null;
      const hi = hiPartial.nums.length >= 3 ? [lte(fmt(hiPartial.nums) + hiPartial.pre)] : hiPartial.nums.length === 0 ? [ANY] : [lt(bump(hiPartial.nums))];
      out.push([...lo, ...hi]);
      continue;
    }
    const tokens = text.replace(/(\^|~>|~|>=|<=|>|<|==|=|!=)\s+/g, "$1").split(composer ? /[\s,]+/ : /\s+/);
    const preds = [];
    for (const token of tokens) {
      if (token === "") continue;
      const m = COMPARATOR.exec(token);
      if (m === null) return null;
      const c = comparator(m[1] ?? "", m[2] ?? "", composer);
      if (c === null) return null;
      preds.push(...c);
    }
    out.push(preds);
  }
  return out;
}
function pep440Range(range) {
  const preds = [];
  for (const spec of range.split(",")) {
    if (spec.trim() === "") continue;
    const m = PEP440.exec(spec);
    if (m === null) return null;
    const op = m[1] ?? "";
    const ver = m[2] ?? "";
    if (op === "===") {
      preds.push((v) => v === ver);
      continue;
    }
    if (ver.endsWith(".*")) {
      const prefix = partial(ver.slice(0, -2));
      if (prefix === null || prefix.nums.length === 0) return null;
      const inPrefix = (v) => {
        const p = parse5(v);
        return p !== null && prefix.nums.every((n, i) => (p.release[i] ?? 0) === n);
      };
      if (op === "==") preds.push(inPrefix);
      else if (op === "!=") preds.push((v) => !inPrefix(v));
      else return null;
      continue;
    }
    if (parse5(ver) === null) return null;
    switch (op) {
      case "==":
        preds.push(eq(ver));
        break;
      case "!=":
        preds.push((v) => !eq(ver)(v));
        break;
      case ">=":
        preds.push(gte(ver));
        break;
      case "<=":
        preds.push(lte(ver));
        break;
      case ">":
        preds.push(gt(ver));
        break;
      case "<":
        preds.push(lt(ver));
        break;
      case "~=": {
        const p = parse5(ver);
        if (p === null || p.release.length < 2) return null;
        const prefix = p.release.slice(0, -1);
        preds.push(gte(ver), (v) => {
          const q = parse5(v);
          return q !== null && prefix.every((n, i) => (q.release[i] ?? 0) === n);
        });
        break;
      }
      default:
        return null;
    }
  }
  return [preds];
}
function nugetRange(range) {
  const r = range.trim();
  const m = /^([[(])\s*([^,\])]*?)\s*(?:,\s*([^\])]*?)\s*)?([\])])$/.exec(r);
  if (m === null) return parse5(r) === null ? null : [[eq(r)]];
  const open = m[1];
  const lo = m[2] ?? "";
  const hasComma = r.includes(",");
  const hi = m[3] ?? "";
  const close = m[4];
  if (!hasComma) return lo === "" ? null : [[eq(lo)]];
  const preds = [];
  if (lo !== "") preds.push(open === "[" ? gte(lo) : gt(lo));
  if (hi !== "") preds.push(close === "]" ? lte(hi) : lt(hi));
  return [preds];
}
function isExactVersion(ecosystem, range) {
  if (range === void 0) return false;
  const r = range.trim();
  switch (ecosystem) {
    case "npm":
      return EXACT_SEMVER.test(r);
    case "pypi":
      return /^(?:===?)\s*[^*,<>=!~\s]+$/.test(r) || /^\d/.test(r) && parse5(r) !== null && !/[,<>=!~*]/.test(r);
    case "packagist":
      return /^[vV]?\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.]+)?$/.test(r);
    case "nuget":
      return parse5(r) !== null && !/[[\](),]/.test(r);
    default:
      return false;
  }
}
function highest(versions) {
  let best;
  for (const v of versions) if (best === void 0 || compareVersions(v, best) > 0) best = v;
  return best;
}
function resolveVersion(ecosystem, range, ctx) {
  const stable = ctx.versions.filter((v) => !isPrerelease(v));
  const r = range?.trim() ?? "";
  if (r === "" || ecosystem === "npm" && r === "latest") {
    if (ctx.latest !== void 0 && ctx.versions.includes(ctx.latest)) return ctx.latest;
    return highest(stable);
  }
  if (ecosystem === "npm") {
    const tagged = ctx.tags?.[r];
    if (tagged !== void 0) return ctx.versions.includes(tagged) ? tagged : void 0;
  }
  if (ecosystem === "packagist" && /^dev-|-dev$/i.test(r)) return void 0;
  if (isExactVersion(ecosystem, r)) {
    const wanted = r.replace(/^===?\s*/, "");
    return ctx.versions.find((v) => v === wanted) ?? ctx.versions.find((v) => compareVersions(v, wanted) === 0);
  }
  let alternatives;
  switch (ecosystem) {
    case "npm":
      alternatives = semverishRange(r, false);
      break;
    case "packagist":
      alternatives = semverishRange(r, true);
      break;
    case "pypi":
      alternatives = /^(?:\^|~(?!=)|\*$|\d+(?:\.\d+)*\.\*$)/.test(r) ? semverishRange(r, false) : pep440Range(r);
      break;
    case "nuget":
      alternatives = nugetRange(r);
      break;
    default:
      alternatives = null;
  }
  if (alternatives === null) return void 0;
  const matching = stable.filter((v) => alternatives.some((preds) => preds.every((p) => p(v))));
  if (ecosystem === "npm" && ctx.latest !== void 0 && matching.includes(ctx.latest)) return ctx.latest;
  return highest(matching);
}
var POST_REST, DEV_REST, gte, gt, lt, lte, eq, ANY, WILD, fmt, COMPARATOR, PEP440, EXACT_SEMVER;
var init_versions = __esm({
  "src/pkgvet/versions.ts"() {
    "use strict";
    POST_REST = /^[-._]?(?:post|rev|r|p|patch|pl)[-._]?\d*$/i;
    DEV_REST = /(?:^|[-._])dev/i;
    gte = (x) => (v) => compareVersions(v, x) >= 0;
    gt = (x) => (v) => compareVersions(v, x) > 0;
    lt = (x) => (v) => compareVersions(v, x) < 0;
    lte = (x) => (v) => compareVersions(v, x) <= 0;
    eq = (x) => (v) => compareVersions(v, x) === 0;
    ANY = () => true;
    WILD = /^[xX*]$/;
    fmt = (nums) => [0, 1, 2].map((i) => nums[i] ?? 0).join(".");
    COMPARATOR = /^(\^|~>|~|>=|<=|>|<|==|=|!=)?\s*(.*)$/;
    PEP440 = /^\s*(~=|===|==|!=|<=|>=|<|>)\s*([^\s,]+)\s*$/;
    EXACT_SEMVER = /^[vV=]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
  }
});

// src/pkgvet/vet.ts
function popularIndexFor(ecosystem, opts) {
  const override = opts.popular?.[ecosystem];
  if (override === null) return null;
  if (override !== void 0) return buildPopularIndex(ecosystem, override);
  return opts.popularDir === void 0 ? loadPopularIndex(ecosystem) : loadPopularIndex(ecosystem, opts.popularDir);
}
function hoursAgo(iso, now) {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? (now - t) / HOUR : void 0;
}
function ageText(hours) {
  if (hours < FRESH_HOURS) return `${Math.max(0, Math.round(hours))} h ago`;
  const days = hours / 24;
  return days < 10 ? `${Math.round(days * 10) / 10} days ago` : `${Math.round(days)} days ago`;
}
function customFor(spec, opts) {
  const onCommandLine = (opts.commandRegistries ?? []).find((u) => !isPublicRegistryUrl(spec.ecosystem, u));
  if (onCommandLine !== void 0) return { kind: "registry", source: "the command line", url: onCommandLine };
  return customRegistryFor(spec.ecosystem, spec.name, opts.registry ?? {});
}
function resolveFor(w, info) {
  const ctx = { versions: info.versions, latest: info.latest, tags: info.tags ?? {} };
  const v = resolveVersion(w.spec.ecosystem, w.spec.range, ctx);
  if (v !== void 0) w.version = v;
  else if (isExactVersion(w.spec.ecosystem, w.spec.range)) w.versionMissing = true;
  const published = v === void 0 ? void 0 : info.times[v];
  if (published !== void 0) w.publishedAt = published;
}
async function extrasFor(w, info, http, now) {
  const v = w.version;
  if (v === void 0) return;
  if (w.spec.ecosystem === "npm") {
    const modifiedHours = info.modified === void 0 ? void 0 : hoursAgo(info.modified, now);
    const needFull = modifiedHours === void 0 || modifiedHours < FRESH_HOURS;
    const hasScript = info.installScript[v] === true;
    if (!needFull && info.modified !== void 0) w.quietSince = info.modified;
    if (needFull) {
      const full = await npmFullDocument(w.spec.name, http);
      if (full.kind === "ok") {
        const t = full.times[v];
        if (t !== void 0) w.publishedAt = t;
        else w.ageError = "the registry document has no publish time for this version";
        const s = full.scripts[v];
        if (hasScript) w.scripts = s === void 0 ? [] : INSTALL_SCRIPTS.filter((k) => s[k] !== void 0);
      } else {
        w.ageError = full.reason;
        if (hasScript) w.scriptsError = full.reason;
      }
    } else if (hasScript) {
      const s = await npmVersionScripts(w.spec.name, v, http);
      if (s.kind === "ok") w.scripts = INSTALL_SCRIPTS.filter((k) => s.scripts[k] !== void 0);
      else w.scriptsError = s.reason;
    }
    return;
  }
  if (w.spec.ecosystem === "nuget") {
    const p = await nugetPublished(w.spec.name, v, http);
    if (p.kind === "ok" && p.published !== void 0) w.publishedAt = p.published;
    else w.ageError = p.kind === "error" ? p.reason : "the registration entry has no publish time";
    return;
  }
  if (w.publishedAt === void 0) w.ageError = "the registry document has no publish time for this version";
}
function osvIds(osv, w) {
  if (osv === void 0 || w.osvIndex === void 0) return [];
  const eco = OSV_ECOSYSTEM[w.spec.ecosystem];
  const name = w.osvName ?? w.spec.name;
  const hit = osv.vulnerable_packages.find(
    (g) => g.ecosystem === eco && g.name === name && (w.osvVersioned ? g.version === w.version : g.version === void 0)
  );
  return hit?.vuln_ids ?? [];
}
function osvNameFor(w, canonical) {
  if (w.spec.ecosystem === "packagist") return w.spec.name.toLowerCase();
  if (w.spec.ecosystem === "nuget") return canonical ?? w.spec.name;
  return w.spec.name;
}
function buildResult(w, osv, osvError, now, offlineReason) {
  const { spec } = w;
  const eco = spec.ecosystem;
  const registry = REGISTRY_NAME[eco];
  const lookup = w.lookup;
  const info = lookup?.kind === "found" ? lookup.info : void 0;
  const extraWarn = [];
  const extraUnknown = [];
  const typosquat = !w.popularLoaded ? unknown("popular-packages list unavailable \u2014 typosquat check not run") : w.typo !== null ? warn(`name is ${w.typo.distance} edit${w.typo.distance === 1 ? "" : "s"} from the popular package '${w.typo.similar_to}' \u2014 possible typosquat`) : pass();
  const ids = osvIds(osv, w);
  const malIds = ids.filter((id) => id.startsWith("MAL-"));
  const vulnIds = ids.filter((id) => !id.startsWith("MAL-"));
  const osvDown = offlineReason ?? (osv === void 0 || !osv.online ? `OSV lookup failed: ${osvError ?? osv?.error ?? "no answer"}` : void 0);
  let exists;
  let malicious;
  let vulnerabilities;
  let publishAge;
  let installScripts = eco === "npm" ? unknown("not checked") : na("install-script check is npm-only");
  if (lookup === void 0) {
    const why = offlineReason ?? "registry not consulted";
    exists = unknown(why);
    malicious = unknown(why);
    vulnerabilities = unknown(why);
    publishAge = unknown(why);
    if (eco === "npm") installScripts = unknown(why);
  } else if (lookup.kind === "error") {
    exists = unknown(`${registry} lookup failed: ${lookup.reason}`);
    malicious = osvDown !== void 0 ? unknown(osvDown) : malIds.length > 0 ? warn(`OSV lists malicious advisories for this name (${malIds.join(", ")}); the version could not be determined`) : pass("no OSV malicious-package advisory for any version");
    vulnerabilities = unknown(`version unknown: ${lookup.reason}`);
    publishAge = unknown(`version unknown: ${lookup.reason}`);
    if (eco === "npm") installScripts = unknown(`version unknown: ${lookup.reason}`);
  } else if (lookup.kind === "not_found") {
    const didYouMean = w.typo !== null ? ` Did you mean '${w.typo.similar_to}'?` : "";
    const custom = w.custom ?? null;
    if (custom !== null) {
      const where = `${custom.source}${custom.url !== void 0 ? `: ${custom.url}` : ""}`;
      const why = custom.kind === "auth" ? `an npmjs auth token is configured (${where}) and a private scoped package answers 404 to an anonymous lookup` : custom.kind === "workspace" ? `it is a local workspace package (${where})` : custom.kind === "unchecked" ? custom.cut === "time" ? `whether a private registry or a local workspace package explains it could not be checked (${TIME_BUDGET})` : `the workspace at ${custom.source} has more than ${MAX_WORKSPACE_DIRS} directories and was not read to its end \u2014 it may hold the package` : custom.kind === "unreadable" ? custom.what === "workspace manifest" ? `workspace manifest at ${custom.source} could not be read \u2014 possibly a local workspace package` : custom.what === "directory" ? `directory ${custom.source} could not be listed \u2014 it may hold registry configuration` : `registry configuration at ${custom.source} could not be read \u2014 possibly a private registry` : `a custom registry is configured (${where})`;
      exists = unknown(`not on ${registry}, but ${why} \u2014 possibly a private or local package; not vetted.${didYouMean}`);
    } else {
      exists = fail(`does not exist on ${registry} \u2014 most likely a hallucinated or mistyped name.${didYouMean}`);
    }
    malicious = malIds.length > 0 ? custom !== null && custom.kind !== "unreadable" && custom.kind !== "unchecked" ? warn(`OSV lists this name as a malicious package (${malIds.join(", ")}) removed from ${registry}`) : fail(`OSV lists this name as a malicious package (${malIds.join(", ")}), removed from ${registry}`) : osvDown !== void 0 ? unknown(osvDown) : na();
    vulnerabilities = na();
    publishAge = na();
    if (eco === "npm") installScripts = na();
  } else {
    exists = pass();
    const placeholderVersion = [w.version, info?.latest].find((x) => x !== void 0 && NPM_PLACEHOLDER.test(x));
    const placeholder = eco === "npm" && placeholderVersion !== void 0;
    const v = w.version;
    if (w.versionMissing === true) extraWarn.push(`requested version ${spec.range ?? ""} is not published on ${registry} \u2014 possibly a hallucinated version`);
    else if (v === void 0) extraUnknown.push(`no published version matches '${spec.range ?? ""}'`);
    const versionUnknown = v === void 0 ? `could not determine which version '${spec.range ?? "latest"}' installs` : void 0;
    if (placeholder) {
      malicious = fail(`npm replaced this package with a security placeholder (${placeholderVersion ?? "x-security"}): it was taken down as malicious`);
    } else if (osvDown !== void 0) {
      malicious = unknown(osvDown);
    } else if (malIds.length > 0) {
      malicious = w.osvVersioned ? fail(`OSV malicious-package advisory for ${v ?? "this version"}: ${malIds.join(", ")}`) : warn(`OSV lists malicious advisories for some versions of this package (${malIds.join(", ")}) \u2014 which version installs could not be determined`);
    } else {
      malicious = pass();
    }
    if (osvDown !== void 0) vulnerabilities = unknown(osvDown);
    else if (vulnIds.length > 0) {
      vulnerabilities = w.osvVersioned ? warn(`${vulnIds.length} known vulnerabilit${vulnIds.length === 1 ? "y" : "ies"} in ${v ?? "this version"}: ${vulnIds.slice(0, 5).join(", ")}${vulnIds.length > 5 ? ", \u2026" : ""}`) : unknown(`${vulnIds.length} advisories exist for some versions \u2014 which version installs could not be determined`);
    } else vulnerabilities = pass();
    if (versionUnknown !== void 0) publishAge = unknown(versionUnknown);
    else if (w.publishedAt !== void 0) {
      const h = hoursAgo(w.publishedAt, now);
      publishAge = h === void 0 ? unknown("unparseable publish time") : h < FRESH_HOURS ? warn(
        `${v ?? ""} was published ${ageText(h)} (< ${FRESH_HOURS} h) \u2014 fresh releases are how the 2025-26 npm/PyPI worms spread; consider pinning the previous version until this one has aged`
      ) : pass(`published ${ageText(h)}`);
    } else if (w.quietSince !== void 0) {
      publishAge = pass(`no change to the package since ${w.quietSince.slice(0, 10)}`);
    } else publishAge = unknown(w.ageError ?? "publish time unavailable");
    if (eco === "npm") {
      if (versionUnknown !== void 0) installScripts = unknown(versionUnknown);
      else if (info?.installScript[v ?? ""] === true) {
        const names = w.scripts !== void 0 && w.scripts.length > 0 ? w.scripts.join(", ") : w.scriptsError !== void 0 ? `names unavailable (${w.scriptsError})` : "install (e.g. a native build)";
        installScripts = warn(`${v ?? ""} runs install scripts on install: ${names}`);
      } else installScripts = pass();
    }
  }
  const checks = {
    exists,
    malicious,
    vulnerabilities,
    publish_age: publishAge,
    install_scripts: installScripts,
    typosquat
  };
  const all = Object.values(checks);
  const reasonsOf = (status) => all.filter((c) => c.status === status && c.detail !== void 0).map((c) => c.detail ?? "");
  const reasons = [...reasonsOf("fail"), ...reasonsOf("warn"), ...extraWarn, ...reasonsOf("unknown"), ...extraUnknown];
  let verdict = "ok";
  if (all.some((c) => c.status === "fail")) verdict = "block";
  else if (all.some((c) => c.status === "warn") || extraWarn.length > 0) verdict = "warn";
  else if (all.some((c) => c.status === "unknown") || extraUnknown.length > 0) verdict = "unknown";
  const result = { ecosystem: eco, name: spec.name, verdict, reasons: [...new Set(reasons)], checks };
  if (spec.range !== void 0) result.requested = spec.range;
  if (w.version !== void 0) result.version = w.version;
  if (w.publishedAt !== void 0) result.published_at = w.publishedAt;
  if (malIds.length > 0) result.malicious_ids = malIds;
  if (vulnIds.length > 0) result.vulnerability_ids = vulnIds;
  if (w.scripts !== void 0 && w.scripts.length > 0) result.install_scripts = w.scripts;
  if (w.typo !== null) result.similar_to = w.typo.similar_to;
  if (lookup?.kind === "not_found") result.not_on_public_registry = true;
  if (w.versionMissing === true) result.requested_version_unpublished = true;
  return result;
}
async function vetPackages(specs, opts = {}) {
  const now = opts.now ?? Date.now();
  const offline = opts.offline ?? process.env["GUARDIAN_OFFLINE"] === "1";
  const registry = {
    ...opts.registry ?? {},
    cache: opts.registry?.cache ?? registryCache(),
    deadlineAt: opts.deadlineAt ?? opts.registry?.deadlineAt
  };
  const withCache = { ...opts, registry };
  const indexes = /* @__PURE__ */ new Map();
  const work = specs.map((spec) => {
    if (!indexes.has(spec.ecosystem)) indexes.set(spec.ecosystem, popularIndexFor(spec.ecosystem, opts));
    const index = indexes.get(spec.ecosystem) ?? null;
    return {
      spec,
      typo: index === null ? null : findTyposquatTarget(index, spec.name),
      popularLoaded: index !== null
    };
  });
  if (offline) {
    return work.map((w) => buildResult(w, void 0, void 0, now, "network disabled (GUARDIAN_OFFLINE=1)"));
  }
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === "function" ? fetch : void 0);
  if (fetchImpl === void 0) {
    return work.map((w) => buildResult(w, void 0, void 0, now, "no fetch implementation available"));
  }
  const left = opts.deadlineAt === void 0 ? Number.POSITIVE_INFINITY : opts.deadlineAt - Date.now();
  if (left <= 0) return work.map((w) => buildResult(w, void 0, void 0, now, TIME_BUDGET));
  const budgetMs = Math.max(1, Math.min(opts.budgetMs ?? TOOL_BUDGET_MS, left));
  const deadline = Date.now() + budgetMs;
  const budget = new AbortController();
  const timer = setTimeout(() => budget.abort(new Error("network budget exhausted")), budgetMs);
  const signal = opts.signal === void 0 ? budget.signal : AbortSignal.any([opts.signal, budget.signal]);
  const http = { fetchImpl, signal };
  try {
    return await networkRounds(work, http, signal, deadline, now, (w) => explain404(w, withCache));
  } finally {
    clearTimeout(timer);
  }
}
function explain404(w, opts) {
  if (w.custom !== void 0) return;
  const deadlineAt = opts.registry?.deadlineAt;
  if (deadlineAt !== void 0 && Date.now() > deadlineAt) {
    const onCommandLine = (opts.commandRegistries ?? []).find((u) => !isPublicRegistryUrl(w.spec.ecosystem, u));
    w.custom = onCommandLine !== void 0 ? { kind: "registry", source: "the command line", url: onCommandLine } : { kind: "unchecked", source: "the vetting deadline", cut: "time" };
    return;
  }
  w.custom = customFor(w.spec, opts);
}
async function networkRounds(work, http, signal, deadline, now, explain) {
  const fetchImpl = http.fetchImpl;
  const lookups = /* @__PURE__ */ new Map();
  const pending = work.map((w) => {
    const key = `${w.spec.ecosystem}\0${w.spec.name.toLowerCase()}`;
    let p = lookups.get(key);
    if (p === void 0) {
      p = lookupRegistry(w.spec.ecosystem, w.spec.name, http);
      lookups.set(key, p);
    }
    return p;
  });
  const canonical = /* @__PURE__ */ new Map();
  for (const w of work) {
    const key = w.spec.name.toLowerCase();
    if (w.spec.ecosystem === "nuget" && !canonical.has(key)) canonical.set(key, nugetCanonicalId(w.spec.name, http));
  }
  const answers = await Promise.all(pending);
  work.forEach((w, i) => {
    const answer = answers[i];
    if (answer !== void 0) w.lookup = answer;
    if (answer?.kind === "found") resolveFor(w, answer.info);
  });
  if (signal.aborted) {
    const why = "network budget exhausted before OSV was consulted";
    for (const w of work) if (w.lookup?.kind === "not_found") explain(w);
    return work.map((w) => buildResult(w, void 0, why, now, void 0));
  }
  let osvError;
  const osvPromise = (async () => {
    const queries = [];
    for (const w of work) {
      const canonicalId = await (canonical.get(w.spec.name.toLowerCase()) ?? Promise.resolve(void 0));
      w.osvName = osvNameFor(w, canonicalId);
      const q = { ecosystem: OSV_ECOSYSTEM[w.spec.ecosystem], name: w.osvName };
      if (w.version !== void 0) q.version = w.version;
      w.osvVersioned = w.version !== void 0;
      w.osvIndex = queries.length;
      queries.push(q);
    }
    return queryOsv(queries, { fetchImpl, signal, timeoutMs: Math.max(1, deadline - Date.now()) });
  })().catch((e) => {
    osvError = e instanceof Error ? e.message : String(e);
    return { online: false, queried: 0, vulnerable_packages: [] };
  });
  const extras = work.map(
    (w) => w.lookup?.kind === "found" ? extrasFor(w, w.lookup.info, http, now).catch(() => void 0) : Promise.resolve()
  );
  const [osv] = await Promise.all([osvPromise, ...extras]);
  if (signal.aborted && osv.online === false && osvError === void 0) {
    osvError = "network budget exhausted before OSV answered";
  }
  for (const w of work) if (w.lookup?.kind === "not_found") explain(w);
  return work.map((w) => buildResult(w, osv, osvError ?? (osv.online ? void 0 : osv.error), now, void 0));
}
var FRESH_HOURS, HOOK_BUDGET_MS, TOOL_BUDGET_MS, HOUR, NPM_PLACEHOLDER, INSTALL_SCRIPTS, REGISTRY_NAME, TIME_BUDGET, pass, warn, fail, unknown, na;
var init_vet = __esm({
  "src/pkgvet/vet.ts"() {
    "use strict";
    init_osv();
    init_popular();
    init_privateRegistry();
    init_registry();
    init_typosquat();
    init_types();
    init_versions();
    FRESH_HOURS = 72;
    HOOK_BUDGET_MS = 3e3;
    TOOL_BUDGET_MS = 1e4;
    HOUR = 3600 * 1e3;
    NPM_PLACEHOLDER = /^0\.0\.\d+-security$/;
    INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"];
    REGISTRY_NAME = {
      npm: "the npm registry",
      pypi: "PyPI",
      packagist: "Packagist",
      nuget: "nuget.org"
    };
    TIME_BUDGET = "vetting time budget exhausted";
    pass = (detail) => detail === void 0 ? { status: "pass" } : { status: "pass", detail };
    warn = (detail) => ({ status: "warn", detail });
    fail = (detail) => ({ status: "fail", detail });
    unknown = (detail) => ({ status: "unknown", detail });
    na = (detail) => detail === void 0 ? { status: "not_applicable" } : { status: "not_applicable", detail };
  }
});

// src/pkgvet/hookDecision.ts
var hookDecision_exports = {};
__export(hookDecision_exports, {
  DEFAULT_DEADLINE_MS: () => DEFAULT_DEADLINE_MS,
  MAX_DEADLINE_MS: () => MAX_DEADLINE_MS,
  MAX_VETTED_PACKAGES: () => MAX_VETTED_PACKAGES,
  decideInstallCommand: () => decideInstallCommand,
  escapeHatch: () => escapeHatch,
  vetDeadlineMs: () => vetDeadlineMs
});
import { lstatSync as lstatSync3 } from "node:fs";
import { homedir as homedir5 } from "node:os";
import { dirname as dirname4, join as join8, resolve as resolve5 } from "node:path";
function vetDeadlineMs(env) {
  const raw = env["GUARDIAN_PKG_VET_DEADLINE_MS"]?.trim();
  if (raw === void 0 || !/^\d+$/.test(raw)) return DEFAULT_DEADLINE_MS;
  return Math.min(Number(raw), MAX_DEADLINE_MS);
}
function label(r) {
  return r.version !== void 0 ? `${r.name}@${r.version}` : r.name;
}
function firstLine(r) {
  return r.reasons[0] ?? "no reason recorded";
}
function boundedInstalls(command, shell, isPopular, runsLocally) {
  const cut = command.length > MAX_PARSED_LENGTH;
  const parsed = parseInstallCommands(cut ? command.slice(0, MAX_PARSED_LENGTH) : command, { shell }).map(
    (c) => (
      // `npx`, `npm exec` and `bunx` run a bin the project has installed, and
      // fetch nothing: there is nothing to vet (review P1).
      c.localFirst === true ? { ...c, packages: c.packages.filter((p) => !runsLocally(p, c)) } : c
    )
  );
  const key = (pkg) => `${pkg.ecosystem}\0${pkg.name.toLowerCase()}\0${pkg.range ?? ""}`;
  const seen = /* @__PURE__ */ new Set();
  const unique = [];
  for (const c of parsed) {
    for (const pkg of c.packages) {
      if (seen.has(key(pkg))) continue;
      seen.add(key(pkg));
      unique.push(pkg);
    }
  }
  const chosen = new Set(
    [...unique.filter((p) => !isPopular(p)), ...unique.filter(isPopular)].slice(0, MAX_VETTED_PACKAGES).map(key)
  );
  const commands = [];
  for (const c of parsed) {
    const packages = c.packages.filter((pkg) => chosen.delete(key(pkg)));
    if (packages.length === 0) continue;
    const uncertain = cut ? [...c.uncertain, "the command is over 512 KB and only its start was read"] : c.uncertain;
    commands.push({ ...c, packages, uncertain });
  }
  return { commands, notVetted: Math.max(0, unique.length - MAX_VETTED_PACKAGES), cut };
}
function popularTest(opts) {
  const indexes = /* @__PURE__ */ new Map();
  return (pkg) => {
    let index = indexes.get(pkg.ecosystem);
    if (index === void 0) {
      const override = opts.popular?.[pkg.ecosystem];
      index = override === null ? null : override !== void 0 ? buildPopularIndex(pkg.ecosystem, override) : opts.popularDir === void 0 ? loadPopularIndex(pkg.ecosystem) : loadPopularIndex(pkg.ecosystem, opts.popularDir);
      indexes.set(pkg.ecosystem, index);
    }
    return index !== null && index.set.has(normalizePackageName(pkg.ecosystem, pkg.name));
  };
}
function presentBelow(under, path) {
  if (!walkLinksUnder(under, path).ok) return false;
  try {
    lstatSync3(path);
    return true;
  } catch {
    return false;
  }
}
function installedLocally(name, cwd) {
  const bin = name.replace(/^@[^/]+\//, "");
  let dir = resolve5(cwd);
  for (let i = 0; i < 32; i += 1) {
    const modules = join8(dir, "node_modules");
    for (const candidate of [join8(modules, name, "package.json"), join8(modules, ".bin", bin), join8(modules, ".bin", `${bin}.cmd`)]) {
      if (presentBelow(dir, candidate)) return true;
    }
    if (presentBelow(dir, join8(dir, ".git"))) return false;
    const parent = dirname4(dir);
    if (parent === dir) return false;
    dir = parent;
  }
  return false;
}
function runsInstalledCopy(pkg, c, opts) {
  if (pkg.range !== void 0 || pkg.raw !== pkg.name) return false;
  const dir = commandDir(c, opts);
  return dir !== null && installedLocally(pkg.name, dir);
}
function commandDir(c, opts) {
  if (c.workdir === void 0) return resolve5(opts.cwd);
  if (c.workdir === null) return null;
  const home = opts.homeDir ?? homedir5();
  const windows = (opts.platform ?? process.platform) === "win32";
  let dir = resolve5(opts.cwd);
  for (const step of c.workdir) {
    let target = step;
    if (target === "~" || /^~[\\/]/.test(target)) target = join8(home, target.slice(1));
    else if (target.startsWith("~")) return null;
    else if (windows) target = target.replace(/^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/, (_, drive) => `${drive.toUpperCase()}:/`);
    dir = resolve5(dir, target);
  }
  return dir;
}
async function decideInstallCommand(command, opts) {
  const shell = opts.shell ?? "bash";
  const { commands, notVetted, cut } = boundedInstalls(command, shell, popularTest(opts), (pkg, c) => runsInstalledCopy(pkg, c, opts));
  if (commands.length === 0) return cut ? { context: CUT_NOTE } : null;
  const env = opts.env ?? process.env;
  const offline = env["GUARDIAN_OFFLINE"] === "1";
  const budgetMs = opts.budgetMs ?? HOOK_BUDGET_MS;
  const deadlineAt = opts.deadlineAt ?? (opts.startedAt ?? Date.now()) + vetDeadlineMs(env);
  const cache2 = registryCache();
  const batches = await Promise.all(
    commands.map(
      (c) => vetPackages(c.packages, {
        budgetMs,
        offline,
        deadlineAt,
        now: opts.now ?? Date.now(),
        registry: {
          projectDir: opts.cwd,
          homeDir: opts.homeDir,
          env,
          etcDir: opts.etcDir,
          platform: opts.platform,
          nodeExecPath: opts.nodeExecPath,
          systemLibraryDir: opts.systemLibraryDir,
          cache: cache2
        },
        commandRegistries: c.registries,
        ...opts.fetchImpl !== void 0 ? { fetchImpl: opts.fetchImpl } : {},
        ...opts.popularDir !== void 0 ? { popularDir: opts.popularDir } : {},
        ...opts.popular !== void 0 ? { popular: opts.popular } : {}
      })
    )
  );
  const denies = [];
  const warnings = [];
  const unverified = [];
  let malicious = false;
  let missingIn;
  commands.forEach((cmd, i) => {
    for (const r of batches[i] ?? []) {
      const d = decideOne(r, cmd.uncertain);
      if (d.deny !== void 0) denies.push(d.deny);
      if (d.malicious === true) malicious = true;
      else if (d.deny !== void 0) missingIn = missingIn ?? cmd.manager;
      if (d.warn !== void 0) warnings.push(d.warn);
      if (d.unverified !== void 0) unverified.push(d.unverified);
    }
  });
  if (denies.length > 0) {
    return {
      deny: `dev-guardian blocked this install: ${denies.join(" ")} Check the package name against the project documentation or the registry before installing anything. ` + // Controller ruling (round 2): a missing-name deny carries its own
      // escape hatch — a registry flag, or an inline prefix, takes the
      // command out of the confident shape, so the agent can always
      // proceed. A MALICIOUS package gets no such hint.
      (malicious ? "If this package is genuinely intended, ask the user to install it themselves." : escapeHatch(missingIn ?? "", shell))
    };
  }
  const lines = [];
  if (warnings.length > 0) {
    lines.push("\u26A0\uFE0F dev-guardian package vetting \u2014 review before relying on these:");
    for (const w of warnings) lines.push(`  \u2022 ${w}`);
  }
  if (unverified.length > 0) lines.push(`dev-guardian could not vet ${unverified.join(", ")} \u2014 not verified.`);
  if (notVetted > 0) {
    lines.push(
      `dev-guardian: ${notVetted} more packages in this command were not vetted (only the first ${MAX_VETTED_PACKAGES} are) \u2014 not verified.`
    );
  }
  if (cut) lines.push(CUT_NOTE);
  return lines.length > 0 ? { context: lines.join("\n") } : null;
}
function escapeHatch(manager, shell = "bash") {
  const prefix = shell === "powershell" ? "run `$env:GUARDIAN_PKG_VET = '0'` before it, in the same command" : "prefix the command with `GUARDIAN_PKG_VET=0`";
  const flag = REGISTRY_FLAG[manager];
  if (flag !== void 0) return `If this package is private or local, re-run the install with an explicit ${flag}, or ${prefix}.`;
  const none = NO_REGISTRY_FLAG[manager];
  return `If this package is private or local, ${prefix}${none !== void 0 ? ` (${none})` : ""}.`;
}
function sentence(text) {
  return /[.?!]$/.test(text) ? text : `${text}.`;
}
function decideOne(r, uncertain) {
  if (r.checks.malicious.status === "fail") {
    const why = Object.values(r.checks).filter((c) => c.status === "fail" && c.detail !== void 0).map((c) => c.detail ?? "").join("; ");
    return { deny: `'${label(r)}': ${sentence(why)}`, malicious: true };
  }
  if (r.not_on_public_registry === true) {
    if (r.verdict === "block" && uncertain.length === 0) {
      return { deny: `'${label(r)}': ${sentence(r.checks.exists.detail ?? firstLine(r))}` };
    }
    const didYouMean = r.similar_to !== void 0 ? ` Did you mean '${r.similar_to}'?` : "";
    const why = r.verdict === "block" ? `not denied: ${uncertain.join("; ")}` : r.checks.exists.detail ?? "";
    return { warn: `'${label(r)}': ${NOT_FOUND}${didYouMean} (${why})` };
  }
  const pinned = isExactVersion(r.ecosystem, r.requested);
  const warns = CHECK_KEYS.filter((key) => key !== "vulnerabilities" || pinned).map((key) => r.checks[key]).filter((c) => c.status === "warn" && c.detail !== void 0).map((c) => c.detail ?? "");
  if (r.requested_version_unpublished === true) {
    warns.push(`requested version ${r.requested ?? ""} is not published \u2014 possibly a hallucinated version`);
  }
  if (warns.length > 0) return { warn: `${label(r)}: ${warns.slice(0, 3).join("; ")}` };
  const unknownCheck = Object.values(r.checks).find((c) => c.status === "unknown" && c.detail !== void 0);
  if (unknownCheck !== void 0) return { unverified: `${label(r)} (${unknownCheck.detail ?? ""})` };
  return {};
}
var DEFAULT_DEADLINE_MS, MAX_DEADLINE_MS, MAX_VETTED_PACKAGES, MAX_PARSED_LENGTH, CUT_NOTE, NOT_FOUND, REGISTRY_FLAG, NO_REGISTRY_FLAG, CHECK_KEYS;
var init_hookDecision = __esm({
  "src/pkgvet/hookDecision.ts"() {
    "use strict";
    init_configFile();
    init_parseCommand();
    init_popular();
    init_privateRegistry();
    init_typosquat();
    init_vet();
    init_versions();
    DEFAULT_DEADLINE_MS = 8e3;
    MAX_DEADLINE_MS = 12e3;
    MAX_VETTED_PACKAGES = 50;
    MAX_PARSED_LENGTH = 512 * 1024;
    CUT_NOTE = "dev-guardian: installs past the first 512 KB of this command were not looked for \u2014 not verified.";
    NOT_FOUND = "not found on the public registry \u2014 if it is private or local, ignore this.";
    REGISTRY_FLAG = {
      npm: "`--registry <url>`",
      npx: "`--registry <url>`",
      pipx: "`--index-url <url>`",
      pnpm: "`--registry <url>`",
      bun: "`--registry <url>`",
      pip: "`--index-url <url>`",
      "uv-pip": "`--index-url <url>`",
      uv: "`--index <url>`",
      poetry: "`--source <name>`",
      dotnet: "`--source <url>`"
    };
    NO_REGISTRY_FLAG = {
      yarn: "Yarn Berry has no registry flag",
      composer: "composer has no registry flag"
    };
    CHECK_KEYS = [
      "exists",
      "malicious",
      "vulnerabilities",
      "publish_age",
      "install_scripts",
      "typosquat"
    ];
  }
});

// src/hooks/secretScan.ts
var secretScan_exports = {};
__export(secretScan_exports, {
  SECRET_RULES: () => SECRET_RULES,
  redact: () => redact,
  scanForSecrets: () => scanForSecrets,
  shannonEntropy: () => shannonEntropy
});
function isB64url(c) {
  return c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122 || c === 95 || c === 45;
}
function isWordChar(c) {
  return c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122 || c === 95;
}
function isBoundary(text, at) {
  const before = at > 0 && isWordChar(text.charCodeAt(at - 1));
  const after2 = at < text.length && isWordChar(text.charCodeAt(at));
  return before !== after2;
}
function runEnds(text, inClass) {
  const ends = new Int32Array(text.length + 1);
  ends[text.length] = text.length;
  for (let i = text.length - 1; i >= 0; i -= 1) ends[i] = inClass(text.charCodeAt(i)) ? ends[i + 1] ?? i : i;
  return (i) => i >= text.length ? text.length : ends[i] ?? i;
}
function findJwt(text, from) {
  if (!text.includes(".eyJ", from)) return null;
  const end = runEnds(text, isB64url);
  let lastThird = -1;
  let lastThirdEnd = -1;
  for (let p = text.indexOf("eyJ", from); p >= 0; p = text.indexOf("eyJ", p + 1)) {
    if (p > 0 && isWordChar(text.charCodeAt(p - 1))) continue;
    const e1 = end(p + 3);
    const l1 = e1 - (p + 3);
    if (l1 < 8 || l1 > 2e3 || !text.startsWith(".eyJ", e1)) continue;
    const q = e1 + 4;
    const e2 = end(q);
    const l2 = e2 - q;
    if (l2 < 8 || l2 > 2e3 || text.charCodeAt(e2) !== 46) continue;
    const r = e2 + 1;
    if (r !== lastThird) {
      lastThird = r;
      lastThirdEnd = -1;
      const longest = Math.min(end(r) - r, 2e3);
      for (let x = r + longest; x >= r + 8; x -= 1) {
        if (isBoundary(text, x)) {
          lastThirdEnd = x;
          break;
        }
      }
    }
    if (lastThirdEnd >= 0) return { index: p, text: text.slice(p, lastThirdEnd) };
  }
  return null;
}
function isEnvValueChar(c) {
  return !(c === 32 || c >= 9 && c <= 13 || c === 160 || c === 5760 || c >= 8192 && c <= 8202 || c === 8232 || c === 8233 || c === 8239 || c === 8287 || c === 12288 || c === 65279 || c === 34 || c === 39 || c === 96 || c === 36 || c === 123 || c === 125 || c === 60 || c === 62 || c === 40 || c === 41);
}
function findEnvAssignment(text, from) {
  if (!text.includes("=", from)) return null;
  const end = runEnds(text, isEnvValueChar);
  const key = new RegExp(ENV_KEY.source, ENV_KEY.flags);
  key.lastIndex = from;
  for (let m = key.exec(text); m !== null; m = key.exec(text)) {
    const v = m.index + m[0].length;
    const e = end(v);
    if (e - v >= 8 && (e === text.length || /\s/.test(text.charAt(e)))) {
      return { index: m.index, text: text.slice(m.index, e), value: text.slice(v, e) };
    }
    key.lastIndex = m.index + 1;
  }
  return null;
}
function tokenIsPlaceholder(ruleId, token) {
  const lower = token.toLowerCase();
  if (TOKEN_PLACEHOLDER_MARKERS.some((m) => lower.includes(m))) return true;
  if (/(.)\1{7,}/.test(token)) return true;
  if (MIXED_TOKEN_RULES.has(ruleId)) {
    const body = token.replace(/^(?:sk-(?:ant-|proj-|svcacct-|admin-)?|hf_)/, "");
    if (ruleId === "huggingface-token") return !(/[a-z]/.test(body) && /[A-Z]/.test(body));
    return !(/[0-9]/.test(body) && /[A-Z]/.test(body) && /[a-z]/.test(body));
  }
  return false;
}
function shannonEntropy(s) {
  if (s.length === 0) return 0;
  const freq = /* @__PURE__ */ new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
function looksLikePlaceholder(value) {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_MARKERS.some((m) => lower.includes(m))) return true;
  if (/^(.)\1{6,}$/.test(value)) return true;
  return false;
}
function redact(secret) {
  const trimmed = secret.trim();
  const head = trimmed.slice(0, 4);
  const tail2 = trimmed.length >= 16 ? trimmed.slice(-2) : "";
  return `${head}\u2026${tail2} (${trimmed.length})`;
}
function lineWindows(line, overlap = OVERLAP) {
  if (line.length <= WINDOW) return [{ text: line, cutLeft: false, cutRight: false }];
  const out = [];
  for (let s = 0; ; s += WINDOW - overlap) {
    const e = Math.min(line.length, s + WINDOW);
    const from = Math.max(0, s - 1);
    const to = Math.min(line.length, e + 1);
    out.push({ text: line.slice(from, to), cutLeft: from > 0, cutRight: to < line.length });
    if (e >= line.length) return out;
  }
}
function firstMatch(rule, re, w) {
  let from = 0;
  for (let tries = 0; tries < 2; tries += 1) {
    let m;
    if (rule.find !== void 0) m = rule.find(w.text, from);
    else {
      re.lastIndex = from;
      const r = re.exec(w.text);
      m = r === null ? null : { index: r.index, text: r[0], ...r[1] !== void 0 ? { value: r[1] } : {} };
    }
    if (m === null) return null;
    if (w.cutRight && m.index + m.text.length >= w.text.length) return null;
    if (w.cutLeft && m.index === 0) {
      from = 1;
      continue;
    }
    return m;
  }
  return null;
}
function scanForSecrets(text, options = {}) {
  if (!text) return [];
  const minRank = CONFIDENCE_RANK[options.minConfidence ?? "medium"];
  const skipPlaceholders = options.skipPlaceholders !== false;
  const allow = (options.allowlist ?? []).map((a) => a.toLowerCase()).filter(Boolean);
  const rules = SECRET_RULES.filter((rule) => CONFIDENCE_RANK[rule.confidence] >= minRank).map((rule) => ({
    rule,
    re: new RegExp(rule.pattern.source, `${rule.pattern.flags.replace(/[gy]/g, "")}g`)
  }));
  const byOverlap = /* @__PURE__ */ new Map();
  for (const r of rules) {
    const overlap = r.rule.overlap ?? OVERLAP;
    byOverlap.set(overlap, [...byOverlap.get(overlap) ?? [], r]);
  }
  const lines = text.split(/\r?\n/);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine === void 0 || rawLine.length === 0) continue;
    const found2 = /* @__PURE__ */ new Map();
    for (const [overlap, group] of byOverlap) {
      for (const w of lineWindows(rawLine, overlap)) {
        const lower = w.text.toLowerCase();
        if (allow.some((a) => lower.includes(a))) continue;
        for (const { rule, re } of group) {
          if (found2.has(rule)) continue;
          const hit = judge(rule, firstMatch(rule, re, w), i, skipPlaceholders);
          if (hit !== null) found2.set(rule, hit);
        }
      }
    }
    for (const { rule } of rules) {
      const hit = found2.get(rule);
      if (hit !== void 0) hits.push(hit);
    }
  }
  return hits;
}
function judge(rule, m, i, skipPlaceholders = true) {
  if (!m) return null;
  if (skipPlaceholders && !VALUE_CAPTURE_RULES.has(rule.id) && rule.id !== "jwt" && rule.id !== "private-key-block" && rule.id !== "putty-private-key") {
    if (tokenIsPlaceholder(rule.id, m.text)) return null;
  }
  if (VALUE_CAPTURE_RULES.has(rule.id)) {
    const value = m.value ?? "";
    if (looksLikePlaceholder(value)) return null;
    if (skipPlaceholders && QUOTED_VALUE_RULES.has(rule.id) && /\s\S*\s/.test(value)) return null;
    if (rule.id === "yaml-credential" && !(/\d/.test(value) && /[A-Za-z]/.test(value))) return null;
    if (rule.id !== "generic-assignment-env" && shannonEntropy(value) < 3.2) return null;
  }
  const matched = VALUE_CAPTURE_RULES.has(rule.id) ? m.value ?? m.text : m.text;
  return {
    ruleId: rule.id,
    title: rule.title,
    confidence: rule.confidence,
    line: i + 1,
    preview: redact(matched)
  };
}
var CONFIDENCE_RANK, SECRET_RULES, ENV_KEY, VALUE_CAPTURE_RULES, QUOTED_VALUE_RULES, TOKEN_PLACEHOLDER_MARKERS, MIXED_TOKEN_RULES, PLACEHOLDER_MARKERS, WINDOW, OVERLAP;
var init_secretScan = __esm({
  "src/hooks/secretScan.ts"() {
    "use strict";
    CONFIDENCE_RANK = { medium: 0, high: 1 };
    SECRET_RULES = [
      // ── Cloud / provider tokens (unambiguous shapes → 'high') ────────────────
      { id: "aws-access-key-id", title: "AWS access key ID", confidence: "high", pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b/ },
      { id: "aws-secret-access-key", title: "AWS secret access key", confidence: "high", pattern: /\baws_?secret_?access_?key\b["'\s:=]+["']?[A-Za-z0-9/+]{40}\b/i },
      { id: "github-token", title: "GitHub token", confidence: "high", pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/ },
      { id: "github-fine-grained-pat", title: "GitHub fine-grained PAT", confidence: "high", pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/ },
      { id: "gitlab-pat", title: "GitLab personal access token", confidence: "high", pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/ },
      { id: "slack-token", title: "Slack token", confidence: "high", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,48}\b/ },
      { id: "slack-webhook", title: "Slack incoming webhook", confidence: "high", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_/]{6,}/ },
      { id: "stripe-live-key", title: "Stripe live secret key", confidence: "high", pattern: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/ },
      { id: "google-api-key", title: "Google API key", confidence: "high", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
      { id: "google-oauth-token", title: "Google OAuth access token", confidence: "high", pattern: /\bya29\.[0-9A-Za-z_-]{20,}\b/ },
      { id: "anthropic-api-key", title: "Anthropic API key", confidence: "high", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
      // `(?!ant-)` — an Anthropic key (`sk-ant-…`) otherwise also satisfies this
      // shape (`sk-` + 32+ alnum/hyphen chars) and was reported twice, once under
      // each rule id.
      { id: "openai-api-key", title: "OpenAI API key", confidence: "high", pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
      { id: "sendgrid-key", title: "SendGrid API key", confidence: "high", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
      { id: "npm-token", title: "npm access token", confidence: "high", pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
      { id: "pypi-token", title: "PyPI upload token", confidence: "high", pattern: /\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{10,}/ },
      { id: "twilio-account-sid", title: "Twilio account SID", confidence: "high", pattern: /\bAC[0-9a-fA-F]{32}\b/ },
      // `PRIVATE KEY BLOCK`: a PGP key's own header — the `PGP ` alternative never
      // matched without it (review 8, item 12).
      { id: "private-key-block", title: "Private key", confidence: "high", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
      { id: "putty-private-key", title: "PuTTY private key", confidence: "high", pattern: /\bPuTTY-User-Key-File-\d+: / },
      { id: "huggingface-token", title: "Hugging Face token", confidence: "high", pattern: /\bhf_[A-Za-z]{34}\b/ },
      { id: "digitalocean-token", title: "DigitalOcean token", confidence: "high", pattern: /\bdo[opr]_v1_[a-f0-9]{64}\b/ },
      { id: "shopify-token", title: "Shopify access token", confidence: "high", pattern: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/ },
      { id: "azure-storage-key", title: "Azure storage account key", confidence: "high", pattern: /\bAccountKey=[A-Za-z0-9+/]{86}==/ },
      { id: "telegram-bot-token", title: "Telegram bot token", confidence: "high", pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/ },
      // ── Heuristics (ambiguous → 'medium', warn only) ─────────────────────────
      //
      // Quantifiers bounded at 2000 (a real JWT segment is a few hundred base64
      // chars at most) rather than unbounded `{8,}`: unbounded, three greedy
      // classes each backed by a literal `.` that may not exist nearby turned
      // `'eyJ-'.repeat(50000)` (no dot anywhere in it) into ~27s of backtracking.
      // Bounding caps the work per candidate start at a constant instead of
      // letting it grow with input size — the other half of the fix is the 16KB
      // window below, which bounds input size itself. Even so, every `eyJ` of a
      // 16 KB run rescanned up to 2000 characters (~90 ms a window), so the
      // scanner uses `findJwt`, which reads each run once (review I3).
      {
        id: "jwt",
        title: "JSON Web Token (JWT)",
        confidence: "medium",
        pattern: /\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000}\b/,
        find: (text, from) => findJwt(text, from),
        // At most 3 + 2000 + 4 + 2000 + 1 + 2000 characters: 8 KB holds any of
        // them, where the 2 KB every other rule shares did not (round 3, item 6).
        overlap: 8 * 1024
      },
      {
        id: "generic-assignment",
        title: "Hard-coded credential",
        confidence: "medium",
        // SCREAMING_SNAKE / kebab / bare key (DB_PASSWORD, api-key, password)
        // assigned a quoted value. The key must sit at a name boundary — start of
        // string or preceded by a non-alnum char — via the lookbehind, which is
        // also what lets `DB_PASSWORD` match at all: a plain `\b` sits between
        // two word characters at the `_` before PASSWORD ('_' and 'P' are both
        // \w), so no boundary exists there for `\b` to find.
        // An optional closing quote (`["'\`]?`) is allowed between the key and
        // the separator so JSON's `"password":` — the key's own closing `"`
        // sitting right before the colon — matches; that quote used to be
        // unaccounted for and silently broke every JSON-shaped hit.
        pattern: /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i
      },
      {
        id: "generic-assignment-camel",
        title: "Hard-coded credential",
        confidence: "medium",
        // camelCase key (stripeSecretKey, dbPassword, githubToken) assigned a
        // quoted value. Case-SENSITIVE and gated on a lowercase letter right
        // before the capitalised keyword (the camelCase boundary itself) —
        // deliberately not folded into the rule above via a case-insensitive
        // flag: that would also match the keyword in the MIDDLE of an ordinary
        // lowercase word ("monkey", "donkey" both contain "key") with nothing to
        // tell a real name boundary from a coincidence.
        pattern: /(?<=[a-z])(?:ApiKey|SecretKey|Secret|AccessToken|AuthToken|ClientSecret|Passwd|Password|PrivateKey|Token)["'`]?\s*[:=]\s*["'`]([^"'`]{12,})["'`]/
      },
      {
        id: "generic-assignment-env",
        title: "Hard-coded credential",
        confidence: "medium",
        // Same SCREAMING_SNAKE/bare key, unquoted `.env`-style assignment
        // (`DB_PASSWORD=hunter2hunter2`, `export ANTHROPIC_API_KEY=sk-ant-…`).
        // `=` only, never `:` — a bare `token: string` TypeScript annotation is
        // exactly this shape with `:`, and must stay silent. The value charset
        // excludes `$`, `{`, `}`, `<`, `>`, `(`, `)` and whitespace, which is what
        // keeps `${VAR}`, `<your-key>` and `password = getPassword()` unmatched
        // without needing a placeholder check to catch them.
        //
        // The value's run is rescanned from every key inside it when it does not
        // end at whitespace (`token=token=…"`: ~250 ms a window), so the scanner
        // uses `findEnvAssignment`, which reads each run once (review I3).
        pattern: /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*=\s*([^\s"'`${}<>()]{8,})(?=\s|$)/i,
        find: (text, from) => findEnvAssignment(text, from)
      },
      {
        id: "bearer-token",
        title: "Bearer token in an Authorization header",
        confidence: "medium",
        // `Authorization: Bearer <token>` written into a file — a curl line, a
        // .http request, a test fixture (review 8, item 12). The token is vetted
        // like the other captured values (placeholders, entropy).
        pattern: /\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/-]{20,}=*)/i
      },
      {
        id: "yaml-credential",
        title: "Hard-coded credential",
        confidence: "medium",
        // An unquoted YAML value (`password: Zx9…`) on a line of its own — the
        // quoted rules need quotes and the `.env` rule an `=` (review 8, item
        // 12). The value must hold a digit and a letter, so a type annotation
        // (`token: AccessToken`) or a reference (`password: ${DB_PASS}`) is not one.
        pattern: /^\s*(?:[\w-]*[_-])?(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*:\s*([^\s'"`#{}[\]$<>(),;|&*!%@]{8,})\s*$/i
      },
      {
        id: "uri-credentials",
        title: "Credentials embedded in a URI",
        confidence: "medium",
        // scheme://user:password@host — postgres://user:pass@host/db and the like.
        // The scheme is at most 32 characters (`mongodb+srv` is 11): unbounded,
        // every word start of a long `a-a-a-…` run rescanned the rest of it — up
        // to 0.5 s a window (review I3).
        pattern: /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s/:@]+:([^\s/:@]{3,})@[^\s/'"]+/i
      }
    ];
    ENV_KEY = /(?<![A-Za-z0-9])(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password|private[_-]?key|token)\s*=\s*/gi;
    VALUE_CAPTURE_RULES = /* @__PURE__ */ new Set([
      "generic-assignment",
      "generic-assignment-camel",
      "generic-assignment-env",
      "uri-credentials",
      "bearer-token",
      "yaml-credential"
    ]);
    QUOTED_VALUE_RULES = /* @__PURE__ */ new Set(["generic-assignment", "generic-assignment-camel"]);
    TOKEN_PLACEHOLDER_MARKERS = [
      "example",
      "xxxxx",
      "your-",
      "your_",
      "yourkey",
      "yourtoken",
      "placeholder",
      "changeme",
      "change-me",
      "redacted",
      "dummy",
      "sample",
      "fake",
      "notreal",
      "not-real",
      "replace",
      "insert",
      "<your"
    ];
    MIXED_TOKEN_RULES = /* @__PURE__ */ new Set(["openai-api-key", "anthropic-api-key", "huggingface-token"]);
    PLACEHOLDER_MARKERS = [
      "example",
      "changeme",
      "change-me",
      "placeholder",
      "your-",
      "your_",
      "yourkey",
      "yourtoken",
      "redacted",
      "dummy",
      "sample",
      "xxxxx",
      "test-token",
      "fake",
      "notreal",
      "<your",
      "${",
      "{{",
      "env.",
      "process.env",
      "os.environ"
    ];
    WINDOW = 16 * 1024;
    OVERLAP = 2 * 1024;
  }
});

// src/hooks/settingsGuard.ts
var settingsGuard_exports = {};
__export(settingsGuard_exports, {
  applyEdit: () => applyEdit,
  hookLooseningSettings: () => hookLooseningSettings,
  isClaudeSettingsPath: () => isClaudeSettingsPath,
  newlyLoosened: () => newlyLoosened
});
function isClaudeSettingsPath(path, configDir) {
  if (/(?:^|[\\/])\.claude[\\/]settings(?:\.local)?\.json$/i.test(path)) return true;
  if (configDir === void 0 || configDir.trim() === "") return false;
  const fold = process.platform === "win32";
  const m = (fold ? /^(.*)[\\/](settings(?:\.local)?\.json)$/i : /^(.*)\/(settings(?:\.local)?\.json)$/).exec(path);
  if (m === null) return false;
  const norm = (p) => {
    const t = p.replace(/\\/g, "/").replace(/\/+$/, "");
    return fold ? t.toLowerCase() : t;
  };
  return norm(m[1] ?? "") === norm(configDir);
}
function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function fromObject(settings) {
  const found2 = [];
  if (settings["disableAllHooks"] === true) found2.push("disableAllHooks: true");
  const env = settings["env"];
  if (isPlainObject(env)) {
    for (const [key, value] of Object.entries(env)) {
      const sw = ENV_SWITCHES.find((s) => s.name === key.toUpperCase());
      if (sw !== void 0 && sw.off.includes(String(value))) found2.push(`env ${sw.name}=${String(value)}`);
    }
  }
  const plugins = settings["enabledPlugins"];
  if (isPlainObject(plugins)) {
    for (const [id, enabled] of Object.entries(plugins)) {
      if (enabled === false && OUR_PLUGIN.test(id)) found2.push(`enabledPlugins ${id}=false`);
    }
  }
  return found2;
}
function fromText(text) {
  const found2 = TEXT_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);
  for (const m of text.matchAll(PLUGIN_OFF)) found2.push(`enabledPlugins ${m[1] ?? ""}=false`);
  return found2;
}
function hookLooseningSettings(content) {
  const text = content.charCodeAt(0) === 65279 ? content.slice(1) : content;
  try {
    const parsed = JSON.parse(text);
    if (isPlainObject(parsed)) return fromObject(parsed);
  } catch {
  }
  return fromText(text);
}
function newlyLoosened(before, after2) {
  const had = new Set(before === void 0 ? [] : hookLooseningSettings(before));
  return hookLooseningSettings(after2).filter((label2) => !had.has(label2));
}
function applyEdit(content, oldString, newString, replaceAll = false) {
  if (oldString === "") return void 0;
  if (replaceAll) return content.includes(oldString) ? content.split(oldString).join(newString) : void 0;
  const at = content.indexOf(oldString);
  return at < 0 ? void 0 : content.slice(0, at) + newString + content.slice(at + oldString.length);
}
var ENV_SWITCHES, OUR_PLUGIN, TEXT_PATTERNS, PLUGIN_OFF;
var init_settingsGuard = __esm({
  "src/hooks/settingsGuard.ts"() {
    "use strict";
    ENV_SWITCHES = [
      { name: "GUARDIAN_HOOKS", off: ["off"] },
      { name: "GUARDIAN_HOOKS_BASH_BLOCK", off: ["0", "false"] },
      { name: "GUARDIAN_PKG_VET", off: ["0"] }
    ];
    OUR_PLUGIN = /dev-guardian/i;
    TEXT_PATTERNS = [
      { label: "disableAllHooks: true", re: /"disableAllHooks"\s*:\s*true\b/ },
      { label: "env GUARDIAN_HOOKS=off", re: /"GUARDIAN_HOOKS"\s*:\s*"off"/i },
      { label: "env GUARDIAN_HOOKS_BASH_BLOCK=0", re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"0"|0\b)/i },
      { label: "env GUARDIAN_HOOKS_BASH_BLOCK=false", re: /"GUARDIAN_HOOKS_BASH_BLOCK"\s*:\s*(?:"false"|false\b)/i },
      { label: "env GUARDIAN_PKG_VET=0", re: /"GUARDIAN_PKG_VET"\s*:\s*(?:"0"|0\b)/i }
    ];
    PLUGIN_OFF = /"([^"\n]*dev-guardian[^"\n]*)"\s*:\s*false\b/gi;
  }
});

// src/platform/binaryPath.ts
import { accessSync, constants as constants2, lstatSync as lstatSync4, statSync as statSync2 } from "node:fs";
import { extname, join as join9 } from "node:path";
function envValue2(env, name, platform) {
  if (platform !== "win32") return env[name];
  const key = Object.keys(env).filter((k) => k.toUpperCase() === name).sort()[0];
  return key === void 0 ? void 0 : env[key];
}
function searchable(entry, platform) {
  return platform === "win32" ? /^[A-Za-z]:[\\/]/.test(entry) : entry.startsWith("/");
}
function searchDirs(pathText, platform = process.platform) {
  const out = [];
  for (const raw of pathText.split(platform === "win32" ? ";" : ":")) {
    const entry = platform === "win32" ? raw.trim().replace(/^"(.*)"$/, "$1") : raw;
    if (entry !== "" && searchable(entry, platform)) out.push(entry);
  }
  return out;
}
function extensionsFor(name, env) {
  const pathext = (envValue2(env, "PATHEXT", "win32") ?? DEFAULT_PATHEXT).split(";").map((e) => e.trim().toLowerCase()).filter((e) => /^\.[a-z0-9]{1,8}$/.test(e));
  const exts = pathext.length > 0 ? pathext : DEFAULT_PATHEXT.toLowerCase().split(";");
  return exts.includes(extname(name).toLowerCase()) ? [""] : exts;
}
function runnable(file, platform) {
  try {
    const st = statSync2(file);
    if (!st.isFile()) return false;
    if (platform === "win32") return true;
    accessSync(file, constants2.X_OK);
    return true;
  } catch (err) {
    if (platform === "win32" && err.code === "EACCES") {
      try {
        return lstatSync4(file).isSymbolicLink();
      } catch {
        return false;
      }
    }
    return false;
  }
}
function isBareName(name, platform = process.platform) {
  return name !== "" && name !== "." && name !== ".." && !/[\\/]/.test(name) && !(platform === "win32" && name.includes(":"));
}
function findOnPath(name, env = process.env, platform = process.platform) {
  if (!isBareName(name, platform)) return null;
  const cacheKey = `${platform}\0${envValue2(env, "PATH", platform) ?? ""}\0${envValue2(env, "PATHEXT", platform) ?? ""}\0${name}`;
  const cached = found.get(cacheKey);
  if (cached !== void 0 && runnable(cached, platform)) return cached;
  const exts = platform === "win32" ? extensionsFor(name, env) : [""];
  for (const dir of searchDirs(envValue2(env, "PATH", platform) ?? "", platform)) {
    for (const ext of exts) {
      const candidate = join9(dir, `${name}${ext}`);
      if (runnable(candidate, platform)) {
        if (found.size >= FOUND_CACHE_MAX) found.clear();
        found.set(cacheKey, candidate);
        return candidate;
      }
    }
  }
  return null;
}
var DEFAULT_PATHEXT, found, FOUND_CACHE_MAX;
var init_binaryPath = __esm({
  "src/platform/binaryPath.ts"() {
    "use strict";
    DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD";
    found = /* @__PURE__ */ new Map();
    FOUND_CACHE_MAX = 256;
  }
});

// src/platform/boundedJson.ts
var init_boundedJson = __esm({
  "src/platform/boundedJson.ts"() {
    "use strict";
  }
});

// src/platform/projectFs.ts
import {
  closeSync as closeSync2,
  constants as constants3,
  fstatSync as fstatSync2,
  linkSync,
  lstatSync as lstatSync5,
  mkdirSync,
  openSync as openSync2,
  readdirSync as readdirSync4,
  readSync as readSync2,
  realpathSync as realpathSync2,
  renameSync,
  unlinkSync,
  writeSync
} from "node:fs";
import { dirname as dirname5, isAbsolute as isAbsolute5, join as join10, parse as parse6, relative as relative4, resolve as resolve6, sep } from "node:path";
function isWithinDir(root, path) {
  const rel = relative4(caseFold(resolve6(root)), caseFold(resolve6(path)));
  return rel === "" || rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute5(rel);
}
function projectEntryKind(path) {
  let st;
  try {
    st = lstatSync5(path);
  } catch {
    return "absent";
  }
  if (st.isSymbolicLink()) return "link";
  if (st.isFile()) return "file";
  if (st.isDirectory()) return "directory";
  return "other";
}
function projectEntryKindIn(root, path) {
  const abs = resolve6(root, path);
  if (!isWithinDir(root, abs)) return "absent";
  const walk2 = walkLinksUnder(root, abs);
  if (!walk2.ok) return walk2.reason === "remote-link" ? "remote" : "other";
  return projectEntryKind(abs);
}
function entryKindAnywhere(path) {
  const lexicallyRemote = /^(?:\\\\|\/\/)/;
  if (lexicallyRemote.test(path)) return "remote";
  const abs = resolve6(path);
  if (lexicallyRemote.test(abs)) return "remote";
  return projectEntryKindIn(parse6(abs).root, abs);
}
var PROJECT_FILE_MAX_BYTES, PROJECT_LOCKFILE_MAX_BYTES, OPEN_FLAGS2, caseFold;
var init_projectFs = __esm({
  "src/platform/projectFs.ts"() {
    "use strict";
    init_configFile();
    init_boundedJson();
    PROJECT_FILE_MAX_BYTES = 8 * 1024 * 1024;
    PROJECT_LOCKFILE_MAX_BYTES = 64 * 1024 * 1024;
    OPEN_FLAGS2 = constants3.O_RDONLY | (constants3.O_NONBLOCK ?? 0);
    caseFold = (p) => process.platform === "win32" ? p.toLowerCase() : p;
  }
});

// src/platform/gitSafety.ts
var gitSafety_exports = {};
__export(gitSafety_exports, {
  COMMAND_KEYS_REGEX: () => COMMAND_KEYS_REGEX,
  GIT_COMMAND: () => GIT_COMMAND,
  PROBE_KEY: () => PROBE_KEY,
  applyGitSafety: () => applyGitSafety,
  describeNotApplied: () => describeNotApplied,
  dockerGitEnvArgs: () => dockerGitEnvArgs,
  execGit: () => execGit,
  execGitBuffer: () => execGitBuffer,
  execGitSync: () => execGitSync,
  forgetGitConfigReads: () => forgetGitConfigReads,
  gitSafetyFor: () => gitSafetyFor,
  gitSafetyForSync: () => gitSafetyForSync,
  isRepositoryScope: () => isRepositoryScope,
  localReceivePackCommand: () => localReceivePackCommand,
  neutralValue: () => neutralValue,
  noHooksPath: () => noHooksPath,
  parseConfigListing: () => parseConfigListing,
  safetyFromListing: () => safetyFromListing,
  staticGitSafety: () => staticGitSafety,
  useGitSpawner: () => useGitSpawner,
  withoutHooksPath: () => withoutHooksPath
});
import { spawn, spawnSync } from "node:child_process";
import { dirname as dirname6, join as join11, relative as relative5, resolve as resolve7 } from "node:path";
function gitExecutable(env) {
  return findOnPath(GIT_COMMAND, env) ?? join11(dirname6(process.execPath), "no-git-on-path", GIT_COMMAND);
}
function noHooksPath(platform = process.platform, execPath = process.execPath) {
  if (platform === "win32") return `${execPath.replace(/\\/g, "/")}/no-git-hooks`;
  return "/dev/null/no-git-hooks";
}
function staticConfig(hooksPath) {
  return [
    ["core.fsmonitor", "false"],
    ["core.hooksPath", hooksPath],
    ["protocol.ext.allow", "never"],
    ["log.showSignature", "false"],
    ["gc.auto", "0"],
    ["maintenance.auto", "false"],
    ["diff.submodule", "short"]
  ];
}
function withoutHooksPath(safety) {
  return { ...safety, config: safety.config.filter(([key]) => key !== "core.hooksPath") };
}
function staticGitSafety(platform = process.platform) {
  return { config: staticConfig(noHooksPath(platform)), vars: STATIC_VARS, notApplied: [], refused: null };
}
function isRepositoryScope(scope) {
  return !TRUSTED_SCOPES.has(scope);
}
function parseConfigListing(bytes) {
  const entries = [];
  const tokens = [];
  let start = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) {
      tokens.push(bytes.subarray(start, i));
      start = i + 1;
    }
  }
  for (let i = 0; i + 1 < tokens.length; i += 2) {
    const scopeBytes = tokens[i];
    const kv = tokens[i + 1];
    if (scopeBytes === void 0 || kv === void 0) break;
    const lf = kv.indexOf(10);
    const keyBytes = lf < 0 ? kv : kv.subarray(0, lf);
    let key;
    try {
      key = STRICT_UTF8.decode(keyBytes);
    } catch {
      return {
        refused: `the repository's git configuration has a key that is not UTF-8 (${JSON.stringify(keyBytes.toString("latin1"))}), which cannot be overridden from the environment`
      };
    }
    let value = null;
    if (lf >= 0) {
      try {
        value = STRICT_UTF8.decode(kv.subarray(lf + 1));
      } catch {
        value = null;
      }
    }
    entries.push({ scope: scopeBytes.toString("utf8"), key, value });
  }
  return { entries };
}
function neutralValue(key, env) {
  if (FILTER_KEY.test(key)) return "";
  if (/^diff\..+\.textconv$/.test(key)) return "cat";
  if (key === "core.sshcommand") {
    const gitSsh = envValue3(env, "GIT_SSH");
    return gitSsh !== void 0 && gitSsh !== "" ? shellQuote(gitSsh) : "ssh";
  }
  if (key === "gpg.program" || key === "gpg.openpgp.program") return "gpg";
  if (key === "gpg.x509.program") return "gpgsm";
  if (key === "gpg.ssh.program") return "ssh-keygen";
  const http = HTTP_KEY.exec(key);
  if (http !== null) {
    const name = http[2] ?? "";
    if (name === "proxy") return envProxy(env, http[1]);
    if (name === "sslverify") return "true";
    if (name === "savecookies") return "false";
    if (name === "followredirects") return "initial";
    return "";
  }
  if (/^remote\..+\.proxy$/.test(key)) return envProxy(env, void 0);
  return "";
}
function envProxy(env, url) {
  const exact = (name) => {
    const v = env[name];
    return v === void 0 || v === "" ? void 0 : v;
  };
  const all = exact("all_proxy") ?? exact("ALL_PROXY");
  if (url === void 0) return exact("https_proxy") ?? exact("HTTPS_PROXY") ?? exact("http_proxy") ?? all ?? "";
  const primary = /^http:\/\//i.test(url) ? exact("http_proxy") : exact("https_proxy") ?? exact("HTTPS_PROXY");
  return primary ?? all ?? "";
}
function shellQuote(s) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
function neutraliseListing(entries, env) {
  const trusted = entries.filter((e) => TRUSTED_SCOPES.has(e.scope));
  const untrusted = entries.filter((e) => !TRUSTED_SCOPES.has(e.scope) && e.key !== PROBE_KEY);
  const probeSeen = entries.some((e) => e.scope === "command" && e.key === PROBE_KEY);
  const config = [];
  const vars = {};
  const notApplied = /* @__PURE__ */ new Set();
  const drivers = /* @__PURE__ */ new Set();
  const extraHeaders = /* @__PURE__ */ new Set();
  let credentials = false;
  const trustedValue = (key) => {
    let v = null;
    for (const e of trusted) if (e.key === key) v = e.value;
    return v;
  };
  for (const { key } of untrusted) {
    notApplied.add(key);
    if (STATIC_KEYS.has(key) || /^pager\./.test(key)) continue;
    if (CREDENTIAL_HELPER.test(key)) {
      credentials = true;
      continue;
    }
    const http = HTTP_KEY.exec(key);
    if (http?.[2] === "extraheader") {
      extraHeaders.add(key);
      continue;
    }
    if (http !== null) {
      const mine2 = trustedValue(key) ?? (http[1] !== void 0 ? trustedValue(`http.${http[2] ?? ""}`) : null);
      config.push([key, mine2 ?? neutralValue(key, env)]);
      continue;
    }
    if (key === "core.gitproxy") {
      if (envValue3(env, "GIT_PROXY_COMMAND") === void 0) vars["GIT_PROXY_COMMAND"] = "";
      continue;
    }
    if (/^remote\..+\.(uploadpack|receivepack)$/.test(key)) {
      if (key.endsWith(".uploadpack")) vars["GIT_NO_LAZY_FETCH"] = "1";
      continue;
    }
    const mine = trustedValue(key);
    const value = mine ?? neutralValue(key, env);
    config.push([key, value]);
    const filter = FILTER_KEY.exec(key);
    if (filter?.[1] !== void 0 && mine === null) drivers.add(filter[1]);
  }
  for (const driver of drivers) config.push([`filter.${driver}.required`, "false"]);
  for (const key of extraHeaders) {
    config.push([key, ""]);
    for (const e of trusted) {
      if ((e.key === key || e.key === "http.extraheader") && e.value !== null) config.push([key, e.value]);
    }
  }
  if (credentials) {
    config.push(["credential.helper", ""]);
    for (const e of trusted) {
      if (CREDENTIAL_HELPER.test(e.key) && e.value !== null) config.push([e.key, e.value]);
    }
  }
  return { config, vars, notApplied: [...notApplied].sort(), probeSeen };
}
function probeArgs(dir) {
  return ["-c", "safe.directory=*", "-C", dir, "config", "--includes", "--show-scope", "-z", "--get-regexp", COMMAND_KEYS_REGEX];
}
function probeEnv(base2, platform) {
  const env = { ...base2 };
  for (const name of Object.keys(env)) if (sameName(name, "GIT_CONFIG", platform)) delete env[name];
  const stat = staticGitSafety(platform);
  return applyGitSafety({ ...stat, config: [...stat.config, [PROBE_KEY, "1"]] }, env, platform);
}
function countProblem(env, platform) {
  const raw = envValue3(env, "GIT_CONFIG_COUNT", platform) ?? "";
  const t = raw.trim();
  if (t === "" || /^\+?\d+$/.test(t)) return null;
  return `GIT_CONFIG_COUNT in the environment is ${JSON.stringify(raw)}, not a number, and git refuses to run with it`;
}
function interpretExit(status, stdout, stderr, dir) {
  if (status === 0) return { kind: "listing", bytes: stdout };
  if (status === 1) return { kind: "listing", bytes: Buffer.alloc(0) };
  if (status === 3) return { kind: "none" };
  if (status === 128 && GIT_CANNOT_READ.test(stderr)) return { kind: "none" };
  return {
    kind: "refused",
    message: `could not read the git configuration of ${dir}: git config exited ${status ?? "on a signal"}${firstLine2(stderr) !== "" ? ` (${firstLine2(stderr)})` : ""}`
  };
}
function combine(probes, env, platform) {
  const base2 = staticGitSafety(platform);
  const config = [...base2.config];
  const vars = { ...base2.vars };
  const notApplied = /* @__PURE__ */ new Set();
  const refusals = [];
  const seen = /* @__PURE__ */ new Set();
  for (const { dir, probe, submodule } of probes) {
    if (probe.kind === "refused") refusals.push(probe.message);
    if (probe.kind !== "listing") continue;
    const parsed = parseConfigListing(probe.bytes);
    if ("refused" in parsed) {
      refusals.push(`${parsed.refused} (${dir})`);
      continue;
    }
    const n = neutraliseListing(parsed.entries, env);
    if (!n.probeSeen) {
      refusals.push(
        "the git on PATH does not take configuration from the environment (GIT_CONFIG_COUNT needs git 2.31 or later), so a scanned repository's own git configuration could not be kept from running commands"
      );
      continue;
    }
    if (n.notApplied.length > MAX_REPOSITORY_KEYS) {
      refusals.push(`the git configuration of ${dir} names ${n.notApplied.length} commands, more than ${MAX_REPOSITORY_KEYS}`);
      continue;
    }
    const earlier = new Set(seen);
    for (const pair of n.config) {
      const id = `${pair[0]}\0${pair[1]}`;
      if (earlier.has(id)) continue;
      seen.add(id);
      config.push(pair);
    }
    Object.assign(vars, n.vars);
    for (const k of n.notApplied) notApplied.add(submodule === void 0 ? k : `${k} (submodule ${submodule})`);
  }
  return {
    config,
    vars,
    notApplied: [...notApplied].sort(),
    refused: refusals.length > 0 ? [...new Set(refusals)].join("; ") : null
  };
}
function safetyFromListing(dir, listing, env = process.env, platform = process.platform) {
  return combine([{ dir, probe: { kind: "listing", bytes: listing } }], env, platform);
}
async function gitSafetyFor(dirs, opts = {}) {
  const platform = opts.platform ?? process.platform;
  const env = opts.env ?? process.env;
  const problem = countProblem(env, platform);
  if (problem !== null) return { ...staticGitSafety(platform), refused: problem };
  const walk2 = {
    git: opts.git ?? gitExecutable(env),
    env: probeEnv(env, platform),
    timeoutMs: opts.timeoutMs ?? PROBE_TIMEOUT_MS,
    reuseMs: opts.reuseMs ?? PROBE_REUSE_MS,
    read: [],
    visited: /* @__PURE__ */ new Set(),
    submodules: 0
  };
  for (const dir of new Set(dirs)) await walkAsync(walk2, dir, dir, 0);
  return combine(walk2.read, env, platform);
}
function gitSafetyForSync(dirs, opts = {}) {
  const platform = opts.platform ?? process.platform;
  const env = opts.env ?? process.env;
  const problem = countProblem(env, platform);
  if (problem !== null) return { ...staticGitSafety(platform), refused: problem };
  const walk2 = {
    git: opts.git ?? gitExecutable(env),
    env: probeEnv(env, platform),
    timeoutMs: opts.timeoutMs ?? PROBE_TIMEOUT_MS,
    reuseMs: opts.reuseMs ?? PROBE_REUSE_MS,
    read: [],
    visited: /* @__PURE__ */ new Set(),
    submodules: 0
  };
  for (const dir of new Set(dirs)) walkSync(walk2, dir, dir, 0);
  return combine(walk2.read, env, platform);
}
function nextSubmodules(walk2, dir, depth, links) {
  if (links.kind === "refused") {
    walk2.read.push({ dir, probe: { kind: "refused", message: links.message } });
    return [];
  }
  const next = [];
  for (const sub of links.dirs) {
    if (walk2.visited.has(sub)) continue;
    walk2.visited.add(sub);
    walk2.submodules += 1;
    if (walk2.submodules > MAX_SUBMODULES || depth + 1 > MAX_SUBMODULE_DEPTH) {
      walk2.read.push({
        dir: sub,
        probe: {
          kind: "refused",
          message: `${dir} has initialised submodules past what dev-guardian reads (${MAX_SUBMODULES} in all, ${MAX_SUBMODULE_DEPTH} levels deep), so their git configuration could not be kept from running commands`
        }
      });
      return [];
    }
    next.push(sub);
  }
  return next;
}
async function walkAsync(walk2, root, dir, depth) {
  walk2.visited.add(dir);
  const probe = await probeAsync(walk2.git, dir, walk2.env, walk2.timeoutMs, walk2.reuseMs);
  walk2.read.push(depth === 0 ? { dir, probe } : { dir, probe, submodule: relativeLabel(root, dir) });
  if (probe.kind !== "listing") return;
  const links = await gitlinksAsync(walk2.git, dir, walk2.env, walk2.timeoutMs, walk2.reuseMs);
  for (const sub of nextSubmodules(walk2, dir, depth, links)) await walkAsync(walk2, root, sub, depth + 1);
}
function walkSync(walk2, root, dir, depth) {
  walk2.visited.add(dir);
  const probe = probeSync(walk2.git, dir, walk2.env, walk2.timeoutMs, walk2.reuseMs);
  walk2.read.push(depth === 0 ? { dir, probe } : { dir, probe, submodule: relativeLabel(root, dir) });
  if (probe.kind !== "listing") return;
  const links = gitlinksSync(walk2.git, dir, walk2.env, walk2.timeoutMs, walk2.reuseMs);
  for (const sub of nextSubmodules(walk2, dir, depth, links)) walkSync(walk2, root, sub, depth + 1);
}
function relativeLabel(root, dir) {
  const rel = relative5(root, dir).split("\\").join("/");
  return rel === "" ? "." : rel;
}
function gitlinkArgs(dir) {
  return ["-c", "safe.directory=*", "-C", dir, "ls-files", "-z", "--stage", "--", ":/"];
}
function parseGitlinks(dir, status, stdout) {
  if (status !== 0) return { kind: "dirs", dirs: [] };
  const dirs = [];
  let start = 0;
  for (let i = 0; i <= stdout.length; i++) {
    if (i < stdout.length && stdout[i] !== 0) continue;
    const entry = stdout.subarray(start, i);
    start = i + 1;
    if (entry.length < 8 || entry.toString("latin1", 0, 7) !== "160000 ") continue;
    const tab = entry.indexOf(9);
    if (tab < 0) continue;
    let path;
    try {
      path = STRICT_UTF8.decode(entry.subarray(tab + 1));
    } catch {
      return { kind: "refused", message: `${dir} has a submodule whose path is not UTF-8, which dev-guardian cannot follow` };
    }
    const abs = resolve7(dir, path);
    if (dirs.includes(abs)) continue;
    const kind = entryKindAnywhere(join11(abs, ".git"));
    if (kind === "remote") {
      return { kind: "refused", message: `${dir} has a submodule (${path}) whose .git reaches a network path through a link, which dev-guardian does not follow` };
    }
    if (kind !== "absent") dirs.push(abs);
  }
  return { kind: "dirs", dirs };
}
function gitlinksError(error, dir, timeoutMs) {
  if (error.code === "ENOENT") return { kind: "dirs", dirs: [] };
  if (error.code === "ETIMEDOUT") return { kind: "refused", message: `listing the submodules of ${dir} took longer than ${timeoutMs} ms` };
  if (error.code === "ENOBUFS") {
    return { kind: "refused", message: `the index of ${dir} lists more than ${GITLINK_LISTING_MAX_BYTES} bytes of files; its submodules were not read` };
  }
  return { kind: "refused", message: `could not list the submodules of ${dir}: ${error.message}` };
}
function cachedGitlinks(key, reuseMs) {
  const hit = gitlinkCache.get(key);
  if (hit === void 0 || Date.now() - hit.at > reuseMs) return null;
  return hit.links;
}
function rememberGitlinks(key, links) {
  if (links.kind === "refused") return links;
  if (gitlinkCache.size >= PROBE_CACHE_MAX) gitlinkCache.clear();
  gitlinkCache.set(key, { at: Date.now(), links });
  return links;
}
function gitlinksSync(git, dir, env, timeoutMs, reuseMs) {
  const key = probeCacheKey(git, dir, env);
  const hit = cachedGitlinks(key, reuseMs);
  if (hit !== null) return hit;
  const r = spawnSync(git, gitlinkArgs(dir), {
    env,
    timeout: timeoutMs,
    maxBuffer: GITLINK_LISTING_MAX_BYTES,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (r.error !== void 0) return gitlinksError(r.error, dir, timeoutMs);
  return rememberGitlinks(key, parseGitlinks(dir, r.status, Buffer.isBuffer(r.stdout) ? r.stdout : Buffer.alloc(0)));
}
async function gitlinksAsync(git, dir, env, timeoutMs, reuseMs) {
  const key = probeCacheKey(git, dir, env);
  const hit = cachedGitlinks(key, reuseMs);
  if (hit !== null) return hit;
  const r = await gitSpawner(git, gitlinkArgs(dir), { env, timeoutMs, maxBuffer: GITLINK_LISTING_MAX_BYTES });
  if (r.error !== void 0) return gitlinksError(r.error, dir, timeoutMs);
  return rememberGitlinks(key, parseGitlinks(dir, r.status, r.stdout));
}
function probeCacheKey(git, dir, env) {
  const relevant = Object.keys(env).filter((k) => /^(GIT_|HOME$|USERPROFILE$|XDG_CONFIG_HOME$|PATH$|PROGRAMDATA$|APPDATA$)/i.test(k)).sort().map((k) => `${k}=${env[k] ?? ""}`);
  return JSON.stringify([git, dir, relevant]);
}
function cachedProbe(key, reuseMs) {
  const hit = probeCache.get(key);
  if (hit === void 0) return null;
  if (Date.now() - hit.at > reuseMs) {
    probeCache.delete(key);
    return null;
  }
  return hit.probe;
}
function rememberProbe(key, probe) {
  if (probe.kind === "refused") return probe;
  if (probeCache.size >= PROBE_CACHE_MAX) probeCache.clear();
  probeCache.set(key, { at: Date.now(), probe });
  return probe;
}
function forgetGitConfigReads() {
  probeCache.clear();
  gitlinkCache.clear();
}
function probeSync(git, dir, env, timeoutMs, reuseMs) {
  const key = probeCacheKey(git, dir, env);
  return cachedProbe(key, reuseMs) ?? rememberProbe(key, probeSyncUncached(git, dir, env, timeoutMs));
}
async function probeAsync(git, dir, env, timeoutMs, reuseMs) {
  const key = probeCacheKey(git, dir, env);
  return cachedProbe(key, reuseMs) ?? rememberProbe(key, await probeAsyncUncached(git, dir, env, timeoutMs));
}
function probeSyncUncached(git, dir, env, timeoutMs) {
  const r = spawnSync(git, probeArgs(dir), {
    env,
    timeout: timeoutMs,
    maxBuffer: PROBE_MAX_BYTES,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (r.error !== void 0) return probeError(r.error, dir, timeoutMs);
  return interpretExit(r.status, Buffer.isBuffer(r.stdout) ? r.stdout : Buffer.alloc(0), String(r.stderr ?? ""), dir);
}
async function probeAsyncUncached(git, dir, env, timeoutMs) {
  const r = await gitSpawner(git, probeArgs(dir), { env, timeoutMs, maxBuffer: PROBE_MAX_BYTES });
  if (r.error !== void 0) return probeError(r.error, dir, timeoutMs);
  return interpretExit(r.status, r.stdout, r.stderr.toString("utf8"), dir);
}
function probeError(error, dir, timeoutMs) {
  if (error.code === "ENOENT") return { kind: "none" };
  if (error.code === "ETIMEDOUT") {
    return { kind: "refused", message: `reading the git configuration of ${dir} took longer than ${timeoutMs} ms` };
  }
  if (error.code === "ENOBUFS") {
    return { kind: "refused", message: `the git configuration of ${dir} is larger than ${PROBE_MAX_BYTES} bytes of command settings` };
  }
  return { kind: "refused", message: `could not read the git configuration of ${dir}: ${error.message}` };
}
function applyGitSafety(safety, base2, platform = process.platform) {
  const env = { ...base2 };
  for (const [name, value] of Object.entries(safety.vars)) setVar(env, name, value, platform);
  if (countProblem(env, platform) !== null) return env;
  const countName = Object.keys(env).find((name) => sameName(name, "GIT_CONFIG_COUNT", platform));
  const trimmed = (countName === void 0 ? "" : env[countName] ?? "").trim();
  let n = trimmed === "" ? 0 : Number(trimmed);
  for (const [key, value] of safety.config) {
    setVar(env, `GIT_CONFIG_KEY_${n}`, key, platform);
    setVar(env, `GIT_CONFIG_VALUE_${n}`, value, platform);
    n += 1;
  }
  setVar(env, countName ?? "GIT_CONFIG_COUNT", String(n), platform);
  return env;
}
function dockerGitEnvArgs(safety) {
  const hooks = noHooksPath("linux");
  const config = safety.config.map(([k, v]) => k === "core.hooksPath" ? [k, hooks] : [k, v]);
  const args = [];
  config.forEach(([k, v], i) => {
    args.push("-e", `GIT_CONFIG_KEY_${i}=${k}`, "-e", `GIT_CONFIG_VALUE_${i}=${v}`);
  });
  args.push("-e", `GIT_CONFIG_COUNT=${config.length}`);
  for (const [name, value] of Object.entries(safety.vars)) args.push("-e", `${name}=${value}`);
  return args;
}
function localReceivePackCommand(safety) {
  const words = [GIT_COMMAND];
  for (const [key, value] of safety.config) {
    if (key.includes("=")) return null;
    words.push("-c", shellQuote(`${key}=${value}`));
  }
  words.push("receive-pack");
  return words.join(" ");
}
function describeNotApplied(keys) {
  if (keys.length === 0) return null;
  const shown = keys.slice(0, 6).join(", ");
  const more = keys.length > 6 ? ` and ${keys.length - 6} more` : "";
  return `the repository's own git configuration was not applied for ${shown}${more} \u2014 dev-guardian never runs a command a scanned repository configures (files were read as stored in git)`;
}
async function execGit(dir, args, opts = {}) {
  const r = await execGitBuffer(dir, args, opts);
  return { ...r, stdout: r.stdout.toString("utf8") };
}
async function execGitBuffer(dir, args, opts = {}) {
  const safety = await gitSafetyFor([dir, ...opts.alsoRepos ?? []], opts);
  if (safety.refused !== null) return refusedResult(safety, Buffer.alloc(0));
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS2;
  const maxBuffer = opts.maxBuffer ?? DEFAULT_MAX_BUFFER;
  const r = await gitSpawner(opts.git ?? gitExecutable(opts.env ?? process.env), ["-C", dir, ...args], {
    env: applyGitSafety(safety, opts.env ?? process.env, opts.platform ?? process.platform),
    timeoutMs,
    maxBuffer
  });
  return {
    status: r.error === void 0 ? r.status : null,
    stdout: r.stdout,
    stderr: r.stderr.toString("utf8"),
    failure: r.error === void 0 ? null : execFailure(r.error, timeoutMs, maxBuffer),
    notApplied: safety.notApplied
  };
}
function execGitSync(dir, args, opts = {}) {
  const safety = gitSafetyForSync([dir, ...opts.alsoRepos ?? []], opts);
  if (safety.refused !== null) return refusedResult(safety, "");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS2;
  const maxBuffer = opts.maxBuffer ?? DEFAULT_MAX_BUFFER;
  const r = spawnSync(opts.git ?? gitExecutable(opts.env ?? process.env), ["-C", dir, ...args], {
    env: applyGitSafety(safety, opts.env ?? process.env, opts.platform ?? process.platform),
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  return {
    status: r.error === void 0 ? r.status : null,
    stdout: typeof r.stdout === "string" ? r.stdout : "",
    stderr: typeof r.stderr === "string" ? r.stderr : "",
    failure: r.error === void 0 ? null : execFailure(r.error, timeoutMs, maxBuffer),
    notApplied: safety.notApplied
  };
}
function refusedResult(safety, empty) {
  const message = `dev-guardian did not run git: ${safety.refused ?? ""}`;
  return { status: null, stdout: empty, stderr: message, failure: { code: "refused", message }, notApplied: safety.notApplied };
}
function execFailure(error, timeoutMs, maxBuffer) {
  if (error.code === "ENOENT") return { code: "not-found", message: "git is not installed" };
  if (error.code === "ETIMEDOUT") return { code: "timeout", message: `git took longer than ${timeoutMs} ms` };
  if (error.code === "ENOBUFS") return { code: "too-large", message: `git printed more than ${maxBuffer} bytes` };
  return { code: "spawn", message: `git failed to run (${error.code ?? error.message})` };
}
function useGitSpawner(spawner) {
  const previous = gitSpawner;
  gitSpawner = spawner;
  return previous;
}
function collect3(command, args, opts) {
  return new Promise((resolveRun) => {
    let settled = false;
    const out = [];
    const err = [];
    let outBytes = 0;
    let errBytes = 0;
    let error;
    const finish = (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveRun({ status, stdout: Buffer.concat(out), stderr: Buffer.concat(err), ...error !== void 0 ? { error } : {} });
    };
    const fail2 = (code, message) => {
      if (error === void 0) error = Object.assign(new Error(message), { code });
      child.kill("SIGKILL");
    };
    const child = spawn(command, args, { env: opts.env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => fail2("ETIMEDOUT", `timed out after ${opts.timeoutMs} ms`), opts.timeoutMs);
    child.stdout.on("data", (chunk) => {
      outBytes += chunk.length;
      if (outBytes > opts.maxBuffer) fail2("ENOBUFS", "stdout maxBuffer exceeded");
      else out.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      errBytes += chunk.length;
      if (errBytes <= 1024 * 1024) err.push(chunk);
    });
    child.on("error", (e) => {
      error ??= e;
      finish(null);
    });
    child.on("close", (code) => finish(code));
  });
}
function setVar(env, name, value, platform) {
  for (const other of Object.keys(env)) if (other !== name && sameName(other, name, platform)) delete env[other];
  env[name] = value;
}
function envValue3(env, name, platform = process.platform) {
  for (const key of Object.keys(env)) if (sameName(key, name, platform)) return env[key];
  return void 0;
}
function sameName(a, b, platform) {
  return platform === "win32" ? a.toUpperCase() === b.toUpperCase() : a === b;
}
function firstLine2(text) {
  return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? "";
}
var GIT_COMMAND, PROBE_TIMEOUT_MS, PROBE_MAX_BYTES, MAX_REPOSITORY_KEYS, STATIC_VARS, COMMAND_KEYS_REGEX, PROBE_KEY, TRUSTED_SCOPES, STRICT_UTF8, FILTER_KEY, CREDENTIAL_HELPER, STATIC_KEYS, HTTP_KEY, GIT_CANNOT_READ, MAX_SUBMODULES, MAX_SUBMODULE_DEPTH, GITLINK_LISTING_MAX_BYTES, gitlinkCache, PROBE_REUSE_MS, PROBE_CACHE_MAX, probeCache, DEFAULT_MAX_BUFFER, DEFAULT_TIMEOUT_MS2, gitSpawner;
var init_gitSafety = __esm({
  "src/platform/gitSafety.ts"() {
    "use strict";
    init_binaryPath();
    init_projectFs();
    GIT_COMMAND = "git";
    PROBE_TIMEOUT_MS = 1e4;
    PROBE_MAX_BYTES = 1024 * 1024;
    MAX_REPOSITORY_KEYS = 200;
    STATIC_VARS = { GIT_PAGER: "cat", GIT_EDITOR: ":", GIT_SEQUENCE_EDITOR: ":" };
    COMMAND_KEYS_REGEX = "^(" + [
      "filter\\..+\\.(clean|smudge|process)",
      "diff\\..+\\.(textconv|command)",
      "diff\\.external",
      "merge\\..+\\.driver",
      "core\\.(sshcommand|askpass|gitproxy|alternaterefscommand|fsmonitor|hookspath|pager|editor)",
      "sequence\\.editor",
      "pager\\..+",
      "credential\\.(.+\\.)?helper",
      "gpg\\.(program|.+\\.program|ssh\\.defaultkeycommand)",
      "alias\\..+",
      "remote\\..+\\.(uploadpack|receivepack|proxy)",
      "http\\.(.+\\.)?(extraheader|proxy|sslverify|sslcainfo|sslcapath|cookiefile|savecookies|followredirects)",
      "devguardian\\.envprobe"
    ].join("|") + ")$";
    PROBE_KEY = "devguardian.envprobe";
    TRUSTED_SCOPES = /* @__PURE__ */ new Set(["system", "global", "command"]);
    STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
    FILTER_KEY = /^filter\.(.+)\.(clean|smudge|process)$/;
    CREDENTIAL_HELPER = /^credential\.(?:.+\.)?helper$/;
    STATIC_KEYS = /* @__PURE__ */ new Set(["core.fsmonitor", "core.hookspath", "core.pager", "core.editor", "sequence.editor"]);
    HTTP_KEY = /^http\.(?:(.+)\.)?(extraheader|proxy|sslverify|sslcainfo|sslcapath|cookiefile|savecookies|followredirects)$/;
    GIT_CANNOT_READ = /cannot change to|bad config line|bad numeric config value|exceeded maximum include depth|not a git repository|gitfile does not point to a valid repository/i;
    MAX_SUBMODULES = 64;
    MAX_SUBMODULE_DEPTH = 8;
    GITLINK_LISTING_MAX_BYTES = 512 * 1024 * 1024;
    gitlinkCache = /* @__PURE__ */ new Map();
    PROBE_REUSE_MS = 2e3;
    PROBE_CACHE_MAX = 64;
    probeCache = /* @__PURE__ */ new Map();
    DEFAULT_MAX_BUFFER = 1e8;
    DEFAULT_TIMEOUT_MS2 = 6e4;
    gitSpawner = collect3;
  }
});

// src/platform/projectPath.ts
import { existsSync as existsSync2, realpathSync as realpathSync3, statSync as statSync3 } from "node:fs";
import { parse as parse7, resolve as resolve8 } from "node:path";
function canonicalPath(p) {
  const resolved = resolve8(p);
  let canonical = resolved;
  try {
    canonical = realpathSync3.native(resolved);
  } catch {
  }
  if (process.platform === "win32") {
    if (canonical.startsWith("\\\\") && !resolved.startsWith("\\\\")) canonical = resolved;
    canonical = canonical.replace(/\//g, "\\").replace(/^([a-z]):/, (_m, drive) => `${drive.toUpperCase()}:`);
  }
  return canonical;
}
var init_projectPath = __esm({
  "src/platform/projectPath.ts"() {
    "use strict";
    init_configFile();
  }
});

// src/storage/dbError.ts
var GuardianDbError;
var init_dbError = __esm({
  "src/storage/dbError.ts"() {
    "use strict";
    GuardianDbError = class extends Error {
      constructor(kind, dbPath, message, reason) {
        super(message);
        this.kind = kind;
        this.dbPath = dbPath;
        this.reason = reason;
        this.name = "GuardianDbError";
      }
      kind;
      dbPath;
      reason;
    };
  }
});

// src/storage/userData.ts
import { chmodSync, lstatSync as lstatSync6, mkdirSync as mkdirSync2, statSync as statSync4 } from "node:fs";
import { join as join12 } from "node:path";
function notPrivate(path, why) {
  return new GuardianDbError("data-dir", path, `'${path}' ${why}`);
}
function dataDirFailure(path, doing, error) {
  if (error instanceof GuardianDbError) return error;
  const detail = error instanceof Error ? error.message : String(error);
  return new GuardianDbError("data-dir", path, `'${path}' cannot be ${doing} (${detail})`);
}
function currentUid() {
  return typeof process.getuid === "function" ? process.getuid() : void 0;
}
function assertPrivateDir(path, st) {
  if (st.isSymbolicLink()) throw notPrivate(path, "is a symbolic link");
  if (!st.isDirectory()) throw notPrivate(path, "is not a directory");
  if (process.platform === "win32") return;
  const uid = currentUid();
  if (uid !== void 0 && st.uid !== uid) throw notPrivate(path, `belongs to uid ${st.uid}, not to this user (${uid})`);
  if ((st.mode & 63) !== 0) {
    try {
      chmodSync(path, 448);
    } catch (error) {
      throw dataDirFailure(path, "made private (chmod 0700)", error);
    }
  }
}
function statOrNull(path, follow) {
  try {
    return follow ? statSync4(path) : lstatSync6(path);
  } catch (error) {
    const code = error.code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw dataDirFailure(path, "read", error);
  }
}
function ensurePrivateDataDir() {
  const dir = userDataDir();
  const existing = statOrNull(dir, true);
  if (existing === null) {
    try {
      mkdirSync2(dir, { recursive: true, mode: 448 });
    } catch (error) {
      throw dataDirFailure(dir, "created", error);
    }
    const created = statOrNull(dir, true);
    if (created === null) throw notPrivate(dir, "vanished as it was created");
    assertPrivateDir(dir, created);
  } else {
    assertPrivateDir(dir, existing);
  }
  return dir;
}
function ensurePrivateSubdir(name) {
  const parent = ensurePrivateDataDir();
  const dir = join12(parent, name);
  const existing = statOrNull(dir, false);
  if (existing === null) {
    try {
      mkdirSync2(dir, { mode: 448 });
    } catch (error) {
      if (error.code !== "EEXIST") throw dataDirFailure(dir, "created", error);
    }
  }
  const st = statOrNull(dir, false);
  if (st === null) throw notPrivate(dir, "vanished as it was created");
  assertPrivateDir(dir, st);
  return dir;
}
function assertOwnedRegularFileIfPresent(path) {
  const st = statOrNull(path, false);
  if (st === null) return;
  if (!st.isFile()) throw notPrivate(path, st.isSymbolicLink() ? "is a symbolic link" : "is not a regular file");
  if (process.platform === "win32") return;
  const uid = currentUid();
  if (uid !== void 0 && st.uid !== uid) throw notPrivate(path, `belongs to uid ${st.uid}, not to this user (${uid})`);
}
var init_userData = __esm({
  "src/storage/userData.ts"() {
    "use strict";
    init_userDataDir();
    init_dbError();
  }
});

// src/storage/dbRegistry.ts
var dbRegistry_exports = {};
__export(dbRegistry_exports, {
  DB_ID_KEY: () => DB_ID_KEY,
  DB_ID_SHAPE: () => DB_ID_SHAPE,
  databaseRegistration: () => databaseRegistration,
  findEntryForDbPath: () => findEntryForDbPath,
  forgetDbId: () => forgetDbId,
  lookupDbId: () => lookupDbId,
  newDbId: () => newDbId,
  registerDbId: () => registerDbId,
  registryDir: () => registryDir2
});
import { randomBytes } from "node:crypto";
import {
  closeSync as closeSync3,
  constants as constants4,
  fstatSync as fstatSync3,
  lstatSync as lstatSync7,
  openSync as openSync3,
  readdirSync as readdirSync5,
  readSync as readSync3,
  renameSync as renameSync2,
  rmSync,
  writeFileSync
} from "node:fs";
import { join as join13 } from "node:path";
function newDbId() {
  return randomBytes(16).toString("hex");
}
function registryDir2() {
  return join13(userDataDir(), "registry");
}
function lookupDbId(id) {
  if (!DB_ID_SHAPE.test(id)) return null;
  const path = join13(registryDir2(), `${id}.json`);
  try {
    assertOwnedRegularFileIfPresent(path);
  } catch {
    return null;
  }
  let text;
  try {
    text = readBounded(path, 4096);
  } catch {
    return null;
  }
  try {
    const parsed = JSON.parse(text);
    if (parsed.db_id !== id) return null;
    return {
      db_id: id,
      db_path: typeof parsed.db_path === "string" ? parsed.db_path : "",
      project_path: typeof parsed.project_path === "string" ? parsed.project_path : "",
      created_at: typeof parsed.created_at === "string" ? parsed.created_at : ""
    };
  } catch {
    return null;
  }
}
function findEntryForDbPath(canonicalDbPath) {
  let names;
  try {
    names = readdirSync5(registryDir2());
  } catch {
    return null;
  }
  for (const name of names) {
    const id = name.endsWith(".json") ? name.slice(0, -".json".length) : "";
    if (!DB_ID_SHAPE.test(id)) continue;
    const entry = lookupDbId(id);
    if (entry !== null && entry.db_path === canonicalDbPath) return entry;
  }
  return null;
}
function databaseRegistration(dbPath) {
  try {
    if (!lstatSync7(dbPath).isFile()) return "none";
  } catch {
    return "none";
  }
  let canonical;
  try {
    canonical = canonicalPath(dbPath);
  } catch {
    return "unknown";
  }
  try {
    readdirSync5(registryDir2());
  } catch (error) {
    return error.code === "ENOENT" ? "unregistered" : "unknown";
  }
  return findEntryForDbPath(canonical) !== null ? "registered" : "unregistered";
}
function registerDbId(entry) {
  if (!DB_ID_SHAPE.test(entry.db_id)) throw new Error(`not a database id: ${entry.db_id}`);
  const dir = ensurePrivateSubdir("registry");
  const target = join13(dir, `${entry.db_id}.json`);
  const temp = `${target}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    writeFileSync(temp, `${JSON.stringify(entry, null, 2)}
`, { flag: "wx", mode: 384 });
  } catch (error) {
    throw dataDirFailure(dir, "written", error);
  }
  try {
    renameSync2(temp, target);
  } catch (error) {
    rmSync(temp, { force: true });
    throw dataDirFailure(dir, "written", error);
  }
}
function forgetDbId(id) {
  if (!DB_ID_SHAPE.test(id)) return;
  try {
    rmSync(join13(registryDir2(), `${id}.json`), { force: true });
  } catch {
  }
}
function readBounded(path, max) {
  const fd = openSync3(path, constants4.O_RDONLY | (constants4.O_NONBLOCK ?? 0));
  try {
    const st = fstatSync3(fd);
    if (!st.isFile() || st.size > max) throw new Error("not a registry entry");
    const buf = Buffer.alloc(st.size);
    let got = 0;
    while (got < st.size) {
      const n = readSync3(fd, buf, got, st.size - got, got);
      if (n === 0) break;
      got += n;
    }
    return buf.subarray(0, got).toString("utf8");
  } finally {
    closeSync3(fd);
  }
}
var DB_ID_SHAPE, DB_ID_KEY;
var init_dbRegistry = __esm({
  "src/storage/dbRegistry.ts"() {
    "use strict";
    init_projectPath();
    init_userData();
    DB_ID_SHAPE = /^[0-9a-f]{32}$/;
    DB_ID_KEY = "db_id";
  }
});

// src/hooksEntry.ts
var loadConfigFile = () => Promise.resolve().then(() => (init_configFile(), configFile_exports));
var loadGuardedPath = () => Promise.resolve().then(() => (init_guardedPath(), guardedPath_exports));
var loadBashGuard = () => Promise.resolve().then(() => (init_bashGuard(), bashGuard_exports));
var loadInstallGate = () => Promise.resolve().then(() => (init_mayInstall(), mayInstall_exports));
var loadInstallVetting = () => Promise.resolve().then(() => (init_hookDecision(), hookDecision_exports));
var loadSecretScan = () => Promise.resolve().then(() => (init_secretScan(), secretScan_exports));
var loadSettingsGuard = () => Promise.resolve().then(() => (init_settingsGuard(), settingsGuard_exports));
var loadDataRegistry = () => Promise.resolve().then(() => (init_dataRegistry(), dataRegistry_exports));
var loadGitSafety = () => Promise.resolve().then(() => (init_gitSafety(), gitSafety_exports));
var loadDbRegistry = () => Promise.resolve().then(() => (init_dbRegistry(), dbRegistry_exports));
export {
  loadBashGuard,
  loadConfigFile,
  loadDataRegistry,
  loadDbRegistry,
  loadGitSafety,
  loadGuardedPath,
  loadInstallGate,
  loadInstallVetting,
  loadSecretScan,
  loadSettingsGuard
};
