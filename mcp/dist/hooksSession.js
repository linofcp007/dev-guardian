import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// <define:__GUARDIAN_ENGINE_DIGEST__>
var define_GUARDIAN_ENGINE_DIGEST_default = { bytes: 4962669, sha256: "bf7123c2a5cbf913375cbce68cfa6e0cce5bbadad35c57e83a7226e527e093ce" };

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
  spawnGitPlain: () => spawnGitPlain,
  staticGitSafety: () => staticGitSafety,
  useGitSpawner: () => useGitSpawner,
  withoutHooksPath: () => withoutHooksPath
});
import { spawn, spawnSync } from "node:child_process";
import { dirname as dirname2, join as join4, relative as relative3, resolve as resolve3 } from "node:path";

// src/platform/binaryPath.ts
import { accessSync, constants, lstatSync, statSync } from "node:fs";
import { extname, join } from "node:path";
var DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD";
function envValue(env, name, platform) {
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
  const pathext = (envValue(env, "PATHEXT", "win32") ?? DEFAULT_PATHEXT).split(";").map((e) => e.trim().toLowerCase()).filter((e) => /^\.[a-z0-9]{1,8}$/.test(e));
  const exts = pathext.length > 0 ? pathext : DEFAULT_PATHEXT.toLowerCase().split(";");
  return exts.includes(extname(name).toLowerCase()) ? [""] : exts;
}
function runnable(file, platform) {
  try {
    const st = statSync(file);
    if (!st.isFile()) return false;
    if (platform === "win32") return true;
    accessSync(file, constants.X_OK);
    return true;
  } catch (err) {
    if (platform === "win32" && err.code === "EACCES") {
      try {
        return lstatSync(file).isSymbolicLink();
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
var found = /* @__PURE__ */ new Map();
var FOUND_CACHE_MAX = 256;
function findOnPath(name, env = process.env, platform = process.platform) {
  if (!isBareName(name, platform)) return null;
  const cacheKey = `${platform}\0${envValue(env, "PATH", platform) ?? ""}\0${envValue(env, "PATHEXT", platform) ?? ""}\0${name}`;
  const cached = found.get(cacheKey);
  if (cached !== void 0 && runnable(cached, platform)) return cached;
  const exts = platform === "win32" ? extensionsFor(name, env) : [""];
  for (const dir of searchDirs(envValue(env, "PATH", platform) ?? "", platform)) {
    for (const ext of exts) {
      const candidate = join(dir, `${name}${ext}`);
      if (runnable(candidate, platform)) {
        if (found.size >= FOUND_CACHE_MAX) found.clear();
        found.set(cacheKey, candidate);
        return candidate;
      }
    }
  }
  return null;
}

// src/platform/projectFs.ts
import {
  closeSync as closeSync2,
  constants as constants3,
  fstatSync as fstatSync2,
  linkSync,
  lstatSync as lstatSync3,
  mkdirSync,
  openSync as openSync2,
  readdirSync,
  readSync as readSync2,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync
} from "node:fs";
import { dirname, isAbsolute as isAbsolute2, join as join3, parse as parse2, relative as relative2, resolve as resolve2, sep } from "node:path";

// src/hooks/configFile.ts
import { closeSync, constants as constants2, fstatSync, lstatSync as lstatSync2, openSync, readlinkSync, readSync } from "node:fs";
import { isAbsolute, join as join2, parse, relative, resolve } from "node:path";
var MAX_HOOK_CONFIG_BYTES = 64 * 1024;
var OPEN_FLAGS = constants2.O_RDONLY | (constants2.O_NONBLOCK ?? 0);
var MAX_LINK_HOPS = 32;
function isRemoteOrDeviceTarget(target) {
  return /^(?:[\\/]{2}|\\\?\?\\)/.test(target);
}
function climbsOut(rel) {
  return rel === ".." || rel.startsWith("../") || rel.startsWith("..\\");
}
function walkLinksUnder(under, path) {
  const rel = relative(resolve(under), resolve(path));
  if (rel === "" || climbsOut(rel) || isAbsolute(rel)) return { ok: true };
  let current = resolve(under);
  const queue = rel.split(/[\\/]+/).filter((p) => p.length > 0);
  let hops = 0;
  for (let part = queue.shift(); part !== void 0; part = queue.shift()) {
    if (part === ".") continue;
    if (part === "..") {
      current = resolve(current, "..");
      continue;
    }
    const next = join2(current, part);
    let isLink;
    try {
      isLink = lstatSync2(next).isSymbolicLink();
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

// src/platform/projectFs.ts
var PROJECT_FILE_MAX_BYTES = 8 * 1024 * 1024;
var PROJECT_LOCKFILE_MAX_BYTES = 64 * 1024 * 1024;
var OPEN_FLAGS2 = constants3.O_RDONLY | (constants3.O_NONBLOCK ?? 0);
var caseFold = (p) => process.platform === "win32" ? p.toLowerCase() : p;
function isWithinDir(root, path) {
  const rel = relative2(caseFold(resolve2(root)), caseFold(resolve2(path)));
  return rel === "" || rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute2(rel);
}
function projectEntryKind(path) {
  let st;
  try {
    st = lstatSync3(path);
  } catch {
    return "absent";
  }
  if (st.isSymbolicLink()) return "link";
  if (st.isFile()) return "file";
  if (st.isDirectory()) return "directory";
  return "other";
}
function projectEntryKindIn(root, path) {
  const abs = resolve2(root, path);
  if (!isWithinDir(root, abs)) return "absent";
  const walk = walkLinksUnder(root, abs);
  if (!walk.ok) return walk.reason === "remote-link" ? "remote" : "other";
  return projectEntryKind(abs);
}
function entryKindAnywhere(path) {
  const lexicallyRemote = /^(?:\\\\|\/\/)/;
  if (lexicallyRemote.test(path)) return "remote";
  const abs = resolve2(path);
  if (lexicallyRemote.test(abs)) return "remote";
  return projectEntryKindIn(parse2(abs).root, abs);
}

// src/platform/gitSafety.ts
var GIT_COMMAND = "git";
function gitExecutable(env) {
  return findOnPath(GIT_COMMAND, env) ?? join4(dirname2(process.execPath), "no-git-on-path", GIT_COMMAND);
}
var PROBE_TIMEOUT_MS = 1e4;
var PROBE_MAX_BYTES = 1024 * 1024;
var MAX_REPOSITORY_KEYS = 200;
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
var STATIC_VARS = { GIT_PAGER: "cat", GIT_EDITOR: ":", GIT_SEQUENCE_EDITOR: ":" };
function withoutHooksPath(safety) {
  return { ...safety, config: safety.config.filter(([key]) => key !== "core.hooksPath") };
}
function staticGitSafety(platform = process.platform) {
  return { config: staticConfig(noHooksPath(platform)), vars: STATIC_VARS, notApplied: [], refused: null };
}
var COMMAND_KEYS_REGEX = "^(" + [
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
var PROBE_KEY = "devguardian.envprobe";
var TRUSTED_SCOPES = /* @__PURE__ */ new Set(["system", "global", "command"]);
function isRepositoryScope(scope) {
  return !TRUSTED_SCOPES.has(scope);
}
var STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
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
var FILTER_KEY = /^filter\.(.+)\.(clean|smudge|process)$/;
var CREDENTIAL_HELPER = /^credential\.(?:.+\.)?helper$/;
var STATIC_KEYS = /* @__PURE__ */ new Set(["core.fsmonitor", "core.hookspath", "core.pager", "core.editor", "sequence.editor"]);
function neutralValue(key, env) {
  if (FILTER_KEY.test(key)) return "";
  if (/^diff\..+\.textconv$/.test(key)) return "cat";
  if (key === "core.sshcommand") {
    const gitSsh = envValue2(env, "GIT_SSH");
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
var HTTP_KEY = /^http\.(?:(.+)\.)?(extraheader|proxy|sslverify|sslcainfo|sslcapath|cookiefile|savecookies|followredirects)$/;
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
      if (envValue2(env, "GIT_PROXY_COMMAND") === void 0) vars["GIT_PROXY_COMMAND"] = "";
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
function probeEnv(base, platform) {
  const env = { ...base };
  for (const name of Object.keys(env)) if (sameName(name, "GIT_CONFIG", platform)) delete env[name];
  const stat = staticGitSafety(platform);
  return applyGitSafety({ ...stat, config: [...stat.config, [PROBE_KEY, "1"]] }, env, platform);
}
function countProblem(env, platform) {
  const raw = envValue2(env, "GIT_CONFIG_COUNT", platform) ?? "";
  const t = raw.trim();
  if (t === "" || /^\+?\d+$/.test(t)) return null;
  return `GIT_CONFIG_COUNT in the environment is ${JSON.stringify(raw)}, not a number, and git refuses to run with it`;
}
var GIT_CANNOT_READ = /cannot change to|bad config line|bad numeric config value|exceeded maximum include depth|not a git repository|gitfile does not point to a valid repository/i;
function interpretExit(status, stdout, stderr, dir) {
  if (status === 0) return { kind: "listing", bytes: stdout };
  if (status === 1) return { kind: "listing", bytes: Buffer.alloc(0) };
  if (status === 3) return { kind: "none" };
  if (status === 128 && GIT_CANNOT_READ.test(stderr)) return { kind: "none" };
  return {
    kind: "refused",
    message: `could not read the git configuration of ${dir}: git config exited ${status ?? "on a signal"}${firstLine(stderr) !== "" ? ` (${firstLine(stderr)})` : ""}`
  };
}
function combine(probes, env, platform) {
  const base = staticGitSafety(platform);
  const config = [...base.config];
  const vars = { ...base.vars };
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
  const walk = {
    git: opts.git ?? gitExecutable(env),
    env: probeEnv(env, platform),
    timeoutMs: opts.timeoutMs ?? PROBE_TIMEOUT_MS,
    reuseMs: opts.reuseMs ?? PROBE_REUSE_MS,
    read: [],
    visited: /* @__PURE__ */ new Set(),
    submodules: 0
  };
  for (const dir of new Set(dirs)) await walkAsync(walk, dir, dir, 0);
  return combine(walk.read, env, platform);
}
function gitSafetyForSync(dirs, opts = {}) {
  const platform = opts.platform ?? process.platform;
  const env = opts.env ?? process.env;
  const problem = countProblem(env, platform);
  if (problem !== null) return { ...staticGitSafety(platform), refused: problem };
  const walk = {
    git: opts.git ?? gitExecutable(env),
    env: probeEnv(env, platform),
    timeoutMs: opts.timeoutMs ?? PROBE_TIMEOUT_MS,
    reuseMs: opts.reuseMs ?? PROBE_REUSE_MS,
    read: [],
    visited: /* @__PURE__ */ new Set(),
    submodules: 0
  };
  for (const dir of new Set(dirs)) walkSync(walk, dir, dir, 0);
  return combine(walk.read, env, platform);
}
var MAX_SUBMODULES = 64;
var MAX_SUBMODULE_DEPTH = 8;
function nextSubmodules(walk, dir, depth, links) {
  if (links.kind === "refused") {
    walk.read.push({ dir, probe: { kind: "refused", message: links.message } });
    return [];
  }
  const next = [];
  for (const sub of links.dirs) {
    if (walk.visited.has(sub)) continue;
    walk.visited.add(sub);
    walk.submodules += 1;
    if (walk.submodules > MAX_SUBMODULES || depth + 1 > MAX_SUBMODULE_DEPTH) {
      walk.read.push({
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
async function walkAsync(walk, root, dir, depth) {
  walk.visited.add(dir);
  const [probe, links] = await Promise.all([
    probeAsync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs),
    gitlinksAsync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs)
  ]);
  walk.read.push(depth === 0 ? { dir, probe } : { dir, probe, submodule: relativeLabel(root, dir) });
  if (probe.kind !== "listing") return;
  for (const sub of nextSubmodules(walk, dir, depth, links)) await walkAsync(walk, root, sub, depth + 1);
}
function walkSync(walk, root, dir, depth) {
  walk.visited.add(dir);
  const probe = probeSync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs);
  walk.read.push(depth === 0 ? { dir, probe } : { dir, probe, submodule: relativeLabel(root, dir) });
  if (probe.kind !== "listing") return;
  const links = gitlinksSync(walk.git, dir, walk.env, walk.timeoutMs, walk.reuseMs);
  for (const sub of nextSubmodules(walk, dir, depth, links)) walkSync(walk, root, sub, depth + 1);
}
function relativeLabel(root, dir) {
  const rel = relative3(root, dir).split("\\").join("/");
  return rel === "" ? "." : rel;
}
function gitlinkArgs(dir) {
  return ["-c", "safe.directory=*", "-C", dir, "ls-files", "-z", "--stage", "--", ":/"];
}
var GITLINK_LISTING_MAX_BYTES = 512 * 1024 * 1024;
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
    const abs = resolve3(dir, path);
    if (dirs.includes(abs)) continue;
    const kind = entryKindAnywhere(join4(abs, ".git"));
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
var gitlinkCache = /* @__PURE__ */ new Map();
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
var PROBE_REUSE_MS = 2e3;
var PROBE_CACHE_MAX = 64;
var probeCache = /* @__PURE__ */ new Map();
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
function applyGitSafety(safety, base, platform = process.platform) {
  const env = { ...base };
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
var DEFAULT_MAX_BUFFER = 1e8;
var DEFAULT_TIMEOUT_MS = 6e4;
async function execGit(dir, args, opts = {}) {
  const r = await execGitBuffer(dir, args, opts);
  return { ...r, stdout: r.stdout.toString("utf8") };
}
async function execGitBuffer(dir, args, opts = {}) {
  const safety = await gitSafetyFor([dir, ...opts.alsoRepos ?? []], opts);
  if (safety.refused !== null) return refusedResult(safety, Buffer.alloc(0));
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
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
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBuffer = opts.maxBuffer ?? DEFAULT_MAX_BUFFER;
  const started = Date.now();
  const options = {
    env: applyGitSafety(safety, opts.env ?? process.env, opts.platform ?? process.platform),
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    detached: process.platform !== "win32"
  };
  const r = spawnSync(opts.git ?? gitExecutable(opts.env ?? process.env), ["-C", dir, ...args], options);
  const code = r.error?.code;
  if ((code === "ETIMEDOUT" || code === "ENOBUFS") && typeof r.pid === "number" && r.pid > 0) {
    stopSyncTree(r.pid, started);
  }
  return {
    status: r.error === void 0 ? r.status : null,
    stdout: typeof r.stdout === "string" ? r.stdout : "",
    stderr: typeof r.stderr === "string" ? r.stderr : "",
    failure: r.error === void 0 ? null : execFailure(r.error, timeoutMs, maxBuffer),
    notApplied: safety.notApplied
  };
}
var SYNC_SWEEP_TIMEOUT_MS = 15e3;
function stopSyncTree(pid, startedAt) {
  try {
    if (process.platform !== "win32") {
      process.kill(-pid, "SIGKILL");
      return;
    }
    const root = envValue2(process.env, "SystemRoot") ?? "C:\\Windows";
    const taskkill = join4(root, "System32", "taskkill.exe");
    const script = `$since = [DateTimeOffset]::FromUnixTimeMilliseconds(${Math.floor(startedAt) - 1e3}).LocalDateTime; Get-CimInstance Win32_Process -Filter 'ParentProcessId=${pid}' | Where-Object { $_.CreationDate -ge $since } | ForEach-Object { & '${taskkill.replace(/'/g, "''")}' /T /F /PID $_.ProcessId | Out-Null }`;
    spawnSync(join4(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-Command", script], {
      windowsHide: true,
      stdio: "ignore",
      timeout: SYNC_SWEEP_TIMEOUT_MS
    });
  } catch {
  }
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
var gitSpawner = spawnGitPlain;
function useGitSpawner(spawner) {
  const previous = gitSpawner;
  gitSpawner = spawner;
  return previous;
}
var PLAIN_ABANDON_MS = 2e3;
function spawnGitPlain(command, args, opts) {
  return new Promise((resolveRun) => {
    let settled = false;
    const out = [];
    const err = [];
    let outBytes = 0;
    let errBytes = 0;
    let error;
    let abandon;
    let timer;
    const finish = (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(abandon);
      resolveRun({ status, stdout: Buffer.concat(out), stderr: Buffer.concat(err), ...error !== void 0 ? { error } : {} });
    };
    let child;
    try {
      child = spawnPiped(command, args, opts.env);
    } catch (e) {
      error = e instanceof Error ? e : Object.assign(new Error(String(e)), { code: "EINVAL" });
      finish(null);
      return;
    }
    const started = child;
    const fail = (code, message) => {
      if (error === void 0) error = Object.assign(new Error(message), { code });
      if (abandon !== void 0) return;
      stopPlainTree(started);
      abandon = setTimeout(() => {
        started.stdout.destroy();
        started.stderr.destroy();
        finish(null);
      }, PLAIN_ABANDON_MS);
    };
    timer = setTimeout(() => fail("ETIMEDOUT", `timed out after ${opts.timeoutMs} ms`), opts.timeoutMs);
    child.stdout.on("data", (chunk) => {
      outBytes += chunk.length;
      if (outBytes > opts.maxBuffer) fail("ENOBUFS", "stdout maxBuffer exceeded");
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
    child.on("close", (code) => finish(error !== void 0 ? null : code));
  });
}
function spawnPiped(command, args, env) {
  return spawn(command, args, {
    env,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    // POSIX: a process group of its own, so that a stop reaches what git started.
    detached: process.platform !== "win32"
  });
}
function stopPlainTree(child) {
  const pid = child.pid;
  if (pid === void 0) return;
  if (process.platform === "win32") {
    const root = envValue2(process.env, "SystemRoot") ?? "C:/Windows";
    const killer = spawn(join4(root, "System32", "taskkill.exe"), ["/T", "/F", "/PID", String(pid)], {
      windowsHide: true,
      stdio: "ignore"
    });
    const last = () => {
      child.kill("SIGKILL");
    };
    killer.on("exit", last);
    killer.on("error", last);
    return;
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}
function setVar(env, name, value, platform) {
  for (const other of Object.keys(env)) if (other !== name && sameName(other, name, platform)) delete env[other];
  env[name] = value;
}
function envValue2(env, name, platform = process.platform) {
  for (const key of Object.keys(env)) if (sameName(key, name, platform)) return env[key];
  return void 0;
}
function sameName(a, b, platform) {
  return platform === "win32" ? a.toUpperCase() === b.toUpperCase() : a === b;
}
function firstLine(text) {
  return text.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim() ?? "";
}

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
  registryDir: () => registryDir
});
import { randomBytes } from "node:crypto";
import {
  closeSync as closeSync3,
  constants as constants4,
  fstatSync as fstatSync3,
  lstatSync as lstatSync5,
  openSync as openSync3,
  readdirSync as readdirSync2,
  readSync as readSync3,
  renameSync as renameSync2,
  rmSync,
  writeFileSync
} from "node:fs";
import { join as join7 } from "node:path";

// src/platform/projectPath.ts
import { existsSync, realpathSync as realpathSync2, statSync as statSync2 } from "node:fs";
import { parse as parse3, resolve as resolve4 } from "node:path";
function canonicalPath(p) {
  const resolved = resolve4(p);
  let canonical = resolved;
  try {
    canonical = realpathSync2.native(resolved);
  } catch {
  }
  if (process.platform === "win32") {
    if (canonical.startsWith("\\\\") && !resolved.startsWith("\\\\")) canonical = resolved;
    canonical = canonical.replace(/\//g, "\\").replace(/^([a-z]):/, (_m, drive) => `${drive.toUpperCase()}:`);
  }
  return canonical;
}

// src/storage/userData.ts
import { chmodSync, lstatSync as lstatSync4, mkdirSync as mkdirSync2, statSync as statSync3 } from "node:fs";
import { join as join6 } from "node:path";

// src/hooks/userDataDir.ts
import { homedir } from "node:os";
import { isAbsolute as isAbsolute3, join as join5, resolve as resolve5 } from "node:path";
function userDataDir(ctx = {}) {
  const env = ctx.env ?? process.env;
  const override = env["GUARDIAN_DATA_DIR"]?.trim();
  if (override !== void 0 && override !== "") return resolve5(override);
  const home = () => ctx.home ?? homedir();
  if ((ctx.platform ?? process.platform) === "win32") {
    const local = env["LOCALAPPDATA"]?.trim();
    return join5(local !== void 0 && isAbsolute3(local) ? local : join5(home(), "AppData", "Local"), "dev-guardian");
  }
  const xdg = env["XDG_DATA_HOME"]?.trim();
  return join5(xdg !== void 0 && isAbsolute3(xdg) ? xdg : join5(home(), ".local", "share"), "dev-guardian");
}

// src/storage/dbError.ts
var GuardianDbError = class extends Error {
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

// src/storage/userData.ts
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
    return follow ? statSync3(path) : lstatSync4(path);
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
  const dir = join6(parent, name);
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

// src/storage/dbRegistry.ts
var DB_ID_SHAPE = /^[0-9a-f]{32}$/;
var DB_ID_KEY = "db_id";
function newDbId() {
  return randomBytes(16).toString("hex");
}
function registryDir() {
  return join7(userDataDir(), "registry");
}
function lookupDbId(id) {
  if (!DB_ID_SHAPE.test(id)) return null;
  const path = join7(registryDir(), `${id}.json`);
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
    names = readdirSync2(registryDir());
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
    if (!lstatSync5(dbPath).isFile()) return "none";
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
    readdirSync2(registryDir());
  } catch (error) {
    return error.code === "ENOENT" ? "unregistered" : "unknown";
  }
  return findEntryForDbPath(canonical) !== null ? "registered" : "unregistered";
}
function registerDbId(entry) {
  if (!DB_ID_SHAPE.test(entry.db_id)) throw new Error(`not a database id: ${entry.db_id}`);
  const dir = ensurePrivateSubdir("registry");
  const target = join7(dir, `${entry.db_id}.json`);
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
    rmSync(join7(registryDir(), `${id}.json`), { force: true });
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

// src/hooks/distCheck.ts
var distCheck_exports = {};
__export(distCheck_exports, {
  engineDamage: () => engineDamage
});
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join as join8 } from "node:path";
function builtDigest() {
  return typeof define_GUARDIAN_ENGINE_DIGEST_default === "undefined" ? void 0 : define_GUARDIAN_ENGINE_DIGEST_default;
}
function engineDamage(distDir, expected = builtDigest()) {
  let bytes;
  try {
    bytes = readFileSync(join8(distDir, "engine.js"));
  } catch (err) {
    return err.code === "ENOENT" ? "missing" : "unreadable";
  }
  if (expected === void 0) return null;
  if (bytes.length !== expected.bytes) return `damaged (${bytes.length} bytes, where the build wrote ${expected.bytes})`;
  if (createHash("sha256").update(bytes).digest("hex") !== expected.sha256) return "damaged (its content is not what the build wrote)";
  return null;
}
export {
  dbRegistry_exports as dbRegistry,
  distCheck_exports as distCheck,
  gitSafety_exports as gitSafety
};
