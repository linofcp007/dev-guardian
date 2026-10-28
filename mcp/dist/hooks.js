import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/hooks/configFile.ts
var configFile_exports = {};
__export(configFile_exports, {
  MAX_HOOK_CONFIG_BYTES: () => MAX_HOOK_CONFIG_BYTES,
  climbsOut: () => climbsOut,
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
import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync, statSync } from "node:fs";
import { isAbsolute, join, parse, relative, resolve } from "node:path";
var MAX_HOOK_CONFIG_BYTES = 64 * 1024;
var OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);
var MAX_LINK_HOPS = 32;
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
  try {
    if (!statSync(path).isFile()) return { status: "refused", reason: "not-a-regular-file" };
  } catch (e) {
    const code = e.code;
    if (code === "ENOENT" || code === "ENOTDIR") return { status: "absent" };
  }
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
    const walk = walkLinksUnder(under, path);
    if (!walk.ok) return { status: "refused", reason: walk.reason };
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
    const walk = walkLinksUnder(under, path);
    if (!walk.ok) return { status: "refused", reason: walk.reason };
  }
  return readText(path, maxBytes);
}
function readSmallTextFile(path, maxBytes, under) {
  const r = readSmallText(path, maxBytes, under);
  return r.status === "ok" ? r.text : void 0;
}

// src/hooks/guardedPath.ts
var guardedPath_exports = {};
__export(guardedPath_exports, {
  fileIdentity: () => fileIdentity,
  guardedPath: () => guardedPath,
  hardLinkedTo: () => hardLinkedTo,
  windowsName: () => windowsName
});
import { realpathSync, statSync as statSync2 } from "node:fs";
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
    const s = statSync2(abs, { bigint: true });
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

// src/hooksEntry.ts
var loadConfigFile = async () => configFile_exports;
var loadGuardedPath = async () => guardedPath_exports;
var loadBashGuard = async () => (await import("./hooksBash.js")).bashGuard;
var loadInstallGate = async () => (await import("./hooksBash.js")).installGate;
var loadInstallVetting = async () => (await import("./hooksVet.js")).installVetting;
var loadSecretScan = async () => (await import("./hooksWrite.js")).secretScan;
var loadSettingsGuard = async () => (await import("./hooksWrite.js")).settingsGuard;
var loadDataRegistry = async () => (await import("./hooksWrite.js")).dataRegistry;
var loadGitSafety = async () => (await import("./hooksSession.js")).gitSafety;
var loadDbRegistry = async () => (await import("./hooksSession.js")).dbRegistry;
var loadDistCheck = async () => (await import("./hooksSession.js")).distCheck;
export {
  loadBashGuard,
  loadConfigFile,
  loadDataRegistry,
  loadDbRegistry,
  loadDistCheck,
  loadGitSafety,
  loadGuardedPath,
  loadInstallGate,
  loadInstallVetting,
  loadSecretScan,
  loadSettingsGuard
};
