import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/pkgvet/hookDecision.ts
var hookDecision_exports = {};
__export(hookDecision_exports, {
  COULD_NOT_VET: () => COULD_NOT_VET,
  DEFAULT_DEADLINE_MS: () => DEFAULT_DEADLINE_MS,
  MAX_DEADLINE_MS: () => MAX_DEADLINE_MS,
  MAX_MANIFEST_PACKAGES: () => MAX_MANIFEST_PACKAGES,
  MAX_VETTED_PACKAGES: () => MAX_VETTED_PACKAGES,
  NOT_VERIFIED: () => NOT_VERIFIED,
  decideInstallCommand: () => decideInstallCommand,
  escapeHatch: () => escapeHatch,
  vetDeadlineMs: () => vetDeadlineMs
});
import { lstatSync as lstatSync3, realpathSync, statSync as statSync2 } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { basename as basename2, dirname as dirname4, isAbsolute as isAbsolute3, join as join5, parse as parse4, relative as relative3, resolve as resolve4, sep } from "node:path";

// src/hooks/configFile.ts
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
function readSmallText(path, maxBytes, under) {
  if (under !== void 0) {
    const walk2 = walkLinksUnder(under, path);
    if (!walk2.ok) return { status: "refused", reason: walk2.reason };
  }
  return readText(path, maxBytes);
}

// src/platform/boundedJson.ts
var JSON_MAX_NODES = 2e6;
function exceedsCount(text, codes, max) {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    if (codes.has(text.charCodeAt(i))) {
      n += 1;
      if (n > max) return true;
    }
  }
  return false;
}
var JSON_NODE_CHARS = /* @__PURE__ */ new Set([123, 91, 44]);
function parseJsonBounded(text, maxNodes = JSON_MAX_NODES) {
  if (exceedsCount(text, JSON_NODE_CHARS, maxNodes)) return { ok: false, reason: "too-complex" };
  try {
    return { ok: true, value: JSON.parse(text.charCodeAt(0) === 65279 ? text.slice(1) : text) };
  } catch (e) {
    return { ok: false, reason: "invalid", detail: e instanceof Error ? e.message : String(e) };
  }
}

// src/pkgvet/versions.ts
var POST_REST = /^[-._]?(?:post|rev|r|p|patch|pl)[-._]?\d*$/i;
var DEV_REST = /(?:^|[-._])dev/i;
function parse2(version) {
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
  const pa = parse2(a);
  const pb = parse2(b);
  if (pa === null || pb === null) return pa === null ? pb === null ? 0 : -1 : 1;
  const r = compareRelease(pa.release, pb.release);
  if (r !== 0) return r;
  if (pa.stage !== pb.stage) return pa.stage - pb.stage;
  return compareRest(pa.rest, pb.rest);
}
function isPrerelease(version) {
  const p = parse2(version);
  return p === null || p.stage < 2;
}
var gte = (x) => (v) => compareVersions(v, x) >= 0;
var gt = (x) => (v) => compareVersions(v, x) > 0;
var lt = (x) => (v) => compareVersions(v, x) < 0;
var lte = (x) => (v) => compareVersions(v, x) <= 0;
var eq = (x) => (v) => compareVersions(v, x) === 0;
var ANY = () => true;
var WILD = /^[xX*]$/;
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
var fmt = (nums) => [0, 1, 2].map((i) => nums[i] ?? 0).join(".");
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
var COMPARATOR = /^(\^|~>|~|>=|<=|>|<|==|=|!=)?\s*(.*)$/;
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
var PEP440 = /^\s*(~=|===|==|!=|<=|>=|<|>)\s*([^\s,]+)\s*$/;
function pep440Range(range) {
  const preds = [];
  for (const spec2 of range.split(",")) {
    if (spec2.trim() === "") continue;
    const m = PEP440.exec(spec2);
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
        const p = parse2(v);
        return p !== null && prefix.nums.every((n, i) => (p.release[i] ?? 0) === n);
      };
      if (op === "==") preds.push(inPrefix);
      else if (op === "!=") preds.push((v) => !inPrefix(v));
      else return null;
      continue;
    }
    if (parse2(ver) === null) return null;
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
        const p = parse2(ver);
        if (p === null || p.release.length < 2) return null;
        const prefix = p.release.slice(0, -1);
        preds.push(gte(ver), (v) => {
          const q = parse2(v);
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
  if (m === null) return parse2(r) === null ? null : [[eq(r)]];
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
var EXACT_SEMVER = /^[vV=]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
function isExactVersion(ecosystem, range) {
  if (range === void 0) return false;
  const r = range.trim();
  switch (ecosystem) {
    case "npm":
      return EXACT_SEMVER.test(r);
    case "pypi":
      return /^(?:===?)\s*[^*,<>=!~\s]+$/.test(r) || /^\d/.test(r) && parse2(r) !== null && !/[,<>=!~*]/.test(r);
    case "packagist":
      return /^[vV]?\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.]+)?$/.test(r);
    case "nuget":
      return parse2(r) !== null && !/[[\](),]/.test(r);
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

// src/pkgvet/lockfile.ts
var LOCKFILES = {
  npm: ["npm-shrinkwrap.json", "package-lock.json"],
  pnpm: ["pnpm-lock.yaml"],
  yarn: ["yarn.lock"],
  bun: ["bun.lock"]
};
function lockFormat(fileName) {
  switch (fileName) {
    case "package-lock.json":
    case "npm-shrinkwrap.json":
      return "package-lock";
    case "pnpm-lock.yaml":
      return "pnpm-lock";
    case "yarn.lock":
      return "yarn-lock";
    case "bun.lock":
      return "bun-lock";
    default:
      return null;
  }
}
function readLock(format, text) {
  switch (format) {
    case "package-lock":
      return readPackageLock(text);
    case "pnpm-lock":
      return readPnpm(text);
    case "yarn-lock":
      return readYarn(text);
    case "bun-lock":
      return readBun(text);
  }
}
var MAX_LINE = 65536;
var MAX_NAME = 214;
var MAX_VERSION = 256;
var MAX_HOST = 80;
var PUBLIC_HOSTS = /* @__PURE__ */ new Set(["registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"]);
var NAME = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;
var VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
var DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
function validName(name) {
  return name.length <= MAX_NAME && NAME.test(name);
}
function validVersion(version) {
  return version.length <= MAX_VERSION && VERSION.test(version) && isExactVersion("npm", version);
}
function makePin(name, version) {
  return validName(name) && validVersion(version) ? { name, version } : void 0;
}
function dnsName(host) {
  const lower = host.toLowerCase();
  if (lower.length === 0 || lower.length > MAX_HOST) return "";
  for (const label3 of lower.split(".")) if (!DNS_LABEL.test(label3)) return "";
  return lower;
}
function satisfies(range, version) {
  try {
    return resolveVersion("npm", range, { versions: [version] }) === version;
  } catch {
    return false;
  }
}
var has = (o, key) => Object.prototype.hasOwnProperty.call(o, key);
var isRecord = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var splitLines = (text) => text.split(/\r\n|\r|\n/);
var SEPARATOR = /[\u0085\u2028\u2029]/;
function unquote(s) {
  if (s.length >= 2 && (s.startsWith("'") || s.startsWith('"')) && s.endsWith(s.charAt(0))) return s.slice(1, -1);
  return s;
}
var LOCAL_SPEC = /^(?:file:|link:|workspace:|portal:|patch:)/i;
var GIT_SPEC = /^(?:git\+|git:|git@|github:|gitlab:|bitbucket:|gist:|ssh:)/i;
var UNSAFE_URL = /[\u0000-\u0020\u007f-\u009f\u2028\u2029]/;
var UNKNOWN_ELSEWHERE = { source: { kind: "elsewhere", host: "", url: "" }, named: void 0 };
function gitHost(spec2) {
  if (spec2.startsWith("github:")) return "github.com";
  if (spec2.startsWith("gitlab:")) return "gitlab.com";
  if (spec2.startsWith("bitbucket:")) return "bitbucket.org";
  if (spec2.startsWith("gist:")) return "gist.github.com";
  if (spec2.startsWith("git@")) {
    const colon = spec2.indexOf(":");
    return dnsName(spec2.slice(4, colon < 0 ? void 0 : colon));
  }
  try {
    return dnsName(new URL(spec2.startsWith("git+") ? spec2.slice(4) : spec2).hostname);
  } catch {
    return "";
  }
}
function archivePair(pathname) {
  if (!pathname.endsWith(".tgz")) return void 0;
  const cut = pathname.lastIndexOf("/-/");
  if (cut < 0) return void 0;
  const file = pathname.slice(cut + 3, -4);
  if (file.includes("/")) return void 0;
  const before = pathname.slice(0, cut);
  const lastSlash = before.lastIndexOf("/");
  let name = before.slice(lastSlash + 1).replace(/%2f/gi, "/");
  if (lastSlash > 0) {
    const scopeStart = before.lastIndexOf("/", lastSlash - 1);
    const scope = before.slice(scopeStart + 1, lastSlash);
    if (scope.startsWith("@") && !name.startsWith("@")) name = `${scope}/${name}`;
  }
  const bare = name.slice(name.lastIndexOf("/") + 1);
  if (!file.startsWith(`${bare}-`)) return void 0;
  return makePin(name, file.slice(bare.length + 1));
}
function locate(spec2) {
  if (spec2.length === 0 || spec2.length > MAX_LINE) return "bad";
  if (spec2.startsWith("//")) return UNSAFE_URL.test(spec2) ? "bad" : { source: { kind: "elsewhere", host: "", url: spec2 }, named: void 0 };
  if (LOCAL_SPEC.test(spec2) || spec2.startsWith("/") || spec2.startsWith("./") || spec2.startsWith("../")) return "local";
  if (UNSAFE_URL.test(spec2)) return "bad";
  if (GIT_SPEC.test(spec2)) return { source: { kind: "git", host: gitHost(spec2) }, named: void 0 };
  let url;
  try {
    url = new URL(spec2);
  } catch {
    return "bad";
  }
  const host = dnsName(url.hostname);
  const web = url.protocol === "https:" || url.protocol === "http:";
  if (!web || url.hostname === "codeload.github.com" || url.pathname.endsWith(".git")) return { source: { kind: "git", host }, named: void 0 };
  const isPublic2 = url.protocol === "https:" && PUBLIC_HOSTS.has(url.hostname) && url.username === "" && url.password === "" && url.port === "";
  return { source: isPublic2 ? { kind: "public" } : { kind: "elsewhere", host, url: spec2 }, named: archivePair(url.pathname) };
}
var newAcc = () => ({ entries: [], seen: /* @__PURE__ */ new Set(), local: 0, unrecognised: 0 });
function sourceKey(source) {
  switch (source.kind) {
    case "elsewhere":
      return `elsewhere\0${source.host}\0${source.url}`;
    case "git":
      return `git\0${source.host}`;
    default:
      return source.kind;
  }
}
function emit(acc, pin, located) {
  const source = located === void 0 ? { kind: "unstated" } : located.source;
  if (source.kind === "public" && located?.named === void 0) acc.unrecognised += 1;
  const named = located?.named;
  const fetched = named !== void 0 && (pin === void 0 || named.name !== pin.name || named.version !== pin.version) ? named : void 0;
  const key = `${pin === void 0 ? "" : `${pin.name}@${pin.version}`}\0${sourceKey(source)}\0${fetched === void 0 ? "" : `${fetched.name}@${fetched.version}`}`;
  if (acc.seen.has(key)) return;
  acc.seen.add(key);
  const entry = { source };
  if (pin !== void 0) entry.pin = pin;
  if (fetched !== void 0) entry.fetched = fetched;
  acc.entries.push(entry);
}
function finish(acc, pin, spec2) {
  if (spec2 === void 0) {
    if (pin !== void 0) emit(acc, pin, void 0);
    return;
  }
  const where = locate(spec2);
  if (where === "local") {
    acc.local += 1;
  } else if (where === "bad") {
    acc.unrecognised += 1;
    if (pin !== void 0) emit(acc, pin, UNKNOWN_ELSEWHERE);
  } else {
    emit(acc, pin, where);
  }
}
var DEPENDENCY_GROUPS = ["dependencies", "devDependencies", "optionalDependencies"];
function readPackageLock(text) {
  const parsed = parseJsonBounded(text);
  if (!parsed.ok) return { unread: parsed.reason === "invalid" ? "it is not valid JSON" : "it holds more JSON values than dev-guardian reads" };
  const doc = parsed.value;
  if (!isRecord(doc)) return { unread: "it is not a JSON object" };
  const version = doc["lockfileVersion"];
  if (version === void 0) return { unread: "it has no lockfileVersion" };
  if (version !== 1 && version !== 2 && version !== 3) return { unread: "its lockfileVersion is not 1, 2 or 3" };
  const acc = newAcc();
  readPackagesTree(acc, doc["packages"]);
  readDependenciesTree(acc, doc["dependencies"]);
  return {
    format: "package-lock",
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    resolutionOf: (rel, name, range) => npmResolution(doc, rel, name, range)
  };
}
function readPackagesTree(acc, packages) {
  if (packages === void 0) return;
  if (!isRecord(packages)) {
    acc.unrecognised += 1;
    return;
  }
  for (const [path, entry] of Object.entries(packages)) {
    if (path === "") continue;
    if (!isRecord(entry)) {
      acc.unrecognised += 1;
      continue;
    }
    const cut = path.lastIndexOf("node_modules/");
    if (entry["link"] === true || cut < 0) {
      acc.local += 1;
      continue;
    }
    const alias = entry["name"];
    const version = entry["version"];
    const resolved = entry["resolved"];
    if (alias !== void 0 && typeof alias !== "string" || typeof resolved === "string" && resolved.length > MAX_LINE) {
      acc.unrecognised += 1;
      continue;
    }
    const pin = typeof version === "string" ? makePin(alias ?? path.slice(cut + "node_modules/".length), version) : void 0;
    const where = typeof resolved === "string" && resolved !== "" ? resolved : void 0;
    if (pin === void 0) {
      if (where !== void 0 && locate(where) === "local") acc.local += 1;
      else acc.unrecognised += 1;
      continue;
    }
    finish(acc, pin, where);
  }
}
function readDependenciesTree(acc, tree) {
  if (tree === void 0) return;
  if (!isRecord(tree)) {
    acc.unrecognised += 1;
    return;
  }
  const stack = [Object.entries(tree)[Symbol.iterator]()];
  for (let top = stack[stack.length - 1]; top !== void 0; top = stack[stack.length - 1]) {
    const next = top.next();
    if (next.done === true) {
      stack.pop();
      continue;
    }
    const [name, entry] = next.value;
    if (!isRecord(entry)) {
      acc.unrecognised += 1;
      continue;
    }
    treeEntry(acc, name, entry);
    const nested = entry["dependencies"];
    if (nested === void 0) continue;
    if (isRecord(nested)) stack.push(Object.entries(nested)[Symbol.iterator]());
    else acc.unrecognised += 1;
  }
}
function treeEntry(acc, key, entry) {
  const version = entry["version"];
  const resolved = entry["resolved"];
  if (typeof version !== "string" || version.length > MAX_LINE || typeof resolved === "string" && resolved.length > MAX_LINE) {
    acc.unrecognised += 1;
    return;
  }
  const where = typeof resolved === "string" && resolved !== "" ? resolved : void 0;
  let name = key;
  let exact = version;
  if (version.startsWith("npm:")) {
    const rest = version.slice("npm:".length);
    const at = rest.lastIndexOf("@");
    if (at <= 0) {
      acc.unrecognised += 1;
      return;
    }
    name = rest.slice(0, at);
    exact = rest.slice(at + 1);
  } else if (!validVersion(version)) {
    finish(acc, void 0, version);
    return;
  }
  const pin = makePin(name, exact);
  if (pin === void 0) acc.unrecognised += 1;
  else finish(acc, pin, where);
}
function npmResolution(doc, rel, name, range) {
  const packages = doc["packages"];
  if (!validName(name) || !isRecord(packages) || !has(packages, rel)) return null;
  const project = packages[rel];
  if (!isRecord(project)) return null;
  const recorded = DEPENDENCY_GROUPS.some((g) => {
    const group = project[g];
    return isRecord(group) && has(group, name) && group[name] === range;
  });
  if (!recorded) return null;
  for (let dir = rel; ; dir = dir.slice(0, Math.max(dir.lastIndexOf("/"), 0))) {
    const key = `${dir === "" ? "" : `${dir}/`}node_modules/${name}`;
    if (has(packages, key)) {
      const entry = packages[key];
      const pinned = isRecord(entry) && entry["link"] !== true ? entry["version"] : void 0;
      return typeof pinned === "string" && validVersion(pinned) && satisfies(range, pinned) ? pinned : null;
    }
    if (dir === "") return null;
  }
}
var SECTION_NAME = /^[A-Za-z][A-Za-z0-9_-]*$/;
var PNPM_VERSION_LINE = /^lockfileVersion: ['"]?(\d+)(?:\.\d+)?['"]?$/;
var PLAIN_KEY = /^[^\s'":&*!|>{[?#,%@`-]\S*$/;
function pnpmFrame(lines) {
  let major = -1;
  let keys = 0;
  let packages = 0;
  let snapshots = 0;
  for (const line of lines) {
    const first = line.charCodeAt(0);
    if (line.length === 0 || first === 32 || first === 9) continue;
    if (line.length > MAX_LINE) return { unread: "a line at column 0 is longer than 65 536 characters" };
    if (first === 35 || line === "---" && keys === 0) continue;
    const colon = line.indexOf(":");
    const name = colon > 0 ? line.slice(0, colon) : "";
    if (!SECTION_NAME.test(name)) return { unread: "a line at column 0 is not a `name:` section" };
    keys += 1;
    if (name === "lockfileVersion") {
      const m = PNPM_VERSION_LINE.exec(line);
      if (m === null || major !== -1) return { unread: "its lockfileVersion line is not in the form pnpm writes" };
      major = Number(m[1]);
    } else if (name === "packages" || name === "snapshots") {
      if (line.trimEnd() !== `${name}:`) return { unread: `its \`${name}:\` section has something on its own line` };
      if ((name === "packages" ? packages += 1 : snapshots += 1) > 1) return { unread: `it has more than one \`${name}:\` section` };
    }
  }
  if (major === -1) return { unread: "it has no lockfileVersion line" };
  if (major !== 5 && major !== 6 && major !== 9) return { unread: "its lockfileVersion is not 5, 6 or 9" };
  return { major };
}
function pnpmKeyOf(rest) {
  let s = rest.trimEnd();
  if (s.endsWith(" {}")) s = s.slice(0, -3);
  if (!s.endsWith(":")) return null;
  s = s.slice(0, -1);
  if (s.length === 0) return null;
  const quote = s.charAt(0);
  if (quote === "'") return s.length > 2 && s.endsWith("'") && !s.slice(1, -1).includes("'") ? s.slice(1, -1) : null;
  if (quote === '"') return s.length > 2 && s.endsWith('"') && !/["\\]/.test(s.slice(1, -1)) ? s.slice(1, -1) : null;
  return PLAIN_KEY.test(s) ? s : null;
}
function pnpmKeyPair(key, v5) {
  const bare = key.startsWith("/") ? key.slice(1) : key;
  let name;
  let rest;
  if (v5) {
    let slash = bare.indexOf("/");
    if (bare.startsWith("@") && slash >= 0) slash = bare.indexOf("/", slash + 1);
    if (slash < 0) return "other";
    name = bare.slice(0, slash);
    rest = bare.slice(slash + 1);
  } else {
    const at = bare.indexOf("@", 1);
    if (at < 0) return "other";
    name = bare.slice(0, at);
    rest = bare.slice(at + 1);
  }
  const suffix = rest.indexOf(v5 ? "_" : "(");
  const version = suffix < 0 ? rest : rest.slice(0, suffix);
  const digit = version.charCodeAt(0);
  if (!(digit >= 48 && digit <= 57)) return "other";
  return makePin(name, version) ?? "invalid";
}
function parsePnpmResolution(body) {
  const t = body.trimEnd();
  if (!t.startsWith("resolution: {") || !t.endsWith("}")) return void 0;
  const out = {};
  for (const field of t.slice("resolution: {".length, -1).split(", ")) {
    const at = field.indexOf(": ");
    if (at < 0) continue;
    const value = unquote(field.slice(at + 2));
    switch (field.slice(0, at)) {
      case "tarball":
        out.tarball ??= value;
        break;
      case "repo":
        out.repo ??= value;
        break;
      case "commit":
        out.commit ??= value;
        break;
      case "directory":
        out.directory ??= value;
        break;
      default:
    }
  }
  return out;
}
function finishPnpmEntry(acc, v5, e) {
  if (e.resolution === "broken") return;
  if (e.section === "packages" && e.resolution === void 0) {
    acc.unrecognised += 1;
    return;
  }
  const res = e.resolution;
  if (res?.directory !== void 0) {
    acc.local += 1;
    return;
  }
  const pair = pnpmKeyPair(e.key, v5);
  if (e.section === "snapshots") {
    if (pair === "invalid") acc.unrecognised += 1;
    else if (pair !== "other") finish(acc, pair, void 0);
    return;
  }
  const git = res?.repo !== void 0 || res?.commit !== void 0 ? { source: { kind: "git", host: gitHost(res.repo ?? "") }, named: void 0 } : void 0;
  const pin = pair === "other" ? e.name !== void 0 && e.version !== void 0 ? makePin(e.name, e.version) : void 0 : pair === "invalid" ? void 0 : pair;
  if (pair === "invalid") {
    acc.unrecognised += 1;
  } else if (res?.tarball !== void 0) {
    finish(acc, pin, res.tarball);
  } else if (git !== void 0) {
    emit(acc, pin, git);
  } else if (pair === "other") {
    acc.unrecognised += 1;
  } else {
    finish(acc, pin, void 0);
  }
}
function readPnpmBody(acc, e, body) {
  if (body.startsWith("resolution:")) {
    if (e.resolution !== void 0) {
      acc.unrecognised += 1;
      return;
    }
    const parsed = parsePnpmResolution(body);
    if (parsed === void 0) acc.unrecognised += 1;
    e.resolution = parsed ?? "broken";
  } else if (body.startsWith("name: ")) {
    e.name ??= unquote(body.slice("name: ".length).trimEnd());
  } else if (body.startsWith("version: ")) {
    e.version ??= unquote(body.slice("version: ".length).trimEnd());
  }
}
function readPnpm(text) {
  const lines = splitLines(text);
  const frame = pnpmFrame(lines);
  if ("unread" in frame) return frame;
  const v5 = frame.major === 5;
  const acc = newAcc();
  let section = "";
  const state = { cur: null };
  const close = () => {
    const cur = state.cur;
    state.cur = null;
    if (cur !== null && cur !== "skip") finishPnpmEntry(acc, v5, cur);
  };
  const odd = SEPARATOR.test(text);
  for (const line of lines) {
    if (line.length === 0) continue;
    if (odd && SEPARATOR.test(line)) {
      acc.unrecognised += 1;
      continue;
    }
    const first = line.charCodeAt(0);
    if (first !== 32 && first !== 9) {
      if (first === 35 || line === "---") continue;
      close();
      const name = line.slice(0, line.indexOf(":"));
      section = name === "packages" || name === "snapshots" ? name : "";
      continue;
    }
    if (section === "") continue;
    if (line.length > MAX_LINE) {
      acc.unrecognised += 1;
      continue;
    }
    let indent = 0;
    while (line.charCodeAt(indent) === 32) indent += 1;
    if (indent === line.length) continue;
    const head = line.charCodeAt(indent);
    if (head === 9) {
      acc.unrecognised += 1;
    } else if (head === 35) {
    } else if (indent === 2) {
      close();
      const key = pnpmKeyOf(line.slice(2));
      if (key === null) {
        acc.unrecognised += 1;
        state.cur = "skip";
      } else {
        state.cur = { section, key };
      }
    } else if (indent === 1 || indent === 3) {
      acc.unrecognised += 1;
    } else if (state.cur === null) {
      acc.unrecognised += 1;
    } else if (state.cur !== "skip" && indent === 4 && section === "packages") {
      readPnpmBody(acc, state.cur, line.slice(4));
    }
  }
  close();
  const projectOf = pnpmProjects(lines, v5);
  return {
    format: "pnpm-lock",
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    resolutionOf: (rel, name, range) => pnpmResolution(projectOf(rel), v5, name, range)
  };
}
var PNPM_GROUPS = /* @__PURE__ */ new Set(["dependencies", "devDependencies", "optionalDependencies", "specifiers"]);
function splitKeyValue(body) {
  if (body.startsWith("'")) {
    const close = body.indexOf("'", 1);
    if (close < 0 || !body.startsWith(": ", close + 1)) return null;
    return [body.slice(1, close), unquote(body.slice(close + 3).trimEnd())];
  }
  const at = body.indexOf(": ");
  return at <= 0 ? null : [body.slice(0, at), unquote(body.slice(at + 2).trimEnd())];
}
var leadingSpaces = (line) => {
  let n = 0;
  while (line.charCodeAt(n) === 32) n += 1;
  return n;
};
function readPnpmProject(lines, v5, from, to, indent) {
  const specifiers = /* @__PURE__ */ new Map();
  const versions = /* @__PURE__ */ new Map();
  let group = null;
  let current = null;
  for (let i = from; i < to; i += 1) {
    const line = lines[i] ?? "";
    const ind = leadingSpaces(line);
    if (ind === line.length || line.charCodeAt(ind) === 35 || ind < indent) continue;
    if (ind === indent) {
      const header = line.trimEnd();
      const label3 = header.endsWith(":") ? header.slice(ind, -1) : "";
      group = PNPM_GROUPS.has(label3) ? label3 : null;
      current = null;
    } else if (group === null) {
      continue;
    } else if (ind === indent + 2) {
      const body = line.slice(ind);
      current = null;
      if (v5) {
        const kv = splitKeyValue(body);
        const into = group === "specifiers" ? specifiers : versions;
        if (kv !== null && !into.has(kv[0])) into.set(kv[0], kv[1]);
      } else if (group !== "specifiers") {
        current = pnpmKeyOf(body);
      }
    } else if (ind === indent + 4 && current !== null) {
      const body = line.slice(ind).trimEnd();
      if (body.startsWith("specifier: ") && !specifiers.has(current)) specifiers.set(current, unquote(body.slice("specifier: ".length)));
      else if (body.startsWith("version: ") && !versions.has(current)) versions.set(current, unquote(body.slice("version: ".length)));
    }
  }
  return { specifiers, versions };
}
function pnpmProjects(lines, v5) {
  const importers = lines.findIndex((l) => l === "importers:");
  let ranges;
  const cache2 = /* @__PURE__ */ new Map();
  const importerRanges = () => {
    if (ranges !== void 0) return ranges;
    const found = /* @__PURE__ */ new Map();
    let open = null;
    let end = lines.length;
    for (let i = importers + 1; i < lines.length; i += 1) {
      const line = lines[i] ?? "";
      const ind = leadingSpaces(line);
      if (ind === line.length) continue;
      if (ind === 0) {
        end = i;
        break;
      }
      if (ind > 2) continue;
      if (open !== null && !found.has(open.key)) found.set(open.key, [open.from, i]);
      open = null;
      const key = ind === 2 ? pnpmKeyOf(line.slice(2)) : null;
      if (key !== null) open = { key, from: i + 1 };
    }
    if (open !== null && !found.has(open.key)) found.set(open.key, [open.from, end]);
    ranges = found;
    return found;
  };
  return (rel) => {
    if (cache2.has(rel)) return cache2.get(rel) ?? null;
    let project = null;
    if (importers < 0) {
      if (rel === "") project = readPnpmProject(lines, v5, 0, lines.length, 0);
    } else {
      const range = importerRanges().get(rel === "" ? "." : rel);
      if (range !== void 0) project = readPnpmProject(lines, v5, range[0], range[1], 4);
    }
    cache2.set(rel, project);
    return project;
  };
}
function pnpmResolution(project, v5, name, range) {
  if (project === null || !validName(name)) return null;
  const pinned = project.versions.get(name);
  if (project.specifiers.get(name) !== range || pinned === void 0) return null;
  const peers = pinned.indexOf(v5 ? "_" : "(");
  const version = peers < 0 ? pinned : pinned.slice(0, peers);
  return validVersion(version) && satisfies(range, version) ? version : null;
}
var SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
function parseDescriptor(d) {
  const at = d.indexOf("@", 1);
  if (at <= 0) return null;
  const name = d.slice(0, at);
  const range = d.slice(at + 1);
  if (!range.startsWith("npm:")) return { name, range };
  const rest = range.slice("npm:".length);
  const inner = rest.indexOf("@", 1);
  return inner > 0 ? { name: rest.slice(0, inner), range: rest.slice(inner + 1) } : { name, range: rest };
}
function splitDescriptors(inner) {
  const out = [];
  let i = 0;
  while (i < inner.length) {
    if (inner.charCodeAt(i) === 34) {
      const end = inner.indexOf('"', i + 1);
      if (end < 0) return null;
      out.push(inner.slice(i + 1, end));
      i = end + 1;
    } else {
      let end = inner.indexOf(", ", i);
      if (end < 0) end = inner.length;
      out.push(inner.slice(i, end));
      i = end;
    }
    if (i < inner.length) {
      if (!inner.startsWith(", ", i)) return null;
      i += 2;
    }
  }
  return out.length > 0 && out.every((d) => d.length > 0 && !d.includes("\\")) ? out : null;
}
function yarnField(line, berry, field) {
  const head = berry ? `  ${field}:` : `  ${field}`;
  if (!line.startsWith(head)) return void 0;
  const after = line.charCodeAt(head.length);
  if (Number.isNaN(after)) return null;
  if (after !== 32) return void 0;
  const rest = line.slice(head.length + 1).trimEnd();
  if (rest.startsWith('"')) return rest.length >= 2 && rest.endsWith('"') ? rest.slice(1, -1) : null;
  return berry && rest.length > 0 && !/\s/.test(rest) ? rest : null;
}
function yarnKey(line, next, berry) {
  if (berry) {
    let text;
    let consumed = false;
    if (line.startsWith("? ")) {
      if (next.trimEnd() !== ":") return null;
      text = line.slice(2).trim();
      consumed = true;
    } else {
      const t2 = line.trimEnd();
      if (!t2.endsWith(":")) return null;
      text = t2.slice(0, -1);
    }
    if (text === "__metadata") return { keys: [], metadata: true, consumed };
    if (text.startsWith('"')) {
      if (text.length < 2 || !text.endsWith('"')) return null;
      text = text.slice(1, -1);
    }
    return { keys: text.split(", "), metadata: false, consumed };
  }
  const t = line.trimEnd();
  if (!t.endsWith(":")) return null;
  const keys = splitDescriptors(t.slice(0, -1));
  return keys === null ? null : { keys, metadata: false, consumed: false };
}
function scanYarn(lines, odd, berry, acc, onBlock) {
  const state = { cur: null };
  const flush = () => {
    const cur = state.cur;
    state.cur = null;
    if (cur !== null && cur !== "skip" && !cur.metadata) onBlock(cur);
  };
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? "";
    if (line.length > MAX_LINE || odd && SEPARATOR.test(line)) {
      acc.unrecognised += 1;
      continue;
    }
    const first = line.charCodeAt(0);
    if (line.length === 0 || first === 35) continue;
    if (first !== 32 && first !== 9) {
      flush();
      const key = yarnKey(line, lines[i + 1] ?? "", berry);
      if (key === null) {
        acc.unrecognised += 1;
        state.cur = "skip";
        continue;
      }
      if (key.consumed) i += 1;
      state.cur = { keys: key.keys, flawed: false, metadata: key.metadata };
      continue;
    }
    const block = state.cur;
    if (block === "skip") continue;
    const trimmed = line.trimStart();
    if (trimmed.length === 0 || trimmed.charCodeAt(0) === 35) continue;
    if (block === null) {
      acc.unrecognised += 1;
      continue;
    }
    for (const field of berry ? ["version", "resolution"] : ["version", "resolved"]) {
      const value = yarnField(line, berry, field);
      if (value === void 0) continue;
      if (value === null || block[field] !== void 0) block.flawed = true;
      else block[field] = field === "resolved" ? value.split("#", 1)[0] ?? "" : value;
      break;
    }
  }
  flush();
}
function yarnClassicBlock(acc, b) {
  const counted = b.flawed || b.version === void 0;
  if (counted) acc.unrecognised += 1;
  if (b.version === void 0) return;
  const parsed = b.keys.map(parseDescriptor);
  const first = parsed[0];
  if (first === void 0 || first === null || parsed.some((p) => p === null || p.name !== first.name)) {
    if (!counted) acc.unrecognised += 1;
    return;
  }
  const where = b.resolved ?? (SCHEME.test(first.range) ? first.range : void 0);
  const pin = makePin(first.name, b.version);
  if (pin !== void 0) {
    finish(acc, pin, where);
    return;
  }
  if (where !== void 0 && locate(where) === "local") acc.local += 1;
  else if (!counted) acc.unrecognised += 1;
}
var LOCAL_BERRY = /^(?:workspace|patch|link|portal|file):/i;
function yarnBerryBlock(acc, b) {
  let counted = b.flawed;
  const note = () => {
    if (!counted) acc.unrecognised += 1;
    counted = true;
  };
  if (counted) acc.unrecognised += 1;
  const resolution = b.resolution;
  const at = resolution === void 0 ? -1 : resolution.indexOf("@", 1);
  if (resolution === void 0 || at <= 0) {
    note();
    return;
  }
  const name = resolution.slice(0, at);
  const spec2 = resolution.slice(at + 1);
  if (LOCAL_BERRY.test(spec2)) {
    acc.local += 1;
    return;
  }
  if (!spec2.startsWith("npm:")) {
    finish(acc, b.version === void 0 ? void 0 : makePin(name, b.version), spec2);
    return;
  }
  const rest = spec2.slice("npm:".length);
  const cut = rest.indexOf("::");
  const pin = makePin(name, cut < 0 ? rest : rest.slice(0, cut));
  let where;
  if (cut >= 0) {
    for (const param of rest.slice(cut + 2).split("&")) {
      if (!param.startsWith("__archiveUrl=")) continue;
      try {
        where = decodeURIComponent(param.slice("__archiveUrl=".length));
      } catch {
        note();
      }
    }
  }
  if (pin === void 0) note();
  else finish(acc, pin, where);
}
function readYarn(text) {
  const lines = splitLines(text);
  const odd = SEPARATOR.test(text);
  let berry = false;
  let classic = false;
  for (const line of lines) {
    if (line.length > 40) continue;
    const t = line.trimEnd();
    if (t === "__metadata:") berry = true;
    else if (t === "# yarn lockfile v1") classic = true;
  }
  if (berry && classic) return { unread: "it has both the header of a v1 lockfile and `__metadata:`" };
  if (!berry && !classic) return { unread: "it has neither the `# yarn lockfile v1` header nor `__metadata:`" };
  const acc = newAcc();
  scanYarn(lines, odd, berry, acc, (b) => berry ? yarnBerryBlock(acc, b) : yarnClassicBlock(acc, b));
  let index;
  const pinnedBy = () => {
    if (index !== void 0) return index;
    const map = /* @__PURE__ */ new Map();
    scanYarn(lines, odd, berry, newAcc(), (b) => {
      if (b.version === void 0 || !validVersion(b.version)) return;
      if (berry && !(b.resolution ?? "").includes("@npm:")) return;
      for (const key of b.keys) if (!map.has(key)) map.set(key, b.version);
    });
    index = map;
    return map;
  };
  return {
    format: "yarn-lock",
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    // yarn.lock lists no workspace member: found above the command's directory it covers nothing.
    resolutionOf: (rel, name, range) => {
      if (rel !== "" || !validName(name)) return null;
      const pinned = pinnedBy().get(berry ? `${name}@npm:${range}` : `${name}@${range}`);
      return pinned !== void 0 && satisfies(range, pinned) ? pinned : null;
    }
  };
}
function stringEnd(line, start) {
  for (let i = start + 1; i < line.length; i += 1) {
    const c = line.charCodeAt(i);
    if (c === 92) i += 1;
    else if (c === 34) return i;
  }
  return -1;
}
function stringAt(line, start, end) {
  const raw = line.slice(start + 1, end);
  if (!raw.includes("\\")) return raw;
  try {
    const value = JSON.parse(`"${raw}"`);
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
}
function parseBunLine(line) {
  if (!line.startsWith('    "')) return null;
  const keyEnd = stringEnd(line, 4);
  if (keyEnd < 0 || !line.startsWith(': ["', keyEnd + 1)) return null;
  const firstStart = keyEnd + 4;
  const firstEnd = stringEnd(line, firstStart);
  if (firstEnd < 0) return null;
  const first = stringAt(line, firstStart, firstEnd);
  let i = firstEnd + 1;
  let second;
  if (line.startsWith(', "', i)) {
    const end = stringEnd(line, i + 2);
    if (end < 0) return null;
    second = stringAt(line, i + 2, end) ?? void 0;
    if (second === void 0) return null;
    i = end + 1;
  }
  let depth = 1;
  let inString = false;
  for (; i < line.length && depth > 0; i += 1) {
    const c = line.charCodeAt(i);
    if (inString) {
      if (c === 92) i += 1;
      else if (c === 34) inString = false;
    } else if (c === 34) {
      inString = true;
    } else if (c === 91 || c === 123) {
      depth += 1;
    } else if (c === 93 || c === 125) {
      depth -= 1;
    }
  }
  if (first === null || depth !== 0) return null;
  const tail = line.slice(i).trim();
  return tail === "" || tail === "," ? { key: line.slice(5, keyEnd), first, second } : null;
}
function scanBun(inner, acc, onEntry) {
  const odd = SEPARATOR.test(inner);
  for (const line of splitLines(inner)) {
    if (line.length > MAX_LINE || odd && SEPARATOR.test(line)) {
      acc.unrecognised += 1;
      continue;
    }
    if (line.trim().length === 0) continue;
    const entry = parseBunLine(line);
    if (entry === null) acc.unrecognised += 1;
    else onEntry(entry);
  }
}
function bunEntry(acc, e) {
  const at = e.first.indexOf("@", 1);
  if (at <= 0) {
    acc.unrecognised += 1;
    return;
  }
  const name = e.first.slice(0, at);
  const spec2 = e.first.slice(at + 1);
  if (spec2.startsWith("workspace:")) {
    acc.local += 1;
  } else if (VERSION.test(spec2)) {
    const pin = makePin(name, spec2);
    if (pin === void 0) acc.unrecognised += 1;
    else finish(acc, pin, e.second === void 0 || e.second === "" ? void 0 : e.second);
  } else {
    finish(acc, void 0, spec2);
  }
}
var JSON_PLAIN = Array.from({ length: 128 }, (_, c) => " 	\n\r,:+-.eE0123456789".includes(String.fromCharCode(c)));
function bunFrame(text) {
  const n = text.length;
  const skipSpace = (from2) => {
    let k = from2;
    while (k < n && (text.charCodeAt(k) === 32 || text.charCodeAt(k) === 9 || text.charCodeAt(k) === 10 || text.charCodeAt(k) === 13)) k += 1;
    return k;
  };
  let i = skipSpace(text.charCodeAt(0) === 65279 ? 1 : 0);
  if (text.charCodeAt(i) !== 123) return { unread: "it is not a JSON object" };
  let depth = 0;
  let version = "";
  const seen = { version: 0, packages: 0, workspaces: 0 };
  const ranges = { packages: [-1, -1], workspaces: [-1, -1] };
  let open = null;
  for (; i < n; i += 1) {
    const c = text.charCodeAt(i);
    if (c === 34) {
      let j = i + 1;
      for (; j < n; j += 1) {
        const d = text.charCodeAt(j);
        if (d === 92) j += 1;
        else if (d === 34) break;
        else if (d === 10 || d === 13) return { unread: "a string runs over a line end" };
      }
      if (j >= n) return { unread: "a string is not closed" };
      const colon = skipSpace(j + 1);
      if (depth === 1 && text.charCodeAt(colon) === 58) {
        const key = text.slice(i + 1, j);
        if (key.includes("\\")) return { unread: "a top-level key is written with an escape" };
        const value = skipSpace(colon + 1);
        if (key === "lockfileVersion") {
          seen.version += 1;
          let end = value;
          while (end < n && text.charCodeAt(end) >= 48 && text.charCodeAt(end) <= 57) end += 1;
          const after = text.charCodeAt(skipSpace(end));
          if (end === value || after !== 44 && after !== 125) return { unread: "its lockfileVersion is not a number" };
          version = text.slice(value, end);
        } else if (key === "packages" || key === "workspaces") {
          seen[key] += 1;
          if (text.charCodeAt(value) === 123) {
            ranges[key] = [value, -1];
            open = key;
          } else if (key === "packages") {
            return { unread: 'its "packages" is not an object' };
          }
        }
      }
      i = j;
    } else if (c === 47) {
      const next = text.charCodeAt(i + 1);
      return { unread: next === 42 || next === 47 ? "it holds a comment, which bun does not write" : "it holds a character JSON does not" };
    } else if (c === 123 || c === 91) {
      depth += 1;
    } else if (c === 125 || c === 93) {
      depth -= 1;
      if (depth < 0) return { unread: "it is not complete JSON" };
      if (depth === 1 && c === 125 && open !== null) {
        ranges[open][1] = i;
        open = null;
      }
    } else if (c === 116 || c === 102 || c === 110) {
      const word = c === 116 ? "true" : c === 102 ? "false" : "null";
      if (!text.startsWith(word, i)) return { unread: "it holds a word that is not a JSON literal" };
      i += word.length - 1;
    } else if (!JSON_PLAIN[c]) {
      return { unread: "it holds a character JSON does not" };
    }
  }
  if (depth !== 0) return { unread: "it is not complete JSON" };
  if (seen.version !== 1) return { unread: seen.version === 0 ? "it has no lockfileVersion" : "it has more than one lockfileVersion" };
  if (version !== "0" && version !== "1") return { unread: "its lockfileVersion is not 0 or 1" };
  if (seen.packages !== 1) return { unread: seen.packages === 0 ? 'it has no "packages" object' : 'it has more than one "packages" object' };
  const [from, to] = ranges.packages;
  const [wFrom, wTo] = ranges.workspaces;
  return { version, packages: text.slice(from + 1, to), workspaces: seen.workspaces === 1 && wFrom >= 0 && wTo >= 0 ? text.slice(wFrom, wTo + 1) : "" };
}
function readBun(text) {
  const frame = bunFrame(text);
  if ("unread" in frame) return frame;
  const acc = newAcc();
  scanBun(frame.packages, acc, (e) => bunEntry(acc, e));
  let hoistedIndex;
  const hoisted = () => {
    if (hoistedIndex !== void 0) return hoistedIndex;
    const map = /* @__PURE__ */ new Map();
    scanBun(frame.packages, newAcc(), (e) => {
      const at = e.first.indexOf("@", 1);
      if (at > 0 && e.first.slice(0, at) === e.key && validName(e.key) && validVersion(e.first.slice(at + 1)) && !map.has(e.key)) map.set(e.key, e.first.slice(at + 1));
    });
    hoistedIndex = map;
    return map;
  };
  let recordedIndex;
  const recorded = () => recordedIndex ??= bunRecords(frame.workspaces);
  return {
    format: "bun-lock",
    entries: acc.entries,
    local: acc.local,
    unrecognised: acc.unrecognised,
    resolutionOf: (rel, name, range) => {
      if (!validName(name) || recorded().get(`${rel}\0${name}`)?.has(range) !== true) return null;
      const pinned = hoisted().get(name);
      return pinned !== void 0 && satisfies(range, pinned) ? pinned : null;
    }
  };
}
function bunMember(line, indent) {
  if (!line.startsWith(`${" ".repeat(indent)}"`)) return null;
  const end = stringEnd(line, indent);
  const key = end < 0 ? null : stringAt(line, indent, end);
  return key === null ? null : { key, rest: line.slice(end + 1) };
}
function bunRecords(workspaces) {
  const index = /* @__PURE__ */ new Map();
  let project = null;
  let inGroup = false;
  for (const raw of splitLines(workspaces).slice(1)) {
    const line = raw.trimEnd();
    if (project === null) {
      const m = bunMember(line, 4);
      project = m !== null && m.rest === ": {" ? m.key : null;
    } else if (!inGroup) {
      if (line === "    }" || line === "    },") project = null;
      else inGroup = DEPENDENCY_GROUPS.some((g) => line === `      "${g}": {`);
    } else if (line === "      }" || line === "      },") {
      inGroup = false;
    } else {
      const m = bunMember(line, 8);
      if (m === null || !m.rest.startsWith(': "')) continue;
      const end = stringEnd(m.rest, 2);
      const range = end < 0 ? null : stringAt(m.rest, 2, end);
      const tail = m.rest.slice(end + 1);
      if (range === null || tail !== "" && tail !== ",") continue;
      const key = `${project}\0${m.key}`;
      const set2 = index.get(key) ?? /* @__PURE__ */ new Set();
      set2.add(range);
      index.set(key, set2);
    }
  }
  return index;
}

// src/pkgvet/manifest.ts
import { dirname, resolve as resolve2 } from "node:path";

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
function handsScript(word) {
  if (word === void 0 || word.quoted) return false;
  return /^-[A-Za-z]*c$/.test(word.value) || word.value === "--command" || word.value.startsWith("--command=");
}
function longNames(option, names) {
  const name = option.slice(2).replace(/=.*$/s, "");
  return name !== "" && names.some((n) => n.startsWith(name));
}
function flockLockFile(words, from) {
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v === "--") return i + 1;
    if (!v.startsWith("-") || v === "-") return i;
    const valued = v.startsWith("--") ? !v.includes("=") && longNames(v, ["timeout", "wait", "conflict-exit-code"]) : /[wE]$/.test(v);
    if (valued) i += 1;
  }
  return words.length;
}
function flockCommand(words, from) {
  const file = flockLockFile(words, from);
  for (let i = from; i < file; i += 1) if (handsScript(words[i])) return void 0;
  const command = file + 1;
  return command >= words.length || handsScript(words[command]) ? void 0 : command;
}
var RUNUSER_VALUED = { short: "gGsuw", long: ["group", "supp-group", "shell", "user", "whitelist-environment"] };
function runuserCommand(words, from) {
  let user = false;
  let i = from;
  for (; i < words.length; i += 1) {
    const word = words[i];
    const v = word?.value ?? "";
    if (v === "--") return i + 1 < words.length ? i + 1 : void 0;
    if (!v.startsWith("-") || v === "-") {
      if (v === "-") continue;
      break;
    }
    if (handsScript(word) || v.startsWith("--") && longNames(v, ["session-command"])) return void 0;
    if (v.startsWith("--")) {
      if (longNames(v, ["user"])) user = true;
      if (!v.includes("=") && longNames(v, RUNUSER_VALUED.long)) i += 1;
      continue;
    }
    for (let k = 1; k < v.length; k += 1) {
      const letter = v.charAt(k);
      if (letter === "c" || letter === "C") return void 0;
      if (!RUNUSER_VALUED.short.includes(letter)) continue;
      if (letter === "u") user = true;
      if (k === v.length - 1) i += 1;
      break;
    }
  }
  if (i >= words.length) return void 0;
  if (user) return i;
  for (let j = i + 1; j < words.length; j += 1) {
    if (handsScript(words[j])) return void 0;
    if (words[j]?.value === "--") return j + 1 < words.length ? j + 1 : void 0;
  }
  return void 0;
}
var CARRIERS = /* @__PURE__ */ new Map([
  ["flock", flockCommand],
  ["runuser", runuserCommand]
]);
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
    const carrier = through === void 0 || through.has(name) ? CARRIERS.get(name) : void 0;
    if (carrier !== void 0) {
      const command = carrier(words, i + 1);
      if (command === void 0) break;
      i = command;
      continue;
    }
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
  const tail = word.value.slice(at);
  const op = /^[<>]+[|&]?/.exec(tail)?.[0] ?? tail.charAt(0);
  return { prefix: word.value.slice(0, at), op, inline: tail.slice(op.length) };
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

// src/hooks/shell/paths.ts
var CD_COMMANDS = /* @__PURE__ */ new Set(["cd", "chdir", "pushd", "set-location", "sl", "push-location"]);
var CD_RETURNS = /* @__PURE__ */ new Set(["popd", "pop-location"]);
function cdOperand(args) {
  const named = psParam(args, ["path", "literalpath"]);
  if (named !== void 0) return named;
  const operands = [];
  let ended = false;
  for (const a of args) {
    if (!ended && a === "--") ended = true;
    else if (!ended && a !== "-" && (/^-[LPe@]+$/.test(a) || /^\/d$/i.test(a))) continue;
    else operands.push(a);
  }
  return operands.length > 1 ? null : operands[0];
}

// src/hooks/shell/effects.ts
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
        const lookedUp = (cdpath || prefixCdpath) && move.target !== void 0 && !/^(?:\.\.?(?:[\\/]|$)|[\\/~]|[A-Za-z]:)/.test(move.target);
        const variable = unread && move.target !== void 0 && VARIABLE_TARGET.test(move.target);
        const nextMay = back ? here.prevMay : unread && !variable ? null : moved(here.may, move.target);
        const nextSure = !surely || unread || lookedUp || move.target === void 0 ? null : back ? here.prevSure : moved(here.sure, move.target);
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
function subexpressionEnd(text, from) {
  let depth = 1;
  for (let i = from; i < text.length; i += 1) {
    const c = text.charAt(i);
    if (c === "`") i += 1;
    else if (c === "(") depth += 1;
    else if (c === ")") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}
function bracedVariableEnd(text, from) {
  for (let i = from; i < text.length; i += 1) {
    const c = text.charAt(i);
    if (c === "`") i += 1;
    else if (c === "}") return i + 1;
  }
  return text.length;
}
function expandablePieceEnd(text, i) {
  if (text.charAt(i) !== "$") return -1;
  const next = text.charAt(i + 1);
  if (next === "{") return bracedVariableEnd(text, i + 2);
  if (next !== "(") return -1;
  const end = subexpressionEnd(text, i + 2);
  return end < 0 ? text.length : end;
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
  for (let i = start; i < text.length; ) {
    if ((i === start || text.charAt(i - 1) === "\n") && closers.includes(text.charAt(i)) && text.charAt(i + 1) === "@") {
      return { body: text.slice(start, i).replace(/\r?\n$/, ""), next: i + 2 };
    }
    if (single) {
      const nl = text.indexOf("\n", i);
      if (nl < 0) break;
      i = nl + 1;
    } else if (text.charAt(i) === "`") i += 2;
    else if (text.startsWith("$(", i)) {
      const end = subexpressionEnd(text, i + 2);
      if (end < 0) break;
      i = end;
    } else i += 1;
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
var PLAIN_BRACED_VARIABLE = /^\$\{[\w:.?\\/-]*\}$/;
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
        const piece = double ? expandablePieceEnd(text, j) : -1;
        if (piece >= 0) {
          lit += text.slice(j, piece);
          j = piece;
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
    if (ch === "$" && text.charAt(i + 1) === "{") {
      const end = bracedVariableEnd(text, i + 2);
      const spelled = text.slice(i, end);
      if (!PLAIN_BRACED_VARIABLE.test(spelled)) {
        out += posixSingle(spelled);
        i = end;
        continue;
      }
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

// src/pkgvet/parseCommand.ts
var NAME_RE = {
  npm: /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-zA-Z0-9][a-zA-Z0-9._~-]*$/,
  pypi: /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/,
  packagist: /^[a-z0-9](?:[_.-]?[a-z0-9]+)*\/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]+)*$/i,
  nuget: /^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$/
};
var SHELL_EXPANSION = /[$`*?{}[\]<>|&;]/;
var URL_OR_VCS = /^(?:[a-z][a-z0-9+.-]*:\/\/|git\+|git:|hg\+|svn\+|bzr\+|github:|gitlab:|bitbucket:|gist:|file:|link:|workspace:|portal:|patch:|exec:)/i;
var NPM_FILE = /\.(?:tgz|tar\.gz|tar)$/i;
var PIP_FILE = /\.(?:zip|whl|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma)$/i;
var UV_FILE = /\.(?:zip|whl|tgz|tar\.gz|tar)$/i;
var POETRY_FILE = /\.(?:zip|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma)$/i;
var ARCHIVE = /\.(?:tgz|tar|tar\.gz|tar\.bz2|tar\.xz|zip|whl|egg|nupkg)$/i;
var UNMEASURED_FILE = /\.(?:zip|whl|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma|egg|nupkg)$/i;
var UNMEASURED = /* @__PURE__ */ new Set(["pipx", "composer", "dotnet"]);
var UNMEASURED_ARCHIVE = "a name that ends like an archive file \u2014 this package manager was not measured, so whether it reads the word as a file or as a registry name is not known";
function readsFileValue(manager, value) {
  return (manager === "npm" || manager === "npx" || manager === "bun") && NPM_FILE.test(value);
}
function fileEndings(manager, scoped) {
  switch (manager) {
    case "npm":
    case "npx":
      return scoped ? null : NPM_FILE;
    case "bun":
      return NPM_FILE;
    case "pip":
      return PIP_FILE;
    case "uv":
    case "uv-pip":
      return UV_FILE;
    case "poetry":
      return POETRY_FILE;
    default:
      return null;
  }
}
function unmeasuredReason(manager, spec2) {
  return UNMEASURED.has(manager) && spec2.name === spec2.raw && UNMEASURED_FILE.test(spec2.raw) ? UNMEASURED_ARCHIVE : void 0;
}
function isPathLike(word) {
  return word === "." || word === ".." || word.startsWith("./") || word.startsWith("../") || word.startsWith(".\\") || word.startsWith("..\\") || word.startsWith("/") || word.startsWith("~") || word.startsWith("\\") || /^[A-Za-z]:[\\/]/.test(word);
}
var SCP_GIT = /^[A-Za-z0-9._-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:/;
function notAPackage(word, archive) {
  if (word.length === 0) return "empty";
  if (SCP_GIT.test(word)) return "SSH git spec (user@host:path) \u2014 not looked up";
  if (isPathLike(word)) return "local path \u2014 not looked up";
  if (URL_OR_VCS.test(word)) return "URL / VCS / protocol spec \u2014 not looked up";
  if (archive !== null && archive.test(word)) return "archive file \u2014 not looked up";
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
function withRange(spec2, range) {
  if (!("name" in spec2)) return spec2;
  const r = range?.trim();
  return r !== void 0 && r !== "" ? { ...spec2, range: r } : spec2;
}
function parseNpm(raw, manager, alias = false) {
  if (/[$`]/.test(raw)) return skip(raw, "not a literal package name (shell expansion)");
  const scoped = raw.startsWith("@");
  const at = raw.indexOf("@", scoped ? 1 : 0);
  const bad = notAPackage(raw, at > 0 || alias ? null : fileEndings(manager, scoped));
  if (bad !== null) return skip(raw, bad);
  const name = at > 0 ? raw.slice(0, at) : raw;
  let range = at > 0 ? raw.slice(at + 1) : void 0;
  if (!scoped && name.includes("/")) return skip(raw, "GitHub shorthand (user/repo) \u2014 not looked up");
  if (range !== void 0) {
    if (/^npm:/i.test(range)) {
      const real = parseNpm(range.slice(4), manager, true);
      return "name" in real ? { ...real, raw } : skip(raw, real.reason);
    }
    const rangeBad = notAPackage(range, null);
    if (rangeBad !== null || URL_OR_VCS.test(range)) return skip(raw, rangeBad ?? "URL / VCS / protocol spec \u2014 not looked up");
    if (readsFileValue(manager, range)) return skip(raw, "archive file \u2014 not looked up");
    if (range === "latest") range = void 0;
  }
  return withRange(checkName("npm", name, raw), range);
}
var PEP440_OP = /(===|==|~=|!=|<=|>=|<|>)/;
function parsePython(raw, poetryAt, manager) {
  let text = raw.trim();
  const semi = text.indexOf(";");
  if (semi >= 0) text = text.slice(0, semi).trim();
  if (/[$`]/.test(text)) return skip(raw, "not a literal package name (shell expansion)");
  if (/\s@\s|@\s*(?:[a-z][a-z0-9+.-]*:\/\/|git\+|file:)/i.test(text)) return skip(raw, "direct URL reference \u2014 not looked up");
  const versioned = PEP440_OP.test(text) || text.indexOf("@") > 0;
  const bad = notAPackage(text, versioned ? ARCHIVE : fileEndings(manager, false));
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
  const versioned = raw.search(/[:=\s]/) > 0 || raw.includes("@") && !raw.startsWith("@");
  const bad = notAPackage(raw, versioned ? ARCHIVE : null);
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
  const bad = notAPackage(raw, raw.indexOf("@") > 0 ? ARCHIVE : null);
  if (bad !== null) return skip(raw, bad);
  const at = raw.indexOf("@");
  const name = at > 0 ? raw.slice(0, at) : raw;
  const range = at > 0 ? raw.slice(at + 1) : void 0;
  return withRange(checkName("nuget", name, raw), range);
}
function parsePackageSpec(ecosystem, raw, manager) {
  switch (ecosystem) {
    case "npm":
      return parseNpm(raw.trim(), manager);
    case "pypi":
      return parsePython(raw, false, manager);
    case "packagist":
      return parseComposer(raw.trim());
    case "nuget":
      return parseNuget(raw.trim());
    default:
      return skip(raw, "unsupported ecosystem");
  }
}
var set = (...xs) => new Set(xs);
var NPM_COMMON_BOOL = [
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
var LOGLEVEL_FLAGS = /* @__PURE__ */ new Set(["--silent", "--quiet", "-q", "--verbose", "-d"]);
var FLAGS = {
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
      "--location",
      // npm 11.20.0 `config` (docs/content/using-npm/config.md, measurements/flags/npm-11.20.0-config.txt): each takes a value.
      "--fetch-retries",
      "--fetch-retry-factor",
      "--fetch-retry-mintimeout",
      "--fetch-retry-maxtimeout",
      "--fetch-timeout",
      "--cache-min",
      "--cache-max",
      "--maxsockets",
      "--depth",
      "--node-options",
      "--script-shell",
      "--auth-type",
      "--cafile",
      "--https-proxy",
      "--proxy",
      "--noproxy",
      "--local-address",
      "--user-agent",
      "--min-release-age"
    ),
    // npm 11.20.0 `config`: Boolean. (`--prefer-dedupe` and `--engine-strict` are Boolean too and left unknown: the
    // regression tests of this fix use them as the examples of a flag the table lacks.)
    bool: set(...NPM_COMMON_BOOL, "--allow-same-version", "--strict-ssl"),
    registry: set("--registry"),
    dir: set("--prefix", "-C"),
    workspace: set("--workspace", "-w", "--workspaces"),
    boolWord: { except: LOGLEVEL_FLAGS }
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
      "--allow-build",
      // pnpm 10.33.2 `add --help` / `install --help` (measurements/flags/pnpm-*-help.txt): shown with an argument.
      "--child-concurrency",
      "--hoist-pattern",
      "--public-hoist-pattern",
      "--filter-prod",
      "--test-pattern",
      "--changed-files-ignore-pattern",
      "--trust-policy-exclude",
      "--trust-policy-ignore-after"
    ),
    // pnpm 10.33.2 `add --help` / `install --help`: shown without one. (`--shamefully-hoist` is one too and left
    // unknown, like npm's `--prefer-dedupe`: the regression tests use it as the example of a flag the table lacks.)
    bool: set(
      ...NPM_COMMON_BOOL,
      "--workspace",
      "-w",
      "--workspace-root",
      "--recursive",
      "-r",
      "--ignore-pnpmfile",
      "--prefer-frozen-lockfile",
      "--fix-lockfile",
      "--ignore-workspace",
      "--lockfile-only",
      "--merge-git-branch-lockfiles",
      "--optimistic-repeat-install",
      "--resolution-only",
      "--side-effects-cache",
      "--side-effects-cache-readonly",
      "--strict-peer-dependencies",
      "--use-running-store-server",
      "--use-store-server",
      "--use-stderr",
      "--stream",
      "--aggregate-output",
      "--fail-if-no-match",
      "--save-catalog",
      "--prod"
    ),
    registry: set("--registry"),
    dir: set("--dir", "-C"),
    workspace: set("--workspace", "--filter", "-F"),
    boolWord: { except: LOGLEVEL_FLAGS }
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
      "--mode",
      // Yarn 1.22.22 `yarn --help` (measurements/flags/yarn-1.22.22-help.txt): shown with an argument.
      "--network-concurrency",
      "--link-folder",
      "--global-folder",
      "--preferred-cache-folder",
      "--use-yarnrc",
      "--https-proxy",
      "--proxy",
      "--otp"
    ),
    // Yarn 1.22.22 `yarn --help`: shown without one. Left out: `--emoji`, `--scripts-prepend-node-path` and `--prod` /
    // `--production`, whose argument is optional (`[bool]`, `[prod]`), and `--ignore-engines`, the example of a flag the
    // table lacks in the regression tests of this fix.
    bool: set(
      ...NPM_COMMON_BOOL,
      "--ignore-workspace-root-check",
      "-W",
      "--cached",
      "--interactive",
      "-i",
      "--prefer-dev",
      "--check-files",
      "--disable-pnp",
      "--enable-pnp",
      "--pnp",
      "--flat",
      "--focus",
      "--har",
      "--ignore-optional",
      "--ignore-platform",
      "--link-duplicates",
      "--no-default-rc",
      "--non-interactive",
      "--no-node-version-check",
      "--pure-lockfile",
      "--skip-integrity-check",
      "--strict-semver",
      "--update-checksums",
      "-A"
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
      "--resolution",
      "--requirements",
      // pip 26.2.1 `install --help` (measurements/flags/pip-install-help.txt): shown with an argument.
      "--use-feature",
      "--use-deprecated",
      "--all-releases",
      "--build-constraint",
      "--only-final",
      "--resume-retries",
      "--refresh-package",
      "--requirements-from-script",
      "--uploaded-prior-to"
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
      "--compile-bytecode",
      // pip 26.2.1 `install --help`: shown without one.
      "--debug",
      "--only-deps"
    ),
    registry: set("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index", "--default-index"),
    registryBool: set("--no-index"),
    reported: /* @__PURE__ */ new Map([
      ["-r", "requirements file (-r) \u2014 read as a manifest, not as a package name"],
      ["--requirement", "requirements file (-r) \u2014 read as a manifest, not as a package name"],
      // `uv pip install` spells it in the plural.
      ["--requirements", "requirements file (-r) \u2014 read as a manifest, not as a package name"],
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
    // composer 2.10.3 `require --help` (measurements/flags/composer-require-help.txt): these options take a value
    // (`--prefer-install` was listed below as a boolean: it is `--prefer-install=PREFER-INSTALL`).
    value: set("--working-dir", "-d", "--prefer-install", "--ignore-platform-req", "--audit-format", "--apcu-autoloader-prefix"),
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
      "-m",
      "--profile",
      "--no-blocking",
      "--no-suggest"
    ),
    registry: set()
  },
  dotnet: {
    // dotnet 10.0.404 `add package --help` (measurements/flags/dotnet-add-package-help.txt): `--project` and `--file` take one.
    value: set("-v", "--version", "-f", "--framework", "-s", "--source", "--package-directory", "--project", "--file"),
    bool: set("-n", "--no-restore", "--interactive", "--prerelease"),
    registry: set("-s", "--source")
  }
};
var UV_VALUED = [
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
var UV_BOOL = [
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
var UV_REGISTRY = ["--index", "--index-url", "--default-index", "--extra-index-url", "--find-links", "-f"];
var LAUNCH_FLAGS = {
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
      "-C",
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
var MAX_CANDIDATES_PER_COMMAND = 50;
function limitCandidates(positionals) {
  const seen = /* @__PURE__ */ new Set();
  const kept = [];
  let dropped = 0;
  for (const p of positionals) {
    if (p.candidate !== true) {
      kept.push(p);
      continue;
    }
    if (seen.has(p.value)) continue;
    if (seen.size >= MAX_CANDIDATES_PER_COMMAND) {
      dropped += 1;
      continue;
    }
    seen.add(p.value);
    kept.push(p);
  }
  return { kept, dropped };
}
var SHORT_CLUSTER = /^-[A-Za-z]{2,}/;
var isBoolWord = (word) => word === "true" || word === "false";
function afterUnknownFlag(v, next, table) {
  if (table.value.has(v) || table.bool.has(v)) return "none";
  if (!v.startsWith("--") || v === "--" || v.startsWith("--no-") || v.includes("=")) return "none";
  if (next === void 0 || next.startsWith("-") && next.length > 1) return "none";
  return isBoolWord(next) ? "value" : "candidate";
}
function takesBoolWord(v, table) {
  const rule = table.boolWord;
  if (rule === void 0) return false;
  if (table.bool.has(v)) return !rule.except.has(v);
  if (v.startsWith("--") || !SHORT_CLUSTER.test(v)) return false;
  const letters = [...v.slice(1)].map((c) => `-${c}`);
  const last = letters[letters.length - 1];
  return letters.every((flag) => table.bool.has(flag)) && last !== void 0 && !rule.except.has(last);
}
function walk(words, table) {
  const positionals = [];
  const skipped = [];
  const uncertain = [];
  let unknownFlags = 0;
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
  let candidateAt = -1;
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    if (w === void 0) break;
    const v = w.value;
    if (v === "--") continue;
    if (!v.startsWith("-") || v.length === 1) {
      positionals.push(i === candidateAt ? { value: v, candidate: true } : { value: v });
      continue;
    }
    const eqAt = v.indexOf("=");
    if (eqAt > 0) {
      const flag = v.slice(0, eqAt);
      if (!known(flag)) {
        uncertain.push(`unknown flag ${flag}`);
        unknownFlags += 1;
      }
      note(flag, v.slice(eqAt + 1));
      continue;
    }
    if (table.value.has(v)) {
      note(v, words[i + 1]?.value);
      i += 1;
      continue;
    }
    if (table.bool.has(v)) {
      const word = words[i + 1]?.value;
      if (takesBoolWord(v, table) && isBoolWord(word)) {
        note(v, word);
        i += 1;
      } else note(v, void 0);
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
        if (!table.bool.has(flag)) {
          uncertain.push(`unknown flag ${flag}`);
          unknownFlags += 1;
        }
        note(flag, void 0);
      }
      if (takesBoolWord(v, table) && isBoolWord(words[i + 1]?.value)) i += 1;
      continue;
    }
    uncertain.push(`unknown flag ${v}`);
    unknownFlags += 1;
    const after = afterUnknownFlag(v, words[i + 1]?.value, table);
    if (after === "value") i += 1;
    else if (after === "candidate") candidateAt = i + 1;
  }
  const out = { positionals, skipped, uncertain, registries, flags, unknownFlags };
  if (customRegistry !== void 0) out.customRegistry = customRegistry;
  return out;
}
var ASSIGNMENT2 = /^[A-Za-z_][A-Za-z0-9_]*=/;
function base(word) {
  const last = word.split(/[\\/]/).pop() ?? word;
  return last.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, "");
}
function commandStart(words) {
  return commandWordIndex(words);
}
var COREPACK_MANAGERS = /* @__PURE__ */ new Map([
  ["yarn", "yarn"],
  ["yarnpkg", "yarn"],
  ["pnpm", "pnpm"],
  ["pnpx", "pnpx"],
  ["npm", "npm"],
  ["npx", "npx"]
]);
function corepackManager(word) {
  if (word === void 0) return void 0;
  const at = word.indexOf("@");
  return COREPACK_MANAGERS.get(at < 0 ? word : word.slice(0, at));
}
var NPM_INSTALL = /* @__PURE__ */ new Set(["install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"]);
var NPM_MANIFEST_INSTALL = /* @__PURE__ */ new Set([
  "ci",
  "clean-install",
  "ic",
  "install-clean",
  "isntall-clean",
  "install-test",
  "it",
  "install-ci-test",
  "cit",
  "clean-install-test",
  "sit"
]);
var COMPOSER_REQUIRE = /* @__PURE__ */ new Set(["require", "r", "req", "requ", "requi", "requir"]);
var BUN_ADD = /* @__PURE__ */ new Set(["add", "a", "install", "i"]);
var PNPM_INSTALL = /* @__PURE__ */ new Set(["install", "i"]);
var YARN_PRINTS = /* @__PURE__ */ new Set(["--version", "-v", "-V", "--help", "-h"]);
var REQUIREMENT_FLAGS = /* @__PURE__ */ new Set(["-r", "--requirement", "--requirements"]);
var isGlobalFlag = (f) => (f.flag === "-g" || f.flag === "--global") && f.value !== "false" || f.flag === "--location" && f.value === "global";
var beforeDoubleDash = (words) => {
  const at = words.findIndex((w) => w.value === "--");
  return at < 0 ? [...words] : words.slice(0, at);
};
function saysGlobal(manager, pre, args) {
  if (manager !== "npm" && manager !== "pnpm" && manager !== "bun") return false;
  if ([...pre, ...args].some((w) => /[$`]/.test(w.value))) return false;
  let says = false;
  for (const list of [beforeDoubleDash(pre), beforeDoubleDash(args)]) {
    for (const [at, w] of list.entries()) {
      const v = w.value;
      const next = list[at + 1]?.value;
      if (!v.startsWith("-")) continue;
      if (v === "-g" || v === "--global") {
        if (next === "false") return false;
        says = true;
      } else if (v === "--global=true") says = true;
      else if (manager === "npm" && (v === "--location=global" || v === "--location" && next === "global")) says = true;
      else if (v.startsWith("-g=") || /global|location/.test(v.toLowerCase())) return false;
      else if (/^-[A-Za-z]{2,}$/.test(v) && v.includes("g")) return false;
    }
  }
  return says;
}
function launcher(manager, ecosystem, args, pre, launch) {
  return { manager, ecosystem, args, pre, uncertain: [], launch };
}
function scanPositional(words, from, table, subcommands) {
  let candidateAt = -1;
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v.startsWith("-") && v.length > 1) {
      if (v.includes("=")) continue;
      if (table.value.has(v)) i += 1;
      else if (takesBoolWord(v, table) && isBoolWord(words[i + 1]?.value)) i += 1;
      else {
        const next = words[i + 1]?.value;
        const after = afterUnknownFlag(v, next, table);
        if (after === "value" || after === "candidate" && subcommands !== void 0 && !subcommands.has(next ?? "")) i += 1;
        else if (after === "candidate") candidateAt = i + 1;
      }
      continue;
    }
    return { at: i, candidate: i === candidateAt };
  }
  return { at: -1, candidate: false };
}
var SUBCOMMANDS = {
  npm: /* @__PURE__ */ new Set([...NPM_INSTALL, ...NPM_MANIFEST_INSTALL, "exec", "x"]),
  pnpm: /* @__PURE__ */ new Set(["add", "dlx", ...PNPM_INSTALL]),
  bun: /* @__PURE__ */ new Set([...BUN_ADD, "x"]),
  yarn: /* @__PURE__ */ new Set(["install", "add", "global", "workspace", "dlx"]),
  pip: /* @__PURE__ */ new Set(["install"]),
  uv: /* @__PURE__ */ new Set(["add", "pip", "tool"]),
  poetry: /* @__PURE__ */ new Set(["add"]),
  composer: COMPOSER_REQUIRE,
  dotnet: /* @__PURE__ */ new Set(["add"])
};
var PIPX_SUBCOMMANDS = /* @__PURE__ */ new Set(["install", "run"]);
var ADD_ONLY = /* @__PURE__ */ new Set(["add"]);
var INSTALL_ONLY = /* @__PURE__ */ new Set(["install"]);
var PACKAGE_ONLY = /* @__PURE__ */ new Set(["package"]);
function detect(words) {
  const nextPositional = (ws, from, table2, subcommands) => scanPositional(ws, from, table2, subcommands).at;
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
  if (head === "yarnpkg") head = "yarn";
  if (head === "corepack") {
    const first = words[start + 1]?.value;
    const via = corepackManager(first);
    if (via !== void 0) {
      head = via;
      i = start + 2;
    } else if (first === "up" || first === "use" && corepackManager(words[start + 2]?.value) !== void 0) {
      return { manager: "npm", ecosystem: "npm", args: [], pre: [], uncertain: [], manifest: "always" };
    } else return null;
  }
  const rest = words.slice(i);
  if (head === "npx") return launcher("npx", "npm", rest, [], { style: "run", flags: "npx", localFirst: true });
  if (head === "pnpx") return launcher("pnpm", "npm", rest, [], { style: "run", flags: "pnpm-dlx" });
  if (head === "bunx") return launcher("bun", "npm", rest, [], { style: "run", flags: "bunx", localFirst: true });
  if (head === "uvx") return launcher("uv", "pypi", rest, [], { style: "run", flags: "uvx" });
  if (head === "pipx") {
    const sub2 = nextPositional(words, i, LAUNCH_FLAGS["pipx-run"] ?? FLAGS["pip"] ?? { value: set(), bool: set(), registry: set() }, PIPX_SUBCOMMANDS);
    const subWord2 = sub2 < 0 ? "" : words[sub2]?.value ?? "";
    if (subWord2 === "install") return launcher("pipx", "pypi", words.slice(sub2 + 1), words.slice(i, sub2), { style: "install", flags: "pipx-install" });
    if (subWord2 === "run") return launcher("pipx", "pypi", words.slice(sub2 + 1), words.slice(i, sub2), { style: "run", flags: "pipx-run" });
    return null;
  }
  const table = FLAGS[head];
  if (table === void 0) return null;
  const sub = nextPositional(words, i, table, SUBCOMMANDS[head]);
  if (sub < 0) {
    if (head === "yarn" && !rest.some((w) => YARN_PRINTS.has(w.value))) {
      return { manager: head, ecosystem: "npm", args: rest, pre: [], uncertain: [], manifest: "always" };
    }
    return null;
  }
  const subName = words[sub]?.value ?? "";
  const after = words.slice(sub + 1);
  const before = words.slice(i, sub);
  if (head === "npm" && (subName === "exec" || subName === "x")) {
    return launcher("npm", "npm", after, before, { style: "run", flags: "npx", localFirst: true });
  }
  if (head === "pnpm" && subName === "dlx") return launcher("pnpm", "npm", after, before, { style: "run", flags: "pnpm-dlx" });
  if (head === "yarn" && subName === "dlx") return launcher("yarn", "npm", after, before, { style: "run", flags: "yarn-dlx" });
  if (head === "bun" && subName === "x") return launcher("bun", "npm", after, before, { style: "run", flags: "bunx", localFirst: true });
  if (head === "uv" && subName === "tool") {
    const toolTable = LAUNCH_FLAGS["uvx"] ?? table;
    const verb = nextPositional(words, sub + 1, toolTable, PIPX_SUBCOMMANDS);
    const verbName = verb < 0 ? "" : words[verb]?.value ?? "";
    const tail = words.slice(verb + 1);
    if (verbName === "run") return launcher("uv", "pypi", tail, before, { style: "run", flags: "uvx" });
    if (verbName === "install") return launcher("uv", "pypi", tail, before, { style: "install", flags: "uv-tool-install" });
    return null;
  }
  const subWord = words[sub]?.value ?? "";
  const pre = words.slice(i, sub);
  switch (head) {
    case "npm":
      if (NPM_INSTALL.has(subWord)) return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "bare" };
      if (NPM_MANIFEST_INSTALL.has(subWord)) return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always" };
      return null;
    case "pnpm":
      if (subWord === "add") return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [] };
      if (PNPM_INSTALL.has(subWord)) return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "bare" };
      return null;
    case "bun": {
      if (!BUN_ADD.has(subWord)) return null;
      const d = { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [] };
      return subWord === "install" || subWord === "i" ? { ...d, manifest: "bare" } : d;
    }
    case "yarn": {
      if (subWord === "install") return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always" };
      let at = sub;
      const uncertain = [];
      if (subWord === "global") at = nextPositional(words, sub + 1, table, ADD_ONLY);
      else if (subWord === "workspace") {
        const ws = nextPositional(words, sub + 1, table);
        at = ws < 0 ? -1 : nextPositional(words, ws + 1, table, ADD_ONLY);
        uncertain.push("workspace context (yarn workspace)");
      }
      if (at < 0 || words[at]?.value !== "add") return null;
      return { manager: head, ecosystem: "npm", args: words.slice(at + 1), pre, uncertain, ...subWord === "global" ? { global: true } : {} };
    }
    case "pip":
      return subWord === "install" ? { manager: head, ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [] } : null;
    case "uv": {
      if (subWord === "add") return { manager: "uv", ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [] };
      if (subWord === "pip") {
        const inst = nextPositional(words, sub + 1, table, INSTALL_ONLY);
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
        at = nextPositional(words, at + 1, table, PACKAGE_ONLY);
      }
      if (at < 0 || words[at]?.value !== "package") return null;
      return { manager: head, ecosystem: "nuget", args: words.slice(at + 1), pre, uncertain };
    }
    default:
      return null;
  }
}
var COMPOSER_CONSTRAINT = /^(?:[\^~<>=!*]|v?\d|dev-|@)/;
function collectLaunch(d, launch, context) {
  const table = LAUNCH_FLAGS[launch.flags] ?? { value: set(), bool: set(), registry: set() };
  const pre = walk(d.pre, table);
  let body = d.args;
  if (launch.style === "run") {
    let scan = scanPositional(d.args, 0, table);
    let end = scan.at;
    while (scan.at >= 0 && scan.candidate) {
      scan = scanPositional(d.args, scan.at + 1, table);
      if (scan.at >= 0) end = scan.at;
    }
    if (end >= 0) body = d.args.slice(0, end + 1);
  }
  const w = walk(body, table);
  const flags = [...pre.flags, ...w.flags];
  const has2 = (names) => names !== void 0 && flags.some((f) => names.has(f.flag));
  const values = (names) => names === void 0 ? [] : flags.filter((f) => names.has(f.flag)).flatMap((f) => (f.value ?? "").split(",")).map((v) => v.trim()).filter((v) => v !== "");
  const raws = [];
  const limited = limitCandidates(w.positionals);
  let byPackageFlag = false;
  if (!has2(table.noFetchFlags)) {
    const named = values(table.packageFlags);
    if (named.length > 0) {
      raws.push(...named);
      byPackageFlag = true;
    } else if (!has2(table.shellFlags)) raws.push(...limited.kept.map((p) => p.value));
    raws.push(...values(table.extraPackageFlags));
  }
  const packages = [];
  const skipped = [...pre.skipped, ...w.skipped];
  const unsure = [];
  for (const raw of raws) {
    const spec2 = d.ecosystem === "npm" ? parseNpm(raw, d.manager) : parsePython(raw, false, d.manager);
    if ("name" in spec2) {
      packages.push(spec2);
      const why = unmeasuredReason(d.manager, spec2);
      if (why !== void 0) unsure.push(why);
    } else skipped.push(spec2);
  }
  const out = {
    ecosystem: d.ecosystem,
    manager: d.manager,
    packages,
    skipped,
    uncertain: [.../* @__PURE__ */ new Set([...context, ...pre.uncertain, ...w.uncertain, ...unsure])],
    registries: [...pre.registries, ...w.registries]
  };
  const registry = pre.customRegistry ?? w.customRegistry;
  if (registry !== void 0) out.customRegistry = registry;
  if (launch.localFirst === true) out.localFirst = true;
  if (byPackageFlag) out.byPackageFlag = true;
  if (limited.dropped > 0) out.candidatesDropped = limited.dropped;
  if (flags.some((f) => f.flag === "--prefix" || f.flag === "-C")) out.prefixed = true;
  return out;
}
function collect(d, context) {
  if (d.launch !== void 0) return collectLaunch(d, d.launch, context);
  const table = FLAGS[d.manager === "uv-pip" ? "pip" : d.manager] ?? FLAGS["npm"];
  const flagTable = table ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, flagTable);
  const walked = walk(d.args, flagTable);
  const { skipped, customRegistry, uncertain, registries } = walked;
  const limited = limitCandidates(walked.positionals);
  const positionals = d.manifest === "always" ? [] : limited.kept;
  const allFlags = [...preWalk.flags, ...walked.flags];
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
  if (limited.dropped > 0 && d.manifest !== "always") out.candidatesDropped = limited.dropped;
  let candidateSkipped = 0;
  let namedPackages = 0;
  let lastComposer;
  for (const p of positionals) {
    let spec2;
    switch (d.ecosystem) {
      case "npm":
        spec2 = parseNpm(p.value, d.manager);
        break;
      case "pypi":
        spec2 = parsePython(p.value, d.manager === "poetry", d.manager);
        break;
      case "packagist":
        if (lastComposer !== void 0 && lastComposer.range === void 0 && !p.value.includes("/") && COMPOSER_CONSTRAINT.test(p.value)) {
          lastComposer.range = p.value;
          continue;
        }
        spec2 = parseComposer(p.value);
        break;
      case "nuget":
        spec2 = parseNuget(p.value);
        break;
      default:
        spec2 = skip(p.value, "unsupported ecosystem");
    }
    if ("name" in spec2) {
      packages.push(spec2);
      if (p.candidate !== true) namedPackages += 1;
      const why = unmeasuredReason(d.manager, spec2);
      if (why !== void 0 && !out.uncertain.includes(why)) out.uncertain.push(why);
      lastComposer = d.ecosystem === "packagist" ? spec2 : void 0;
    } else {
      skipped.push(spec2);
      if (p.candidate === true) candidateSkipped += 1;
      lastComposer = void 0;
    }
  }
  if (d.ecosystem === "nuget") {
    const extra = positionals.some((p) => p.candidate === true) ? [] : packages.splice(1);
    for (const e of extra) skipped.push(skip(e.raw, "unexpected extra argument to dotnet add package"));
    const first = packages[0];
    const version = flagValue(d.args, ["-v", "--version"]);
    if (first !== void 0 && version !== void 0) first.range = version;
  }
  if (allFlags.some((f) => flagTable.dir?.has(f.flag) === true)) out.prefixed = true;
  const knownFlagsOnly = preWalk.unknownFlags + walked.unknownFlags === 0;
  if (d.global === true || knownFlagsOnly && allFlags.some(isGlobalFlag) && saysGlobal(d.manager, d.pre, d.args)) out.global = true;
  if (d.manager === "pip" || d.manager === "uv-pip") {
    const files = walked.flags.flatMap((f) => REQUIREMENT_FLAGS.has(f.flag) && f.value !== void 0 && f.value !== "" ? [f.value] : []);
    if (files.length > 0) out.manifest = { kind: "requirements", files };
  } else if (d.manifest !== void 0 && out.global !== true) {
    const maybeFlags = allFlags.some(isGlobalFlag) && skipped.length > 0 && skipped.every((s) => /[$`]/.test(s.raw));
    if (d.manifest === "always" || namedPackages === 0 && (skipped.length === candidateSkipped || maybeFlags)) out.manifest = { kind: "package-json" };
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
var POWERSHELL_READING = "found by reading the command as PowerShell does (a comma list, a backtick escape or continuation, a doubled quote, a Unicode space) \u2014 vetted for malicious versions only";
function packageKey(p) {
  return `${p.ecosystem}\0${p.name.toLowerCase()}\0${p.range ?? ""}`;
}
function parseInstallCommands(command, opts = {}) {
  const cdpath = opts.cdpath === true;
  const out = readingsOf(command, opts.shell ?? "bash", null, cdpath);
  if (opts.nested === void 0 || opts.nested.length === 0) return out;
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  const moved2 = movesDirectory(stripComments(command));
  for (const script of opts.nested) {
    for (const c of readingsOf(script.text, script.shell, NESTED_SCRIPT, cdpath)) {
      const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
      if (packages.length === 0 && c.manifest === void 0) continue;
      for (const p of packages) seen.add(packageKey(p));
      const unknownDir = moved2 && (c.localFirst === true || c.manifest !== void 0);
      out.push({ ...c, packages, ...unknownDir ? { workdir: null } : {} });
    }
  }
  return out;
}
function manifestKey(c) {
  const m = c.manifest;
  if (m === void 0) return "";
  return JSON.stringify([m.kind, m.kind === "requirements" ? m.files : [], c.workdir ?? null, c.prefixed === true]);
}
var NESTED_SCRIPT = "found in a script the command hands a shell (bash -c, cmd /c, pwsh -c, a script piped to a shell) \u2014 vetted, never denied as missing";
function readingsOf(command, shell, forced, cdpath) {
  const text = stripComments(command);
  const out = parseReading(text, forced, cdpath);
  if (shell !== "powershell") return out;
  const asPowerShell = powershellAsPosix(text);
  if (asPowerShell === text) return out;
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  const seenManifests = new Set(out.map(manifestKey));
  for (const c of parseReading(asPowerShell, POWERSHELL_READING, cdpath)) {
    const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
    const newManifest = c.manifest !== void 0 && !seenManifests.has(manifestKey(c));
    if (packages.length === 0 && !newManifest) continue;
    for (const p of packages) seen.add(packageKey(p));
    seenManifests.add(manifestKey(c));
    const { manifest: _same, ...withoutManifest } = c;
    out.push({ ...newManifest ? c : withoutManifest, packages, skipped: [] });
  }
  return out;
}
function movesDirectory(text) {
  try {
    return splitShell(text).statements.some((s) => s.commands.some((words) => changesDirectory(words)));
  } catch {
    return true;
  }
}
function parseReading(text, forced, cdpath) {
  const out = [];
  let split;
  try {
    split = splitShell(text);
  } catch {
    return out;
  }
  const notConfident = forced ?? confidentShape(text);
  const envChange = changesEnvironment(text, split.statements);
  const dirs = workdirs(split.statements, { cdpath });
  let dirChanged = false;
  split.statements.forEach((statement, s) => {
    statement.commands.forEach((words, w) => {
      const d = detect(withoutRedirectWords(words));
      if (d !== null) {
        const context = [];
        if (envChange) context.push("inline environment assignment in the command (it can redirect the registry)");
        if (dirChanged) context.push("directory change earlier in the command (that directory\u2019s registry configuration was not read)");
        const c = collect(d, context);
        const unmeasured = c.uncertain.filter((r) => r === UNMEASURED_ARCHIVE);
        c.uncertain = notConfident === null ? unmeasured : [.../* @__PURE__ */ new Set([notConfident, ...c.uncertain])];
        const sure = dirs[s]?.[w]?.sure ?? null;
        if (runsElsewhere(words)) c.workdir = null;
        else if (sure === null || sure.length > 0) c.workdir = sure;
        out.push(c);
      }
      if (changesDirectory(words)) dirChanged = true;
    });
  });
  return out;
}
function runsElsewhere(words) {
  const at = resolveCommand(words).index;
  let runner = "";
  for (const w of words.slice(0, at)) {
    const name = base(w.value);
    if (name === "env" || name === "sudo" || name === "doas") runner = name;
    else if (runner === "env" && /^(?:-[A-Za-z]*C|--chdir(?:=|$))/.test(w.value)) return true;
    else if (runner === "sudo" && /^(?:-[A-Za-z]*D|--chdir(?:=|$))/.test(w.value)) return true;
  }
  return false;
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
var NPM_ALLOW_BOOL = ["-D", "--save-dev", "-E", "--save-exact", "-O", "--save-optional", "-P", "--save-prod", "-S", "--save"];
var ALLOW = {
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
var NOT_SIMPLE = /[;&|()<>`$\\\n\r{}*?[\],]/;
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
  let has2 = false;
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
      has2 = true;
      continue;
    }
    if (ch === " " || ch === "	") {
      if (has2) words.push(cur);
      cur = "";
      has2 = false;
      continue;
    }
    if (NOT_SIMPLE.test(ch)) return notSingle(`'${ch === "\n" || ch === "\r" ? "newline" : ch}' outside quotes`);
    cur += ch;
    has2 = true;
  }
  if (quote !== null) return notSingle("unterminated quote");
  if (has2) words.push(cur);
  const viaCorepack = words[0] === "corepack" ? corepackManager(words[1]) : void 0;
  const [named, ...rest] = viaCorepack === void 0 ? words : [viaCorepack, ...words.slice(2)];
  const tool = named === "yarnpkg" ? "yarn" : named;
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
      if (at(0) !== "add" && !(tool === "pnpm" && PNPM_INSTALL.has(at(0)))) return notPlain(`'${tool} ${at(0)}'`);
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
var DIR_COMMANDS = /* @__PURE__ */ new Set(["cd", "chdir", "pushd", "popd", "set-location", "push-location", "pop-location", "sl", "cd.."]);
function changesDirectory(words) {
  const head = words[commandStart(words)];
  return head !== void 0 && DIR_COMMANDS.has(base(head.value));
}
var ENV_COMMANDS = /* @__PURE__ */ new Set(["export", "declare", "typeset", "local", "readonly", "set", "setx"]);
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

// src/pkgvet/manifest.ts
var MAX_MANIFEST_BYTES = 1024 * 1024;
var MAX_REQUIREMENT_FILES = 8;
var MAX_REQUIREMENT_DEPTH = 3;
var REASON = {
  notRegular: "not a regular file",
  tooLarge: "over 1 MiB",
  notJson: "not valid JSON",
  notManifest: "not a package.json object",
  network: "on a network path",
  unreadable: "could not be read",
  tooMany: "past the limit of 8 requirement files",
  tooDeep: "included more than 3 levels deep",
  unknownDir: "where the command runs could not be determined"
};
var MANIFEST_UNREADABLE_REASONS = Object.values(REASON);
var UNKNOWN_DIRECTORY = REASON.unknownDir;
var MAX_NAME_LENGTH = 214;
var MAX_RANGE_LENGTH = 100;
var MAX_LABEL_LENGTH = 120;
function label(file) {
  const clean = file.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return clean.length > MAX_LABEL_LENGTH ? `${clean.slice(0, MAX_LABEL_LENGTH)}\u2026` : clean;
}
function refusal(read2) {
  switch (read2.reason) {
    case "not-a-regular-file":
      return REASON.notRegular;
    case "too-large":
      return REASON.tooLarge;
    case "remote-link":
      return REASON.network;
    default:
      return REASON.unreadable;
  }
}
function readManifestText(path, under) {
  if (isNetworkPath(path) || isNetworkPath(under)) return { status: "unreadable", reason: REASON.network };
  let read2;
  try {
    read2 = readSmallText(path, MAX_MANIFEST_BYTES, under);
  } catch {
    return { status: "unreadable", reason: REASON.unreadable };
  }
  if (read2.status === "ok") return read2;
  if (read2.status === "absent") return read2;
  return { status: "unreadable", reason: refusal(read2) };
}
function validName2(ecosystem, name) {
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) return false;
  const spec2 = parsePackageSpec(ecosystem, name);
  return "name" in spec2 && spec2.name === name && spec2.range === void 0;
}
function spec(ecosystem, name, range) {
  return range === void 0 ? { ecosystem, name, raw: name } : { ecosystem, name, range, raw: ecosystem === "npm" ? `${name}@${range}` : `${name}${range}` };
}
function pushOnce(into, seen, pkg) {
  const key = `${pkg.name.toLowerCase()}\0${pkg.range ?? ""}`;
  if (seen.has(key)) return;
  seen.add(key);
  into.push(pkg);
}
var NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
var SEMVER_WORD = /^(?:\|\||-|\*|[xX]|[<>=~^]{0,2}v?\d[A-Za-z0-9.+-]*|[<>=~^]{1,2}\*)$/;
var DIST_TAG = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
function npmRange(value, manager) {
  const v = value.trim();
  if (v === "" || v === "latest") return void 0;
  if (v.length > MAX_RANGE_LENGTH || readsFileValue(manager, v)) return null;
  if (DIST_TAG.test(v)) return v;
  return v.split(/\s+/).every((word) => SEMVER_WORD.test(word)) ? v : null;
}
function npmDependency(key, value, manager) {
  let name = key;
  let wanted = value.trim();
  if (/^npm:/i.test(wanted)) {
    const real = wanted.slice(4);
    const at = real.indexOf("@", real.startsWith("@") ? 1 : 0);
    name = at > 0 ? real.slice(0, at) : real;
    wanted = at > 0 ? real.slice(at + 1) : "";
  }
  if (!validName2("npm", name)) return null;
  const range = npmRange(wanted, manager);
  return range === null ? null : spec("npm", name, range);
}
function readNpmManifest(dir, manager = "npm") {
  const file = "package.json";
  const read2 = readManifestText(resolve2(dir, file), dir);
  if (read2.status === "absent") return { file, status: "absent", packages: [], registries: [] };
  if (read2.status === "unreadable") return { file, status: "unreadable", packages: [], registries: [], reason: read2.reason };
  let manifest;
  try {
    manifest = JSON.parse(read2.text);
  } catch {
    return { file, status: "unreadable", packages: [], registries: [], reason: REASON.notJson };
  }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    return { file, status: "unreadable", packages: [], registries: [], reason: REASON.notManifest };
  }
  const packages = [];
  const seen = /* @__PURE__ */ new Set();
  for (const section of NPM_SECTIONS) {
    const entries = manifest[section];
    if (entries === null || typeof entries !== "object" || Array.isArray(entries)) continue;
    for (const [key, value] of Object.entries(entries)) {
      if (typeof value !== "string") continue;
      const pkg = npmDependency(key, value, manager);
      if (pkg !== null) pushOnce(packages, seen, pkg);
    }
  }
  return { file, status: "ok", packages, registries: [] };
}
var PEP440_SPECIFIER = /^(?:===|==|~=|!=|<=|>=|<|>)v?(?:\d+!)?\d+(?:\.\d+)*(?:[._-]?(?:a|b|c|rc|alpha|beta|pre|preview)[._-]?\d*)?(?:[._-]?(?:post|rev|r)[._-]?\d*)?(?:[._-]?dev[._-]?\d*)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?(?:\.\*)?$/i;
function pypiRange(range) {
  return range.length <= MAX_RANGE_LENGTH && range.split(",").every((one) => PEP440_SPECIFIER.test(one));
}
function optionValue(line, names) {
  for (const name of names) {
    if (!line.startsWith(name)) continue;
    const rest = line.slice(name.length);
    const attached = !name.startsWith("--") && rest !== "" && !/^[\s=]/.test(rest);
    const m = attached ? [rest, rest] : /^(?:\s+|=)(.+)$/.exec(rest);
    if (m === null) continue;
    const value = (m[1] ?? "").trim().replace(/^(['"])(.*)\1$/, "$2");
    if (value !== "") return value;
  }
  return void 0;
}
function requirementLines(text) {
  const out = [];
  let pending = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(?:^|\s)#.*$/, "");
    if (line.endsWith("\\")) {
      pending += `${line.slice(0, -1)} `;
      continue;
    }
    const whole = (pending + line).trim();
    pending = "";
    if (whole !== "") out.push(whole);
  }
  const last = pending.trim();
  if (last !== "") out.push(last);
  return out;
}
function readRequirementFile(path, under, depth, walk2, found) {
  if (walk2.files >= MAX_REQUIREMENT_FILES) return { status: "unreadable", reason: REASON.tooMany };
  walk2.files += 1;
  walk2.visited.add(path);
  const read2 = readManifestText(path, under);
  if (read2.status !== "ok") return read2;
  for (const line of requirementLines(read2.text)) {
    if (line.startsWith("-")) {
      const include = optionValue(line, ["--requirement", "-r"]);
      if (include !== void 0) {
        const next = resolve2(dirname(path), include);
        if (walk2.visited.has(next)) continue;
        if (depth >= MAX_REQUIREMENT_DEPTH) {
          found.incomplete = found.incomplete ?? REASON.tooDeep;
          continue;
        }
        const included = isNetworkPath(include) ? { status: "unreadable", reason: REASON.network } : readRequirementFile(next, under, depth + 1, walk2, found);
        if (included.status === "unreadable") found.incomplete = found.incomplete ?? included.reason;
        continue;
      }
      const index = optionValue(line, ["--index-url", "--extra-index-url", "--find-links", "-i", "-f"]);
      if (index !== void 0) found.registries.push(index);
      else if (/^--no-index(?:\s|$)/.test(line)) found.registries.push("--no-index");
      continue;
    }
    const requirement = line.replace(/\s+--[A-Za-z].*$/, "").trim();
    const parsed = parsePackageSpec("pypi", requirement, walk2.manager);
    if (!("name" in parsed) || parsed.name.length > MAX_NAME_LENGTH) continue;
    if (parsed.range !== void 0 && !pypiRange(parsed.range)) continue;
    pushOnce(found.packages, found.seen, spec("pypi", parsed.name, parsed.range));
  }
  return { status: "ok" };
}
function readRequirements(dir, files, manager = "pip") {
  const walk2 = { files: 0, visited: /* @__PURE__ */ new Set(), manager };
  return files.map((given) => {
    const file = label(given);
    if (isNetworkPath(given)) return { file, status: "unreadable", packages: [], registries: [], reason: REASON.network };
    const found = { packages: [], registries: [], seen: /* @__PURE__ */ new Set() };
    const read2 = readRequirementFile(resolve2(dir, given), dir, 0, walk2, found);
    if (read2.status === "absent") return { file, status: "absent", packages: [], registries: [] };
    if (read2.status === "unreadable") return { file, status: "unreadable", packages: [], registries: [], reason: read2.reason };
    const out = { file, status: "ok", packages: found.packages, registries: found.registries };
    if (found.incomplete !== void 0) out.incomplete = found.incomplete;
    return out;
  });
}

// src/platform/httpBody.ts
async function readBodyCapped(res, maxBytes) {
  const declared = Number(res.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => void 0);
    return null;
  }
  if (res.body === null) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => void 0);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}
async function readJsonCapped(res, maxBytes) {
  const body = await readBodyCapped(res, maxBytes);
  if (body === null) return null;
  return { json: JSON.parse(body.toString("utf8")) };
}
function mebibytes(n) {
  return `${Math.round(n / (1024 * 1024))} MiB`;
}

// src/runners/osv.ts
var OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
var DEFAULT_TIMEOUT_MS = 6e3;
var MAX_QUERIES = 1e3;
var CHUNK = 100;
var IN_FLIGHT = 4;
var MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
var isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function readBatch(chunk, json) {
  const results = json?.results;
  if (!Array.isArray(results) || results.length !== chunk.length) {
    const got = Array.isArray(results) ? `${results.length} results` : "no results";
    return { groups: [], unanswered: chunk, error: `osv answered ${got} for ${chunk.length} queries` };
  }
  const groups = [];
  const unanswered = [];
  chunk.forEach((pkg, idx) => {
    const res = results[idx];
    if (!isPlainObject(res)) {
      unanswered.push(pkg);
      return;
    }
    let complete = res["next_page_token"] === void 0;
    const vulns = res["vulns"];
    const ids = [];
    if (vulns !== void 0) {
      if (Array.isArray(vulns)) {
        for (const v of vulns) {
          if (isPlainObject(v) && typeof v["id"] === "string") ids.push(v["id"]);
          else complete = false;
        }
      } else {
        complete = false;
      }
    }
    if (ids.length > 0) {
      const group = { ecosystem: pkg.ecosystem, name: pkg.name, vuln_ids: ids, severity: "high" };
      if (pkg.version) group.version = pkg.version;
      groups.push(group);
    }
    if (!complete) unanswered.push(pkg);
  });
  const error = unanswered.length > 0 ? `osv left ${unanswered.length} of ${chunk.length} results incomplete` : void 0;
  return { groups, unanswered, ...error !== void 0 ? { error } : {} };
}
async function queryOsv(packages, opts = {}) {
  const named = packages.filter((p) => p.name);
  const queryable = named.slice(0, opts.maxQueries ?? MAX_QUERIES);
  const unqueried = named.length - queryable.length;
  if (queryable.length === 0) {
    return { online: true, queried: 0, unqueried, vulnerable_packages: [], unanswered: [] };
  }
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === "function" ? fetch : void 0);
  if (fetchImpl === void 0) {
    return { online: false, queried: 0, unqueried, vulnerable_packages: [], unanswered: [], error: "no_fetch" };
  }
  const size = Math.max(1, opts.chunk ?? CHUNK);
  const chunks = [];
  for (let i = 0; i < queryable.length; i += size) chunks.push(queryable.slice(i, i + size));
  const outcomes = [];
  let next = 0;
  const work = async () => {
    for (let c = next++; c < chunks.length; c = next++) {
      const chunk = chunks[c] ?? [];
      const body = {
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          ...p.version ? { version: p.version } : {}
        }))
      };
      try {
        outcomes[c] = readBatch(chunk, await postJson(OSV_BATCH_URL, body, opts, fetchImpl));
      } catch (e) {
        const error2 = e instanceof SyntaxError ? "osv answer is not JSON" : e instanceof Error ? e.message : "osv_request_failed";
        outcomes[c] = { groups: [], unanswered: chunk, error: error2 };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(Math.max(1, opts.inFlight ?? IN_FLIGHT), chunks.length) }, work));
  const unanswered = outcomes.flatMap((o) => o.unanswered);
  const error = outcomes.find((o) => o.error !== void 0)?.error;
  return {
    online: unanswered.length === 0,
    queried: queryable.length,
    unqueried,
    vulnerable_packages: outcomes.flatMap((o) => o.groups),
    unanswered,
    ...error !== void 0 ? { error } : {}
  };
}
async function postJson(url, body, opts, fetchImpl) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const onAbort = () => controller.abort();
  if (opts.signal) {
    if (opts.signal.aborted) controller.abort();
    else opts.signal.addEventListener("abort", onAbort, { once: true });
  }
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`osv http ${res.status}`);
    const read2 = await readJsonCapped(res, MAX_RESPONSE_BYTES);
    if (read2 === null) throw new Error(`osv answer over ${mebibytes(MAX_RESPONSE_BYTES)}`);
    return read2.json;
  } finally {
    clearTimeout(timeout);
    opts.signal?.removeEventListener("abort", onAbort);
  }
}

// src/pkgvet/popular.ts
import { readFileSync } from "node:fs";
import { join as join3 } from "node:path";

// src/platform/configsDir.ts
import { existsSync, readdirSync } from "node:fs";
import { dirname as dirname2, join as join2 } from "node:path";
import { fileURLToPath } from "node:url";
var MARKER_RULES = ["semgrep", "base.yml"];
function resolveConfigsDir() {
  const here = dirname2(fileURLToPath(import.meta.url));
  const bundled = join2(here, "..", "..", "configs");
  if (existsSync(join2(bundled, ...MARKER_RULES))) return bundled;
  const unbundled = join2(here, "..", "..", "..", "configs");
  if (existsSync(join2(unbundled, ...MARKER_RULES))) return unbundled;
  return unbundled;
}

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
var SEGMENT_SPLIT = /[-_./@]+/;
var DIGIT_RUN = /[0-9]+/g;
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

// src/pkgvet/popular.ts
function defaultPopularDir() {
  return join3(resolveConfigsDir(), "popular-packages");
}
function parsePopularList(text) {
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));
}
var cache = /* @__PURE__ */ new Map();
function loadPopularIndex(ecosystem, dir = defaultPopularDir()) {
  const path = join3(dir, `${ecosystem}.txt`);
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

// src/pkgvet/privateRegistry.ts
import { lstatSync as lstatSync2, readdirSync as readdirSync2 } from "node:fs";
import { homedir } from "node:os";
import { dirname as dirname3, isAbsolute as isAbsolute2, join as join4, parse as parse3, relative as relative2, resolve as resolve3 } from "node:path";
function registryCache() {
  return { reads: /* @__PURE__ */ new Map(), workspaces: /* @__PURE__ */ new Map() };
}
var MAX_WORKSPACE_DIRS = 3e3;
var PUBLIC_HOSTS2 = {
  npm: ["registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"],
  pypi: ["pypi.org", "pypi.python.org", "files.pythonhosted.org"],
  packagist: ["packagist.org", "repo.packagist.org"],
  nuget: ["api.nuget.org", "www.nuget.org", "nuget.org"]
};
var UNSAFE_TEXT = /[\\\s\u0000-\u001f\u007f]/;
var URL_SHAPE = /^(?:(https?):)?\/\/([^/?#@:]+)(?::(\d*))?(?:[/?#]|$)/i;
function isPublic(ecosystem, url) {
  const text = url.trim().replace(/^["']|["']$/g, "");
  if (UNSAFE_TEXT.test(text)) return false;
  const m = URL_SHAPE.exec(text);
  if (m === null) return false;
  const scheme = (m[1] ?? "").toLowerCase();
  const port = m[3];
  if (port !== void 0 && port !== "" && port !== (scheme === "http" ? "80" : "443")) return false;
  return PUBLIC_HOSTS2[ecosystem].includes((m[2] ?? "").toLowerCase());
}
function isPublicRegistryUrl(ecosystem, url) {
  return isPublic(ecosystem, url);
}
var MAX_REGISTRY_CONFIG_BYTES = 1024 * 1024;
function isInside(dir, path) {
  const rel = relative2(dir, path);
  return rel !== "" && !climbsOut(rel) && !isAbsolute2(rel);
}
function walkRoot(path, ctx, under) {
  const abs = resolve3(path);
  if (isRemoteOrDeviceTarget(abs)) return void 0;
  if (under !== void 0) return under;
  const holds = (dir2, base2) => samePath(dir2, base2) || isInside(dir2, base2);
  const project = ctx.projectDir === void 0 ? void 0 : resolve3(ctx.projectDir);
  const home = resolve3(homeOf(ctx));
  if (project !== void 0 && holds(abs, project) || holds(abs, home)) return void 0;
  if (project !== void 0 && isInside(project, abs)) return project;
  const dir = dirname3(abs);
  if (project !== void 0 && holds(dir, project)) return dir;
  if (isInside(home, abs)) return home;
  return parse3(abs).root;
}
var firstUnread;
function noteUnread(path, what) {
  firstUnread = firstUnread ?? { path, what };
}
function takeUnread() {
  const unread = firstUnread;
  firstUnread = void 0;
  return unread;
}
var firstUnchecked;
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
    return readdirSync2(dir);
  } catch (e) {
    const code = e.code;
    if (code !== "ENOENT" && code !== "ENOTDIR") noteUnread(dir, "directory");
    return [];
  }
}
function samePath(a, b) {
  const norm = (p) => resolve3(p).replace(/[\\/]+$/, "");
  return process.platform === "win32" ? norm(a).toLowerCase() === norm(b).toLowerCase() : norm(a) === norm(b);
}
function ancestors(ctx) {
  if (ctx.projectDir === void 0) return [];
  const stops = [ctx.homeDir, homedir()].filter((x) => typeof x === "string");
  const out = [];
  let dir = resolve3(ctx.projectDir);
  for (let i = 0; i < 16; i += 1) {
    if (stops.some((s) => samePath(s, dir))) break;
    out.push(dir);
    if (present(join4(dir, ".git"))) break;
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
  return ctx.homeDir ?? homedir();
}
function envValue(env, name) {
  const v = env[name] ?? env[name.toLowerCase()];
  return v !== void 0 && v.trim() !== "" ? v.trim() : void 0;
}
function npmScope(name) {
  const m = /^@([^/]+)\//.exec(name);
  return m?.[1];
}
function npmrcValue(raw) {
  const value = raw.trim();
  if (value.includes("\\")) return value;
  let quote;
  let end = value.length;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value.charAt(i);
    if (quote !== void 0) {
      if (ch === quote) quote = void 0;
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ";" || ch === "#") {
      end = i;
      break;
    }
  }
  return value.slice(0, end).trim().replace(/^(["'])(.*)\1$/, "$2");
}
var UNREADABLE_VALUE = "(configured)";
function yamlServer(lines, at, keyIndent, raw) {
  const next = lines.slice(at + 1).find((l) => l.trim() !== "" && !l.trim().startsWith("#"));
  if (next !== void 0 && next.length - next.trimStart().length > keyIndent) return UNREADABLE_VALUE;
  const value = raw.trim();
  const quote = value.charAt(0);
  if (quote === '"' || quote === "'") {
    const close = value.indexOf(quote, 1);
    if (close < 0) return UNREADABLE_VALUE;
    const content = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (content.includes("\\") || rest.trim() !== "" && !/^\s+#/.test(rest)) return UNREADABLE_VALUE;
    return content;
  }
  const comment = value.search(/\s#/);
  return (comment === -1 ? value : value.slice(0, comment)).trim();
}
function fromNpmrc(text, scope, all) {
  let found;
  let scoped;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^(@[^:=\s]+:)?registry\s*=\s*(.+)$/i.exec(line);
    if (m === null) continue;
    const lineScope = m[1]?.slice(1, -1);
    const url = npmrcValue(m[2] ?? "");
    all?.push(url);
    if (lineScope === void 0) found = url;
    else if (scope !== void 0 && lineScope.toLowerCase() === scope.toLowerCase()) scoped = url;
  }
  return scoped ?? found;
}
function fromYarnrcYml(text, scope, all) {
  let global;
  let scoped;
  let inScopes = false;
  let currentScope;
  const lines = text.split(/\r?\n/);
  for (const [at, raw] of lines.entries()) {
    if (raw.trim() === "" || raw.trim().startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      inScopes = /^npmScopes\s*:/.test(line);
      currentScope = void 0;
      const m = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
      if (m !== null) global = yamlServer(lines, at, indent, m[1] ?? "");
      if (m !== null) all?.push(global ?? "");
      continue;
    }
    if (!inScopes) continue;
    const scopeKey = /^["']?@?([^"':]+)["']?\s*:\s*$/.exec(line);
    if (scopeKey !== null) {
      currentScope = scopeKey[1];
      continue;
    }
    const server = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
    if (server !== null) all?.push(yamlServer(lines, at, indent, server[1] ?? ""));
    if (server !== null && scope !== void 0 && currentScope?.toLowerCase() === scope.toLowerCase()) {
      scoped = yamlServer(lines, at, indent, server[1] ?? "");
    }
  }
  return scoped ?? global;
}
function fromYarnrc(text, scope, all) {
  let found;
  let scoped;
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*["']?(@[^:"']+:)?registry["']?\s+["']?([^"'\s]+)["']?/.exec(raw);
    if (m === null) continue;
    const lineScope = m[1]?.slice(1, -1);
    all?.push(m[2] ?? "");
    if (lineScope === void 0) found = m[2];
    else if (scope !== void 0 && lineScope.toLowerCase() === scope.toLowerCase()) scoped = m[2];
  }
  return scoped ?? found;
}
function fromBunfig(text, scope, all) {
  let section = "";
  let found;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header !== null) {
      section = (header[1] ?? "").trim();
      continue;
    }
    const url = /https?:\/\/[^"'\s}]+/.exec(line)?.[0] ?? "(configured)";
    if (section === "install" && /^registry\s*=/.test(line)) {
      all?.push(url);
      found = found ?? url;
    }
    if (section === "install.scopes" && /^["']?@?[^"'=\s]+["']?\s*=/.test(line)) all?.push(url);
    if (section === "install.scopes" && scope !== void 0) {
      const key = /^["']?@?([^"'=\s]+)["']?\s*=/.exec(line)?.[1];
      if (key !== void 0 && key.toLowerCase() === scope.toLowerCase()) return url;
    }
  }
  return found;
}
var NPM_AUTH = /^\s*(?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/:)?_(?:authToken|auth|password)\s*=|^\s*npmAuth(?:Token|Ident)\s*:/m;
function npmConfigFiles(ctx) {
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const files = [];
  const near = ancestors(ctx);
  for (const dir of near) {
    files.push(
      { path: join4(dir, ".npmrc"), parse: fromNpmrc, user: false },
      { path: join4(dir, ".yarnrc.yml"), parse: fromYarnrcYml, user: false },
      { path: join4(dir, ".yarnrc"), parse: fromYarnrc, user: false },
      { path: join4(dir, "bunfig.toml"), parse: fromBunfig, user: false }
    );
  }
  const top = near[near.length - 1];
  if (top !== void 0) {
    for (let dir = dirname3(top), i = 0; i < 64; dir = dirname3(dir), i += 1) {
      files.push({ path: join4(dir, ".yarnrc.yml"), parse: fromYarnrcYml, user: false });
      if (dirname3(dir) === dir) break;
    }
  }
  const xdg = envValue(env, "XDG_CONFIG_HOME") ?? join4(home, ".config");
  const localAppData = envValue(env, "LOCALAPPDATA") ?? join4(home, "AppData", "Local");
  files.push(
    { path: envValue(env, "NPM_CONFIG_USERCONFIG") ?? join4(home, ".npmrc"), parse: fromNpmrc, user: true },
    { path: join4(home, ".yarnrc.yml"), parse: fromYarnrcYml, user: true },
    { path: join4(home, ".yarnrc"), parse: fromYarnrc, user: true },
    { path: join4(home, ".bunfig.toml"), parse: fromBunfig, user: true },
    { path: join4(xdg, ".bunfig.toml"), parse: fromBunfig, user: true },
    { path: join4(xdg, "pnpm", "rc"), parse: fromNpmrc, user: true },
    { path: join4(localAppData, "pnpm", "config", "rc"), parse: fromNpmrc, user: true },
    { path: join4(home, "Library", "Preferences", "pnpm", "rc"), parse: fromNpmrc, user: true }
  );
  const globalConfig = envValue(env, "NPM_CONFIG_GLOBALCONFIG");
  if (globalConfig !== void 0) files.push({ path: globalConfig, parse: fromNpmrc, user: true });
  const prefix = envValue(env, "NPM_CONFIG_PREFIX") ?? ((ctx.platform ?? process.platform) === "win32" ? join4(envValue(env, "APPDATA") ?? join4(home, "AppData", "Roaming"), "npm") : dirname3(dirname3(ctx.nodeExecPath ?? process.execPath)));
  files.push({ path: join4(prefix, "etc", "npmrc"), parse: fromNpmrc, user: true });
  return files;
}
var ENV_REGISTRY = {
  npm: /^(?:YARN_NPM_REGISTRY_SERVER|YARN_REGISTRY|BUN_CONFIG_REGISTRY|npm_config_.*registry.*)$/i,
  pypi: /^(?:(?:PIP|UV)_.*INDEX.*|PIP_FIND_LINKS|UV_FIND_LINKS)$/i,
  packagist: /^$/,
  nuget: /^(?:NUGET_\w*(?:SOURCE|FEED|CONFIG)\w*|NUGET_FALLBACK_PACKAGES|NuGetPackageSourceCredentials_.+)$/i
};
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
  for (const { path, parse: parse5 } of npmConfigFiles(ctx)) {
    const text = read(path, ctx);
    if (text === void 0) continue;
    const url = parse5(text, scope);
    if (url !== void 0 && !isPublic("npm", url)) return { kind: "registry", source: path, url };
    if (authSource === void 0 && NPM_AUTH.test(text)) authSource = path;
  }
  if (scope !== void 0 && authSource !== void 0) return { kind: "auth", source: authSource };
  const local = npmWorkspacePackage(name, ctx);
  return local === void 0 ? null : { kind: "workspace", source: local };
}
function npmScopeRegistryOf(ctx = {}) {
  let prepared;
  const prepare = () => {
    try {
      const env = Object.entries(envOf(ctx)).map(([key, raw]) => ({ key, lower: key.toLowerCase(), value: raw?.trim() ?? "" }));
      const near = ancestors(ctx);
      const files = [];
      for (const { path, parse: parse5 } of npmConfigFiles(ctx)) {
        const text = read(path, ctx);
        if (text === void 0) continue;
        files.push({ path, text, parse: parse5, project: near.some((dir) => samePath(dir, dirname3(path))) });
      }
      return { env, files };
    } catch {
      return null;
    }
  };
  const answers = /* @__PURE__ */ new Map();
  return (name) => {
    const scope = npmScope(name);
    if (scope === void 0) return null;
    const known = answers.get(scope);
    if (known !== void 0) return known;
    if (prepared === void 0) prepared = prepare();
    const answer = prepared === null ? null : answerFor(scope, prepared);
    answers.set(scope, answer);
    return answer;
  };
  function answerFor(scope, from) {
    try {
      const wanted = `npm_config_@${scope.toLowerCase()}:registry`;
      for (const { key, lower, value } of from.env) {
        if (value !== "" && lower === wanted && !isPublic("npm", value)) return { scope, source: key, url: value, from: "user" };
      }
      for (const file of from.files) {
        const url = file.parse(file.text, scope);
        if (url === void 0 || url === file.parse(file.text, void 0) || isPublic("npm", url)) continue;
        return { scope, source: file.path, url, from: file.project ? "project" : "user" };
      }
    } catch {
    }
    return null;
  }
}
var PROJECT_DEFAULT_FILES = {
  npm: [{ name: ".npmrc", parse: fromNpmrc }],
  npx: [{ name: ".npmrc", parse: fromNpmrc }],
  pnpm: [{ name: ".npmrc", parse: fromNpmrc }],
  bun: [
    { name: ".npmrc", parse: fromNpmrc },
    { name: "bunfig.toml", parse: fromBunfig }
  ],
  yarn: [
    { name: ".npmrc", parse: fromNpmrc },
    { name: ".yarnrc.yml", parse: fromYarnrcYml },
    { name: ".yarnrc", parse: fromYarnrc }
  ]
};
function npmProjectDefaultRegistry(manager, ctx = {}) {
  const found = [];
  try {
    const files = Object.hasOwn(PROJECT_DEFAULT_FILES, manager) ? PROJECT_DEFAULT_FILES[manager] : void 0;
    if (files === void 0) return found;
    const near = ancestors(ctx);
    const first = near.findIndex((dir) => present(join4(dir, "package.json")));
    const from = first < 0 ? 0 : first;
    for (const dir of near.slice(from)) {
      const isBase = dir === near[from];
      const obeyed = isBase || manager === "yarn" || hasWorkspaces(read(join4(dir, "package.json"), ctx, void 0, "workspace manifest")) || manager === "pnpm" && present(join4(dir, "pnpm-workspace.yaml"));
      if (!obeyed) continue;
      for (const { name, parse: parse5 } of files) {
        const source = join4(dir, name);
        const text = read(source, ctx);
        const url = text === void 0 ? void 0 : parse5(text, void 0);
        if (url !== void 0 && !isPublic("npm", url)) found.push({ source, url });
      }
    }
  } catch {
  }
  return found;
}
function userRegistryUrl(raw) {
  let u;
  try {
    u = new URL(raw.trim().replace(/^["']|["']$/g, ""));
  } catch {
    return void 0;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return void 0;
  const publicHost = PUBLIC_HOSTS2.npm.includes(u.hostname);
  if (publicHost && u.protocol === "https:" && u.username === "" && u.password === "" && u.port === "") return void 0;
  const path = u.pathname.endsWith("/") ? u.pathname : `${u.pathname}/`;
  return `${u.origin}${path}`;
}
var ENV_USER_REGISTRY = /^(?:npm_config_(?:@[^:]+:)?registry|YARN_NPM_REGISTRY_SERVER|YARN_REGISTRY|BUN_CONFIG_REGISTRY)$/i;
function npmEnvNamesDefaultRegistry(ctx = {}) {
  try {
    return Object.entries(envOf(ctx)).some(([key, value]) => ENV_USER_REGISTRY.test(key) && !key.includes("@") && (value ?? "").trim() !== "");
  } catch {
    return false;
  }
}
function npmUserRegistries(ctx = {}) {
  const urls = /* @__PURE__ */ new Set();
  const add = (raw) => {
    const url = userRegistryUrl(raw);
    if (url !== void 0) urls.add(url);
  };
  try {
    for (const [key, value] of Object.entries(envOf(ctx))) {
      if (value !== void 0 && ENV_USER_REGISTRY.test(key)) add(value);
    }
    for (const { path, parse: parse5, user } of npmConfigFiles(ctx)) {
      if (!user) continue;
      const text = read(path, ctx);
      if (text === void 0) continue;
      const named = [];
      parse5(text, void 0, named);
      named.forEach(add);
    }
  } catch {
  }
  return [...urls];
}
var SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", ".venv", "venv", "__pycache__", "vendor", "dist", "build", "target"]);
var MAX_SCAN_DIRS = MAX_WORKSPACE_DIRS;
var MAX_SCAN_DEPTH = 5;
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
    const manifest = join4(next.dir, file);
    const r = readSmallText(manifest, MAX_REGISTRY_CONFIG_BYTES, walkRoot(manifest, ctx, root));
    if (r.status === "refused") index.unread = index.unread ?? { path: manifest, what: "workspace manifest" };
    else if (r.status === "ok") {
      const name = nameOf(r.text);
      if (name !== void 0 && !index.names.has(name)) index.names.set(name, manifest);
    }
    if (next.depth >= MAX_SCAN_DEPTH) continue;
    let entries = [];
    try {
      entries = readdirSync2(next.dir, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.name.startsWith(".") && !SKIP_DIRS.has(e.name)).map((e) => e.name);
    } catch {
      continue;
    }
    for (const e of entries) queue.push({ dir: join4(next.dir, e), depth: next.depth + 1 });
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
    const isRoot = hasWorkspaces(read(join4(dir, "package.json"), ctx, void 0, "workspace manifest")) || present(join4(dir, "pnpm-workspace.yaml"));
    if (!isRoot) continue;
    const hit = findManifest(dir, "package.json", npmManifestName, name, ctx);
    if (hit !== void 0) return hit;
  }
  return void 0;
}
var pep503 = (n) => n.trim().toLowerCase().replace(/[-_.]+/g, "-");
function uvWorkspacePackage(name, ctx) {
  const wanted = pep503(name);
  for (const dir of ancestors(ctx)) {
    const path = join4(dir, "pyproject.toml");
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
  const xdg = envValue(env, "XDG_CONFIG_HOME") ?? join4(home, ".config");
  confs.push(
    join4(xdg, "pip", "pip.conf"),
    join4(home, ".pip", "pip.conf"),
    join4(home, "Library", "Application Support", "pip", "pip.conf")
  );
  const appdata = envValue(env, "APPDATA") ?? join4(home, "AppData", "Roaming");
  confs.push(join4(appdata, "pip", "pip.ini"), join4(home, "pip", "pip.ini"));
  for (const prefix of [envValue(env, "VIRTUAL_ENV"), envValue(env, "CONDA_PREFIX")]) {
    if (prefix !== void 0) confs.push(join4(prefix, "pip.conf"), join4(prefix, "pip.ini"));
  }
  confs.push(join4(etc, "pip.conf"), join4(etc, "xdg", "pip", "pip.conf"));
  confs.push(join4(ctx.systemLibraryDir ?? "/Library", "Application Support", "pip", "pip.conf"));
  for (const d of (envValue(env, "XDG_CONFIG_DIRS") ?? "").split(":").filter(Boolean)) confs.push(join4(d, "pip", "pip.conf"));
  const programData = envValue(env, "ProgramData") ?? envValue(env, "PROGRAMDATA");
  if (programData !== void 0) confs.push(join4(programData, "pip", "pip.ini"));
  for (const path of confs) {
    const text = read(path, ctx);
    const url = text === void 0 ? void 0 : fromPipConf(text);
    if (url !== void 0) return { kind: "registry", source: path, url };
  }
  const uvConfs = [];
  const uvExplicit = envValue(env, "UV_CONFIG_FILE");
  if (uvExplicit !== void 0) uvConfs.push(uvExplicit);
  uvConfs.push(join4(xdg, "uv", "uv.toml"), join4(appdata, "uv", "uv.toml"), join4(etc, "uv", "uv.toml"));
  for (const path of uvConfs) {
    const text = read(path, ctx);
    const url = text === void 0 ? void 0 : fromUvToml(text);
    if (url !== void 0) return { kind: "registry", source: path, url };
  }
  for (const dir of ancestors(ctx)) {
    const uvToml = join4(dir, "uv.toml");
    const uvText = read(uvToml, ctx);
    const uvUrl = uvText === void 0 ? void 0 : fromUvToml(uvText);
    if (uvUrl !== void 0) return { kind: "registry", source: uvToml, url: uvUrl };
    const pyproject = join4(dir, "pyproject.toml");
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
    const path = join4(dir, "composer.json");
    const text = read(path, ctx);
    if (text === void 0) continue;
    if (hasRepositories(text)) return { kind: "registry", source: path };
    break;
  }
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const composerHome = envValue(env, "COMPOSER_HOME");
  const globals = composerHome !== void 0 ? [join4(composerHome, "config.json")] : [join4(home, ".composer", "config.json"), join4(home, ".config", "composer", "config.json"), join4(envValue(env, "APPDATA") ?? join4(home, "AppData", "Roaming"), "Composer", "config.json")];
  for (const path of globals) if (hasRepositories(read(path, ctx))) return { kind: "registry", source: path };
  return null;
}
function nugetConfigIn(dir, ctx) {
  const hit = listDir(dir, ctx).find((f) => f.toLowerCase() === "nuget.config");
  return hit === void 0 ? void 0 : join4(dir, hit);
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
  const dir = resolve3(dirname3(configPath), portable.replace(/[\\/]+$/, ""));
  const lower = id.toLowerCase();
  return listDir(dir, ctx).some((entry) => {
    const e = entry.toLowerCase();
    return e === lower || nupkgIds(e).includes(lower);
  });
}
var NUGET_VERSION = /^\d+(?:\.\d+){0,3}(?:-[0-9a-z-]+(?:\.[0-9a-z-]+)*)?(?:\+[0-9a-z-]+(?:\.[0-9a-z-]+)*)?$/i;
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
    let dir = resolve3(ctx.projectDir);
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
  const appdata = envValue(env, "APPDATA") ?? join4(home, "AppData", "Roaming");
  for (const dir of [join4(appdata, "NuGet"), join4(home, ".nuget", "NuGet"), join4(home, ".config", "NuGet")]) {
    const f = nugetConfigIn(dir, ctx);
    if (f !== void 0) files.push(f);
  }
  const userDirs = [join4(appdata, "NuGet", "config"), join4(home, ".nuget", "config"), join4(home, ".config", "NuGet", "config")];
  const machineDirs = [
    join4(ctx.etcDir ?? "/etc", "opt", "NuGet", "Config"),
    join4(ctx.systemLibraryDir ?? "/Library", "Application Support", "NuGet", "Config")
  ];
  const programFilesX86 = envValue(env, "ProgramFiles(x86)");
  if (programFilesX86 !== void 0) machineDirs.push(join4(programFilesX86, "NuGet", "Config"));
  const machineWide = /* @__PURE__ */ new Set();
  for (const dir of [...userDirs, ...machineDirs]) {
    for (const f of listDir(dir, ctx).filter((e) => /\.config$/i.test(e)).sort()) {
      files.push(join4(dir, f));
      if (machineDirs.includes(dir)) machineWide.add(join4(dir, f));
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
  let found;
  try {
    switch (ecosystem) {
      case "npm":
        found = npmRegistry(name, ctx);
        break;
      case "pypi":
        found = pypiRegistry(name, ctx);
        break;
      case "packagist":
        found = composerRegistry(ctx);
        break;
      case "nuget":
        found = nugetRegistry(name, ctx);
        break;
      default:
        found = null;
    }
  } catch {
    found = null;
  }
  const unread = takeUnread();
  const unchecked = takeUnchecked();
  if (found !== null) return found;
  if (unchecked !== void 0) return { kind: "unchecked", source: unchecked.root, cut: unchecked.cut };
  return unread !== void 0 ? { kind: "unreadable", source: unread.path, what: unread.what } : null;
}

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
    let json;
    try {
      json = await res.json();
    } catch (e) {
      if (e instanceof SyntaxError) return { kind: "error", reason: `${new URL(url).host} gave an answer that is not JSON` };
      throw e;
    }
    return { kind: "ok", json };
  } catch (e) {
    return { kind: "error", reason: describeError(e, http.signal) };
  }
}
function isRecord2(x) {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}
function stringRecord(x) {
  const out = {};
  if (!isRecord2(x)) return out;
  for (const [k, v] of Object.entries(x)) if (typeof v === "string") out[k] = v;
  return out;
}
function npmDocUrl(name) {
  return `https://registry.npmjs.org/${name.replace("/", "%2F")}`;
}
async function lookupNpm(name, http) {
  const r = await fetchJson(npmDocUrl(name), http, { accept: "application/vnd.npm.install-v1+json" });
  if (r.kind !== "ok") return r;
  if (!isRecord2(r.json) || !isRecord2(r.json["versions"])) return { kind: "error", reason: "npm registry returned an unexpected document" };
  const versions = Object.keys(r.json["versions"]);
  const installScript = {};
  for (const [v, meta] of Object.entries(r.json["versions"])) {
    if (isRecord2(meta) && meta["hasInstallScript"] === true) installScript[v] = true;
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
  if (!isRecord2(r.json)) return { kind: "error", reason: "npm registry returned an unexpected document" };
  const scripts = {};
  const versions = r.json["versions"];
  if (isRecord2(versions)) {
    for (const [v, meta] of Object.entries(versions)) {
      if (isRecord2(meta)) scripts[v] = stringRecord(meta["scripts"]);
    }
  }
  return { kind: "ok", times: stringRecord(r.json["time"]), scripts };
}
async function npmVersionScripts(name, version, http) {
  const r = await fetchJson(`${npmDocUrl(name)}/${encodeURIComponent(version)}`, http);
  if (r.kind === "not_found") return { kind: "error", reason: "version manifest not found" };
  if (r.kind === "error") return r;
  return { kind: "ok", scripts: isRecord2(r.json) ? stringRecord(r.json["scripts"]) : {} };
}
async function lookupPypi(name, http) {
  const r = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, http);
  if (r.kind !== "ok") return r;
  if (!isRecord2(r.json) || !isRecord2(r.json["info"])) return { kind: "error", reason: "PyPI returned an unexpected document" };
  const releases = isRecord2(r.json["releases"]) ? r.json["releases"] : {};
  const times = {};
  const versions = [];
  for (const [v, files] of Object.entries(releases)) {
    if (!Array.isArray(files) || files.length === 0) continue;
    versions.push(v);
    let earliest;
    for (const f of files) {
      const t = isRecord2(f) ? f["upload_time_iso_8601"] ?? f["upload_time"] : void 0;
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
  const pkgs = isRecord2(r.json) ? r.json["packages"] : void 0;
  const list = isRecord2(pkgs) ? pkgs[lower] : void 0;
  if (!Array.isArray(list)) return { kind: "error", reason: "Packagist returned an unexpected document" };
  let carried = {};
  const versions = [];
  const times = {};
  for (const entry of list) {
    if (!isRecord2(entry)) continue;
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
  const versions = isRecord2(r.json) && Array.isArray(r.json["versions"]) ? r.json["versions"].filter((v) => typeof v === "string") : null;
  if (versions === null) return { kind: "error", reason: "NuGet returned an unexpected document" };
  return { kind: "found", info: { versions, times: {}, installScript: {} } };
}
function nugetSearchUrl(id) {
  return `https://azuresearch-usnc.nuget.org/query?q=${encodeURIComponent(`packageid:${id.toLowerCase()}`)}&prerelease=true&semVerLevel=2.0.0&take=1`;
}
async function nugetCanonicalId(id, http) {
  const r = await fetchJson(nugetSearchUrl(id), http);
  if (r.kind !== "ok" || !isRecord2(r.json) || !Array.isArray(r.json["data"])) return void 0;
  for (const entry of r.json["data"]) {
    const found = isRecord2(entry) ? entry["id"] : void 0;
    if (typeof found === "string" && found.toLowerCase() === id.toLowerCase()) return found;
  }
  return void 0;
}
async function nugetPublished(name, version, http) {
  const url = `https://api.nuget.org/v3/registration5-gz-semver2/${encodeURIComponent(name.toLowerCase())}/${encodeURIComponent(version.toLowerCase())}.json`;
  const r = await fetchJson(url, http);
  if (r.kind === "not_found") return { kind: "error", reason: "NuGet registration leaf not found" };
  if (r.kind === "error") return r;
  const published = isRecord2(r.json) ? r.json["published"] : void 0;
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

// src/pkgvet/types.ts
var OSV_ECOSYSTEM = {
  npm: "npm",
  pypi: "PyPI",
  packagist: "Packagist",
  nuget: "NuGet"
};

// src/pkgvet/vet.ts
var FRESH_HOURS = 72;
var HOOK_BUDGET_MS = 3e3;
var TOOL_BUDGET_MS = 1e4;
var HOUR = 3600 * 1e3;
var NPM_PLACEHOLDER = /^0\.0\.\d+-security$/;
var INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"];
var REGISTRY_NAME = {
  npm: "the npm registry",
  pypi: "PyPI",
  packagist: "Packagist",
  nuget: "nuget.org"
};
var TIME_BUDGET = "vetting time budget exhausted";
var NOT_REPORTED = "not checked: the caller does not report it";
function popularIndexFor(ecosystem, opts) {
  const override = opts.popular?.[ecosystem];
  if (override === null) return null;
  if (override !== void 0) return buildPopularIndex(ecosystem, override);
  return opts.popularDir === void 0 ? loadPopularIndex(ecosystem) : loadPopularIndex(ecosystem, opts.popularDir);
}
var pass = (detail) => detail === void 0 ? { status: "pass" } : { status: "pass", detail };
var warn = (detail) => ({ status: "warn", detail });
var fail = (detail) => ({ status: "fail", detail });
var unknown = (detail) => ({ status: "unknown", detail });
var na = (detail) => detail === void 0 ? { status: "not_applicable" } : { status: "not_applicable", detail };
function hoursAgo(iso, now) {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? (now - t) / HOUR : void 0;
}
function ageText(hours) {
  if (hours < FRESH_HOURS) return `${Math.max(0, Math.round(hours))} h ago`;
  const days = hours / 24;
  return days < 10 ? `${Math.round(days * 10) / 10} days ago` : `${Math.round(days)} days ago`;
}
var needsNoExtras = (w) => w.unreported?.has("publish_age") === true && w.unreported.has("install_scripts");
function registryHost(ecosystem, value) {
  let named;
  for (const token of value.split(/\s+/)) {
    const candidate = token.replace(/^[^=:/?#@]+=(?=https?:\/\/)/i, "");
    const url = parsedHttpUrl(candidate);
    if (url === void 0) {
      if (candidate.includes("@")) return void 0;
      continue;
    }
    if (url.pathname.includes("@") || url.search.includes("@") || url.hash.includes("@")) return void 0;
    if (named === void 0 && !isPublicRegistryUrl(ecosystem, candidate)) named = `${url.protocol}//${url.hostname}`;
  }
  return named;
}
function parsedHttpUrl(text) {
  try {
    const url = new URL(text);
    return (url.protocol === "https:" || url.protocol === "http:") && url.hostname !== "" ? url : void 0;
  } catch {
    return void 0;
  }
}
function customFor(spec2, opts) {
  const onCommandLine = (opts.commandRegistries ?? []).find((u) => !isPublicRegistryUrl(spec2.ecosystem, u));
  if (onCommandLine !== void 0) return { kind: "registry", source: "the command line", url: onCommandLine };
  return customRegistryFor(spec2.ecosystem, spec2.name, opts.registry ?? {});
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
function typosquatCheck(w) {
  if (!w.popularLoaded) return unknown("popular-packages list unavailable \u2014 typosquat check not run");
  if (w.typo === null) return pass();
  return warn(`name is ${w.typo.distance} edit${w.typo.distance === 1 ? "" : "s"} from the popular package '${w.typo.similar_to}' \u2014 possible typosquat`);
}
var PINNED_ELSEWHERE = "not checked: the lockfile pins this version, which is asked of OSV on its own";
function vetTyposquatOnly(specs, opts = {}) {
  const indexes = /* @__PURE__ */ new Map();
  return specs.map((spec2) => {
    if (!indexes.has(spec2.ecosystem)) indexes.set(spec2.ecosystem, popularIndexFor(spec2.ecosystem, opts));
    const index = indexes.get(spec2.ecosystem) ?? null;
    const w = { spec: spec2, typo: index === null ? null : findTyposquatTarget(index, spec2.name), popularLoaded: index !== null };
    const typosquat = typosquatCheck(w);
    const checks = {
      exists: na(PINNED_ELSEWHERE),
      malicious: na(PINNED_ELSEWHERE),
      vulnerabilities: na(PINNED_ELSEWHERE),
      publish_age: na(PINNED_ELSEWHERE),
      install_scripts: spec2.ecosystem === "npm" ? na(PINNED_ELSEWHERE) : na("install-script check is npm-only"),
      typosquat
    };
    const verdict = typosquat.status === "warn" ? "warn" : typosquat.status === "unknown" ? "unknown" : "ok";
    const result = {
      ecosystem: spec2.ecosystem,
      name: spec2.name,
      verdict,
      reasons: typosquat.detail !== void 0 && typosquat.status !== "pass" ? [typosquat.detail] : [],
      checks
    };
    if (spec2.range !== void 0) result.requested = spec2.range;
    if (w.typo !== null) result.similar_to = w.typo.similar_to;
    return result;
  });
}
function buildResult(w, osv, osvError, now, offlineReason) {
  const { spec: spec2 } = w;
  const eco = spec2.ecosystem;
  const registry = REGISTRY_NAME[eco];
  const lookup = w.lookup;
  const info = lookup?.kind === "found" ? lookup.info : void 0;
  const extraWarn = [];
  const extraUnknown = [];
  const typosquat = typosquatCheck(w);
  const askedByNameOnly = w.osvVersioned === false && w.version !== void 0;
  const ids = osvIds(osv, w);
  const malIds = ids.filter((id) => id.startsWith("MAL-"));
  const vulnIds = askedByNameOnly ? [] : ids.filter((id) => !id.startsWith("MAL-"));
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
    malicious = malIds.length > 0 ? warn(`OSV lists malicious advisories for this name (${malIds.join(", ")}); the version could not be determined`) : osvDown !== void 0 ? unknown(osvDown) : pass("no OSV malicious-package advisory for any version");
    vulnerabilities = unknown(`version unknown: ${lookup.reason}`);
    publishAge = unknown(`version unknown: ${lookup.reason}`);
    if (eco === "npm") installScripts = unknown(`version unknown: ${lookup.reason}`);
  } else if (lookup.kind === "not_found") {
    const didYouMean = w.typo !== null ? ` Did you mean '${w.typo.similar_to}'?` : "";
    const custom = w.custom ?? null;
    if (custom !== null) {
      const host = custom.url === void 0 ? void 0 : registryHost(eco, custom.url);
      const where = `${custom.source}${host !== void 0 ? `: ${host}` : ""}`;
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
    if (w.versionMissing === true) extraWarn.push(`requested version ${spec2.range ?? ""} is not published on ${registry} \u2014 possibly a hallucinated version`);
    else if (v === void 0) extraUnknown.push(`no published version matches '${spec2.range ?? ""}'`);
    const versionUnknown = v === void 0 ? `could not determine which version '${spec2.range ?? "latest"}' installs` : void 0;
    if (placeholder) {
      malicious = fail(`npm replaced this package with a security placeholder (${placeholderVersion ?? "x-security"}): it was taken down as malicious`);
    } else if (malIds.length > 0) {
      malicious = w.osvVersioned ? fail(`OSV malicious-package advisory for ${v ?? "this version"}: ${malIds.join(", ")}`) : warn(
        askedByNameOnly ? `OSV lists malicious advisories for some versions of this package (${malIds.join(", ")}) \u2014 whether ${v ?? "this version"} is one of them was not determined in time` : `OSV lists malicious advisories for some versions of this package (${malIds.join(", ")}) \u2014 which version installs could not be determined`
      );
    } else if (osvDown !== void 0) {
      malicious = unknown(osvDown);
    } else {
      malicious = askedByNameOnly ? pass("no OSV malicious-package advisory for any version") : pass();
    }
    if (osvDown !== void 0) vulnerabilities = unknown(osvDown);
    else if (askedByNameOnly) vulnerabilities = unknown(`vulnerabilities of ${v ?? "this version"} not determined: OSV was asked for the name before the registry answered`);
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
    if (w.unreported?.has("publish_age") === true) publishAge = na(NOT_REPORTED);
    if (eco === "npm" && w.unreported?.has("install_scripts") === true) installScripts = na(NOT_REPORTED);
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
  const result = { ecosystem: eco, name: spec2.name, verdict, reasons: [...new Set(reasons)], checks };
  if (spec2.range !== void 0) result.requested = spec2.range;
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
  const work = specs.map((spec2) => {
    if (!indexes.has(spec2.ecosystem)) indexes.set(spec2.ecosystem, popularIndexFor(spec2.ecosystem, opts));
    const index = indexes.get(spec2.ecosystem) ?? null;
    return {
      spec: spec2,
      typo: index === null ? null : findTyposquatTarget(index, spec2.name),
      popularLoaded: index !== null,
      ...opts.unreported !== void 0 ? { unreported: opts.unreported } : {}
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
function answeredQuery(osv, q) {
  if (osv.online) return true;
  return q !== void 0 && osv.unanswered !== void 0 && !osv.unanswered.includes(q);
}
function viewFor(osv, w) {
  return !osv.online && answeredQuery(osv, w.osvQuery) ? { ...osv, online: true } : osv;
}
async function networkRounds(work, http, signal, deadline, now, explain) {
  const fetchImpl = http.fetchImpl;
  const halfBudgetMs = Math.max(0, (deadline - Date.now()) / 2);
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
  const extras = [];
  const allSettled = Promise.all(
    work.map(
      (w, i) => (pending[i] ?? Promise.resolve(void 0)).then((answer) => {
        if (answer !== void 0) w.lookup = answer;
        if (answer?.kind === "found") {
          resolveFor(w, answer.info);
          if (!needsNoExtras(w)) extras.push(extrasFor(w, answer.info, http, now).catch(() => void 0));
        }
      })
    )
  );
  let halfTimer;
  const halfPassed = new Promise((resolve5) => {
    halfTimer = setTimeout(() => resolve5("half"), halfBudgetMs);
  });
  const first = await Promise.race([allSettled.then(() => "answered"), halfPassed]);
  clearTimeout(halfTimer);
  let osvAsked;
  if (first === "half" && !signal.aborted) osvAsked = askOsv(work, canonical, fetchImpl, signal, deadline, true);
  await allSettled;
  if (osvAsked === void 0) {
    if (signal.aborted) {
      const why = "network budget exhausted before OSV was consulted";
      for (const w of work) if (w.lookup?.kind === "not_found") explain(w);
      return work.map((w) => buildResult(w, void 0, why, now, void 0));
    }
    osvAsked = askOsv(work, canonical, fetchImpl, signal, deadline, false);
  }
  const extrasDone = Promise.all(extras);
  const { result: osv, error } = await osvAsked;
  await Promise.all([extrasDone, askVersionsOfLate(work, osv, fetchImpl, signal, deadline)]);
  let osvError = error;
  if (signal.aborted && osv.online === false && osvError === void 0 && osv.error === void 0) osvError = "network budget exhausted before OSV answered";
  for (const w of work) if (w.lookup?.kind === "not_found") explain(w);
  return work.map((w) => buildResult(w, w.osvSecond ?? viewFor(osv, w), osvError ?? (osv.online ? void 0 : osv.error), now, void 0));
}
function askOsv(work, canonical, fetchImpl, signal, deadline, mixed) {
  const versions = work.map((w) => w.version);
  work.forEach((w, i) => {
    w.osvVersioned = versions[i] !== void 0;
    if (mixed && w.lookup === void 0) w.late = true;
  });
  let error;
  return (async () => {
    const queries = [];
    for (const [i, w] of work.entries()) {
      const canonicalId = await (canonical.get(w.spec.name.toLowerCase()) ?? Promise.resolve(void 0));
      w.osvName = osvNameFor(w, canonicalId);
      const q = { ecosystem: OSV_ECOSYSTEM[w.spec.ecosystem], name: w.osvName };
      const v = versions[i];
      if (v !== void 0) q.version = v;
      w.osvIndex = queries.length;
      w.osvQuery = q;
      queries.push(q);
    }
    return queryOsv(queries, { ...fetchImpl !== void 0 ? { fetchImpl } : {}, signal, timeoutMs: Math.max(1, deadline - Date.now()) });
  })().catch((e) => {
    error = e instanceof Error ? e.message : String(e);
    return { online: false, queried: 0, unqueried: 0, vulnerable_packages: [] };
  }).then((result) => ({ result, error }));
}
async function askVersionsOfLate(work, first, fetchImpl, signal, deadline) {
  if (signal.aborted) return;
  const second = /* @__PURE__ */ new Map();
  for (const w of work) {
    if (w.late !== true || w.lookup?.kind !== "found" || w.version === void 0 || w.osvName === void 0) continue;
    if (!osvIds(first, w).some((id) => id.startsWith("MAL-"))) continue;
    second.set(w, { ecosystem: OSV_ECOSYSTEM[w.spec.ecosystem], name: w.osvName, version: w.version });
  }
  if (second.size === 0) return;
  let answer;
  try {
    answer = await queryOsv([...second.values()], {
      ...fetchImpl !== void 0 ? { fetchImpl } : {},
      signal,
      timeoutMs: Math.max(1, deadline - Date.now())
    });
  } catch {
    return;
  }
  for (const [w, q] of second) {
    const before = { osvVersioned: w.osvVersioned, osvQuery: w.osvQuery };
    w.osvVersioned = true;
    w.osvQuery = q;
    if (answeredQuery(answer, q) || osvIds(answer, w).some((id) => id.startsWith("MAL-"))) w.osvSecond = viewFor(answer, w);
    else Object.assign(w, before);
  }
}

// src/pkgvet/pins.ts
var MAX_PINS = 8e3;
var BATCH = 500;
var IN_FLIGHT2 = 16;
var REQUEST_GRACE_MS = 250;
var keyOf = (p) => `${p.name}@${p.version}`;
function choosePins(pins, opts) {
  const seen = /* @__PURE__ */ new Set();
  const first = [];
  const second = [];
  const third = [];
  for (const pin of pins) {
    const key = keyOf(pin);
    if (seen.has(key)) continue;
    seen.add(key);
    if (opts.direct.has(pin.name)) first.push(pin);
    else if (!opts.popular(pin.name)) second.push(pin);
    else third.push(pin);
  }
  const all = [...first, ...second, ...third];
  return { chosen: all.slice(0, MAX_PINS), left: Math.max(0, all.length - MAX_PINS) };
}
function allUnknown(pins, unknown2) {
  return pins.map((pin) => ({ pin, malicious: null, unknown: unknown2 }));
}
async function vetPins(pins, opts = {}) {
  if (pins.length === 0) return [];
  const offline = opts.offline ?? process.env["GUARDIAN_OFFLINE"] === "1";
  if (offline) return allUnknown(pins, "network disabled (GUARDIAN_OFFLINE=1)");
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === "function" ? fetch : void 0);
  if (fetchImpl === void 0) return allUnknown(pins, "no fetch implementation available");
  const left = opts.deadlineAt === void 0 ? Number.POSITIVE_INFINITY : opts.deadlineAt - Date.now();
  if (left <= 0) return allUnknown(pins, "vetting time budget exhausted");
  const budgetMs = Math.max(1, Math.min(opts.budgetMs ?? TOOL_BUDGET_MS, left));
  const deadline = Date.now() + budgetMs;
  const budget = new AbortController();
  const timer = setTimeout(() => budget.abort(new Error("network budget exhausted")), budgetMs);
  const signal = opts.signal === void 0 ? budget.signal : AbortSignal.any([opts.signal, budget.signal]);
  try {
    const osv = await queryOsv(
      pins.map((p) => ({ ecosystem: "npm", name: p.name, version: p.version })),
      // Each request's own timeout ends AFTER the budget: the budget's abort is what stops a request that never
      // answers. With the two set to end together, which timer fired first decided the reason that was said — the
      // budget's phrase or the request's bare "aborted" — and under load it was sometimes the request's.
      { fetchImpl, signal, timeoutMs: Math.max(1, deadline - Date.now()) + REQUEST_GRACE_MS, chunk: BATCH, inFlight: IN_FLIGHT2, maxQueries: MAX_PINS }
    );
    const mal = /* @__PURE__ */ new Map();
    for (const g of osv.vulnerable_packages) {
      const ids = g.vuln_ids.filter((id) => id.trim().toUpperCase().startsWith("MAL-"));
      if (ids.length > 0 && g.version !== void 0) mal.set(`${g.name}@${g.version}`, ids);
    }
    const unanswered = new Set(osv.unanswered.map((q) => `${q.name}@${q.version ?? ""}`));
    const ranOut = signal.aborted || Date.now() >= deadline;
    const why = ranOut ? "network budget exhausted before OSV answered" : osv.error ?? "OSV gave no complete answer";
    const asked = new Set(pins.slice(0, MAX_PINS).map(keyOf));
    return pins.map((pin) => {
      const key = keyOf(pin);
      const ids = mal.get(key);
      if (ids !== void 0) return { pin, malicious: ids };
      if (!asked.has(key)) return { pin, malicious: null, unknown: `not asked: more than ${MAX_PINS} pins in one call` };
      if (unanswered.has(key)) return { pin, malicious: null, unknown: why };
      return { pin, malicious: [] };
    });
  } finally {
    clearTimeout(timer);
  }
}

// src/pkgvet/hookDecision.ts
var DEFAULT_DEADLINE_MS = 8e3;
var MAX_DEADLINE_MS = 12e3;
function vetDeadlineMs(env) {
  const raw = env["GUARDIAN_PKG_VET_DEADLINE_MS"]?.trim();
  if (raw === void 0 || !/^\d+$/.test(raw)) return DEFAULT_DEADLINE_MS;
  return Math.min(Math.max(Number(raw), HOOK_BUDGET_MS), MAX_DEADLINE_MS);
}
function label2(r) {
  return r.version !== void 0 ? `${r.name}@${r.version}` : r.name;
}
function firstLine(r) {
  return r.reasons[0] ?? "no reason recorded";
}
var MAX_VETTED_PACKAGES = MAX_CANDIDATES_PER_COMMAND;
var MAX_MANIFEST_PACKAGES = 150;
var MANIFEST_UNREPORTED = /* @__PURE__ */ new Set(["publish_age", "install_scripts"]);
var MAX_PARSED_LENGTH = 512 * 1024;
function boundedInstalls(command, shell, isPopular, runsLocally, nested = [], cdpath = false, withManifests = (parsed) => [...parsed]) {
  const cut = command.length > MAX_PARSED_LENGTH;
  const parsed = withManifests(
    parseInstallCommands(cut ? command.slice(0, MAX_PARSED_LENGTH) : command, { shell, nested, cdpath }).map(
      (c) => (
        // `npx`, `npm exec` and `bunx` run a bin the project has installed, and
        // fetch nothing: there is nothing to vet (review P1).
        c.localFirst === true ? { ...c, packages: c.packages.filter((p) => !runsLocally(p, c)) } : c
      )
    )
  );
  const key = (pkg) => `${pkg.ecosystem}\0${pkg.name.toLowerCase()}\0${pkg.range ?? ""}`;
  const seen = /* @__PURE__ */ new Set();
  const named = [];
  const ofManifests = [];
  for (const c of parsed) {
    for (const pkg of c.packages) {
      if (seen.has(key(pkg))) continue;
      seen.add(key(pkg));
      (c.fromManifest === void 0 ? named : ofManifests).push(pkg);
    }
  }
  const firstOf = (unique, cap) => [...unique.filter((p) => !isPopular(p)), ...unique.filter(isPopular)].slice(0, cap).map(key);
  const chosen = /* @__PURE__ */ new Set([...firstOf(named, MAX_VETTED_PACKAGES), ...firstOf(ofManifests, MAX_MANIFEST_PACKAGES)]);
  const commands = [];
  for (const c of parsed) {
    const packages = c.packages.filter((pkg) => chosen.delete(key(pkg)));
    if (packages.length === 0) continue;
    const uncertain = cut ? [...c.uncertain, "the command is over 512 KB and only its start was read"] : c.uncertain;
    commands.push({ ...c, packages, uncertain });
  }
  return {
    commands,
    // The candidates the parse left out past its own ceiling count as packages not vetted.
    notVetted: Math.max(0, named.length - MAX_VETTED_PACKAGES) + parsed.reduce((n, c) => n + (c.candidatesDropped ?? 0), 0),
    manifestNotVetted: Math.max(0, ofManifests.length - MAX_MANIFEST_PACKAGES),
    cut
  };
}
var NAMED_BY_MANIFEST = "it is named by a manifest, where a missing name is usually a private or a workspace package";
var plural = (n) => n === 1 ? "1 package" : `${String(n)} packages`;
function withManifestPackages(parsed, opts, registry, notes, locked) {
  const out = [];
  const lineAsked = /* @__PURE__ */ new Map();
  let userRegistries;
  const user = () => userRegistries ??= npmUserRegistries(registry);
  for (const c of parsed) {
    out.push(c);
    const key = `${c.manager}\0${JSON.stringify(c.workdir)}\0${String(c.prefixed)}\0${String(c.registries.length > 0)}\0${String(c.global === true)}`;
    if (!lineAsked.has(key)) lineAsked.set(key, projectDefaultRegistryLines(c, opts, registry, user));
    notes.push(...lineAsked.get(key) ?? []);
    const manifest = c.manifest;
    if (manifest === void 0) continue;
    const dir = c.prefixed === true ? null : commandDir(c, opts);
    if (dir === null) {
      const what = manifest.kind === "package-json" ? "package.json" : "the requirements file";
      notes.push(`dev-guardian: ${what} was not read (${UNKNOWN_DIRECTORY}) \u2014 its packages were not vetted.`);
      continue;
    }
    let reads;
    try {
      reads = manifest.kind === "package-json" ? [readNpmManifest(dir, c.manager)] : readRequirements(dir, manifest.files, c.manager);
    } catch {
      notes.push("dev-guardian: the manifest was not read (could not be read) \u2014 its packages were not vetted.");
      continue;
    }
    for (const read2 of reads) {
      if (read2.status === "absent") continue;
      const lock = c.ecosystem === "npm" && manifest.kind === "package-json" ? lockedProject(c, dir, read2, opts, registry, notes) : void 0;
      if (lock !== void 0) locked.push(lock);
      if (read2.status === "unreadable") {
        notes.push(`dev-guardian: ${read2.file} was not read (${read2.reason ?? "could not be read"}) \u2014 its packages were not vetted.`);
        continue;
      }
      if (read2.incomplete !== void 0) {
        notes.push(`dev-guardian: a file ${read2.file} includes was not read (${read2.incomplete}) \u2014 its packages were not vetted.`);
      }
      const inScope = c.ecosystem === "npm" ? withoutOwnRegistryScopes(read2, { ...registry, projectDir: dir }, notes) : read2.packages;
      const packages = lock === void 0 ? inScope : withoutCovered(inScope, lock);
      if (packages.length === 0) continue;
      const registries = [...c.registries, ...read2.registries];
      const custom = c.customRegistry ?? read2.registries[0];
      out.push({
        ...c,
        packages,
        skipped: [],
        uncertain: [NAMED_BY_MANIFEST],
        registries,
        ...custom !== void 0 ? { customRegistry: custom } : {},
        fromManifest: read2.file
      });
    }
  }
  return out;
}
var MAX_REGISTRY_LINES = 3;
function projectDefaultRegistryLines(c, opts, registry, userRegistries) {
  try {
    if (c.ecosystem !== "npm" || c.registries.length > 0 || c.prefixed === true || c.global === true || npmEnvNamesDefaultRegistry(registry)) return [];
    const dir = commandDir(c, opts);
    if (dir === null) return [];
    const found = npmProjectDefaultRegistry(c.manager, { ...registry, projectDir: dir }).filter((f) => !fromUserRegistry(f.url, userRegistries()));
    const lines = found.slice(0, MAX_REGISTRY_LINES).map((f) => {
      const host = registryHost("npm", f.url);
      return `dev-guardian: the project's ${basename2(f.source)} sets the default registry${host === void 0 ? "" : ` (${host})`} \u2014 packages are fetched from it, and what it serves was not vetted.`;
    });
    const rest = found.length - lines.length;
    if (rest > 0) lines.push(rest === 1 ? "dev-guardian: 1 more file of the project sets the default registry." : `dev-guardian: ${rest} more files of the project set the default registry.`);
    return lines;
  } catch {
    return [];
  }
}
function withoutOwnRegistryScopes(read2, registry, notes) {
  const kept = [];
  const scopeRegistry = npmScopeRegistryOf(registry);
  const byProject = /* @__PURE__ */ new Set();
  let held = 0;
  let source = "";
  for (const pkg of read2.packages) {
    const own = pkg.name.startsWith("@") ? scopeRegistry(pkg.name) : null;
    if (own === null) {
      kept.push(pkg);
      continue;
    }
    if (own.from !== "project") continue;
    held += 1;
    byProject.add(`@${own.scope}`);
    if (source === "") source = basename2(own.source);
  }
  if (held > 0) notes.push(ownScopeLine(held, read2.file, byProject, source));
  return kept;
}
function ownScopeLine(held, file, scopes, source) {
  const named = [...scopes].slice(0, MAX_NAMED_HOSTS).join(", ");
  const more = scopes.size > MAX_NAMED_HOSTS ? ` and ${scopes.size - MAX_NAMED_HOSTS} more` : "";
  return `dev-guardian: ${plural(held)} of ${file} ${held === 1 ? "is" : "are"} in a scope (${named}${more}) the project's ${source} gives a registry of its own \u2014 not vetted.`;
}
var MAX_LOCKFILE_BYTES = 16 * 1024 * 1024;
var MAX_NAMED_HOSTS = 3;
var MAX_NAMED_IDS = 5;
var MAX_NAMED_DENIES = 20;
var MAX_REASON_LENGTH = 120;
var pairKey = (p) => `${p.name}@${p.version}`;
function said(text) {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").trim();
  return clean === "" ? "no reason recorded" : clean.length > MAX_REASON_LENGTH ? `${clean.slice(0, MAX_REASON_LENGTH)}\u2026` : clean;
}
function pinReason(unknown2) {
  const text = unknown2 ?? "";
  if (/^(?:network disabled \(GUARDIAN_OFFLINE=1\)|no fetch implementation available|vetting time budget exhausted|network budget exhausted before OSV answered)$/.test(text)) return text;
  const http = /^osv http (\d{3})$/.exec(text);
  if (http !== null) return `OSV answered HTTP ${http[1] ?? ""}`;
  if (/^osv (?:answered|left) \d+ /.test(text) || /^osv answer over /.test(text)) return "OSV gave an incomplete answer";
  if (/JSON/.test(text)) return "OSV gave an answer that is not JSON";
  return "OSV lookup failed";
}
var notReadLine = (file, why) => `dev-guardian: ${file} was not read (${said(why)}) \u2014 its packages were not vetted.`;
function isWithin(root, dir) {
  const rel = relative3(resolve4(root), resolve4(dir));
  return rel === "" || rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute3(rel);
}
function findLockfile(manager, dir, projectDir) {
  const names = manager === "npm" || manager === "pnpm" || manager === "yarn" || manager === "bun" ? LOCKFILES[manager] : [];
  if (names.length === 0) return { status: "absent" };
  const root = projectDir !== void 0 && isWithin(projectDir, dir) ? resolve4(projectDir) : resolve4(dir);
  if (isNetworkPath(dir) || isNetworkPath(root)) return { status: "absent" };
  const candidates = manager === "bun" ? [...names, "bun.lockb"] : names;
  let at = resolve4(dir);
  for (let i = 0; i < 64; i += 1) {
    for (const file of candidates) {
      const path = join5(at, file);
      if (file === "bun.lockb") {
        if (presentBelow(root, path)) return { status: "unread", file, why: "it is bun's binary lockfile" };
        continue;
      }
      const read2 = readSmallText(path, MAX_LOCKFILE_BYTES, root);
      if (read2.status === "ok") return { status: "ok", file, dir: at, text: read2.text };
      if (read2.status === "refused") return { status: "unread", file, why: refusedWhy(read2.reason) };
    }
    const parent = dirname4(at);
    if (relative3(root, at) === "" || parent === at) break;
    at = parent;
  }
  return { status: "absent" };
}
function refusedWhy(reason) {
  switch (reason) {
    case "not-a-regular-file":
      return "not a regular file";
    case "too-large":
      return "over 16 MiB";
    case "remote-link":
      return "on a network path";
    default:
      return "could not be read";
  }
}
function fromUserRegistry(url, registries) {
  let normal;
  try {
    const u = new URL(url);
    normal = `${u.origin}${u.pathname.endsWith("/") ? u.pathname : `${u.pathname}/`}`;
  } catch {
    return false;
  }
  return registries.some((registry) => normal.startsWith(registry));
}
function otherSources(read2, userRegistries) {
  const hosts = /* @__PURE__ */ new Set();
  const named = [];
  let count = 0;
  for (const { source } of read2.entries) {
    if (!isOtherSource(source, userRegistries)) continue;
    count += 1;
    if ("host" in source && source.host !== "" && !hosts.has(source.host)) {
      hosts.add(source.host);
      if (named.length < MAX_NAMED_HOSTS) named.push(source.host);
    }
  }
  return { count, named, distinct: hosts.size };
}
function isOtherSource(source, userRegistries) {
  if (source.kind === "git") return true;
  return source.kind === "elsewhere" && !fromUserRegistry(source.url, userRegistries());
}
function otherSourceLine(count, file, named, distinct) {
  const hosts = named.length === 0 ? "" : ` (${named.join(", ")}${distinct > named.length ? ` and ${distinct - named.length} more` : ""})`;
  return `dev-guardian: ${plural(count)} of ${file} ${count === 1 ? "comes" : "come"} from another source${hosts} \u2014 what it serves was not vetted.`;
}
function pairsToAsk(read2, registry) {
  const asked = [];
  const askedKeys = /* @__PURE__ */ new Set();
  const heldKeys = /* @__PURE__ */ new Set();
  const scopes = /* @__PURE__ */ new Set();
  let source = "";
  const ownRegistry = npmScopeRegistryOf(registry);
  for (const entry of read2.entries) {
    if (entry.source.kind === "git") continue;
    for (const pin of [entry.pin, entry.fetched]) {
      if (pin === void 0) continue;
      const key = pairKey(pin);
      const own = entry.source.kind === "public" ? null : ownRegistry(pin.name);
      if (own !== null) {
        if (own.from === "project") {
          heldKeys.add(key);
          scopes.add(`@${own.scope}`);
          if (source === "") source = basename2(own.source);
        }
        continue;
      }
      if (askedKeys.has(key)) continue;
      askedKeys.add(key);
      asked.push(pin);
    }
  }
  return { asked, heldByProject: [...heldKeys].filter((key) => !askedKeys.has(key)).length, scopes, source };
}
function lockedProject(c, dir, manifest, opts, registry, notes) {
  try {
    const found = findLockfile(c.manager, dir, opts.projectDir);
    if (found.status === "absent") return void 0;
    if (found.status === "unread") {
      notes.push(notReadLine(found.file, found.why));
      return void 0;
    }
    const format = lockFormat(found.file);
    const read2 = format === null ? { unread: "its format is not known" } : readLock(format, found.text);
    if ("unread" in read2) {
      notes.push(notReadLine(found.file, read2.unread));
      return void 0;
    }
    const ctx = { ...registry, projectDir: dir };
    let userRegistries;
    const user = () => userRegistries ??= npmUserRegistries(ctx);
    const plan = pairsToAsk(read2, ctx);
    const lines = [];
    if (plan.heldByProject > 0) lines.push(ownScopeLine(plan.heldByProject, found.file, plan.scopes, plan.source));
    const other = otherSources(read2, user);
    if (other.count > 0) lines.push(otherSourceLine(other.count, found.file, other.named, other.distinct));
    const divergent = read2.entries.filter((e) => e.fetched !== void 0).length;
    if (divergent > 0) {
      lines.push(
        `dev-guardian: ${divergent === 1 ? "1 entry" : `${divergent} entries`} of ${found.file} ${divergent === 1 ? "names" : "name"} one package and ${divergent === 1 ? "fetches" : "fetch"} another \u2014 both were looked up; check the lockfile.`
      );
    }
    if (read2.unrecognised > 0) {
      lines.push(`dev-guardian: ${read2.unrecognised === 1 ? "1 entry" : `${read2.unrecognised} entries`} of ${found.file} ${read2.unrecognised === 1 ? "was" : "were"} not recognised \u2014 not vetted.`);
    }
    notes.push(...lines);
    return {
      file: found.file,
      manifestFile: manifest.file,
      read: read2,
      rel: relative3(found.dir, resolve4(dir)).split(sep).join("/"),
      direct: manifest.packages.map((p) => p.name),
      covered: [],
      asked: plan.asked
    };
  } catch {
    notes.push("dev-guardian: the lockfile was not read (could not be read) \u2014 its packages were not vetted.");
    return void 0;
  }
}
function withoutCovered(packages, lock) {
  const rest = [];
  for (const pkg of packages) {
    const pinned = pkg.range === void 0 ? null : lock.read.resolutionOf(lock.rel, pkg.name, pkg.range);
    if (pinned === null) rest.push(pkg);
    else lock.covered.push(pkg);
  }
  return rest;
}
function advisoryIds(ids) {
  const clean = ids.map((id) => id.trim()).filter((id) => /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(id));
  if (clean.length === 0) return "a MAL- advisory";
  return clean.length > MAX_NAMED_IDS ? `${clean.slice(0, MAX_NAMED_IDS).join(", ")} and ${clean.length - MAX_NAMED_IDS} more` : clean.join(", ");
}
function lockOutcome(lock, verdicts, counted) {
  const denies = /* @__PURE__ */ new Set();
  const lines = [];
  const askedKeys = new Set(lock.asked.map(pairKey));
  const advisory = (v) => `OSV malicious-package advisory for ${v.pin.version}: ${advisoryIds(v.malicious ?? [])}`;
  const found = (pin) => {
    const v = pin !== void 0 && askedKeys.has(pairKey(pin)) ? verdicts.get(pairKey(pin)) : void 0;
    return v !== void 0 && v.malicious !== null && v.malicious.length > 0 ? v : void 0;
  };
  for (const entry of lock.read.entries) {
    const own = found(entry.pin);
    if (own !== void 0) denies.add(`${lock.file} pins '${pairKey(own.pin)}': ${sentence(advisory(own))}`);
    const fetched = found(entry.fetched);
    if (fetched !== void 0) {
      const names = entry.pin === void 0 ? `${lock.file} fetches` : `${lock.file} names '${pairKey(entry.pin)}' and fetches`;
      denies.add(`${names} '${pairKey(fetched.pin)}': ${sentence(advisory(fetched))}`);
    }
  }
  let unanswered = 0;
  let why = "";
  let left = 0;
  for (const pin of lock.asked) {
    const key = pairKey(pin);
    const v = verdicts.get(key);
    if (v === void 0) {
      if (!counted.has(key)) left += 1;
      counted.add(key);
    } else if (v.malicious === null) {
      unanswered += 1;
      if (why === "") why = v.unknown ?? "";
    }
  }
  if (unanswered > 0) lines.push(`${COULD_NOT_VET}${plural(unanswered)} of ${lock.file} (${pinReason(why)})${NOT_VERIFIED}`);
  if (left > 0) {
    lines.push(
      `dev-guardian: ${left} more ${left === 1 ? "package" : "packages"} of ${lock.file} ${left === 1 ? "was" : "were"} not vetted (only the first ${MAX_PINS} are) \u2014 not verified.`
    );
  }
  return { denies: [...denies], lines };
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
function fileBelow(under, path) {
  if (!walkLinksUnder(under, path).ok) return false;
  try {
    return statSync2(path).isFile();
  } catch {
    return false;
  }
}
var MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
function npmPrefix(cwd) {
  let dir = resolve4(cwd);
  for (let i = 0; i < 64; i += 1) {
    if (presentBelow(dir, join5(dir, "package.json")) || presentBelow(dir, join5(dir, "node_modules"))) return dir;
    const parent = dirname4(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return resolve4(cwd);
}
function packageNamed(dir, name) {
  const r = readSmallText(join5(dir, "node_modules", name, "package.json"), MAX_PACKAGE_JSON_BYTES, dir);
  if (r.status !== "ok") return false;
  try {
    const manifest = JSON.parse(r.text.charCodeAt(0) === 65279 ? r.text.slice(1) : r.text);
    return manifest !== null && typeof manifest === "object" && manifest["name"] === name;
  } catch {
    return false;
  }
}
function installedLocally(name, cwd, byPackageFlag = false, manager = "") {
  const prefix = npmPrefix(cwd);
  if (packageNamed(prefix, name)) return true;
  if (name.startsWith("@") || byPackageFlag) return false;
  let dir = prefix;
  for (let i = 0; i < 32; i += 1) {
    const bin = join5(dir, "node_modules", ".bin");
    for (const candidate of manager === "bun" ? [join5(bin, name), join5(bin, `${name}.exe`)] : [join5(bin, name)]) {
      if (fileBelow(dir, candidate)) return true;
    }
    if (presentBelow(dir, join5(dir, ".git"))) return false;
    const parent = dirname4(dir);
    if (parent === dir) return false;
    dir = parent;
  }
  return false;
}
function runsInstalledCopy(pkg, c, opts) {
  if (pkg.range !== void 0 || pkg.raw !== pkg.name || c.prefixed === true) return false;
  const dir = commandDir(c, opts);
  return dir !== null && installedLocally(pkg.name, dir, c.byPackageFlag === true, c.manager);
}
function commandDir(c, opts) {
  if (c.workdir === void 0) return resolve4(opts.cwd);
  if (c.workdir === null) return null;
  const home = opts.homeDir ?? homedir2();
  const windows = (opts.platform ?? process.platform) === "win32";
  let dir = resolve4(opts.cwd);
  if (isNetworkPath(dir)) return null;
  let real = realDir(dir);
  for (const step of c.workdir) {
    let target = step;
    if (target === "~" || /^~[\\/]/.test(target)) target = join5(home, target.slice(1));
    else if (target.startsWith("~")) return null;
    else if (windows) target = target.replace(/^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/, (_, drive) => `${drive.toUpperCase()}:/`);
    if (real === null) return null;
    const moved2 = plainMove(dir, real, target, windows);
    if (moved2 === null) return null;
    [dir, real] = moved2;
  }
  return dir;
}
function realDir(path) {
  try {
    return realpathSync.native(path);
  } catch {
    return null;
  }
}
function plainMove(dir, real, target, windows) {
  if (windows && /^[A-Za-z]:(?![\\/])/.test(target)) return null;
  const next = resolve4(dir, target);
  if (isNetworkPath(next)) return null;
  const root = isAbsolute3(target) ? parse4(target).root : "";
  let at = root === "" ? dir : resolve4(dir, root);
  for (const part of target.slice(root.length).split(windows ? /[\\/]+/ : /\/+/)) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      at = dirname4(at);
      continue;
    }
    at = join5(at, part);
    try {
      const kind = lstatSync3(at);
      if (kind.isSymbolicLink() || !kind.isDirectory()) return null;
    } catch {
      return null;
    }
  }
  const landed = realDir(next);
  if (landed === null) return null;
  const expected = resolve4(real, target);
  return (windows ? landed.toLowerCase() === expected.toLowerCase() : landed === expected) ? [next, landed] : null;
}
var COULD_NOT_VET = "dev-guardian could not vet ";
var NOT_VERIFIED = " \u2014 not verified.";
var CUT_NOTE = "dev-guardian: installs past the first 512 KB of this command were not looked for \u2014 not verified.";
async function decideInstallCommand(command, opts) {
  const shell = opts.shell ?? "bash";
  const env = opts.env ?? process.env;
  const cdpath = (env["CDPATH"] ?? "").trim() !== "";
  const registry = {
    projectDir: opts.cwd,
    homeDir: opts.homeDir,
    env,
    etcDir: opts.etcDir,
    platform: opts.platform,
    nodeExecPath: opts.nodeExecPath,
    systemLibraryDir: opts.systemLibraryDir,
    cache: registryCache()
  };
  const manifestNotes = [];
  const locked = [];
  const isPopular = popularTest(opts);
  const { commands, notVetted, manifestNotVetted, cut } = boundedInstalls(
    command,
    shell,
    isPopular,
    (pkg, c) => runsInstalledCopy(pkg, c, opts),
    opts.nested,
    cdpath,
    (parsed) => withManifestPackages(parsed, opts, registry, manifestNotes, locked)
  );
  if (commands.length === 0 && locked.length === 0) {
    const said2 = [...manifestNotes, ...cut ? [CUT_NOTE] : []];
    return said2.length > 0 ? { context: said2.join("\n") } : null;
  }
  const offline = env["GUARDIAN_OFFLINE"] === "1";
  const budgetMs = opts.budgetMs ?? HOOK_BUDGET_MS;
  const deadlineAt = opts.deadlineAt ?? (opts.startedAt ?? Date.now()) + vetDeadlineMs(env);
  const now = opts.now ?? Date.now();
  const pairs = choosePins(
    locked.flatMap((l) => l.asked),
    {
      direct: new Set(locked.flatMap((l) => l.direct)),
      popular: (name) => isPopular({ ecosystem: "npm", name, raw: name })
    }
  );
  const pinned = vetPins(pairs.chosen, {
    budgetMs,
    offline,
    deadlineAt,
    now,
    ...opts.fetchImpl !== void 0 ? { fetchImpl: opts.fetchImpl } : {}
  });
  const [batches, verdicts] = await Promise.all([
    Promise.all(
      commands.map(
        (c) => vetPackages(c.packages, {
          budgetMs,
          offline,
          deadlineAt,
          now,
          registry,
          commandRegistries: c.registries,
          // A manifest's packages are told neither of a fresh version nor of install scripts (`decideManifestOne`):
          // what only those two checks need is not asked of the registry.
          ...c.fromManifest !== void 0 ? { unreported: MANIFEST_UNREPORTED } : {},
          ...opts.fetchImpl !== void 0 ? { fetchImpl: opts.fetchImpl } : {},
          ...opts.popularDir !== void 0 ? { popularDir: opts.popularDir } : {},
          ...opts.popular !== void 0 ? { popular: opts.popular } : {}
        })
      )
    ),
    pinned
  ]);
  const denies = [];
  const manifestDenies = [];
  const warnings = [];
  const unverified = [];
  const unverifiedIn = /* @__PURE__ */ new Map();
  const lockLines = [];
  const lockCounts = [];
  const lockDenies = /* @__PURE__ */ new Set();
  let malicious = false;
  let missingIn;
  const verdictOf = new Map(verdicts.map((v) => [pairKey(v.pin), v]));
  const counted = /* @__PURE__ */ new Set();
  const warnedCovered = /* @__PURE__ */ new Set();
  for (const lock of locked) {
    try {
      const covered = lock.covered.filter((pkg) => !warnedCovered.has(`${lock.manifestFile}\0${pkg.name}\0${pkg.range ?? ""}`));
      for (const pkg of covered) warnedCovered.add(`${lock.manifestFile}\0${pkg.name}\0${pkg.range ?? ""}`);
      for (const r of vetTyposquatOnly(covered, {
        ...opts.popularDir !== void 0 ? { popularDir: opts.popularDir } : {},
        ...opts.popular !== void 0 ? { popular: opts.popular } : {}
      })) {
        const d = decideManifestOne(r, lock.manifestFile);
        if (d.warn !== void 0) warnings.push(d.warn);
      }
      const outcome = lockOutcome(lock, verdictOf, counted);
      for (const text of outcome.denies) lockDenies.add(text);
      lockLines.push(...outcome.lines);
      lockCounts.push(...outcome.lines);
    } catch {
      lockLines.push(notReadLine(lock.file, "could not be read"));
    }
  }
  if (lockDenies.size > 0) {
    manifestDenies.push(...[...lockDenies].slice(0, MAX_NAMED_DENIES));
    const more = lockDenies.size - MAX_NAMED_DENIES;
    if (more > 0) manifestDenies.push(`and ${more} more pair${more === 1 ? "" : "s"} of the lockfiles have a malicious-package advisory.`);
  }
  commands.forEach((cmd, i) => {
    for (const r of batches[i] ?? []) {
      if (cmd.fromManifest !== void 0) {
        const d2 = decideManifestOne(r, cmd.fromManifest);
        if (d2.deny !== void 0) manifestDenies.push(d2.deny);
        if (d2.warn !== void 0) warnings.push(d2.warn);
        if (d2.unverified !== void 0) {
          const sofar = unverifiedIn.get(cmd.fromManifest);
          unverifiedIn.set(cmd.fromManifest, { count: (sofar?.count ?? 0) + 1, why: sofar?.why ?? d2.unverified });
        }
        continue;
      }
      const d = decideOne(r, cmd.uncertain);
      if (d.deny !== void 0) denies.push(d.deny);
      if (d.malicious === true) malicious = true;
      else if (d.deny !== void 0) missingIn = missingIn ?? cmd.manager;
      if (d.warn !== void 0) warnings.push(d.warn);
      if (d.unverified !== void 0) unverified.push(d.unverified);
    }
  });
  if (denies.length > 0 || manifestDenies.length > 0) {
    const parts = [];
    if (denies.length > 0) {
      parts.push(
        `${denies.join(" ")} Check the package name against the project documentation or the registry before installing anything. ` + // Controller ruling (round 2): a missing-name deny carries its own
        // escape hatch — a registry flag, or an inline prefix, takes the
        // command out of the confident shape, so the agent can always
        // proceed. A MALICIOUS package gets no such hint.
        (malicious ? "If this package is genuinely intended, ask the user to install it themselves." : escapeHatch(missingIn ?? "", shell))
      );
    }
    if (manifestDenies.length > 0) {
      parts.push(
        `${manifestDenies.join(" ")} Installing it or removing the dependency is the user's decision: tell them which file names it, and install nothing from that manifest until they have decided.`
      );
    }
    const counts = [...new Set(lockCounts)];
    return { deny: `dev-guardian blocked this install: ${parts.join(" ")}${counts.length > 0 ? `
${counts.join(`
`)}` : ""}` };
  }
  const lines = [];
  if (warnings.length > 0) {
    lines.push("\u26A0\uFE0F dev-guardian package vetting \u2014 review before relying on these:");
    for (const w of warnings) lines.push(`  \u2022 ${w}`);
  }
  if (unverified.length > 0) lines.push(`${COULD_NOT_VET}${unverified.join(", ")}${NOT_VERIFIED}`);
  for (const [file, { count, why }] of unverifiedIn) {
    lines.push(`${COULD_NOT_VET}${plural(count)} of ${file} (${why})${NOT_VERIFIED}`);
  }
  lines.push(.../* @__PURE__ */ new Set([...lockLines, ...manifestNotes]));
  if (notVetted > 0) {
    lines.push(
      `dev-guardian: ${notVetted} more packages in this command were not vetted (only the first ${MAX_VETTED_PACKAGES} are) \u2014 not verified.`
    );
  }
  if (manifestNotVetted > 0) {
    lines.push(
      `dev-guardian: ${manifestNotVetted} more packages of the manifest were not vetted (only the first ${MAX_MANIFEST_PACKAGES} are) \u2014 not verified.`
    );
  }
  if (cut) lines.push(CUT_NOTE);
  return lines.length > 0 ? { context: lines.join("\n") } : null;
}
var NOT_FOUND = "not found on the public registry \u2014 if it is private or local, ignore this.";
var REGISTRY_FLAG = {
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
var NO_REGISTRY_FLAG = {
  yarn: "Yarn Berry has no registry flag",
  composer: "composer has no registry flag"
};
function escapeHatch(manager, shell = "bash") {
  const prefix = shell === "powershell" ? "run `$env:GUARDIAN_PKG_VET = '0'` before it, in the same command" : "prefix the command with `GUARDIAN_PKG_VET=0`";
  const flag = REGISTRY_FLAG[manager];
  if (flag !== void 0) return `If this package is private or local, re-run the install with an explicit ${flag}, or ${prefix}.`;
  const none = NO_REGISTRY_FLAG[manager];
  return `If this package is private or local, ${prefix}${none !== void 0 ? ` (${none})` : ""}.`;
}
var CHECK_KEYS = [
  "exists",
  "malicious",
  "vulnerabilities",
  "publish_age",
  "install_scripts",
  "typosquat"
];
var VERSION_CHECKS = /* @__PURE__ */ new Set(["vulnerabilities", "publish_age", "install_scripts"]);
function sentence(text) {
  return /[.?!]$/.test(text) ? text : `${text}.`;
}
function decideManifestOne(r, file) {
  if (r.checks.malicious.status === "fail") {
    const why = Object.values(r.checks).filter((c) => c.status === "fail" && c.detail !== void 0).map((c) => c.detail ?? "").join("; ");
    return { deny: `${file} names '${label2(r)}': ${sentence(why)}` };
  }
  if (r.not_on_public_registry === true) {
    const didYouMean = r.similar_to !== void 0 ? ` Did you mean '${r.similar_to}'?` : "";
    const why = r.verdict === "block" ? `not denied: ${NAMED_BY_MANIFEST}` : r.checks.exists.detail ?? "";
    return { warn: `${file}: '${label2(r)}': ${NOT_FOUND}${didYouMean} (${why})` };
  }
  const out = {};
  const typo = r.checks.typosquat;
  if (typo.status === "warn" && typo.detail !== void 0) out.warn = `${file}: ${label2(r)}: ${typo.detail}`;
  const unknown2 = [r.checks.exists, r.checks.malicious].find((c) => c.status === "unknown" && c.detail !== void 0);
  if (unknown2 !== void 0) out.unverified = unknown2.detail ?? "";
  return out;
}
function decideOne(r, uncertain) {
  if (r.checks.malicious.status === "fail") {
    const why = Object.values(r.checks).filter((c) => c.status === "fail" && c.detail !== void 0).map((c) => c.detail ?? "").join("; ");
    return { deny: `'${label2(r)}': ${sentence(why)}`, malicious: true };
  }
  if (r.not_on_public_registry === true) {
    if (r.verdict === "block" && uncertain.length === 0) {
      return { deny: `'${label2(r)}': ${sentence(r.checks.exists.detail ?? firstLine(r))}` };
    }
    const didYouMean = r.similar_to !== void 0 ? ` Did you mean '${r.similar_to}'?` : "";
    const why = r.verdict === "block" ? `not denied: ${uncertain.join("; ")}` : r.checks.exists.detail ?? "";
    return { warn: `'${label2(r)}': ${NOT_FOUND}${didYouMean} (${why})` };
  }
  const pinned = isExactVersion(r.ecosystem, r.requested);
  const warns = CHECK_KEYS.filter((key) => key !== "vulnerabilities" || pinned).map((key) => r.checks[key]).filter((c) => c.status === "warn" && c.detail !== void 0).map((c) => c.detail ?? "");
  if (r.requested_version_unpublished === true) {
    warns.push(`requested version ${r.requested ?? ""} is not published \u2014 possibly a hallucinated version`);
  }
  const out = {};
  if (warns.length > 0) out.warn = `${label2(r)}: ${warns.slice(0, 3).join("; ")}`;
  const couldRun = r.requested_version_unpublished === true ? CHECK_KEYS.filter((key) => !VERSION_CHECKS.has(key)).map((key) => r.checks[key]) : Object.values(r.checks);
  const unknownCheck = couldRun.find((c) => c.status === "unknown" && c.detail !== void 0);
  if (unknownCheck !== void 0) out.unverified = `${label2(r)} (${unknownCheck.detail ?? ""})`;
  return out;
}
export {
  hookDecision_exports as installVetting
};
