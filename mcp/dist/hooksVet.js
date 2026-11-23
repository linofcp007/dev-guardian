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
import { basename as basename3, dirname as dirname4, isAbsolute as isAbsolute3, join as join5, parse as parse4, relative as relative3, resolve as resolve4, sep } from "node:path";

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

// src/pkgvet/strayAt.ts
function strayAt(url, ownName) {
  let path = url.pathname.toLowerCase();
  const slash = ownName === void 0 ? -1 : ownName.indexOf("/");
  if (ownName !== void 0 && ownName.startsWith("@") && slash > 1) {
    const scope = ownName.slice(0, slash).toLowerCase();
    const rest = ownName.slice(slash + 1).toLowerCase();
    for (const form of [`/${scope}/${rest}`, `/${scope}%2f${rest}`]) path = path.split(form).join("/");
  }
  return path.includes("@") || url.search.includes("@") || url.hash.includes("@");
}
function writtenStrayAt(text, ownName) {
  try {
    return strayAt(new URL(text.startsWith("git+") ? text.slice(4) : text), ownName);
  } catch {
    return true;
  }
}
var COMMENT_HOLDS_AT = "#@";
function withCommentAt(value, cutOff) {
  return cutOff.includes("@") ? `${value}${COMMENT_HOLDS_AT}` : value;
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
var sayable = (host, written, name) => writtenStrayAt(written, name) ? "" : host;
function gitHost(spec2, name, written = spec2) {
  if (spec2.startsWith("github:")) return "github.com";
  if (spec2.startsWith("gitlab:")) return "gitlab.com";
  if (spec2.startsWith("bitbucket:")) return "bitbucket.org";
  if (spec2.startsWith("gist:")) return "gist.github.com";
  if (spec2.startsWith("git@")) {
    const colon = spec2.indexOf(":");
    return dnsName(spec2.slice(4, colon < 0 ? void 0 : colon));
  }
  try {
    return sayable(dnsName(new URL(spec2.startsWith("git+") ? spec2.slice(4) : spec2).hostname), written, name);
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
function locate(spec2, name, written = spec2) {
  if (spec2.length === 0 || spec2.length > MAX_LINE) return "bad";
  if (spec2.startsWith("//")) return UNSAFE_URL.test(spec2) ? "bad" : { source: { kind: "elsewhere", host: "", url: spec2 }, named: void 0 };
  if (LOCAL_SPEC.test(spec2) || spec2.startsWith("/") || spec2.startsWith("./") || spec2.startsWith("../")) return "local";
  if (UNSAFE_URL.test(spec2)) return "bad";
  if (GIT_SPEC.test(spec2)) return { source: { kind: "git", host: gitHost(spec2, name, written) }, named: void 0 };
  let url;
  try {
    url = new URL(spec2);
  } catch {
    return "bad";
  }
  const host = sayable(dnsName(url.hostname), written, name);
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
function finish(acc, pin, spec2, written = spec2) {
  if (spec2 === void 0) {
    if (pin !== void 0) emit(acc, pin, void 0);
    return;
  }
  const where = locate(spec2, pin?.name, written);
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
      else {
        block[field] = field === "resolved" ? value.split("#", 1)[0] ?? "" : value;
        if (field === "resolved") block.resolvedWritten = value;
      }
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
    finish(acc, pin, where, b.resolved === void 0 ? where : b.resolvedWritten);
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
function nameAndSpec(first) {
  const at = first.indexOf("@", 1);
  return at < 0 ? null : [first.slice(0, at), first.slice(at + 1)];
}
function stringAfter(line, from) {
  let k = from;
  while (line.charCodeAt(k) === 32 || line.charCodeAt(k) === 9) k += 1;
  const end = line.charCodeAt(k) === 34 ? stringEnd(line, k) : -1;
  return end < 0 ? void 0 : stringAt(line, k, end);
}
function objectEnd(line, start) {
  let depth = 0;
  let inString = false;
  for (let i = start; i < line.length; i += 1) {
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
      if (depth === 0) return c === 125 ? i : -1;
    }
  }
  return -1;
}
function bunShape(line, from) {
  let shape = "";
  let last = "";
  let i = from;
  while (shape.length < 3 && line.startsWith(", ", i)) {
    const start = i + 2;
    const c = line.charCodeAt(start);
    const end = c === 34 ? stringEnd(line, start) : c === 123 ? objectEnd(line, start) : -1;
    if (end < 0) return null;
    shape += c === 34 ? "s" : "o";
    last = c === 34 ? line.slice(start + 1, end) : "";
    i = end + 1;
  }
  return i === line.length - 2 && line.endsWith("],") ? { shape, last } : null;
}
function parseBunLine(line) {
  if (!line.startsWith('    "')) return null;
  const keyEnd = stringEnd(line, 4);
  if (keyEnd < 0 || !line.startsWith(': ["', keyEnd + 1)) return null;
  const firstStart = keyEnd + 4;
  const firstEnd = stringEnd(line, firstStart);
  if (firstEnd < 0) return null;
  const first = stringAt(line, firstStart, firstEnd);
  let depth = 1;
  let inString = false;
  let commas = 0;
  let firstComma = -1;
  let filled = true;
  let empty = false;
  let i = firstEnd + 1;
  for (; i < line.length && depth > 0; i += 1) {
    const c = line.charCodeAt(i);
    if (inString) {
      if (c === 92) i += 1;
      else if (c === 34) inString = false;
    } else if (c === 34) {
      inString = true;
      filled = true;
    } else if (c === 91 || c === 123) {
      depth += 1;
      filled = true;
    } else if (c === 93 || c === 125) {
      depth -= 1;
      if (depth === 0 && !filled) empty = true;
    } else if (c === 44 && depth === 1) {
      if (!filled) empty = true;
      if (firstComma < 0) firstComma = i;
      commas += 1;
      filled = false;
    } else if (c !== 32 && c !== 9) {
      filled = true;
    }
  }
  if (first === null || depth !== 0) return null;
  const tail = line.slice(i).trim();
  if (tail !== "" && tail !== ",") return null;
  const second = firstComma < 0 ? void 0 : stringAfter(line, firstComma + 1);
  const cut = nameAndSpec(first);
  if (second === null && line.startsWith(', "', firstEnd + 1) && (cut === null || !VERSION.test(cut[1]))) return null;
  const written = bunShape(line, firstEnd + 1);
  return { key: line.slice(5, keyEnd), first, second, elements: empty ? 0 : commas + 1, shape: written?.shape ?? null, last: written?.last ?? "" };
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
var TARBALL_SEGMENT = /^[A-Za-z0-9._+-]+$/;
function localTarball(spec2) {
  const path = spec2.startsWith("./") ? spec2.slice(2) : spec2.startsWith("/") ? spec2.slice(1) : spec2;
  return path.endsWith(".tgz") && path.split("/").every((segment) => segment !== "." && segment !== ".." && TARBALL_SEGMENT.test(segment));
}
var BUN_SEQUENCES = /* @__PURE__ */ new Set(["", "o", "os"]);
var ARCHIVE_ENDINGS = [".tgz", ".tar.gz", ".tar"];
var SHA512 = /^sha512-[A-Za-z0-9+/]{85}[AQgw]==$/;
function bunRegistryLine(acc, pin, e) {
  const { second } = e;
  if (second === void 0 || second === "") {
    const inForm2 = second === "" && e.shape === "sos";
    if (!inForm2) acc.unrecognised += 1;
    emit(acc, pin, void 0);
    return inForm2;
  }
  const unknown2 = () => {
    acc.unrecognised += 1;
    emit(acc, pin, UNKNOWN_ELSEWHERE);
    return false;
  };
  if (second === null) return unknown2();
  const where = locate(second, pin.name);
  if (where === "local" || where === "bad") return unknown2();
  if (where.source.kind === "git") {
    acc.unrecognised += 1;
    emit(acc, pin, { source: { kind: "elsewhere", host: where.source.host, url: "" }, named: void 0 });
    return false;
  }
  const inForm = e.shape === "sos" && (second.startsWith("https://") || second.startsWith("http://"));
  if (!inForm) acc.unrecognised += 1;
  emit(acc, pin, where);
  return inForm;
}
function bunEntry(acc, e, sha512Only) {
  const cut = nameAndSpec(e.first);
  if (cut === null) {
    acc.unrecognised += 1;
    return false;
  }
  const [name, spec2] = cut;
  if (spec2.startsWith("workspace:")) {
    acc.local += 1;
  } else if (VERSION.test(spec2)) {
    const pin = makePin(name, spec2);
    if (pin === void 0) {
      acc.unrecognised += 1;
      return false;
    }
    const inForm = bunRegistryLine(acc, pin, e);
    return inForm && !ARCHIVE_ENDINGS.some((ending) => spec2.endsWith(ending)) && (!sha512Only || SHA512.test(e.last));
  } else if ((e.elements === 2 || e.elements === 3) && localTarball(spec2) && locate(spec2) === "bad") {
    acc.local += 1;
  } else {
    finish(acc, void 0, spec2);
  }
  return e.shape !== null && BUN_SEQUENCES.has(e.shape);
}
var BUN_VERSIONS = /* @__PURE__ */ new Set(["0", "1", "2", "3"]);
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
  if (!BUN_VERSIONS.has(version)) return { unread: "its lockfileVersion is not 0, 1, 2 or 3" };
  if (seen.packages !== 1) return { unread: seen.packages === 0 ? 'it has no "packages" object' : 'it has more than one "packages" object' };
  const [from, to] = ranges.packages;
  const [wFrom, wTo] = ranges.workspaces;
  return { version, packages: text.slice(from + 1, to), workspaces: seen.workspaces === 1 && wFrom >= 0 && wTo >= 0 ? text.slice(wFrom, wTo + 1) : "" };
}
function readBun(text) {
  const frame = bunFrame(text);
  if ("unread" in frame) return frame;
  const acc = newAcc();
  let asBunWrites = frame.version !== "3";
  scanBun(frame.packages, acc, (e) => {
    if (!bunEntry(acc, e, frame.version === "2")) asBunWrites = false;
  });
  const covers = asBunWrites && acc.unrecognised === 0;
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
      if (!covers || !validName(name) || recorded().get(`${rel}\0${name}`)?.has(range) !== true) return null;
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
var NOT_A_WORD_PREFIX_OR_STREAMS = /^(?:\d*|&|\*)$/;
function wordsWithoutRedirections(words) {
  const out = [];
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === void 0) continue;
    const r = parseRedirect(word);
    if (r === null) {
      out.push(word);
      continue;
    }
    const prefix = r.prefix.endsWith("&") ? r.prefix.slice(0, -1) : r.prefix;
    if (!NOT_A_WORD_PREFIX_OR_STREAMS.test(prefix)) out.push({ value: prefix, quoted: word.quoted });
    if (r.inline === "") i += 1;
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
function powershellAsPosix(text, options = {}) {
  const seen = hereStrings();
  let token = "";
  let glued = null;
  const braces = [];
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text.charAt(i);
    const boundary = atBoundary(text, i);
    if (boundary || UNICODE_SPACE.test(text.charAt(i - 1))) {
      token = "";
      glued = null;
    }
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
      token += lit === "" ? '""' : lit;
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
    else if (options.literalGluedRedirects === true && (ch === "<" || ch === ">")) {
      glued ??= !/^(?:\d*|\*|&)$/.test(token);
      out += glued ? posixSingle(ch) : ch;
    } else out += ch;
    token += ch;
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
var MEASURED_ENDING = /\.(?:zip|whl|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma|egg|nupkg)$/;
var PIPX_FILE = /\.(?:zip|whl|tar|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma)$/;
var COMPOSER_UNMEASURED = /\.(?:whl|tar|tgz|tar\.bz2|tbz|tar\.xz|txz|tlz|tar\.lz|tar\.lzma|egg|nupkg)$/i;
var UNMEASURED = /* @__PURE__ */ new Set(["dotnet"]);
var LAUNCHER_NAME_AT = "a name ending in @ under a launcher was not measured";
var UNMEASURED_ARCHIVE = "a name that ends like an archive file \u2014 this package manager was not measured, so whether it reads the word as a file or as a registry name is not known";
var FORM_NOT_MEASURED = "a name that ends like an archive file, in a form that was not measured (only pipx install <word>, pipx run <word> and composer require <word> were, with no flag and the ending in lower case)";
var COMPOSER_ENDING_NOT_MEASURED = "a name that ends like an archive file \u2014 composer was measured only with .zip and .tar.gz, so whether it reads this ending as a file or as a registry name is not known";
var ARCHIVE_REASONS = /* @__PURE__ */ new Set([UNMEASURED_ARCHIVE, FORM_NOT_MEASURED, COMPOSER_ENDING_NOT_MEASURED]);
var LOCAL_PATH = "local path \u2014 not looked up";
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
function archiveReasons(d, spec2) {
  if (UNMEASURED.has(d.manager)) {
    const why = unmeasuredReason(d.manager, spec2);
    return why === void 0 ? [] : [why];
  }
  if (d.manager !== "pipx" && d.manager !== "composer" || spec2.name !== spec2.raw || !UNMEASURED_FILE.test(spec2.raw)) return [];
  const measured = d.measuredArchiveForm === true;
  if (d.manager === "pipx") return measured ? [] : [FORM_NOT_MEASURED];
  const ending = COMPOSER_UNMEASURED.test(spec2.raw);
  return [...measured ? [] : [FORM_NOT_MEASURED], ...ending ? [COMPOSER_ENDING_NOT_MEASURED] : []];
}
function readsAsPipxFile(d, spec2) {
  return d.measuredArchiveForm === true && d.manager === "pipx" && spec2.name === spec2.raw && PIPX_FILE.test(spec2.raw);
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
var SEMVER_WORD = /^(?:\|\||-|\*|[xX]|[<>=~^]{0,2}v?\d[A-Za-z0-9.+-]*|[<>=~^]{1,2}\*)$/;
function isSemverRange(text) {
  return text.split(/\s+/).every((word) => SEMVER_WORD.test(word));
}
function npmProtocolReading(manager, rest) {
  if (manager !== "yarn" && manager !== "bun") return "alias";
  if (/[$`]/.test(rest)) return "alias";
  if (rest.indexOf("@", rest.startsWith("@") ? 1 : 0) > 0) return "alias";
  if (rest !== "" && !isSemverRange(rest) && notAPackage(rest, null) !== null) return "alias";
  return NAME_RE.npm.test(rest) ? "both" : "key";
}
var MAX_RANGE_LENGTH = 100;
function npmKeyRange(manager, rest) {
  return rest.length <= MAX_RANGE_LENGTH && isSemverRange(rest) && !readsFileValue(manager, rest) ? rest : void 0;
}
function npmProtocolRest(raw, manager) {
  const at = raw.indexOf("@", raw.startsWith("@") ? 1 : 0);
  const range = at > 0 ? raw.slice(at + 1) : "";
  if (!/^npm:/i.test(range) || npmProtocolReading(manager, range.slice(4)) !== "both") return void 0;
  const real = parseNpm(range.slice(4), manager, true);
  return "name" in real ? { ...real, raw } : void 0;
}
var TWO_READINGS = " is read two ways";
function bothReadings(pairs) {
  const [first, second] = pairs[0] ?? [];
  if (first === void 0 || second === void 0) return void 0;
  const more = pairs.length - 1;
  const others = more === 0 ? "" : ` (and ${more} more ${more === 1 ? "word" : "words"} like it)`;
  return `\`${first.raw}\`${others}${TWO_READINGS} \u2014 Yarn 4 asks the registry for \`${first.name}\`, Yarn 1 for \`${second.name}\`, and bun for one or the other \u2014 both are looked up`;
}
function npmReadings(spec2, manager) {
  const second = npmProtocolRest(spec2.raw, manager);
  return second === void 0 ? { packages: [spec2] } : { packages: [spec2, second], pair: [spec2, second] };
}
function isTildeWord(word) {
  return word.startsWith("~") && !/[\\/]/.test(word);
}
function notARegistryRange(text) {
  if (isSemverRange(text) || isTildeWord(text)) return null;
  return notAPackage(text, null) ?? (URL_OR_VCS.test(text) ? "URL / VCS / protocol spec \u2014 not looked up" : null);
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
  if (range === "") range = void 0;
  if (range !== void 0) {
    if (/^npm:/i.test(range)) {
      const rest = range.slice(4);
      const reading = alias ? "alias" : npmProtocolReading(manager, rest);
      if (reading !== "alias") return withRange(checkName("npm", name, raw), npmKeyRange(manager, rest));
      const real = parseNpm(range.slice(4), manager, true);
      return "name" in real ? { ...real, raw } : skip(raw, real.reason);
    }
    const rangeBad = notARegistryRange(range);
    if (rangeBad !== null) return skip(raw, rangeBad);
    if (readsFileValue(manager, range)) return skip(raw, "archive file \u2014 not looked up");
    if (isTildeWord(range) && !isSemverRange(range)) range = void 0;
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
function parseNuget(raw, colons = false) {
  if (/[$`]/.test(raw)) return skip(raw, "not a literal package name (shell expansion)");
  const colon = colons ? raw.indexOf("::") : -1;
  const at = colon > 0 ? colon : raw.indexOf("@");
  const bad = notAPackage(colon > 0 ? raw.slice(0, colon) : raw, at > 0 ? ARCHIVE : null);
  if (bad !== null) return skip(raw, bad);
  const name = at > 0 ? raw.slice(0, at) : raw;
  const range = at > 0 ? raw.slice(at + (colon > 0 ? 2 : 1)) : void 0;
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
var LOGLEVEL_FLAGS = /* @__PURE__ */ new Set(["--silent", "--quiet", "-q", "--verbose", "-d", "-s"]);
var NPM_VALUE_FLAGS = [
  // `-C` is npm's short form of `--prefix`.
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
];
var NPM_BOOL_FLAGS = [...NPM_COMMON_BOOL, "--allow-same-version", "--strict-ssl", "-s"];
var NPM_WORKSPACE_FLAGS = ["--workspace", "-w", "--workspaces"];
var NPM_LONG = /* @__PURE__ */ new Map([["-L", "--location"]]);
var NPM_LETTERS = /* @__PURE__ */ new Map([
  // No value. `d`, `q` and `s` are two words each.
  ["a", "--all"],
  ["f", "--force"],
  ["g", "--global"],
  ["l", "--long"],
  ["p", "--parseable"],
  ["S", "--save"],
  ["B", "--save-bundle"],
  ["D", "--save-dev"],
  ["E", "--save-exact"],
  ["O", "--save-optional"],
  ["P", "--save-prod"],
  ["y", "--yes"],
  ["h", "--usage"],
  ["H", "--usage"],
  ["v", "--version"],
  ["n", "--no-yes"],
  ["d", "--loglevel info"],
  ["q", "--loglevel warn"],
  ["s", "--loglevel silent"],
  // A value: `c` and `m` are of type String; `L`, `C` and `w` take any word.
  ["c", "--call"],
  ["m", "--message"],
  ["L", "--location"],
  ["C", "--prefix"],
  ["w", "--workspace"]
]);
var NPM_TAKE_NEXT_LETTER = /* @__PURE__ */ new Set(["L", "C", "w"]);
var NPM_STRING_LETTERS = /* @__PURE__ */ new Set(["c", "m"]);
var NOPT_FLAG_LIKE = /^-{1,2}[^-]/;
var NPM_TABLE = {
  // The value letters of npm 11.19.0 (`-L` is noted as `--location`, NPM_LONG), and `-ca` and `-call`, two of the six words
  // npm reads whole instead of opening them (`--ca` and `--call`; measured, `single-dash-words…:13-14`).
  value: set(...NPM_VALUE_FLAGS, "-L", "-m", "-c", "-ca", "-call"),
  // The letters npm has and the table had not (`-a` … `-H`), and the four other whole words: `-all` (`--all`), `-ws`
  // (`--workspaces`), `-dd` and `-ddd` (`--loglevel verbose|silly`).
  bool: set(...NPM_BOOL_FLAGS, "-a", "-l", "-p", "-n", "-h", "-v", "-H", "-all", "-ws", "-dd", "-ddd"),
  registry: set("--registry"),
  dir: set("--prefix", "-C"),
  workspace: set(...NPM_WORKSPACE_FLAGS, "-ws"),
  // The letters added, `-all` and the two loglevel words take no `true` / `false` either: the word after them is a package.
  boolWord: { except: /* @__PURE__ */ new Set([...LOGLEVEL_FLAGS, "-a", "-l", "-p", "-n", "-h", "-v", "-H", "-all", "-dd", "-ddd"]) },
  long: NPM_LONG,
  stringValue: set("-m", "-c", "-call"),
  groups: "npm"
};
var PIP_REQUIREMENTS_REASON = "requirements file (-r) \u2014 read as a manifest, not as a package name";
var PIP_CONSTRAINTS_REASON = "constraints file (-c) \u2014 not vetted";
var PIP_EDITABLE_REASON = "editable install (-e) \u2014 local or VCS source, not looked up";
var PIP_FETCH_VALUE = [
  "-c",
  "--constraint",
  "-r",
  "--requirement",
  "--global-option",
  "--no-binary",
  "--only-binary",
  "--src",
  "--source",
  "--source-dir",
  "--source-directory",
  "--progress-bar",
  "-i",
  "--index-url",
  "--pypi-url",
  "--extra-index-url",
  "-f",
  "--find-links",
  "--python",
  "--log",
  "--log-file",
  "--local-log",
  "--proxy",
  "--retries",
  "--timeout",
  "--default-timeout",
  "--exists-action",
  "--trusted-host",
  "--cert",
  "--client-cert",
  "--cache-dir",
  "--use-feature",
  "--use-deprecated"
];
var PIP_FETCH_BOOL = [
  "--no-deps",
  "--no-dependencies",
  "--prefer-binary",
  "--pre",
  "--require-hashes",
  "--no-build-isolation",
  "--use-pep517",
  "--no-use-pep517",
  "--check-build-dependencies",
  "--ignore-requires-python",
  "--no-clean",
  "--no-index",
  "--debug",
  "--isolated",
  "--require-virtualenv",
  "--require-venv",
  "-v",
  "--verbose",
  "-V",
  "--version",
  "-q",
  "--quiet",
  "--no-input",
  "--no-cache-dir",
  "--disable-pip-version-check",
  "--no-color",
  "--no-python-version-warning"
];
var PIP_FETCH_REGISTRY = ["-i", "--index-url", "--pypi-url", "--extra-index-url", "-f", "--find-links"];
var PIP_FETCH_REPORTED = [
  ["-r", PIP_REQUIREMENTS_REASON],
  ["--requirement", PIP_REQUIREMENTS_REASON],
  ["-c", PIP_CONSTRAINTS_REASON],
  ["--constraint", PIP_CONSTRAINTS_REASON]
];
var PIP_DOWNLOAD_TABLE = {
  value: set(
    ...PIP_FETCH_VALUE,
    "-d",
    "--dest",
    "--destination-dir",
    "--destination-directory",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi"
  ),
  bool: set(...PIP_FETCH_BOOL),
  registry: set(...PIP_FETCH_REGISTRY),
  registryBool: set("--no-index"),
  reported: new Map(PIP_FETCH_REPORTED)
};
var PIP_WHEEL_TABLE = {
  value: set(...PIP_FETCH_VALUE, "-w", "--wheel-dir", "-e", "--editable", "--config-settings", "--build-option"),
  bool: set(...PIP_FETCH_BOOL, "--no-verify"),
  registry: set(...PIP_FETCH_REGISTRY),
  registryBool: set("--no-index"),
  reported: new Map([...PIP_FETCH_REPORTED, ["-e", PIP_EDITABLE_REASON], ["--editable", PIP_EDITABLE_REASON]])
};
var PIPX_UPGRADE_TABLE = {
  value: set("--python", "--index-url", "-i", "--pip-args", "--cooldown", "--backend", "--fetch-python", "--output"),
  bool: set(
    "--install",
    "--include-injected",
    "--force",
    "-f",
    "--system-site-packages",
    "--editable",
    "-e",
    "--quiet",
    "-q",
    "--verbose",
    "-v",
    "--skip-maintenance",
    "--global",
    "--fetch-missing-python"
  ),
  registry: set("--index-url", "-i")
};
var UV_TOOL_UPGRADE_TABLE = {
  value: set(
    "--python",
    "-p",
    "--index",
    "--index-url",
    "-i",
    "--default-index",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--index-strategy",
    "--keyring-provider",
    "--resolution",
    "--prerelease",
    "--prerelease-package",
    "--fork-strategy",
    "--exclude-newer",
    "--exclude-newer-package",
    "--link-mode",
    "--directory",
    "--project",
    "--config-file",
    "--cache-dir",
    "--color",
    "--python-platform",
    "--no-sources-package",
    "--reinstall-package",
    "-C",
    "--config-setting",
    "--config-settings",
    "--config-setting-package",
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-binary-package",
    "--allow-insecure-host",
    "--python-preference"
  ),
  bool: set(
    "--all",
    "--offline",
    "-q",
    "--quiet",
    "-v",
    "--verbose",
    "--no-cache",
    "-n",
    "--reinstall",
    "--no-config",
    "--no-progress",
    "--no-python-downloads",
    "--no-index",
    "--compile-bytecode",
    "--managed-python",
    "--no-managed-python",
    "--no-sources",
    "--no-build-isolation",
    "--no-build",
    "--no-binary",
    "--require-build-hashes",
    "--no-require-build-hashes",
    "--system-certs",
    "--isolated",
    "--upgrade",
    "-U",
    "--native-tls",
    "--no-offline",
    "--force-reinstall"
  ),
  registry: set("--index", "--index-url", "-i", "--default-index", "--extra-index-url", "--find-links", "-f"),
  registryBool: set("--no-index"),
  dir: set("--directory", "--project")
};
var FLAGS = {
  npm: NPM_TABLE,
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
      ["-r", PIP_REQUIREMENTS_REASON],
      ["--requirement", PIP_REQUIREMENTS_REASON],
      // `uv pip install` spells it in the plural.
      ["--requirements", PIP_REQUIREMENTS_REASON],
      ["-c", PIP_CONSTRAINTS_REASON],
      ["--constraint", PIP_CONSTRAINTS_REASON],
      ["-e", PIP_EDITABLE_REASON],
      ["--editable", PIP_EDITABLE_REASON]
    ])
  },
  "pip-download": PIP_DOWNLOAD_TABLE,
  "pip-wheel": PIP_WHEEL_TABLE,
  "pipx-upgrade": PIPX_UPGRADE_TABLE,
  "pipx-reinstall": {
    value: set("--python", "--fetch-python", "--backend", "--output"),
    bool: set("--quiet", "-q", "--verbose", "-v", "--skip-maintenance", "--global", "--fetch-missing-python"),
    registry: set()
  },
  "pipx-upgrade-all": {
    value: set("--skip", "--pip-args", "--backend", "--index-url", "-i", "--cooldown", "--output"),
    bool: set(
      "--include-injected",
      "--force",
      "-f",
      "--quiet",
      "-q",
      "--verbose",
      "-v",
      "--skip-maintenance",
      "--global",
      "--system-site-packages",
      "--editable",
      "-e"
    ),
    registry: set("--index-url", "-i")
  },
  "uv-tool-upgrade": UV_TOOL_UPGRADE_TABLE,
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
  },
  // dotnet 10.0.404 `tool install --help` (.specs/install-vet-dotnet-forms/measurements/help/dotnet-tool-install-help.txt):
  // `-v` is the MSBuild verbosity here (a version in `add package`), and the sources are `--add-source` and `--source`;
  // `--configfile` names a NuGet configuration, which may hold a private source: it is read as one.
  "dotnet-tool": {
    value: set(
      "--tool-path",
      "--version",
      "--configfile",
      "--tool-manifest",
      "--add-source",
      "--source",
      "--framework",
      "-v",
      "--verbosity",
      "-a",
      "--arch"
    ),
    bool: set(
      "-g",
      "--global",
      "--local",
      "--prerelease",
      "--disable-parallel",
      "--ignore-failed-sources",
      "--no-http-cache",
      "--interactive",
      "--allow-downgrade",
      "--create-manifest-if-needed",
      "--allow-roll-forward"
    ),
    registry: set("--add-source", "--source", "--configfile")
  },
  // The forms that fetch a package by name, each with the flags of its own verb (the help of the SDK 10.0.404,
  // .specs/_findings-2026-11-20/measurements/dotnet-forms/help-windows-2026-11-20.txt): `-v` is the MSBuild verbosity in every one of
  // them, a version only in `add package`. `--yes` is accepted by the run command and is not in its help (measured, table-windows-2026-11-20.txt lines 25-26).
  "dotnet-run": {
    value: set("--version", "--configfile", "--source", "--add-source", "-v", "--verbosity"),
    bool: set("--allow-roll-forward", "--prerelease", "--disable-parallel", "--ignore-failed-sources", "--no-http-cache", "--interactive", "--yes"),
    registry: set("--source", "--add-source", "--configfile")
  },
  "dotnet-tool-update": {
    value: set("--tool-path", "--version", "--configfile", "--tool-manifest", "--add-source", "--source", "--framework", "-v", "--verbosity"),
    bool: set("-g", "--global", "--local", "--prerelease", "--disable-parallel", "--ignore-failed-sources", "--no-http-cache", "--interactive", "--allow-downgrade", "--all"),
    registry: set("--add-source", "--source", "--configfile")
  },
  "dotnet-new-install": {
    value: set("--add-source", "--nuget-source", "-v", "--verbosity"),
    bool: set("--interactive", "--force", "-d", "--diagnostics"),
    registry: set("--add-source", "--nuget-source")
  },
  "dotnet-download": {
    value: set("--configfile", "-o", "--output", "-s", "--source", "-v", "--verbosity"),
    bool: set("--allow-insecure-connections", "--interactive", "--prerelease"),
    registry: set("-s", "--source", "--configfile")
  },
  "dotnet-package-update": {
    value: set("--file", "--project", "-v", "--verbosity"),
    bool: set("--vulnerable", "--interactive"),
    registry: set()
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
    // `-L` (`--location`) and `-m` (`--message`, of type String): measured 2026-11-21 (npm 11.19.0), `npx -L global P` asks the
    // registry for P, never for `global` (M-4; the owner's answer B to question 4). A group of letters keeps the rule of today.
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
      "--node-options",
      "-L",
      "-m"
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
      "--verbose",
      "--no-yes"
    ),
    registry: set("--registry"),
    workspace: set(...NPM_WORKSPACE_FLAGS),
    packageFlags: set("--package", "-p"),
    shellFlags: set("--call", "-c"),
    noFetchFlags: set("--no", "--no-install", "--offline"),
    // Measured 2026-11-19 (npx, npm 11.20.0): `--no false P` and `--no-yes false P` ask for P; the word is their value.
    // `--no-install false P` and `--offline false P` fetch nothing (measured); they are read like `--no` (the word is their
    // value, the next one is looked up, the command is uncertain): looking up more, never less (US-1.AC-4).
    optionalWord: set("--no", "--no-yes", "--no-install", "--offline"),
    bothWays: "clusters",
    long: NPM_LONG,
    stringValue: set("-m"),
    notInGroups: set("-L", "-m")
  },
  // `npm exec` / `npm x` are npm's own command: npm's flags and its `true` / `false` rule, not npx's (measured 2026-11-19:
  // `-p` is a boolean flag here, `--no-install` does not stop the download, `--no` / `--no-yes` / `--ignore-existing` are booleans).
  // Built from npm's flags as they were before its groups were read as npm reads them, plus `-L` and `-m` (M-4; the owner's
  // answer B to question 4): `npm exec -L global P` and `npm exec -m <v> P` ask for P. A group of letters keeps the rule of today.
  "npm-exec": {
    value: set(...NPM_VALUE_FLAGS, "--package", "--call", "-c", "-L", "-m"),
    bool: set(...NPM_BOOL_FLAGS, "-p", "--no", "--no-install", "--no-yes", "--ignore-existing"),
    registry: NPM_TABLE.registry,
    workspace: set(...NPM_WORKSPACE_FLAGS),
    packageFlags: set("--package"),
    shellFlags: set("--call", "-c"),
    noFetchFlags: set("--no", "--offline"),
    boolWord: { except: LOGLEVEL_FLAGS },
    long: NPM_LONG,
    stringValue: set("-m"),
    notInGroups: set("-L", "-m")
  },
  // `npm init` / `create` / `innit` (one npm command): npm's flags and its `true` / `false` rule, plus the flags of `npm init --help`
  // (the stored help of npm 11.20.0). Measured 2026-11-20 (npm 11.20.0): `init -y X`, `init --yes X`, `init -q X`, `init --quiet X`,
  // `init --silent X` and `init -w <dir> X` ask the registry for `create-X`.
  // Built, as `npm exec`, from npm's flags of before plus `-L` and `-m`: `npm init -L global x` asks for `create-x` (M-4).
  "npm-init": {
    value: set(
      ...NPM_VALUE_FLAGS,
      "--init-author-name",
      "--init-author-url",
      "--init-license",
      "--init-module",
      "--init-type",
      "--init-version",
      "-L",
      "-m"
    ),
    bool: set(...NPM_BOOL_FLAGS, "--init-private", "--no-workspaces-update"),
    registry: NPM_TABLE.registry,
    dir: NPM_TABLE.dir,
    workspace: set(...NPM_WORKSPACE_FLAGS),
    boolWord: { except: LOGLEVEL_FLAGS },
    long: NPM_LONG,
    stringValue: set("-m"),
    notInGroups: set("-L", "-m")
  },
  // `yarn create`: `-p` / `--package` (the help of Yarn 3 and 4; Yarn 1 has none, not measured) and `-q` / `--quiet` (measured, Yarn 1, 3 and 4).
  "yarn-create": {
    value: set("--package", "-p"),
    bool: set("--quiet", "-q"),
    registry: set(),
    packageFlags: set("--package", "-p")
  },
  // `pnpm create` (pnpm 11.24.0): the flags of `pnpm dlx` that are no package flags; no flag was measured with it.
  "pnpm-create": {
    value: set("--allow-build", "--registry", "--dir", "-C", "--reporter"),
    bool: set("--silent", "-s", "--quiet", "--verbose"),
    registry: set("--registry"),
    dir: set("--dir", "-C")
  },
  // `bun create` / `bun c`: no flag was measured.
  "bun-create": { value: set(), bool: set(), registry: set() },
  "pnpm-dlx": {
    value: set("--package", "--allow-build", "--registry", "--dir", "-C", "--reporter"),
    // `--quiet` and `--verbose` (measured 2026-11-19, pnpm 10.33.2: `--quiet false P` asks for `false`).
    bool: set("--silent", "-s", "--shell-mode", "-c", "--quiet", "--verbose", "-p"),
    registry: set("--registry"),
    dir: set("--dir", "-C"),
    packageFlags: set("--package"),
    shellFlags: set("--shell-mode", "-c"),
    // Measured 2026-11-19 (pnpm 10.33.2): `-c P`, `--shell-mode P`, `-c false P` and `-p false P` ask for P.
    optionalWord: set("--shell-mode", "-c", "-p"),
    shellWord: true,
    bothWays: "flags"
  },
  "yarn-dlx": {
    value: set("--package", "-p"),
    bool: set("--quiet", "-q"),
    registry: set(),
    packageFlags: set("--package", "-p"),
    bothWays: "flags"
  },
  bunx: {
    value: set("--package", "-p"),
    // `--quiet` (bun 1.4.4, measured 2026-11-19: `bunx --quiet false P` asks for `false`).
    bool: set("--bun", "--silent", "--verbose", "--quiet"),
    registry: set(),
    packageFlags: set("--package", "-p"),
    bothWays: "flags"
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
  // `uv run` (the help of uv 0.13.8 stored by the measurement M-2 of install-vet-inline-script-deps, `.specs/install-vet-inline-script-deps/
  // measurements/m2-linux-container-2026-11-21.txt:15-242`): the options written with `<…>` take a value, the others do not. The short
  // spellings are noted under the long one. The words after the program are the program's own: they are never read with this table.
  "uv-run": {
    value: set(
      "--extra",
      "--no-extra",
      "--group",
      "--no-group",
      "--only-group",
      "--no-editable-package",
      "--env-file",
      "--with",
      "-w",
      "--with-editable",
      "--with-requirements",
      "--package",
      "--python-platform",
      "--index",
      "--default-index",
      "--index-url",
      "-i",
      "--extra-index-url",
      "--find-links",
      "-f",
      "--index-strategy",
      "--keyring-provider",
      "--upgrade-package",
      "-P",
      "--upgrade-group",
      "--resolution",
      "--prerelease",
      "--prerelease-package",
      "--fork-strategy",
      "--exclude-newer",
      "--exclude-newer-package",
      "--no-sources-package",
      "--reinstall-package",
      "--link-mode",
      "--config-setting",
      "-C",
      "--config-settings-package",
      "--no-build-isolation-package",
      "--no-build-package",
      "--no-binary-package",
      "--cache-dir",
      "--refresh-package",
      "--python",
      "-p",
      "--color",
      "--allow-insecure-host",
      "--directory",
      "--project",
      "--config-file"
    ),
    bool: set(
      "--all-extras",
      "--no-dev",
      "--only-dev",
      "--no-default-groups",
      "--all-groups",
      "--module",
      "-m",
      "--no-editable",
      "--exact",
      "--no-env-file",
      "--isolated",
      "--active",
      "--no-sync",
      "--locked",
      "--frozen",
      "--script",
      "-s",
      "--gui-script",
      "--all-packages",
      "--no-project",
      "--no-index",
      "--no-sources",
      "--upgrade",
      "-U",
      "--reinstall",
      "--compile-bytecode",
      "--no-build-isolation",
      "--no-build",
      "--no-binary",
      "--require-build-hashes",
      "--no-require-build-hashes",
      "--no-cache",
      "-n",
      "--refresh",
      "--managed-python",
      "--no-managed-python",
      "--no-python-downloads",
      "--quiet",
      "-q",
      "--verbose",
      "-v",
      "--system-certs",
      "--offline",
      "--no-progress",
      "--no-config",
      "--help",
      "-h"
    ),
    registry: set("--index", "--default-index", "--index-url", "--extra-index-url", "--find-links"),
    registryBool: set("--no-index"),
    long: /* @__PURE__ */ new Map([["-m", "--module"], ["-s", "--script"], ["-w", "--with"], ["-i", "--index-url"], ["-f", "--find-links"]]),
    extraPackageFlags: set("--with")
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
    // `--path` takes no value (the help of pipx 1.18.16, M-2 of install-vet-inline-script-deps): the app is a path to a script.
    value: set("--spec", "--index-url", "-i", "--python", "--with"),
    bool: set("--no-cache", "--quiet", "-q", "--verbose", "-v", "--system-site-packages", "--fetch-missing-python", "--path"),
    registry: set("--index-url", "-i"),
    packageFlags: set("--spec"),
    extraPackageFlags: set("--with")
  },
  // `pipx inject <environment> <package>…` (pipx, the parser dumped 2026-11-21, 23 spellings): `--include-resources-from` names a
  // package pipx fetches as well, and `-r` a requirements file pip reads (its manifest is read, `collectLaunch`).
  "pipx-inject": {
    value: set("-r", "--requirement", "--include-resources-from", "--index-url", "-i", "--pip-args", "--cooldown", "--backend", "--output"),
    bool: set(
      "--quiet",
      "-q",
      "--verbose",
      "-v",
      "--skip-maintenance",
      "--global",
      "--include-apps",
      "--include-deps",
      "--system-site-packages",
      "--editable",
      "-e",
      "--force",
      "-f",
      "--with-suffix"
    ),
    registry: set("--index-url", "-i"),
    reported: /* @__PURE__ */ new Map([["-r", PIP_REQUIREMENTS_REASON], ["--requirement", PIP_REQUIREMENTS_REASON]]),
    extraPackageFlags: set("--include-resources-from")
  },
  // `pipx runpip <environment> <pip arguments>`: only pipx's own flags, the rest is a pip command ({@link runpipDetected}).
  "pipx-runpip": {
    value: set(),
    bool: set("--quiet", "-q", "--verbose", "-v", "--global", "--skip-maintenance"),
    registry: set()
  },
  "pipx-upgrade": PIPX_UPGRADE_TABLE
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
var isNpmGroupWord = (v, table) => table.groups === "npm" && !v.startsWith("--") && SHORT_CLUSTER.test(v) && !table.value.has(v) && !table.bool.has(v);
function openNpmGroup(word) {
  const letters = [...word.slice(1)];
  if (!letters.every((c) => NPM_LETTERS.has(c))) return void 0;
  const group = { flags: [], positionals: [], next: "none" };
  for (let k = 0; k < letters.length; k += 1) {
    const letter = letters[k] ?? "";
    const after = letters[k + 1];
    if (after === void 0) {
      group.flags.push({ flag: `-${letter}` });
      group.next = NPM_TAKE_NEXT_LETTER.has(letter) ? "value" : NPM_STRING_LETTERS.has(letter) ? "string" : "none";
    } else if (NPM_TAKE_NEXT_LETTER.has(letter)) {
      const [first = "", second] = (NPM_LETTERS.get(after) ?? "").split(" ");
      group.flags.push({ flag: `-${letter}`, value: first });
      if (second !== void 0) group.positionals.push(second);
      k += 1;
    } else group.flags.push({ flag: `-${letter}` });
  }
  return group;
}
var takesNextWord = (next, word) => word !== void 0 && (next === "value" || next === "string" && !NOPT_FLAG_LIKE.test(word));
var valueKind = (v, table) => table.stringValue?.has(v) === true ? "string" : "value";
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
function takesWord(v, table) {
  return takesBoolWord(v, table) || table.optionalWord?.has(v) === true;
}
function readsBothWays(v, next, table) {
  if (table.bothWays === void 0 || !isBoolWord(next)) return false;
  if (!v.startsWith("--") && SHORT_CLUSTER.test(v)) return true;
  return table.bothWays === "flags" && table.bool.has(v);
}
var bothWaysReason = (word, flag) => `\`${word}\` after \`${flag}\`${TWO_READINGS} \u2014 the value of the flag, or the package \u2014 both are looked up`;
var productionWordReason = (word) => `\`${word}\` after \`--production\`${TWO_READINGS} \u2014 Yarn 1 takes it as the value of the flag and Yarn 4 as the subcommand; no manager installs it as a package, so it is not looked up and the manifest is read`;
function walk(words, table) {
  const positionals = [];
  const skipped = [];
  const uncertain = [];
  let unknownFlags = 0;
  let customRegistry;
  const registries = [];
  const flags = [];
  let here = 0;
  const note = (written, value, eq2) => {
    const flag = table.long?.get(written) ?? written;
    flags.push(value === void 0 ? { flag, at: here } : eq2 === true ? { flag, value, eq: eq2, at: here } : { flag, value, at: here });
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
    here = i;
    const v = w.value;
    if (v === "--") continue;
    if (!v.startsWith("-") || v.length === 1) {
      positionals.push(i === candidateAt ? { value: v, at: i, candidate: true } : { value: v, at: i });
      continue;
    }
    const eqAt = v.indexOf("=");
    if (eqAt > 0) {
      const flag = v.slice(0, eqAt);
      if (!known(flag)) {
        uncertain.push(`unknown flag ${flag}`);
        unknownFlags += 1;
      }
      note(flag, v.slice(eqAt + 1), true);
      continue;
    }
    if (table.value.has(v)) {
      const word = words[i + 1]?.value;
      if (takesNextWord(valueKind(v, table), word)) {
        note(v, word);
        i += 1;
      } else note(v, void 0);
      continue;
    }
    if (table.bool.has(v)) {
      const word = words[i + 1]?.value;
      if (takesWord(v, table) && isBoolWord(word)) {
        note(v, word);
        i += 1;
      } else {
        note(v, void 0);
        if (readsBothWays(v, word, table)) {
          candidateAt = i + 1;
          uncertain.push(bothWaysReason(word ?? "", v));
        }
      }
      continue;
    }
    if (isNpmGroupWord(v, table)) {
      const group = openNpmGroup(v);
      if (group === void 0) {
        uncertain.push(`unknown flag ${v}`);
        unknownFlags += 1;
        continue;
      }
      const word = words[i + 1]?.value;
      const last = group.flags.length - 1;
      for (const [k, f] of group.flags.entries()) {
        if (k < last || f.value !== void 0) note(f.flag, f.value);
        else if (takesNextWord(group.next, word) || takesWord(v, table) && isBoolWord(word)) {
          note(f.flag, word);
          i += 1;
        } else note(f.flag, void 0);
      }
      for (const value of group.positionals) positionals.push({ value, at: i });
      continue;
    }
    if (!v.startsWith("--") && SHORT_CLUSTER.test(v)) {
      for (let k = 1; k < v.length; k += 1) {
        const flag = `-${v.charAt(k)}`;
        if (table.value.has(flag) && table.notInGroups?.has(flag) !== true) {
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
      const word = words[i + 1]?.value;
      if (takesWord(v, table) && isBoolWord(word)) i += 1;
      else if (readsBothWays(v, word, table)) {
        candidateAt = i + 1;
        uncertain.push(bothWaysReason(word ?? "", v));
      }
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
var NPM_INSTALL = /* @__PURE__ */ new Set(["install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "install-test", "it"]);
var NPM_MANIFEST_INSTALL = /* @__PURE__ */ new Set([
  "ci",
  "clean-install",
  "ic",
  "install-clean",
  "isntall-clean",
  "install-ci-test",
  "cit",
  "clean-install-test",
  "sit"
]);
var NPM_UPDATE = /* @__PURE__ */ new Set(["update", "u", "up", "upgrade", "udpate"]);
var NPM_MAINTENANCE = /* @__PURE__ */ new Set(["dedupe", "ddp", "prune"]);
var PNPM_UPDATE = /* @__PURE__ */ new Set(["update", "up", "upgrade"]);
var YARN_UPDATE = /* @__PURE__ */ new Set(["upgrade", "upgrade-interactive"]);
var COMPOSER_REQUIRE = /* @__PURE__ */ new Set(["require", "r", "req", "requ", "requi", "requir"]);
var BUN_ADD = /* @__PURE__ */ new Set(["add", "a", "install", "i"]);
var PNPM_INSTALL = /* @__PURE__ */ new Set(["install", "i"]);
var YARN_PRINTS = /* @__PURE__ */ new Set(["--version", "-v", "-V", "--help", "-h"]);
var REQUIREMENT_FLAGS = /* @__PURE__ */ new Set(["-r", "--requirement", "--requirements"]);
var isGlobalFlag = (f) => (f.flag === "-g" || f.flag === "--global") && f.value !== "false" || f.flag === "--location" && f.value === "global";
var GLOBAL_FLAG_WORD = /^(?:--global(?:=.*)?|--location(?:=.*)?|-[A-Za-z]*g[A-Za-z]*)$/;
var hasGlobalFlagWord = (pre, args) => [...beforeDoubleDash(pre), ...beforeDoubleDash(args)].some((w) => GLOBAL_FLAG_WORD.test(w.value));
var beforeDoubleDash = (words) => {
  const at = words.findIndex((w) => w.value === "--");
  return at < 0 ? [...words] : words.slice(0, at);
};
function saysGlobal(manager, pre, args) {
  if (manager !== "npm" && manager !== "pnpm" && manager !== "bun") return false;
  if ([...pre, ...args].some((w) => /[$`]/.test(w.value))) return false;
  let says = false;
  for (const list of [beforeDoubleDash(pre), beforeDoubleDash(args)]) {
    const read2 = manager === "npm" ? npmFlagWords(list) : rawFlagWords(list);
    for (const { flag: v, next } of read2) {
      if (v === "-g" || v === "--global") {
        if (next === "false") return false;
        says = true;
      } else if (v === "--global=true") says = true;
      else if (manager === "npm" && (v === "--location=global" || v === "--location" && next === "global")) says = true;
      else if (v.startsWith("-g=") || /global|location/.test(v.toLowerCase())) return false;
      else if (manager !== "npm" && /^-[A-Za-z]{2,}$/.test(v) && v.includes("g")) return false;
    }
  }
  return says;
}
var rawFlagWords = (list) => list.flatMap((w, at) => w.value.startsWith("-") ? [{ flag: w.value, next: list[at + 1]?.value }] : []);
function npmFlagWords(list) {
  const out = [];
  for (const { flag: v, next } of rawFlagWords(list)) {
    const group = isNpmGroupWord(v, NPM_TABLE) ? openNpmGroup(v) : void 0;
    if (group === void 0) {
      out.push({ flag: NPM_LONG.get(v) ?? v, next });
      continue;
    }
    for (const [k, f] of group.flags.entries()) {
      const following = group.flags[k + 1];
      out.push({ flag: NPM_LONG.get(f.flag) ?? f.flag, next: f.value ?? (following === void 0 ? next : following.flag) });
    }
  }
  return out;
}
var DOTNET_FORM_TABLES = {
  run: "dotnet-run",
  "tool-update": "dotnet-tool-update",
  "new-install": "dotnet-new-install",
  download: "dotnet-download",
  "package-update": "dotnet-package-update"
};
function launcher(manager, ecosystem, args, pre, launch) {
  return { manager, ecosystem, args, pre, uncertain: [], launch };
}
function scanPositional(words, from, table, subcommands) {
  let candidateAt = -1;
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (v.startsWith("-") && v.length > 1) {
      if (v.includes("=")) continue;
      const next = words[i + 1]?.value;
      const group = isNpmGroupWord(v, table) ? openNpmGroup(v) : void 0;
      if (table.value.has(v)) {
        if (takesNextWord(valueKind(v, table), next)) i += 1;
      } else if (takesWord(v, table) && isBoolWord(next)) i += 1;
      else if (readsBothWays(v, next, table)) candidateAt = i + 1;
      else if (group !== void 0) {
        if (takesNextWord(group.next, next)) i += 1;
      } else {
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
var NPM_INITIALIZER = /* @__PURE__ */ new Set(["create", "init", "innit"]);
var CREATE_ONLY = /* @__PURE__ */ new Set(["create"]);
var BUN_INITIALIZER = /* @__PURE__ */ new Set(["create", "c"]);
var INITIALIZER_VERBS = { npm: NPM_INITIALIZER, pnpm: CREATE_ONLY, yarn: CREATE_ONLY, bun: BUN_INITIALIZER };
var INITIALIZER_FLAGS = { npm: "npm-init", pnpm: "pnpm-create", yarn: "yarn-create", bun: "bun-create" };
var SUBCOMMANDS = {
  npm: /* @__PURE__ */ new Set([...NPM_INSTALL, ...NPM_MANIFEST_INSTALL, ...NPM_UPDATE, ...NPM_MAINTENANCE, "audit", "exec", "x", ...NPM_INITIALIZER]),
  pnpm: /* @__PURE__ */ new Set(["add", "dlx", "dedupe", ...PNPM_INSTALL, ...PNPM_UPDATE, ...CREATE_ONLY]),
  bun: /* @__PURE__ */ new Set([...BUN_ADD, "update", "x", ...BUN_INITIALIZER]),
  yarn: /* @__PURE__ */ new Set(["install", "add", "global", "workspace", "workspaces", "dlx", "dedupe", "up", ...YARN_UPDATE, ...CREATE_ONLY]),
  pip: /* @__PURE__ */ new Set(["install", "download", "wheel"]),
  uv: /* @__PURE__ */ new Set(["add", "pip", "tool", "run"]),
  poetry: /* @__PURE__ */ new Set(["add"]),
  composer: COMPOSER_REQUIRE,
  dotnet: /* @__PURE__ */ new Set(["add", "package", "tool", "new", "dnx"])
};
var PIPX_SUBCOMMANDS = /* @__PURE__ */ new Set(["install", "run", "inject", "upgrade", "reinstall", "runpip", "upgrade-all"]);
var UV_TOOL_SUBCOMMANDS = /* @__PURE__ */ new Set(["run", "install", "upgrade"]);
var PIP_FETCH_TABLES = /* @__PURE__ */ new Map([["install", void 0], ["download", "pip-download"], ["wheel", "pip-wheel"]]);
var ADD_OR_UP = /* @__PURE__ */ new Set(["add", "up"]);
var ADD_OR_UPGRADE = /* @__PURE__ */ new Set(["add", "upgrade"]);
var FOREACH_ONLY = /* @__PURE__ */ new Set(["foreach"]);
var FOREACH_UNKNOWN_FLAG = "a flag of yarn workspaces foreach the hook does not know";
var FOREACH_VALUE = /* @__PURE__ */ new Set(["--from", "--include", "--exclude", "-j", "--jobs"]);
var FOREACH_BOOL = /* @__PURE__ */ new Set(["-A", "--all", "-R", "--recursive", "-W", "--worktree", "-v", "--verbose", "-p", "--parallel", "-i", "--interlaced", "-t", "--topological", "--topological-dev", "--no-private", "-n", "--dry-run"]);
function foreachVerb(words, from) {
  let unknown2 = false;
  for (let i = from; i < words.length; i += 1) {
    const v = words[i]?.value ?? "";
    if (!v.startsWith("-") || v.length === 1) return ADD_OR_UP.has(v) ? { at: i, unknown: unknown2 } : { at: -1, unknown: unknown2 };
    const flag = v.includes("=") ? v.slice(0, v.indexOf("=")) : v;
    if (FOREACH_VALUE.has(flag)) {
      if (!v.includes("=")) i += 1;
    } else if (!FOREACH_BOOL.has(flag)) unknown2 = true;
  }
  return { at: -1, unknown: unknown2 };
}
function yarnWorkspaceVerb(words, at, table, head, pre, uncertain, tag) {
  const verb = words[at]?.value;
  if (verb === "up") {
    const update = scanPositional(words, at + 1, table).at >= 0;
    return tag({ manager: head, ecosystem: "npm", args: words.slice(at + 1), pre, uncertain, manifest: "always", names: "always", ...update ? { update: true } : {} });
  }
  if (verb !== "add") return null;
  return tag({ manager: head, ecosystem: "npm", args: words.slice(at + 1), pre, uncertain, manifest: "bare" });
}
function injectDetected(after, before) {
  const table = LAUNCH_FLAGS["pipx-inject"];
  const environment = table === void 0 ? void 0 : walk(after, table).positionals[0];
  if (environment === void 0) return null;
  const d = launcher("pipx", "pypi", after.slice(environment.at + 1), [...before, ...after.slice(0, environment.at + 1)], {
    style: "install",
    flags: "pipx-inject"
  });
  return environment.candidate === true ? { ...d, firstIsCandidate: true } : d;
}
function runpipDetected(after, before) {
  const table = LAUNCH_FLAGS["pipx-runpip"];
  const [first, second, third] = table === void 0 ? [] : walk(after, table).positionals;
  if (table === void 0 || first === void 0) return null;
  let environment = first;
  if (first.candidate === true && !(second !== void 0 && PIP_FETCH_TABLES.has(second.value))) {
    if (second === void 0 || third === void 0 || !PIP_FETCH_TABLES.has(third.value)) return null;
    environment = second;
  }
  const word = after[environment.at];
  if (word === void 0) return null;
  const inner = detect([{ ...word, value: "pip" }, ...after.slice(environment.at + 1)]);
  if (inner === null) return null;
  const own = walk([...before, ...after.slice(0, environment.at + 1)], table).uncertain;
  return { ...inner, uncertain: [...own, ...inner.uncertain] };
}
function upgradeDetected(after, before) {
  if (walk(after, PIPX_UPGRADE_TABLE).flags.some((f) => f.flag === "--install")) {
    return launcher("pipx", "pypi", after, before, { style: "install", flags: "pipx-upgrade" });
  }
  return { manager: "pipx", ecosystem: "pypi", args: after, pre: before, uncertain: [], flagTable: "pipx-upgrade", names: "always" };
}
var INSTALL_ONLY = /* @__PURE__ */ new Set(["install"]);
var DOTNET_TOOL_VERBS = /* @__PURE__ */ new Set(["install", "exec", "execute", "update"]);
var DOTNET_PACKAGE_VERBS = /* @__PURE__ */ new Set(["add", "download", "update"]);
function dotnetDetected(form, spelling, args, pre) {
  return { manager: "dotnet", ecosystem: "nuget", args, pre, uncertain: [], flagTable: DOTNET_FORM_TABLES[form], dotnet: { form, spelling } };
}
var PACKAGE_ONLY = /* @__PURE__ */ new Set(["package"]);
function measuredWord(words, start, program, verb) {
  const last = words[start + 2]?.value;
  if (words.length !== start + 3 || last === void 0 || last.startsWith("-")) return false;
  const rightVerb = program === "pipx" ? verb === "install" || verb === "run" : verb === "require";
  return words[start]?.value === program && words[start + 1]?.value === verb && rightVerb && MEASURED_ENDING.test(last);
}
function detect(input) {
  let words = input;
  const nextPositional = (ws, from, table2, subcommands2) => scanPositional(ws, from, table2, subcommands2).at;
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
  let viaCorepack = false;
  if (head === "corepack") {
    const first2 = words[start + 1]?.value;
    const via = corepackManager(first2);
    if (via !== void 0) {
      head = via;
      viaCorepack = true;
      i = start + 2;
    } else if (first2 === "up" || first2 === "use" && corepackManager(words[start + 2]?.value) !== void 0) {
      return { manager: "npm", ecosystem: "npm", args: [], pre: [], uncertain: [], manifest: "always" };
    } else return null;
  }
  const rest = words.slice(i);
  const corepackMark = viaCorepack ? { viaCorepack: true } : {};
  if (head === "npx") return launcher("npx", "npm", rest, [], { style: "run", flags: "npx", localFirst: true, spelling: "npx", ...corepackMark });
  if (head === "pnpx") return launcher("pnpm", "npm", rest, [], { style: "run", flags: "pnpm-dlx", spelling: "pnpx", ...corepackMark });
  if (head === "bunx") return launcher("bun", "npm", rest, [], { style: "run", flags: "bunx", localFirst: true, spelling: "bunx", ...corepackMark });
  if (head === "uvx") return launcher("uv", "pypi", rest, [], { style: "run", flags: "uvx" });
  if (head === "pipx") {
    const sub2 = nextPositional(words, i, LAUNCH_FLAGS["pipx-run"] ?? FLAGS["pip"] ?? { value: set(), bool: set(), registry: set() }, PIPX_SUBCOMMANDS);
    const subWord2 = sub2 < 0 ? "" : words[sub2]?.value ?? "";
    const after2 = words.slice(sub2 + 1);
    const before2 = words.slice(i, sub2);
    const measured = measuredWord(words, start, "pipx", subWord2) ? { measuredArchiveForm: true } : {};
    switch (subWord2) {
      case "install":
        return { ...launcher("pipx", "pypi", after2, before2, { style: "install", flags: "pipx-install" }), registryForm: "pipx install", ...measured };
      case "run":
        return { ...launcher("pipx", "pypi", after2, before2, { style: "run", flags: "pipx-run" }), registryForm: "pipx run", ...measured };
      case "inject":
        return injectDetected(after2, before2);
      case "runpip":
        return runpipDetected(after2, before2);
      case "upgrade":
        return upgradeDetected(after2, before2);
      // The names of an update (`names`), read with the flags of the verb ({@link FLAGS}).
      case "reinstall":
        return { manager: "pipx", ecosystem: "pypi", args: after2, pre: before2, uncertain: [], flagTable: "pipx-reinstall", names: "always" };
      // `pipx upgrade-all` takes no name: its words are none (a word after `--skip a` is another value of `--skip`).
      case "upgrade-all":
        return { manager: "pipx", ecosystem: "pypi", args: after2, pre: before2, uncertain: [], flagTable: "pipx-upgrade-all", everyTool: "always" };
      default:
        return null;
    }
  }
  if (head === "dnx") return dotnetDetected("run", "dnx", rest, []);
  const table = FLAGS[head];
  if (table === void 0) return null;
  const initVerbs = INITIALIZER_VERBS[head];
  const subcommands = SUBCOMMANDS[head];
  let first = scanPositional(words, i, table, subcommands);
  while (initVerbs !== void 0 && first.at >= 0 && first.candidate && initVerbs.has(words[first.at]?.value ?? "")) {
    const following = scanPositional(words, first.at + 1, table, subcommands).at;
    const followingWord = following < 0 ? void 0 : words[following]?.value ?? "";
    if (followingWord !== void 0 && !(subcommands?.has(followingWord) === true && !initVerbs.has(followingWord))) break;
    first = scanPositional(words, first.at + 1, table, subcommands);
  }
  let sub = first.at;
  let productionWord;
  const wordAt = words[sub];
  if (head === "yarn" && wordAt !== void 0 && isBoolWord(wordAt.value) && words[sub - 1]?.value === "--production") {
    productionWord = wordAt.value;
    words = [...words.slice(0, sub), ...words.slice(sub + 1)];
    sub = nextPositional(words, sub, table, SUBCOMMANDS[head]);
  }
  const tag = (d) => productionWord === void 0 ? d : { ...d, uncertain: [...d.uncertain, productionWordReason(productionWord)] };
  if (sub < 0) {
    if (head === "yarn" && !rest.some((w) => YARN_PRINTS.has(w.value))) {
      return tag({ manager: head, ecosystem: "npm", args: rest, pre: [], uncertain: [], manifest: "always" });
    }
    return null;
  }
  const subName = words[sub]?.value ?? "";
  const after = words.slice(sub + 1);
  const before = words.slice(i, sub);
  if (head === "npm" && (subName === "exec" || subName === "x")) {
    return launcher("npm", "npm", after, before, { style: "run", flags: "npm-exec", localFirst: true, spelling: `npm ${subName}`, ...corepackMark });
  }
  if (head === "pnpm" && subName === "dlx") return launcher("pnpm", "npm", after, before, { style: "run", flags: "pnpm-dlx", spelling: "pnpm dlx", ...corepackMark });
  if (head === "yarn" && subName === "dlx") return launcher("yarn", "npm", after, before, { style: "run", flags: "yarn-dlx", spelling: "yarn dlx", ...corepackMark });
  if (head === "bun" && subName === "x") return launcher("bun", "npm", after, before, { style: "run", flags: "bunx", localFirst: true, spelling: "bun x", ...corepackMark });
  if (initVerbs?.has(subName) === true) return initializerLaunch(head, after, before);
  if (head === "uv" && subName === "tool") {
    const toolTable = LAUNCH_FLAGS["uvx"] ?? table;
    const verb = nextPositional(words, sub + 1, toolTable, UV_TOOL_SUBCOMMANDS);
    const verbName = verb < 0 ? "" : words[verb]?.value ?? "";
    const tail = words.slice(verb + 1);
    if (verbName === "run") return launcher("uv", "pypi", tail, before, { style: "run", flags: "uvx" });
    if (verbName === "install") return launcher("uv", "pypi", tail, before, { style: "install", flags: "uv-tool-install" });
    if (verbName === "upgrade") {
      return { manager: "uv", ecosystem: "pypi", args: tail, pre: before, uncertain: [], flagTable: "uv-tool-upgrade", names: "always", everyTool: "all-flag" };
    }
    return null;
  }
  const subWord = words[sub]?.value ?? "";
  const pre = words.slice(i, sub);
  switch (head) {
    case "npm":
      if (NPM_INSTALL.has(subWord)) return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "bare" };
      if (NPM_MANIFEST_INSTALL.has(subWord) || NPM_MAINTENANCE.has(subWord)) {
        return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always" };
      }
      if (NPM_UPDATE.has(subWord)) return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always", update: true, names: "global-word" };
      if (subWord === "audit" && words[nextPositional(words, sub + 1, table)]?.value === "fix") {
        return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always" };
      }
      return null;
    case "pnpm":
      if (subWord === "add") return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "bare" };
      if (PNPM_INSTALL.has(subWord)) return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "bare" };
      if (subWord === "dedupe") return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always" };
      if (PNPM_UPDATE.has(subWord)) return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always", update: true, names: "global-word" };
      return null;
    case "bun": {
      if (subWord === "update") return { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always", update: true, names: "global-word" };
      if (!BUN_ADD.has(subWord)) return null;
      const d = { manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "bare" };
      return subWord === "add" || subWord === "install" ? { ...d, registryForm: `bun ${subWord}` } : d;
    }
    case "yarn": {
      if (subWord === "install" || subWord === "dedupe") return tag({ manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always" });
      if (YARN_UPDATE.has(subWord)) return tag({ manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always", update: true });
      if (subWord === "up") {
        const update = nextPositional(words, sub + 1, table) >= 0;
        return tag({ manager: head, ecosystem: "npm", args: words.slice(sub + 1), pre, uncertain: [], manifest: "always", names: "always", ...update ? { update: true } : {} });
      }
      let at = sub;
      const uncertain = [];
      if (subWord === "workspaces") {
        const foreach = nextPositional(words, sub + 1, table, FOREACH_ONLY);
        if (foreach < 0 || words[foreach]?.value !== "foreach") return null;
        const verb = foreachVerb(words, foreach + 1);
        if (verb.at < 0) return null;
        uncertain.push("workspace context (yarn workspaces)");
        if (verb.unknown) uncertain.push(FOREACH_UNKNOWN_FLAG);
        return yarnWorkspaceVerb(words, verb.at, table, head, pre, uncertain, tag);
      }
      if (subWord === "global") at = nextPositional(words, sub + 1, table, ADD_OR_UPGRADE);
      else if (subWord === "workspace") {
        const ws = nextPositional(words, sub + 1, table);
        at = ws < 0 ? -1 : nextPositional(words, ws + 1, table, ADD_OR_UP);
        uncertain.push("workspace context (yarn workspace)");
      }
      if (at < 0) return null;
      if (subWord === "global" && words[at]?.value === "upgrade") {
        return tag({ manager: head, ecosystem: "npm", args: words.slice(at + 1), pre, uncertain, global: true, names: "always" });
      }
      if (subWord === "global") {
        if (words[at]?.value !== "add") return null;
        return tag({ manager: head, ecosystem: "npm", args: words.slice(at + 1), pre, uncertain, manifest: "bare", global: true });
      }
      return yarnWorkspaceVerb(words, at, table, head, pre, uncertain, tag);
    }
    case "pip": {
      if (!PIP_FETCH_TABLES.has(subWord)) return null;
      const flagTable = PIP_FETCH_TABLES.get(subWord);
      const d = { manager: head, ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [] };
      if (flagTable !== void 0) return { ...d, flagTable };
      return subWord === "install" ? { ...d, registryForm: "pip install" } : d;
    }
    case "uv": {
      if (subWord === "run") {
        const d = launcher("uv", "pypi", words.slice(sub + 1), pre, { style: "run", flags: "uv-run", program: true });
        const envDir = leadingWorkingDir(words.slice(0, start));
        return envDir === void 0 ? d : { ...d, envDir };
      }
      if (subWord === "add") return { manager: "uv", ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [], registryForm: "uv add" };
      if (subWord === "pip") {
        const inst = nextPositional(words, sub + 1, table, INSTALL_ONLY);
        if (inst >= 0 && words[inst]?.value === "install") {
          return { manager: "uv-pip", ecosystem: "pypi", args: words.slice(inst + 1), pre, uncertain: [], registryForm: "uv pip install" };
        }
      }
      return null;
    }
    case "poetry":
      return subWord === "add" ? { manager: head, ecosystem: "pypi", args: words.slice(sub + 1), pre, uncertain: [], registryForm: "poetry add" } : null;
    case "composer":
      return COMPOSER_REQUIRE.has(subWord) ? {
        manager: head,
        ecosystem: "packagist",
        args: words.slice(sub + 1),
        pre,
        uncertain: [],
        ...measuredWord(words, start, "composer", subWord) ? { measuredArchiveForm: true } : {}
      } : null;
    case "dotnet": {
      if (subWord === "dnx") return dotnetDetected("run", "dotnet dnx", words.slice(sub + 1), pre);
      if (subWord === "new") {
        const verb = nextPositional(words, sub + 1, FLAGS["dotnet-new-install"] ?? table, INSTALL_ONLY);
        return verb >= 0 && words[verb]?.value === "install" ? dotnetDetected("new-install", "dotnet new install", words.slice(verb + 1), pre) : null;
      }
      if (subWord === "package") {
        const verb = nextPositional(words, sub + 1, table, DOTNET_PACKAGE_VERBS);
        const verbName = verb < 0 ? "" : words[verb]?.value ?? "";
        if (verbName === "download") return dotnetDetected("download", "dotnet package download", words.slice(verb + 1), pre);
        if (verbName === "update") return dotnetDetected("package-update", "dotnet package update", words.slice(verb + 1), pre);
        if (verbName !== "add") return null;
        const args = words.slice(verb + 1);
        const uncertain2 = args.some((w) => /^--(?:project|file)(?:=|$)/.test(w.value)) ? ["dotnet project argument (the NuGet configuration next to that project was not read)"] : [];
        return { manager: head, ecosystem: "nuget", args, pre, uncertain: uncertain2 };
      }
      if (subWord === "tool") {
        const toolTable = FLAGS["dotnet-tool"] ?? table;
        const verb = nextPositional(words, sub + 1, toolTable, DOTNET_TOOL_VERBS);
        const verbName = verb < 0 ? "" : words[verb]?.value ?? "";
        const after2 = verb < 0 ? [] : words.slice(verb + 1);
        if (verbName === "exec" || verbName === "execute") return dotnetDetected("run", `dotnet tool ${verbName}`, after2, pre);
        if (verbName === "update") return dotnetDetected("tool-update", "dotnet tool update", after2, pre);
        if (verbName !== "install") return null;
        return { manager: head, ecosystem: "nuget", args: after2, pre, uncertain: [], flagTable: "dotnet-tool" };
      }
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
function leadingWorkingDir(front) {
  let found;
  for (const w of front) if (w.value.startsWith("UV_WORKING_DIR=")) found = w.value.slice("UV_WORKING_DIR=".length);
  return found;
}
var COMPOSER_CONSTRAINT = /^(?:[\^~<>=!*]|v?\d|dev-|@)/;
function launchEnd(args, table) {
  let scan = scanPositional(args, 0, table);
  let end = scan.at;
  while (scan.at >= 0 && scan.candidate) {
    scan = scanPositional(args, scan.at + 1, table);
    if (scan.at >= 0) end = scan.at;
  }
  return end;
}
function isInitializerName(word, manager) {
  const scoped = word.startsWith("@");
  const versioned = word.indexOf("@", scoped ? 1 : 0) > 0;
  if (notAPackage(word, versioned ? null : fileEndings(manager, scoped)) !== null) return false;
  return "name" in parseNpm(initializerNames(word, manager).names[0] ?? word, manager);
}
function initializerLaunch(head, after, before) {
  const flags = INITIALIZER_FLAGS[head];
  const table = flags === void 0 ? void 0 : LAUNCH_FLAGS[flags];
  if (flags === void 0 || table === void 0) return null;
  const end = launchEnd(after, table);
  if (end < 0) return null;
  if (!walk(after.slice(0, end + 1), table).positionals.some((p) => isInitializerName(p.value, head))) return null;
  return launcher(head, "npm", after, before, { style: "run", flags, initializer: true });
}
function initializerNames(word, manager) {
  const scoped = word.startsWith("@");
  const at = word.indexOf("@", scoped ? 1 : 0);
  const bare = at > 0 ? word.slice(0, at) : word;
  const version = at > 0 ? word.slice(at) : "";
  const unmeasured = (names) => ({
    names,
    why: `\`${word}\`${TWO_READINGS} \u2014 with the \`create-\` prefix added again, or as written (not measured) \u2014 both are looked up`
  });
  if (scoped) {
    const slash = bare.indexOf("/");
    if (slash < 0) {
      const names = [`${bare}/create${version}`];
      if (manager !== "yarn" || version === "") return { names };
      return {
        names,
        why: `\`${word}\`${TWO_READINGS} \u2014 Yarn 3 and 4 ask the registry for \`${bare}/create\`, Yarn 1 does not ask it \u2014 \`${bare}/create\` is looked up`
      };
    }
    const scope = bare.slice(0, slash);
    const rest = bare.slice(slash + 1);
    if (rest === "create" || rest.startsWith("create-")) return unmeasured([`${scope}/create-${rest}${version}`, `${bare}${version}`]);
    return { names: [`${scope}/create-${rest}${version}`] };
  }
  if (bare === "create") return unmeasured([`create-create${version}`, `create${version}`]);
  if (bare.startsWith("create-")) {
    if (manager === "pnpm") return { names: [`${bare}${version}`] };
    if (manager === "yarn") {
      return {
        names: [`create-${bare}${version}`, `${bare}${version}`],
        why: `\`${word}\`${TWO_READINGS} \u2014 Yarn 1 and 3 ask the registry for \`create-${bare}\`, Yarn 4 for \`${bare}\` \u2014 both are looked up`
      };
    }
  }
  return { names: [`create-${bare}${version}`] };
}
function collectLaunch(d, launch, context) {
  const table = LAUNCH_FLAGS[launch.flags] ?? { value: set(), bool: set(), registry: set() };
  const pre = walk(d.pre, table);
  let body = d.args;
  if (launch.style === "run") {
    const end = launchEnd(d.args, table);
    if (end >= 0) body = d.args.slice(0, end + 1);
  }
  const w = walk(body, table);
  const firstWord = w.positionals[0];
  if (d.firstIsCandidate === true && firstWord !== void 0) w.positionals[0] = { ...firstWord, candidate: true };
  const flags = [...pre.flags, ...w.flags];
  const has2 = (names) => names !== void 0 && flags.some((f) => names.has(f.flag) && !isBoolWord(f.value));
  const wordFlags = (names) => names === void 0 ? [] : flags.filter((f) => names.has(f.flag) && isBoolWord(f.value) && f.eq !== true);
  const values = (names) => names === void 0 ? [] : flags.filter((f) => names.has(f.flag)).flatMap((f) => d.ecosystem === "pypi" ? splitOutsideBrackets(f.value ?? "") : (f.value ?? "").split(",")).map((v) => v.trim()).filter((v) => v !== "");
  const raws = [];
  const pathApp = launch.flags === "pipx-run" && launch.style === "run" && flags.some((f) => f.flag === "--path");
  const initializer = launch.initializer === true;
  const limited = limitCandidates(initializer ? w.positionals.filter((p) => isInitializerName(p.value, d.manager)) : w.positionals);
  const written = /* @__PURE__ */ new Map();
  const initWhy = [];
  let byPackageFlag = false;
  if (initializer) {
    raws.push(...values(table.packageFlags));
    for (const p of limited.kept) {
      const read2 = initializerNames(p.value, d.manager);
      for (const name of read2.names) {
        raws.push(name);
        written.set(name, p.value);
      }
      if (read2.why !== void 0) initWhy.push(read2.why);
    }
  } else if (!has2(table.noFetchFlags)) {
    const named = values(table.packageFlags);
    if (named.length > 0) {
      raws.push(...named);
      byPackageFlag = true;
    } else if (!has2(table.shellFlags) && launch.program !== true && !pathApp) raws.push(...limited.kept.map((p) => p.value));
    else if (table.shellWord === true && d.args.length === body.length) raws.push(...limited.kept.map((p) => p.value).filter((v) => !/\s/.test(v)));
    raws.push(...values(table.extraPackageFlags));
  }
  const packages = [];
  const candidates = [];
  const certainRaws = new Set(limited.kept.filter((p) => p.candidate !== true).map((p) => p.value));
  const candidateRaws = new Set(limited.kept.filter((p) => p.candidate === true).map((p) => p.value));
  const skipped = [...pre.skipped, ...w.skipped];
  const unsure = [...wordFlags(table.noFetchFlags), ...wordFlags(table.shellFlags)].map((f) => bothWaysReason(f.value ?? "", f.flag));
  const bothPairs = [];
  for (const raw of raws) {
    const parsed = d.ecosystem === "npm" ? parseNpm(raw, d.manager) : parsePython(raw, false, d.manager);
    const asWritten = written.get(raw) ?? raw;
    const parsedAs = asWritten === raw ? parsed : { ...parsed, raw: asWritten };
    if ("name" in parsedAs) {
      const spec2 = readsAsPipxFile(d, parsedAs) ? { ...parsedAs, malwareOnly: true } : parsedAs;
      const read2 = d.ecosystem === "npm" ? npmReadings(spec2, d.manager) : { packages: [spec2] };
      for (const each of read2.packages) {
        packages.push(each);
        if (!byPackageFlag && candidateRaws.has(asWritten) && !certainRaws.has(asWritten)) candidates.push(each);
      }
      if ("pair" in read2 && read2.pair !== void 0) bothPairs.push(read2.pair);
      unsure.push(...archiveReasons(d, spec2));
      if (d.ecosystem === "npm" && asWritten.endsWith("@")) unsure.push(LAUNCHER_NAME_AT);
    } else skipped.push(parsedAs);
  }
  const bothWhy = bothReadings(bothPairs);
  if (bothWhy !== void 0) unsure.push(bothWhy);
  unsure.push(...initWhy);
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
  if (candidates.length > 0) out.candidates = candidates;
  if (flags.some((f) => f.flag === "--prefix" || f.flag === "-C")) out.prefixed = true;
  if (launch.flags === "uv-run") attachUvRun(out, d, pre, w, flags);
  else if (launch.flags === "pipx-run" && launch.style === "run" && !initializer && !byPackageFlag) attachPipxApp(out, w, pathApp, d.measuredArchiveForm === true);
  const script = pathApp || (out.inlineScripts ?? []).some((w2) => PYTHON_FILE.test(w2.file));
  if (d.registryForm !== void 0 && !script) out.registryForm = d.registryForm;
  if (d.manager === "bun") out.bunLauncher = true;
  if (d.manager === "bun" && [...d.pre, ...d.args].some(isEnvFileWord)) out.envFileFlag = true;
  if (launch.flags === "pipx-inject") {
    const files = requirementFiles(flags, PIPX_REQUIREMENT_FLAGS);
    if (files.length > 0) out.manifest = { kind: "requirements", files };
  }
  return out;
}
var PYTHON_FILE = /\.pyw?$/i;
var isFileWord = (word) => word !== "-" && !word.includes("://") && !URL_OR_VCS.test(word);
var scriptWord = (file) => SHELL_EXPANSION.test(file) ? { file, literal: false } : { file };
function attachUvRun(out, d, pre, w, flags) {
  const scripts = [];
  const seen = /* @__PURE__ */ new Set();
  const add = (word) => {
    const key = `${word.file}|${String(word.literal)}`;
    if (seen.has(key)) return;
    seen.add(key);
    scripts.push(word);
  };
  for (const p of w.positionals) {
    if (!isFileWord(p.value)) continue;
    const before = [...pre.flags, ...w.flags.filter((f) => f.at !== void 0 && f.at < p.at)];
    if (before.some((f) => f.flag === "--module")) continue;
    if (before.some((f) => f.flag === "--script" || f.flag === "--gui-script") || PYTHON_FILE.test(p.value)) add(scriptWord(p.value));
  }
  const required = requirementFiles(flags, /* @__PURE__ */ new Set(["--with-requirements"]));
  for (const file of required) if (PYTHON_FILE.test(file)) add(scriptWord(file));
  const others = required.filter((file) => !PYTHON_FILE.test(file));
  if (others.length > 0) out.manifest = { kind: "requirements", files: others };
  if (scripts.length > 0) out.inlineScripts = scripts;
  const given = flags.filter((f) => f.flag === "--directory" && f.value !== void 0 && f.value !== "").map((f) => f.value ?? "");
  const dir = given.length > 0 ? given[given.length - 1] : d.envDir;
  if (dir === void 0 || dir === "") return;
  if (SHELL_EXPANSION.test(dir)) out.scriptDirUnknown = true;
  else out.scriptDir = dir;
}
function attachPipxApp(out, w, pathApp, measured) {
  const words = w.positionals.filter((p) => isFileWord(p.value));
  const scripts = [];
  for (const p of words) {
    const expands = SHELL_EXPANSION.test(p.value);
    if (pathApp && words.length === 1) scripts.push(scriptWord(p.value));
    else if (!expands) scripts.push({ file: p.value, ifFile: true });
  }
  if (scripts.length > 0) out.inlineScripts = scripts;
  const word = measured ? words[0]?.value : void 0;
  if (word === void 0 || !PIPX_FILE.test(word) || !scripts.some((s) => s.file === word)) return;
  const asPath = out.skipped.some((s) => s.raw === word && s.reason === LOCAL_PATH);
  if (asPath || out.packages.some((p) => p.raw === word && p.malwareOnly === true)) out.runsAsScript = word;
}
var PIPX_REQUIREMENT_FLAGS = /* @__PURE__ */ new Set(["-r", "--requirement"]);
function requirementFiles(flags, names) {
  return flags.flatMap((f) => names.has(f.flag) && f.value !== void 0 && f.value !== "" ? [f.value] : []);
}
function splitOutsideBrackets(value) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let k = 0; k < value.length; k += 1) {
    const ch = value.charAt(k);
    if (ch === "[") depth += 1;
    else if (ch === "]") depth = Math.max(0, depth - 1);
    else if (ch === "," && depth === 0) {
      parts.push(value.slice(start, k));
      start = k + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}
function isEnvFileWord(w) {
  return w.value === "--env-file" || w.value === "--no-env-file" || w.value.startsWith("--env-file=");
}
function collect(d, context) {
  if (d.launch !== void 0) return collectLaunch(d, d.launch, context);
  if (d.dotnet !== void 0) return collectDotnet(d, d.dotnet, context);
  const table = FLAGS[d.flagTable ?? (d.manager === "uv-pip" ? "pip" : d.manager)] ?? FLAGS["npm"];
  const flagTable = table ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, flagTable);
  const walked = walk(d.args, flagTable);
  const { skipped, customRegistry, uncertain, registries } = walked;
  const limited = limitCandidates(walked.positionals);
  const readsNoPackage = d.manifest === "always" || d.names !== void 0 || d.everyTool === "always";
  const positionals = readsNoPackage ? [] : limited.kept;
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
  if (d.registryForm !== void 0) out.registryForm = d.registryForm;
  if (d.manager === "bun" && [...d.pre, ...d.args].some(isEnvFileWord)) out.envFileFlag = true;
  if (limited.dropped > 0 && !readsNoPackage) out.candidatesDropped = limited.dropped;
  const candidatePackages = [];
  const bothPairs = [];
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
      const read2 = d.ecosystem === "npm" ? npmReadings(spec2, d.manager) : { packages: [spec2] };
      for (const each of read2.packages) {
        packages.push(each);
        if (p.candidate === true) candidatePackages.push(each);
      }
      if ("pair" in read2 && read2.pair !== void 0) bothPairs.push(read2.pair);
      for (const why of archiveReasons(d, spec2)) if (!out.uncertain.includes(why)) out.uncertain.push(why);
      lastComposer = d.ecosystem === "packagist" ? spec2 : void 0;
    } else {
      skipped.push(spec2);
      lastComposer = void 0;
    }
  }
  const bothWhy = bothReadings(bothPairs);
  if (bothWhy !== void 0) out.uncertain.push(bothWhy);
  if (candidatePackages.length > 0) out.candidates = candidatePackages;
  if (d.ecosystem === "nuget") {
    const extra = positionals.some((p) => p.candidate === true) ? [] : packages.splice(1);
    for (const e of extra) skipped.push(skip(e.raw, "unexpected extra argument to dotnet add package"));
    const first = packages[0];
    const version = flagValue(d.args, d.flagTable === "dotnet-tool" ? ["--version"] : ["-v", "--version"]);
    if (first !== void 0 && version !== void 0) first.range = version;
  }
  if (allFlags.some((f) => flagTable.dir?.has(f.flag) === true)) out.prefixed = true;
  const knownFlagsOnly = preWalk.unknownFlags + walked.unknownFlags === 0;
  if (d.names === "always" || d.names === "global-word" && hasGlobalFlagWord(d.pre, d.args)) {
    out.updateNames = [];
    for (const p of limited.kept) {
      const spec2 = d.ecosystem === "pypi" ? parsePython(p.value, false, d.manager) : parseNpm(p.value, d.manager);
      if ("name" in spec2) out.updateNames.push(spec2);
      else skipped.push(spec2);
    }
    if (limited.dropped > 0) out.candidatesDropped = limited.dropped;
  } else if (d.everyTool === "always") out.updateNames = [];
  if (d.everyTool === "always" || d.everyTool === "all-flag" && allFlags.some((f) => f.flag === "--all")) out.updatesEveryTool = true;
  if (d.global === true || knownFlagsOnly && allFlags.some(isGlobalFlag) && saysGlobal(d.manager, d.pre, d.args)) out.global = true;
  if (d.manager === "pip" || d.manager === "uv-pip") {
    const files = requirementFiles(walked.flags, REQUIREMENT_FLAGS);
    const scripts = d.manager === "uv-pip" ? files.filter((f) => PYTHON_FILE.test(f)) : [];
    const rest = files.filter((f) => !scripts.includes(f));
    if (scripts.length > 0) out.inlineScripts = scripts.map(scriptWord);
    if (rest.length > 0) out.manifest = { kind: "requirements", files: rest };
  } else if (d.manifest !== void 0 && out.global !== true) {
    out.manifest = { kind: "package-json" };
    if (d.update === true) out.update = true;
  }
  return out;
}
var NUGET_EXACT_VERSION = /^\d+(?:\.\d+){0,3}(?:-[0-9a-z-]+(?:\.[0-9a-z-]+)*)?(?:\+[0-9a-z-]+(?:\.[0-9a-z-]+)*)?$/i;
var SDK_REFUSED_VERSION = "a version SDK 10.0.404 refuses before any request \u2014 looked up in case another SDK accepts it";
function isPlainNugetName(word) {
  if (word.startsWith("-")) return false;
  const spec2 = parseNuget(word);
  return "name" in spec2 && spec2.name === word && spec2.range === void 0;
}
function refusedVersionLine(spelling, args) {
  const [word = "", flag] = args;
  const sep2 = spelling === "dotnet new install" ? "::" : "@";
  const at = word.indexOf(sep2);
  if (at <= 0 || !isPlainNugetName(word.slice(0, at))) return false;
  const text = word.slice(at + sep2.length);
  switch (spelling) {
    case "dnx":
      return args.length === 1 && text === "latest";
    case "dotnet package download":
      return args.length === 2 && text === "1.*" && flag === "--allow-insecure-connections";
    case "dotnet new install":
      return args.length === 2 && text === "latest" && flag === "--force";
    default:
      return false;
  }
}
function collectDotnet(d, dotnet, context) {
  const table = FLAGS[d.flagTable ?? ""] ?? { value: set(), bool: set(), registry: set() };
  const preWalk = walk(d.pre, table);
  let body = d.args;
  if (dotnet.form === "run") {
    const dash = d.args.findIndex((w) => w.value === "--");
    if (dash >= 0) {
      const before = d.args.slice(0, dash);
      const named = walk(before, table).positionals.length > 0;
      const idWord = d.args[dash + 1];
      body = named || idWord === void 0 ? before : [...before, idWord];
    }
  }
  const walked = walk(body, table);
  const limited = limitCandidates(walked.positionals);
  const colons = dotnet.form === "new-install";
  const several = dotnet.form === "new-install" || dotnet.form === "download" || dotnet.form === "package-update";
  const candidate = limited.kept.some((p) => p.candidate === true);
  const skipped = walked.skipped;
  const packages = [];
  const candidates = [];
  const names = [];
  const out = {
    ecosystem: "nuget",
    manager: "dotnet",
    packages,
    skipped,
    uncertain: [.../* @__PURE__ */ new Set([...context, ...d.uncertain, ...preWalk.uncertain, ...walked.uncertain])],
    registries: [...preWalk.registries, ...walked.registries]
  };
  const registry = preWalk.customRegistry ?? walked.customRegistry;
  if (registry !== void 0) out.customRegistry = registry;
  if (limited.dropped > 0) out.candidatesDropped = limited.dropped;
  const spelled = limited.kept.slice(0, several || candidate ? void 0 : 1);
  for (const p of spelled) {
    const spec2 = parseNuget(p.value, colons);
    if (!("name" in spec2)) {
      skipped.push(spec2);
      continue;
    }
    if (dotnet.form === "package-update") names.push(spec2);
    else {
      packages.push(spec2);
      if (p.candidate === true) candidates.push(spec2);
    }
    const why = unmeasuredReason("dotnet", spec2);
    if (why !== void 0 && !out.uncertain.includes(why)) out.uncertain.push(why);
  }
  if (dotnet.form === "tool-update" && !candidate) {
    for (const p of limited.kept.slice(1)) skipped.push(skip(p.value, "unexpected extra argument to dotnet tool update"));
  }
  if (candidates.length > 0) out.candidates = candidates;
  const first = packages[0];
  const version = dotnet.form === "run" || dotnet.form === "tool-update" ? flagValue(body, ["--version"]) : void 0;
  if (first !== void 0 && version !== void 0) first.range = version;
  if (first !== void 0 && refusedVersionLine(dotnet.spelling, d.pre.length === 0 ? d.args.map((w) => w.value) : [])) {
    delete first.range;
    if (!out.uncertain.includes(SDK_REFUSED_VERSION)) out.uncertain.push(SDK_REFUSED_VERSION);
  }
  if (dotnet.form === "package-update") {
    if (names.length > 0) out.updateNames = names;
    if (body.some((w) => /^--(?:project|file)(?:=|$)/.test(w.value))) {
      out.uncertain.push("dotnet project argument (the NuGet configuration next to that project was not read)");
    }
  }
  if (dotnet.form === "new-install") {
    out.localPathFirst = true;
    out.sourceFlag = "`--add-source <url>`";
  }
  return out;
}
var MEASURED_DOTNET_FORMS = (() => {
  const f = (spelling, ...rest) => [...spelling.split(" "), ...rest];
  const run = (spelling) => [
    f(spelling, "<id>"),
    f(spelling, "<id>@<v>"),
    f(spelling, "<id>", "--version", "<v>"),
    f(spelling, "<id>", "<args>"),
    f(spelling, "--yes", "<id>")
  ];
  return [
    ...run("dotnet tool execute"),
    ...run("dotnet tool exec"),
    f("dotnet tool exec", "<id>", "--yes"),
    ...run("dotnet dnx"),
    ...run("dnx"),
    f("dnx", "<id>", "--yes"),
    f("dnx", "--version", "<v>", "<id>"),
    f("dnx", "<id>@<n>.*"),
    f("dnx", "--", "<id>"),
    f("dnx", "<id>", "--", "<rest>"),
    f("dotnet tool update", "-g", "<id>"),
    f("dotnet tool update", "-g", "<id>", "--version", "<v>"),
    f("dotnet tool update", "--tool-path", "<dir>", "<id>"),
    f("dotnet tool update", "--global", "<id>"),
    f("dotnet tool update", "<id>", "-g"),
    f("dotnet tool update", "-g", "<id>@<v>"),
    f("dotnet tool update", "--tool-path", "<dir>", "<id>", "--version", "<v>"),
    f("dotnet tool update", "<id>"),
    f("dotnet tool update", "<id>", "--version", "<v>"),
    f("dotnet tool update", "<id>@<v>"),
    f("dotnet tool update", "--local", "<id>"),
    f("dotnet new install", "<id>", "--force"),
    f("dotnet new install", "<id>::<v>", "--force"),
    f("dotnet new install", "<id>@<v>", "--force"),
    f("dotnet new install", "--force", "<id>"),
    f("dotnet new install", "<ids>", "--force"),
    f("dotnet package download", "<id>"),
    f("dotnet package download", "<id>", "--allow-insecure-connections"),
    f("dotnet package download", "<id>@<v>", "--allow-insecure-connections"),
    f("dotnet package download", "<id>@<v>"),
    f("dotnet package download", "<ids>")
  ];
})();
function fitsDotnetPlace(token, word) {
  const pair = (sep2) => {
    const at = word.indexOf(sep2);
    return at > 0 ? { id: word.slice(0, at), text: word.slice(at + sep2.length) } : void 0;
  };
  switch (token) {
    case "<id>":
      return isPlainNugetName(word);
    case "<v>":
      return NUGET_EXACT_VERSION.test(word);
    case "<dir>":
      return word !== "";
    case "<id>@<v>": {
      const p = pair("@");
      return p !== void 0 && isPlainNugetName(p.id) && NUGET_EXACT_VERSION.test(p.text);
    }
    case "<id>::<v>": {
      const p = pair("::");
      return p !== void 0 && isPlainNugetName(p.id) && NUGET_EXACT_VERSION.test(p.text);
    }
    case "<id>@<n>.*": {
      const p = pair("@");
      return p !== void 0 && isPlainNugetName(p.id) && /^\d+\.\*$/.test(p.text);
    }
    default:
      return token === word;
  }
}
function isMeasuredDotnetForm(words) {
  return MEASURED_DOTNET_FORMS.some((form) => {
    let at = 0;
    for (const token of form) {
      if (token === "<ids>" || token === "<args>" || token === "<rest>") {
        let n = 0;
        while (at + n < words.length && (token === "<rest>" || (token === "<ids>" ? isPlainNugetName(words[at + n] ?? "") : !(words[at + n] ?? "").startsWith("-")))) n += 1;
        if (n < (token === "<ids>" ? 2 : 1)) return false;
        at += n;
      } else {
        if (at >= words.length || !fitsDotnetPlace(token, words[at] ?? "")) return false;
        at += 1;
      }
    }
    return at === words.length;
  });
}
function dotnetFormOf(words) {
  const [a = "", b = "", c = ""] = words;
  if (a === "dnx") return { spelling: "dnx", form: "run", rest: words.slice(1) };
  if (a !== "dotnet") return void 0;
  if (b === "dnx") return { spelling: "dotnet dnx", form: "run", rest: words.slice(2) };
  if (b === "tool" && (c === "exec" || c === "execute")) return { spelling: `dotnet tool ${c}`, form: "run", rest: words.slice(3) };
  if (b === "tool" && c === "update") return { spelling: "dotnet tool update", form: "tool-update", rest: words.slice(3) };
  if (b === "new" && c === "install") return { spelling: "dotnet new install", form: "new-install", rest: words.slice(3) };
  if (b === "package" && c === "download") return { spelling: "dotnet package download", form: "download", rest: words.slice(3) };
  if (b === "package" && c === "update") return { spelling: "dotnet package update", form: "package-update", rest: words.slice(3) };
  return void 0;
}
function versionTextOf(word) {
  const colon = word.indexOf("::");
  const at = colon > 0 ? colon : word.indexOf("@");
  return at > 0 ? word.slice(at + (colon > 0 ? 2 : 1)) : void 0;
}
function dotnetGap(spelling, form, rest) {
  const own = MEASURED_DOTNET_FORMS.filter((m) => m.join(" ").startsWith(`${spelling} `));
  const measuredFlags = new Set(own.flatMap((m) => m.filter((t) => t.startsWith("-") && t !== "--")));
  if (rest.includes("--")) return "the `--`";
  const valueFlags = FLAGS[DOTNET_FORM_TABLES[form]]?.value ?? /* @__PURE__ */ new Set();
  const flags = [];
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const w = rest[i] ?? "";
    if (!w.startsWith("-")) {
      positionals.push(w);
      continue;
    }
    flags.push(w);
    if (valueFlags.has(w)) i += 1;
  }
  for (const w of positionals) {
    const text = versionTextOf(w);
    if (text !== void 0 && !NUGET_EXACT_VERSION.test(text)) return `the version text ${text}`;
  }
  const unknown2 = flags.find((w) => !measuredFlags.has(w.includes("=") ? w.slice(0, w.indexOf("=")) : w));
  if (unknown2 !== void 0) return `the flag ${unknown2}`;
  if (positionals.length > 1) return form === "run" ? "a tool argument after the package" : "more than one package";
  const [only, ...more] = flags;
  return only !== void 0 && more.length === 0 ? `the place of the flag ${only}` : "the flags together";
}
var NEW_INSTALL_WITHOUT_FORCE = "dotnet new install without --force was measured to contact an https source, not to ask it for the package \u2014 not measured";
function judgeDotnetForm(words) {
  const line = dotnetFormOf(words);
  if (line === void 0) return void 0;
  if (line.form === "package-update") return notPlain("dotnet package update names a package given to an update");
  if (line.form === "new-install" && !line.rest.includes("--force")) return NEW_INSTALL_WITHOUT_FORCE;
  if (refusedVersionLine(line.spelling, line.rest)) return SDK_REFUSED_VERSION;
  if (isMeasuredDotnetForm(words)) return null;
  return `a dotnet command form that was not measured (${dotnetGap(line.spelling, line.form, line.rest)})`;
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
var POWERSHELL_READING = "found by reading the command as PowerShell does (a comma list, a backtick escape or continuation, a doubled quote, a Unicode space, a `>` or `<` glued to a word) \u2014 vetted for malicious versions only";
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
      if (packages.length === 0 && c.manifest === void 0 && c.updateNames === void 0 && c.inlineScripts === void 0 && c.runsAsScript === void 0) continue;
      for (const p of packages) seen.add(packageKey(p));
      const unknownDir = moved2 && (c.localFirst === true || c.manifest !== void 0 || c.inlineScripts !== void 0);
      out.push({ ...c, packages, ...unknownDir ? { workdir: null } : {} });
    }
  }
  return out;
}
function manifestKey(c) {
  const m = c.manifest;
  if (m === void 0) return "";
  return JSON.stringify([m.kind, m.kind === "requirements" ? m.files : [], c.workdir ?? null, c.prefixed === true, c.update === true]);
}
function scriptKey(c) {
  return c.inlineScripts === void 0 ? "" : JSON.stringify([c.inlineScripts, c.scriptDir ?? null, c.scriptDirUnknown ?? null, c.workdir ?? null]);
}
var NESTED_SCRIPT = "found in a script the command hands a shell (bash -c, cmd /c, pwsh -c, a script piped to a shell) \u2014 vetted, never denied as missing";
function readingsOf(command, shell, forced, cdpath) {
  const text = stripComments(command);
  const out = parseReading(text, forced, cdpath);
  if (shell !== "powershell") return out;
  const asPowerShell = powershellAsPosix(text, { literalGluedRedirects: true });
  if (asPowerShell === text) return withoutRanges(out);
  const seen = new Set(out.flatMap((c) => c.packages.map(packageKey)));
  const seenManifests = new Set(out.map(manifestKey));
  const seenScripts = new Set(out.map(scriptKey));
  for (const c of parseReading(asPowerShell, POWERSHELL_READING, cdpath)) {
    const packages = c.packages.filter((p) => !seen.has(packageKey(p)));
    const newManifest = c.manifest !== void 0 && !seenManifests.has(manifestKey(c));
    const newScripts = c.inlineScripts !== void 0 && !seenScripts.has(scriptKey(c));
    if (packages.length === 0 && !newManifest && !newScripts && c.updateNames === void 0) continue;
    for (const p of packages) seen.add(packageKey(p));
    seenManifests.add(manifestKey(c));
    seenScripts.add(scriptKey(c));
    const { manifest: _same, inlineScripts: _scripts, runsAsScript: _runs, ...stripped } = c;
    out.push({
      ...stripped,
      ...newManifest && c.manifest !== void 0 ? { manifest: c.manifest } : {},
      ...newScripts && c.inlineScripts !== void 0 ? { inlineScripts: c.inlineScripts } : {},
      ...newScripts && c.runsAsScript !== void 0 ? { runsAsScript: c.runsAsScript } : {},
      packages,
      skipped: []
    });
  }
  return withoutRanges(out);
}
var NPM_FAMILY = /* @__PURE__ */ new Set(["npm", "pnpm", "yarn", "bun"]);
function withoutRanges(commands) {
  const seen = new Set(commands.flatMap((c) => c.packages.map(packageKey)));
  const extra = [];
  for (const c of commands) {
    if (c.ecosystem !== "npm" || !NPM_FAMILY.has(c.manager)) continue;
    const packages = [];
    for (const p of c.packages) {
      if (p.range === void 0 || !/[<>]/.test(p.range)) continue;
      const bare = { ecosystem: p.ecosystem, name: p.name, raw: p.name };
      if (seen.has(packageKey(bare))) continue;
      seen.add(packageKey(bare));
      packages.push(bare);
    }
    if (packages.length === 0) continue;
    const { manifest: _manifest, updateNames: _names, ...rest } = c;
    extra.push({ ...rest, packages, skipped: [] });
  }
  return [...commands, ...extra];
}
function movesDirectory(text) {
  try {
    return splitShell(text).statements.some((s) => s.commands.some((words) => changesDirectory(words)));
  } catch {
    return true;
  }
}
var MEASURED_LAUNCHES = [
  { spelling: "npx", launched: "pnpm", flags: ["-y"], dash: "none" },
  { spelling: "npx", launched: "yarn", flags: ["-y"], dash: "none" },
  { spelling: "npx", launched: "corepack", flags: ["-y"], dash: "none", behindCorepack: "yarn" },
  { spelling: "npm exec", launched: "pnpm", flags: [], dash: "before" },
  { spelling: "npm exec", launched: "corepack", flags: [], dash: "after", behindCorepack: "yarn" },
  { spelling: "pnpm dlx", launched: "yarn", flags: [], dash: "none", prefix: true },
  { spelling: "yarn dlx", launched: "pnpm", flags: [], dash: "none", prefix: true },
  { spelling: "bunx", launched: "pnpm", flags: [], dash: "none" }
];
var MEASURED_PYTHON_FORMS = [
  ["pip", "download", "<P>"],
  ["pip", "wheel", "<P>"],
  ["pip", "download", "--no-deps", "<P>"],
  ["pip", "download", "--no-binary", ":all:", "<P>"],
  ["pip", "install", "--dry-run", "<P>"],
  ["pipx", "inject", "<ENV>", "<P>"],
  ["pipx", "upgrade", "--install", "<P>"],
  ["pipx", "runpip", "<ENV>", "install", "<P>"],
  ["pipx", "run", "--spec", "<P>", "<CMD>"],
  ["pipx", "run", "--with", "<D>", "<P>"],
  ["uvx", "--from", "<P>", "<CMD>"],
  ["uv", "tool", "run", "--from", "<P>", "<CMD>"],
  ["uvx", "--with", "<P>", "<T>"],
  ["uv", "tool", "install", "--with", "<P>", "<T>"],
  ["python", "-m", "pip", "download", "<P>"],
  ["pip3", "wheel", "<P>"],
  ["python", "-m", "pip", "install", "--dry-run", "<P>"],
  ["pip", "download", "<P>", "<D>"],
  ["pip", "download", "<P>==<V>"],
  ["pip", "download", "-d", "<DIR>", "<P>"],
  ["pip", "wheel", "--no-deps", "<P>"],
  ["pip", "download", "<P>", "--no-deps"],
  ["pipx", "inject", "<ENV>", "<P>", "<D>"],
  ["uvx", "--from=<P>", "<CMD>"],
  ["uv", "tool", "run", "--with", "<P>", "<T>"],
  ["uvx", "-w", "<P>", "<T>"],
  ["uv", "tool", "install", "<T>", "--with", "<P>"],
  ["pipx", "run", "--spec=<P>", "<CMD>"],
  ["uvx", "--from", "<P>", "<CMD>", "<ARG>"],
  ["pipx", "run", "--spec", "<P>", "<CMD>", "<ARG>"],
  ["uvx", "--with", "<P>", "<T>", "<ARG>"],
  ["pipx", "run", "--with", "<D>", "<P>", "<ARG>"]
];
var PLAIN_VERSION = /^\d+(?:\.\d+)*$/;
function isPlainName(word) {
  if (word.startsWith("-")) return false;
  const spec2 = parsePython(word, false);
  return "name" in spec2 && spec2.name === word && spec2.range === void 0;
}
function fitsPlace(token, word) {
  const at = token.indexOf("<");
  if (at < 0) return token === word;
  const prefix = token.slice(0, at);
  if (!word.startsWith(prefix)) return false;
  const rest = word.slice(prefix.length);
  switch (token.slice(at)) {
    case "<P>":
    case "<D>":
    case "<T>":
      return isPlainName(rest);
    case "<ENV>":
    case "<CMD>":
    case "<DIR>":
      return rest !== "" && !rest.startsWith("-");
    case "<ARG>":
      return true;
    case "<P>==<V>": {
      const eq2 = rest.indexOf("==");
      return eq2 > 0 && isPlainName(rest.slice(0, eq2)) && PLAIN_VERSION.test(rest.slice(eq2 + 2));
    }
    default:
      return false;
  }
}
function isMeasuredPythonForm(words) {
  return MEASURED_PYTHON_FORMS.some((form) => form.length === words.length && form.every((token, k) => fitsPlace(token, words[k] ?? "")));
}
function unmeasuredVerb(words) {
  const [tool = "", first = "", second = "", third = ""] = words;
  if (isMeasuredPythonForm(words)) return void 0;
  const verb = (name) => `this form of '${name}' was not measured`;
  if (tool === "pipx") {
    if (first === "inject" || first === "runpip") return verb(`pipx ${first}`);
    return first === "upgrade" && words.includes("--install") ? verb("pipx upgrade --install") : void 0;
  }
  if ((tool === "pip" || tool === "pip3") && (first === "download" || first === "wheel")) return verb(`pip ${first}`);
  const viaPython = tool === "python" || tool === "python3" || tool === "py";
  if (viaPython && first === "-m" && (second === "pip" || second === "pip3") && (third === "download" || third === "wheel")) return verb(`pip ${third}`);
  return void 0;
}
var MEASURED_VERB = "add";
var NPM_LAUNCH_TABLES = /* @__PURE__ */ new Set(["npx", "npm-exec", "pnpm-dlx", "yarn-dlx", "bunx"]);
var LAUNCHED_MANAGERS = /* @__PURE__ */ new Set(["npm", "pnpm", "yarn", "yarnpkg", "bun", "corepack"]);
var MOVING_FLAGS = ["--prefix", "-C", "--dir", "--cwd", "-w", "--workspace", "--workspaces", "--filter", "-F"];
function unmeasuredLaunch(why) {
  return `a package manager run by a launcher \u2014 this form was not measured (${why})`;
}
function unmeasuredForm(launch, launched, ownFlags, dash, inner) {
  const spelling = launch.spelling ?? "";
  const ofSpelling = MEASURED_LAUNCHES.filter((m2) => m2.spelling === spelling);
  if (ofSpelling.length === 0) return unmeasuredLaunch(`the launcher's spelling: ${spelling}`);
  const m = ofSpelling.find((each) => each.launched === launched);
  if (m === void 0 || launch.viaCorepack === true && m.prefix !== true) return unmeasuredLaunch(`the pair: ${spelling} ${launched}`);
  const stray = ownFlags.find((f) => !m.flags.includes(f));
  if (stray !== void 0) return unmeasuredLaunch(`a flag of the launcher: ${stray}`);
  const placed = dash.before ? dash.after ? "both" : "before" : dash.after ? "after" : "none";
  if (placed !== m.dash) return unmeasuredLaunch(`a flag of the launcher: the \`--\` is ${placed === "none" ? "missing" : "not where it was measured"}`);
  if (m.behindCorepack !== void 0 && inner[0] !== m.behindCorepack) return unmeasuredLaunch(`the pair: ${spelling} ${launched} ${inner[0] ?? ""}`);
  const verb = inner[m.behindCorepack === void 0 ? 0 : 1];
  if (verb !== MEASURED_VERB) return unmeasuredLaunch(`the inner verb: ${verb ?? "none"}`);
  return void 0;
}
function readLaunchedManager(d, context, notConfident) {
  const launch = d.launch;
  if (launch === void 0 || launch.style !== "run" || launch.initializer === true || d.ecosystem !== "npm" || !NPM_LAUNCH_TABLES.has(launch.flags)) {
    return void 0;
  }
  const table = LAUNCH_FLAGS[launch.flags];
  if (table === void 0) return void 0;
  const found = scanPositional(d.args, 0, table);
  if (found.at < 0 || found.candidate) return void 0;
  const launchedWord = d.args[found.at];
  if (launchedWord === void 0) return void 0;
  const before = [...d.pre, ...d.args.slice(0, found.at)];
  if (before.some((w) => table.shellFlags?.has(w.value) === true)) return void 0;
  const spec2 = parseNpm(launchedWord.value, d.manager);
  if (!("name" in spec2) || !LAUNCHED_MANAGERS.has(spec2.name)) return void 0;
  const dash = { before: before.some((w) => w.value === "--"), after: d.args[found.at + 1]?.value === "--" };
  const words = d.args.slice(found.at + (dash.after ? 2 : 1));
  const head = { ...launchedWord, value: spec2.name };
  const innerDetected = detect([head, ...words]);
  if (innerDetected === null) return void 0;
  const c = collect(innerDetected, context);
  const moving = /* @__PURE__ */ new Set([...MOVING_FLAGS, ...table.dir ?? [], ...table.workspace ?? [], ...FLAGS[d.manager]?.dir ?? [], ...FLAGS[d.manager]?.workspace ?? []]);
  const named = (w) => {
    const eq2 = w.value.indexOf("=");
    return moving.has(eq2 > 0 ? w.value.slice(0, eq2) : w.value);
  };
  if (before.some(named)) c.prefixed = true;
  if (launch.flags === "npm-exec" && !dash.before && !dash.after && c.global === true) {
    delete c.global;
    if (innerDetected.manifest !== void 0) {
      c.manifest = { kind: "package-json" };
      if (innerDetected.update === true) c.update = true;
    }
  }
  const ownFlags = before.filter((w) => w.value !== "--").map((w) => w.value);
  const innerWords = words.map((w) => w.value);
  const unmeasured = unmeasuredForm(launch, spec2.name, ownFlags, dash, innerWords);
  const shape = notConfident ?? unmeasured ?? confidentWords(spec2.name === "corepack" ? ["corepack", ...innerWords] : [spec2.name, ...innerWords]);
  const keep = c.uncertain.filter((r) => r === UNMEASURED_ARCHIVE || r === LAUNCHER_NAME_AT || r.includes(TWO_READINGS));
  c.uncertain = shape === null ? keep : [.../* @__PURE__ */ new Set([shape, ...c.uncertain])];
  return c;
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
  let sourced;
  const workingDirWords = (text.match(/UV_WORKING_DIR/gi) ?? []).length;
  split.statements.forEach((statement, s) => {
    statement.commands.forEach((words, w) => {
      const sourcedBefore = sourced;
      const at = commandStart(words);
      const headWord = words[at]?.value;
      if (headWord === "source" || headWord === ".") sourced = sourced ?? words[at + 1]?.value;
      const d = detect(wordsWithoutRedirections(words));
      if (d !== null) {
        const context = [];
        if (envChange) context.push("inline environment assignment in the command (it can redirect the registry)");
        if (dirChanged) context.push("directory change earlier in the command (that directory\u2019s registry configuration was not read)");
        const c = collect(d, context);
        if (d.launch?.program === true && c.packages.length === 0 && c.skipped.length === 0 && c.inlineScripts === void 0 && c.manifest === void 0) {
          if (changesDirectory(words)) dirChanged = true;
          return;
        }
        if (d.launch?.flags === "uv-run" && workingDirWords > (d.envDir === void 0 ? 0 : 1)) {
          delete c.scriptDir;
          c.scriptDirUnknown = true;
        }
        if (sourcedBefore !== void 0 && c.inlineScripts !== void 0) c.sourced = sourcedBefore;
        const unmeasured = c.uncertain.filter((r) => ARCHIVE_REASONS.has(r) || r === LAUNCHER_NAME_AT || r.includes(TWO_READINGS));
        const unmeasuredVerbReason = notConfident === null ? void 0 : unmeasuredVerb(words.map((word) => word.value));
        c.uncertain = notConfident === null ? unmeasured : [.../* @__PURE__ */ new Set([notConfident, ...unmeasuredVerbReason === void 0 ? [] : [unmeasuredVerbReason], ...c.uncertain])];
        const sure = dirs[s]?.[w]?.sure ?? null;
        const elsewhere = runsElsewhere(words);
        const place = (command) => {
          if (elsewhere) command.workdir = null;
          else if (sure === null || sure.length > 0) command.workdir = sure;
        };
        place(c);
        out.push(c);
        const inner = readLaunchedManager(d, context, notConfident);
        if (inner !== void 0) {
          place(inner);
          out.push(inner);
        }
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
  // `dotnet tool install`: no source, configuration file or verbosity flag; a tool is global, local or in a folder.
  "dotnet-tool": {
    bool: set("--prerelease", "-g", "--global", "--local", "--allow-downgrade", "--create-manifest-if-needed", "--allow-roll-forward"),
    value: set("--version", "--framework", "--tool-path")
  },
  // The launchers (review P1): consent and verbosity only. A package flag
  // (`-p`, `--from`, `--spec`), a registry or `--pip-args` takes the command
  // out of the confident shape.
  npx: { bool: set("-y", "--yes", "-q", "--quiet", "--silent"), value: set() },
  // `npm exec` is npm's own command: `--ignore-scripts` is a boolean flag of npm that changes nothing about the lookup.
  "npm-exec": { bool: set("-y", "--yes", "-q", "--quiet", "--silent", "--ignore-scripts"), value: set() },
  "pnpm-dlx": { bool: set("--silent", "-s"), value: set() },
  // The initializers (measured 2026-11-20): consent and verbosity only; pnpm none, bun has no entry (it never denies).
  "npm-init": { bool: set("-y", "--yes", "-q", "--quiet", "--silent"), value: set() },
  "yarn-create": { bool: set("-q", "--quiet"), value: set() },
  "pnpm-create": { bool: set(), value: set() },
  "yarn-dlx": { bool: set("-q", "--quiet"), value: set() },
  bunx: { bool: set("--bun", "--silent", "--verbose"), value: set() },
  uvx: { bool: set("-q", "--quiet", "-v", "--verbose", "--isolated"), value: set() },
  // `uv run`: the flags of `uvx`; `--with` and `-w` are left out, so a name of them the registry does not have only warns (the owner's answer 2-A).
  "uv-run": { bool: set("-q", "--quiet", "-v", "--verbose", "--isolated"), value: set() },
  "uv-tool-install": { bool: set("-q", "--quiet", "-v", "--verbose", "--force", "--upgrade", "-U"), value: set() },
  "pipx-install": { bool: set("--force", "-f", "-q", "--quiet", "-v", "--verbose", "--include-deps"), value: set() },
  "pipx-run": { bool: set("-q", "--quiet", "-v", "--verbose", "--no-cache"), value: set() }
};
var NOT_SIMPLE = /[;&|()<>`$\\\n\r{}*?[\],]/;
var BUN_TEMPLATE_REASON = "`bun create` uses a template of that name from a `.bun-create` folder when there is one, which was not looked for";
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
  return confidentWords(words);
}
function confidentWords(words) {
  const viaCorepack = words[0] === "corepack" ? corepackManager(words[1]) : void 0;
  const [named, ...rest] = viaCorepack === void 0 ? words : [viaCorepack, ...words.slice(2)];
  const tool = named === "yarnpkg" ? "yarn" : named;
  if (tool === void 0) return notSingle("empty");
  if (isMeasuredPythonForm([tool, ...rest])) return null;
  const dotnetForm = judgeDotnetForm([tool, ...rest]);
  if (dotnetForm !== void 0) return dotnetForm;
  const unmeasured = unmeasuredVerb([tool, ...rest]);
  if (unmeasured !== void 0) return unmeasured;
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
        [key, args, launch] = ["npm-exec", rest.slice(1), true];
        break;
      }
      if (NPM_INITIALIZER.has(at(0))) {
        [key, args, launch] = ["npm-init", rest.slice(1), true];
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
      if (at(0) === "create") {
        [key, args, launch] = [`${tool}-create`, rest.slice(1), true];
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
      if (BUN_INITIALIZER.has(at(0))) return BUN_TEMPLATE_REASON;
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
      else if (at(0) === "run") [key, args, launch] = ["uv-run", rest.slice(1), true];
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
      if (at(0) === "add" && at(1) === "package" || at(0) === "package" && at(1) === "add") [key, args] = ["dotnet", rest.slice(2)];
      else if (at(0) === "tool" && at(1) === "install") [key, args] = ["dotnet-tool", rest.slice(2)];
      else return notPlain(`'dotnet ${at(0)} ${at(1)}' (dotnet add <project> package \u2026)`);
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
  unknownDir: "where the command runs could not be determined",
  notInForm: "its `# /// script` block is not in the form the hook reads",
  deadline: "vetting time budget exhausted",
  notLiteral: "not a literal file name"
};
var MANIFEST_UNREADABLE_REASONS = Object.values(REASON);
var UNKNOWN_DIRECTORY = REASON.unknownDir;
var MAX_NAME_LENGTH = 214;
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
var DIST_TAG = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
var NOT_OF_THE_REGISTRY = /^(?:(?:file|link|workspace|portal|patch|exec|jsr):|[A-Za-z]:|[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#.*)?$)/i;
function npmRange(value, manager) {
  const v = value.trim();
  if (v === "" || v === "latest") return void 0;
  if (notARegistryRange(v) !== null || NOT_OF_THE_REGISTRY.test(v) || readsFileValue(manager, v)) return null;
  if (v.length > MAX_RANGE_LENGTH) return void 0;
  if (DIST_TAG.test(v)) return v;
  return isSemverRange(v) ? v : void 0;
}
var NPM_PROTOCOL = /^npm:/i;
var PATCH_PROTOCOL = /^patch:/i;
var PATCH_WORD = "patch:";
var NPM_REST_RANGE = /^v*(?:[0-9]+|[xX])(?:\.(?:[0-9]+|[xX])(?:\.(?:[0-9]+|[xX])(?:-?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)?)?)?$/;
function npmValueReading(manager, rest) {
  const tildeIsKey = manager === "pnpm" || manager === "yarn" || manager === "bun";
  if (!tildeIsKey || /[$`]/.test(rest) || rest.indexOf("@", rest.startsWith("@") ? 1 : 0) > 0) return npmProtocolReading(manager, rest);
  if (isTildeWord(rest)) return "key";
  if (manager !== "pnpm") return npmProtocolReading(manager, rest);
  if (validName2("npm", rest)) return NPM_REST_RANGE.test(rest) ? "both" : "alias";
  return rest !== "" && notAPackage(rest, null) !== null ? "alias" : "key";
}
function npmProtocolDependency(key, rest, manager) {
  const reading = npmValueReading(manager, rest);
  if (reading === "alias") {
    const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
    const name = at > 0 ? rest.slice(0, at) : rest;
    const range = npmRange(at > 0 ? rest.slice(at + 1) : "", manager);
    return range !== null && validName2("npm", name) ? [spec("npm", name, range)] : [];
  }
  const own = validName2("npm", key) ? [spec("npm", key, npmKeyRange(manager, rest.trim()))] : [];
  return reading === "both" && validName2("npm", rest) ? [...own, spec("npm", rest, void 0)] : own;
}
var HEX_DIGITS = "0123456789abcdefABCDEF";
var ASCII_HIGH_DIGITS = "01234567";
function decodeAsciiEscapes(text) {
  const out = [];
  for (const c of text) {
    out.push(c);
    for (let n = out.length; n >= 3; n -= 2) {
      const high = out[n - 2];
      const low = out[n - 1];
      if (out[n - 3] !== "%" || high === void 0 || low === void 0 || !ASCII_HIGH_DIGITS.includes(high) || !HEX_DIGITS.includes(low)) break;
      out.length = n - 3;
      out.push(String.fromCharCode(Number.parseInt(`${high}${low}`, 16)));
    }
  }
  return out.join("");
}
var NAME_SPAN = MAX_NAME_LENGTH + 1;
function nameEnd(text, from, end) {
  const stop = Math.min(end, from + NAME_SPAN);
  for (let i = from + 1; i < stop; i += 1) if (text.charCodeAt(i) === 64) return i;
  return -1;
}
function prefixAt(text, at, end, prefix) {
  return at + prefix.length <= end && text.slice(at, at + prefix.length).toLowerCase() === prefix;
}
function patchSource(value, manager) {
  const hash = value.indexOf("#");
  const text = decodeAsciiEscapes(value.slice(PATCH_WORD.length, hash < 0 ? value.length : hash));
  let start = 0;
  let end = text.length;
  let cut = -1;
  for (; ; ) {
    const at = nameEnd(text, start, end);
    if (at < 0 && end - start > MAX_NAME_LENGTH) return void 0;
    const name = text.slice(start, at < 0 ? end : at);
    if (!validName2("npm", name)) return void 0;
    const rest = at < 0 ? end : at + 1;
    if (!prefixAt(text, rest, end, PATCH_WORD)) return sourcePackage(name, text.slice(rest, end), manager);
    start = rest + PATCH_WORD.length;
    if (cut < 0) {
      const next = text.indexOf("#", start);
      cut = next < 0 ? text.length : next;
    }
    end = cut;
  }
}
function sourcePackage(name, rest, manager) {
  const isAlias = NPM_PROTOCOL.test(rest);
  const wanted = isAlias ? rest.slice(4) : rest;
  const at = isAlias ? nameEnd(wanted, 0, wanted.length) : -1;
  if (at > 0) {
    const real = wanted.slice(0, at);
    const range = wanted.slice(at + 1);
    return validName2("npm", real) && npmRange(range, manager) !== null ? spec("npm", real, npmKeyRange(manager, range)) : void 0;
  }
  if (isAlias && wanted.indexOf("@", 1) > 0) return void 0;
  return npmRange(wanted, manager) === null ? void 0 : spec("npm", name, npmKeyRange(manager, wanted));
}
function patchDependency(key, value, manager) {
  const source = patchSource(value, manager);
  if (!validName2("npm", key)) return source === void 0 ? [] : [source];
  const own = spec("npm", key, void 0);
  if (source === void 0) return [own];
  if (source.name === key) return [manager === "yarn" ? source : own];
  return [own, source];
}
function npmDependency(key, value, manager) {
  const wanted = value.trim();
  if (PATCH_PROTOCOL.test(wanted)) return patchDependency(key, wanted, manager);
  if (NPM_PROTOCOL.test(wanted)) return npmProtocolDependency(key, wanted.slice(4), manager);
  const range = npmRange(wanted, manager);
  return range !== null && validName2("npm", key) ? [spec("npm", key, range)] : [];
}
function readNpmManifest(dir, manager = "npm") {
  const file = "package.json";
  const read2 = readManifestText(resolve2(dir, file), dir);
  if (read2.status === "absent") return { file, status: "absent", packages: [], names: [], registries: [] };
  if (read2.status === "unreadable") return { file, status: "unreadable", packages: [], names: [], registries: [], reason: read2.reason };
  let manifest;
  try {
    manifest = JSON.parse(read2.text);
  } catch {
    return { file, status: "unreadable", packages: [], names: [], registries: [], reason: REASON.notJson };
  }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    return { file, status: "unreadable", packages: [], names: [], registries: [], reason: REASON.notManifest };
  }
  const packages = [];
  const names = /* @__PURE__ */ new Set();
  const seen = /* @__PURE__ */ new Set();
  for (const section of NPM_SECTIONS) {
    const entries = manifest[section];
    if (entries === null || typeof entries !== "object" || Array.isArray(entries)) continue;
    for (const [key, value] of Object.entries(entries)) {
      names.add(key);
      if (typeof value !== "string") continue;
      for (const pkg of npmDependency(key, value, manager)) pushOnce(packages, seen, pkg);
    }
  }
  return { file, status: "ok", packages, names: [...names], registries: [] };
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
var OTHER_SOURCE_REASONS = ["direct URL reference", "local path", "URL / VCS / protocol spec", "SSH git spec", "archive file"];
function readRequirement(requirement, manager) {
  const parsed = parsePackageSpec("pypi", requirement, manager);
  if (!("name" in parsed)) return OTHER_SOURCE_REASONS.some((r) => parsed.reason.startsWith(r)) ? { kind: "other-source" } : { kind: "none" };
  if (parsed.name.length > MAX_NAME_LENGTH) return { kind: "none" };
  const rangeUnread = parsed.range !== void 0 && !pypiRange(parsed.range);
  return { kind: "package", name: parsed.name, range: rangeUnread ? void 0 : parsed.range, rangeUnread };
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
    const reading = readRequirement(requirement, walk2.manager);
    if (reading.kind !== "package" || reading.rangeUnread) continue;
    pushOnce(found.packages, found.seen, spec("pypi", reading.name, reading.range));
  }
  return { status: "ok" };
}
function readRequirements(dir, files, manager = "pip") {
  const walk2 = { files: 0, visited: /* @__PURE__ */ new Set(), manager };
  return files.map((given) => {
    const file = label(given);
    if (isNetworkPath(given)) return { file, status: "unreadable", packages: [], names: [], registries: [], reason: REASON.network };
    const found = { packages: [], registries: [], seen: /* @__PURE__ */ new Set() };
    const read2 = readRequirementFile(resolve2(dir, given), dir, 0, walk2, found);
    if (read2.status === "absent") return { file, status: "absent", packages: [], names: [], registries: [] };
    if (read2.status === "unreadable") return { file, status: "unreadable", packages: [], names: [], registries: [], reason: read2.reason };
    const out = { file, status: "ok", packages: found.packages, names: found.packages.map((p) => p.name), registries: found.registries };
    if (found.incomplete !== void 0) out.incomplete = found.incomplete;
    return out;
  });
}
var isBlank = (c) => c === " " || c === "	";
var isBareKeyChar = (c) => {
  const n = c.charCodeAt(0);
  return n >= 48 && n <= 57 || n >= 65 && n <= 90 || n >= 97 && n <= 122 || c === "_" || c === "-";
};
var isBareValueChar = (c) => isBareKeyChar(c) || c === "." || c === ":" || c === "+";
var HEX = "0123456789abcdefABCDEF";
var SIMPLE_ESCAPES = { b: "\b", t: "	", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\" };
function skipToLineEnd(x) {
  while (x.p < x.s.length && x.s[x.p] !== "\n") x.p += 1;
}
function skipBlanks(x) {
  while (isBlank(x.s[x.p])) x.p += 1;
}
function skipBlankLines(x) {
  for (; ; ) {
    const c = x.s[x.p];
    if (isBlank(c) || c === "\n") x.p += 1;
    else if (c === "#") skipToLineEnd(x);
    else return;
  }
}
function endsLine(x) {
  skipBlanks(x);
  const c = x.s[x.p];
  if (c === void 0 || c === "\n") return true;
  if (c !== "#") return false;
  skipToLineEnd(x);
  return true;
}
function readCodePoint(x, digits) {
  let code = 0;
  for (let i = 0; i < digits; i += 1) {
    const c = x.s[x.p];
    if (c === void 0 || !HEX.includes(c)) return void 0;
    code = code * 16 + Number.parseInt(c, 16);
    x.p += 1;
  }
  return code > 1114111 || code >= 55296 && code <= 57343 ? void 0 : String.fromCodePoint(code);
}
function readString(x) {
  const quote = x.s[x.p];
  if (x.s[x.p + 1] === quote && x.s[x.p + 2] === quote) return void 0;
  x.p += 1;
  let out = "";
  for (; ; ) {
    const c = x.s[x.p];
    if (c === void 0 || c === "\n") return void 0;
    x.p += 1;
    if (c === quote) return out;
    const code = c.charCodeAt(0);
    if (code < 32 && c !== "	" || code === 127) return void 0;
    if (quote === "'" || c !== "\\") {
      out += c;
      continue;
    }
    const e = x.s[x.p];
    if (e === void 0) return void 0;
    x.p += 1;
    const decoded = e === "u" ? readCodePoint(x, 4) : e === "U" ? readCodePoint(x, 8) : SIMPLE_ESCAPES[e];
    if (decoded === void 0) return void 0;
    out += decoded;
  }
}
function readKey(x) {
  const parts = [];
  for (; ; ) {
    skipBlanks(x);
    const c = x.s[x.p];
    if (c === void 0) return void 0;
    let part;
    if (c === '"' || c === "'") part = readString(x);
    else {
      const start = x.p;
      while (x.p < x.s.length && isBareKeyChar(x.s[x.p] ?? " ")) x.p += 1;
      part = x.p > start ? x.s.slice(start, x.p) : void 0;
    }
    if (part === void 0) return void 0;
    parts.push(part);
    skipBlanks(x);
    if (x.s[x.p] !== ".") return parts;
    x.p += 1;
  }
}
function skipScalar(x) {
  const c = x.s[x.p];
  if (c === '"' || c === "'") return readString(x) !== void 0;
  const start = x.p;
  while (x.p < x.s.length && isBareValueChar(x.s[x.p] ?? " ")) x.p += 1;
  return x.p > start;
}
function readStringList(x) {
  if (x.s[x.p] !== "[") return void 0;
  x.p += 1;
  const out = [];
  for (; ; ) {
    skipBlankLines(x);
    const c = x.s[x.p];
    if (c === "]") {
      x.p += 1;
      return out;
    }
    if (c !== '"' && c !== "'") return void 0;
    const item = readString(x);
    if (item === void 0) return void 0;
    out.push(item);
    skipBlankLines(x);
    const next = x.s[x.p];
    if (next === ",") x.p += 1;
    else if (next !== "]") return void 0;
  }
}
function readHeader(x) {
  x.p += 1;
  const double = x.s[x.p] === "[";
  if (double) x.p += 1;
  const key = readKey(x);
  if (key === void 0) return void 0;
  skipBlanks(x);
  if (x.s[x.p] !== "]") return void 0;
  x.p += 1;
  if (double) {
    if (x.s[x.p] !== "]") return void 0;
    x.p += 1;
  }
  return endsLine(x) ? key : void 0;
}
function readToml(content) {
  const x = { s: content, p: 0 };
  let dependencies;
  let toolUv = false;
  let inTables = false;
  while (x.p < x.s.length) {
    skipBlanks(x);
    const c = x.s[x.p];
    if (c === void 0) break;
    if (c === "\n") {
      x.p += 1;
      continue;
    }
    if (c === "#") {
      skipToLineEnd(x);
      continue;
    }
    if (c === "[") {
      const header = readHeader(x);
      if (header === void 0 || header[0] === "dependencies" || header[0] === "requires-python") return void 0;
      if (header[0] === "tool" && (header.length === 1 || header[1] === "uv")) toolUv = true;
      inTables = true;
      continue;
    }
    if (inTables) {
      skipToLineEnd(x);
      continue;
    }
    const key = readKey(x);
    if (key === void 0) return void 0;
    skipBlanks(x);
    if (x.s[x.p] !== "=") return void 0;
    x.p += 1;
    skipBlanks(x);
    if (key.length === 1 && key[0] === "dependencies") {
      if (dependencies !== void 0) return void 0;
      dependencies = readStringList(x);
      if (dependencies === void 0 || !endsLine(x)) return void 0;
      continue;
    }
    if (key[0] === "tool" && key[1] === "uv") toolUv = true;
    if (!skipScalar(x) || !endsLine(x)) return void 0;
  }
  return { dependencies: dependencies ?? [], toolUv };
}
var isOpening = (line) => line.startsWith("# /// script") && line.slice("# /// script".length).trim() === "" && !line.slice("# /// script".length).includes("\r");
var isContent = (line) => line === "#" || line.startsWith("# ");
var isClosing = (line) => line.startsWith("# ///") && line.slice("# ///".length).trim() === "" && !line.slice("# ///".length).includes("\r");
function linesAtLineFeed(text) {
  return text.split("\n").map((line) => line.endsWith("\r") ? line.slice(0, -1) : line);
}
function linesAtAnyBreak(text) {
  const out = [];
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c !== "\r" && c !== "\n") continue;
    out.push(text.slice(start, i));
    if (c === "\r" && text[i + 1] === "\n") i += 1;
    start = i + 1;
  }
  out.push(text.slice(start));
  return out;
}
function hasLoneCarriageReturn(text) {
  for (let i = text.indexOf("\r"); i >= 0; i = text.indexOf("\r", i + 1)) if (text[i + 1] !== "\n") return true;
  return false;
}
function readBlocksOf(lines, manager) {
  const packages = [];
  const seen = /* @__PURE__ */ new Set();
  let toolUv = false;
  let otherSource = false;
  let i = 0;
  while (i < lines.length) {
    if (!isOpening(lines[i] ?? "")) {
      i += 1;
      continue;
    }
    let end = i + 1;
    let closing = -1;
    while (end < lines.length && isContent(lines[end] ?? "")) {
      if (isClosing(lines[end] ?? "")) closing = end;
      end += 1;
    }
    if (closing < 0) {
      i = end;
      continue;
    }
    const content = lines.slice(i + 1, closing).map((line) => line.slice(2)).join("\n");
    const toml = readToml(content);
    if (toml === void 0) return { status: "unreadable", reason: REASON.notInForm };
    if (toml.toolUv) toolUv = true;
    for (const requirement of toml.dependencies) {
      const reading = readRequirement(requirement, manager);
      if (reading.kind === "none") return { status: "unreadable", reason: REASON.notInForm };
      if (reading.kind === "other-source") otherSource = true;
      else pushOnce(packages, seen, spec("pypi", reading.name, reading.range));
    }
    i = closing + 1;
  }
  const out = { status: "ok", packages };
  if (toolUv) out.toolUv = true;
  if (otherSource) out.otherSource = true;
  return out;
}
function inlineScriptBlock(text, manager = "uv") {
  const clean = text.startsWith("\uFEFF") ? text.slice(1) : text;
  const first = readBlocksOf(linesAtLineFeed(clean), manager);
  if (!hasLoneCarriageReturn(clean)) return first;
  const second = readBlocksOf(linesAtAnyBreak(clean), manager);
  if (first.status === "unreadable") return second.status === "unreadable" ? first : { ...second, incomplete: first.reason };
  if (second.status === "unreadable") return { ...first, incomplete: second.reason };
  const packages = [];
  const seen = /* @__PURE__ */ new Set();
  for (const pkg of [...first.packages, ...second.packages]) pushOnce(packages, seen, pkg);
  const out = { status: "ok", packages };
  if (first.toolUv === true || second.toolUv === true) out.toolUv = true;
  if (first.otherSource === true || second.otherSource === true) out.otherSource = true;
  return out;
}
function readInlineScript(dir, file, manager, under) {
  const shown = label(file);
  const none = { file: shown, packages: [], names: [], registries: [] };
  if (isNetworkPath(file)) return { ...none, status: "unreadable", reason: REASON.network };
  const read2 = readManifestText(resolve2(dir, file), under);
  if (read2.status === "absent") return { ...none, status: "absent" };
  if (read2.status === "unreadable") return { ...none, status: "unreadable", reason: read2.reason };
  const block = inlineScriptBlock(read2.text, manager);
  if (block.status === "unreadable") return { ...none, status: "unreadable", reason: block.reason };
  const out = { file: shown, status: "ok", packages: block.packages, names: block.packages.map((p) => p.name), registries: [] };
  if (block.incomplete !== void 0) out.incomplete = block.incomplete;
  if (block.toolUv === true) out.toolUv = true;
  if (block.otherSource === true) out.otherSource = true;
  return out;
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
import { basename as basename2, dirname as dirname3, isAbsolute as isAbsolute2, join as join4, parse as parse3, relative as relative2, resolve as resolve3 } from "node:path";
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
  const r = readRaw(path, ctx, under);
  if (r.status === "refused") noteUnread(path, what);
  return r.status === "ok" ? r.text : void 0;
}
function readRaw(path, ctx, under) {
  const root = walkRoot(path, ctx, under);
  const key = `${path}\0${root ?? ""}`;
  let r = ctx.cache?.reads.get(key);
  if (r === void 0) {
    r = readSmallText(path, MAX_REGISTRY_CONFIG_BYTES, root);
    ctx.cache?.reads.set(key, r);
  }
  return r;
}
function readEnvFile(path, ctx) {
  try {
    const r = readRaw(path, ctx);
    if (r.status === "refused" && r.reason !== "not-a-regular-file") noteUnread(path, "configuration");
    return r.status === "ok" ? r.text : void 0;
  } catch {
    return void 0;
  }
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
function gitRepositoryRoot(ctx) {
  const top = ancestors(ctx).at(-1);
  return top !== void 0 && present(join4(top, ".git")) ? top : void 0;
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
  return withCommentAt(value.slice(0, end).trim().replace(/^(["'])(.*)\1$/, "$2"), value.slice(end));
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
    return withCommentAt(content, rest);
  }
  const comment = value.search(/\s#/);
  return comment === -1 ? value.trim() : withCommentAt(value.slice(0, comment).trim(), value.slice(comment));
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
    const value = withCommentAt(m[2] ?? "", raw.slice(m[0].length));
    all?.push(value);
    if (lineScope === void 0) found = value;
    else if (scope !== void 0 && lineScope.toLowerCase() === scope.toLowerCase()) scoped = value;
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
    const match = /https?:\/\/[^"'\s}]+/.exec(line);
    const unquoted = match !== null && !/["']/.test(line.charAt(match.index - 1));
    const url = match === null ? "(configured)" : withCommentAt(match[0], unquoted ? line.slice(match.index + match[0].length) : "");
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
function urlOrConfigured(value) {
  return /^https?:\/\/\S+$/i.test(value) ? value : UNREADABLE_VALUE;
}
function bunScopeKey(text) {
  return /^@?[A-Za-z0-9._-]+$/.test(text) ? text.replace(/^@/, "").toLowerCase() : void 0;
}
function scopeOfSubtable(header) {
  const quoted = /^install\.scopes\.(["'])([^"']+)\1$/.exec(header);
  if (quoted !== null) return bunScopeKey(quoted[2] ?? "");
  const bare = /^install\.scopes\.([A-Za-z0-9_-]+)$/.exec(header);
  return bare === null ? void 0 : bunScopeKey(bare[1] ?? "");
}
function bunfigValue(line) {
  const match = /https?:\/\/[^"'\s}]+/.exec(line);
  const unquoted = match !== null && !/["']/.test(line.charAt(match.index - 1));
  return match === null ? UNREADABLE_VALUE : withCommentAt(match[0], unquoted ? line.slice(match.index + match[0].length) : "");
}
function bunfigFound(text, scope) {
  try {
    const wanted = scope?.toLowerCase();
    let section = "";
    let exact = "";
    let header = false;
    let found;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      const head = /^\[([^\]]+)\]$/.exec(line);
      if (head !== null) {
        header = true;
        exact = head[1] ?? "";
        section = exact.trim();
        continue;
      }
      if (line === "" || line.startsWith("#")) continue;
      if (section === "install" && /^registry\s*=/.test(line)) found = found ?? { url: bunfigValue(line), explains: true };
      else if (!header && /^install\.registry\s*=/.test(line)) found = found ?? newForm(bunfigValue(line));
      else if (exact === "install.registry" && /^url\s*=/.test(line)) found = found ?? newForm(bunfigValue(line));
      else if (wanted !== void 0) {
        if (section === "install.scopes") {
          const key = /^["']?@?([^"'=\s]+)["']?\s*=/.exec(line)?.[1];
          if (key !== void 0 && key.toLowerCase() === wanted) return { url: bunfigValue(line), explains: true };
        } else if (/^url\s*=/.test(line) && scopeOfSubtable(exact) === wanted) return newForm(bunfigValue(line));
      }
    }
    return found;
  } catch {
    return void 0;
  }
  function newForm(url) {
    return { url, explains: url !== UNREADABLE_VALUE };
  }
}
var BUN_ENV_NAMES = /* @__PURE__ */ new Set(["BUN_CONFIG_REGISTRY", "NPM_CONFIG_REGISTRY", "npm_config_registry"]);
function bunEnvValue(text) {
  let open;
  let bun;
  let other;
  for (const raw of text.split(/\r?\n/)) {
    if (open !== void 0) {
      if (raw.includes(open)) open = void 0;
      continue;
    }
    const assignment = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(raw);
    if (assignment === null) continue;
    const name = assignment[1] ?? "";
    const rest = assignment[2] ?? "";
    const first = rest.charAt(0);
    let value;
    if (first === '"' || first === "'" || first === "`") {
      const close = rest.indexOf(first, 1);
      if (close < 0) {
        open = first;
        value = UNREADABLE_VALUE;
      } else {
        const content = rest.slice(1, close);
        const bad = first !== "'" && (content.includes("\\") || content.includes("$"));
        value = bad || !endsCleanly(rest.slice(close + 1)) ? UNREADABLE_VALUE : content === "" ? void 0 : urlOrConfigured(content);
      }
    } else {
      let end = 0;
      while (end < rest.length && rest.charAt(end) !== " " && rest.charAt(end) !== "	") end += 1;
      const token = rest.slice(0, end);
      if (token === "" || token.startsWith("#")) value = void 0;
      else if (/["'`\\$#]/.test(token) || !endsCleanly(rest.slice(end))) value = UNREADABLE_VALUE;
      else value = urlOrConfigured(token);
    }
    if (!BUN_ENV_NAMES.has(name) || value === void 0) continue;
    if (value !== UNREADABLE_VALUE && isPublic("npm", value)) continue;
    if (name === "BUN_CONFIG_REGISTRY") bun = value;
    else other = value;
  }
  return bun ?? other;
  function endsCleanly(tail) {
    const t = tail.trimStart();
    return t === "" || t !== tail && t.startsWith("#");
  }
}
function bunMode(ctx) {
  const v = envOf(ctx)["NODE_ENV"];
  return v === "development" || v === "test" ? v : "production";
}
function bunEnvNames(mode) {
  return [`.env.${mode}.local`, ...mode === "test" ? [] : [".env.local"], `.env.${mode}`, ".env"];
}
function judgeWorkspaceEntry(entry, rel) {
  if (typeof entry !== "string" || entry === "" || entry.startsWith("!") || entry.startsWith("./")) return "unknown";
  if (entry.endsWith("/") && !entry.endsWith("/*") && !entry.endsWith("/**")) return "unknown";
  let body = entry;
  let kind = "exact";
  if (entry.endsWith("/**")) {
    body = entry.slice(0, -3);
    kind = "globstar";
  } else if (entry.endsWith("/*")) {
    body = entry.slice(0, -2);
    kind = "star";
  }
  if (body === "" || /[*?[\]{}()!+@\\]/.test(body) || body.split("/").some((seg) => seg === "" || seg === "." || seg === "..")) return "unknown";
  if (kind === "exact") return body === rel ? "yes" : "no";
  if (!rel.startsWith(`${body}/`)) return "no";
  return kind === "globstar" || !rel.slice(body.length + 1).includes("/") ? "yes" : "no";
}
function workspacesList(packageJson, rel) {
  if (packageJson === void 0) return "no";
  try {
    const w = JSON.parse(packageJson).workspaces;
    const entries = Array.isArray(w) ? w : w !== null && typeof w === "object" ? w.packages : void 0;
    if (!Array.isArray(entries)) return "no";
    const verdicts = entries.map((e) => judgeWorkspaceEntry(e, rel));
    return verdicts.includes("yes") ? "yes" : verdicts.includes("unknown") ? "unknown" : "no";
  } catch {
    return "no";
  }
}
function bunEnvPlan(ctx) {
  const cmd = ctx.command;
  if (cmd === void 0 || cmd.manager !== "bun" || cmd.global || cmd.envFileFlag || cmd.bunLauncher) return void 0;
  try {
    const near = ancestors(ctx);
    const first = near.findIndex((dir) => present(join4(dir, "package.json")));
    const base2 = near[first < 0 ? 0 : first];
    if (base2 === void 0) return void 0;
    if (first < 0) return { dirs: [base2], explains: true };
    let unsure;
    for (const dir of near.slice(first + 1)) {
      const listed = workspacesList(read(join4(dir, "package.json"), ctx, void 0, "workspace manifest"), relative2(dir, base2).split(/[\\/]/).join("/"));
      if (listed === "yes") return { dirs: [dir], explains: true };
      if (listed === "unknown" && unsure === void 0) unsure = dir;
    }
    return unsure === void 0 ? { dirs: [base2], explains: true } : { dirs: [unsure, base2], explains: false };
  } catch {
    return void 0;
  }
}
function envFound(text, explainsAllowed) {
  const value = bunEnvValue(text);
  if (value === void 0) return void 0;
  return { url: value, explains: explainsAllowed && value !== UNREADABLE_VALUE };
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
      if (/^(?:1|true|yes|on)$/i.test(value)) return { kind: "registry", source: key, from: "user" };
      continue;
    }
    if (value.split(/\s+/).some((u) => !isPublic(ecosystem, u.replace(/^[^=]+=(?=https?:)/, "")))) {
      return { kind: "registry", source: key, url: value, from: "user" };
    }
  }
  return null;
}
function scopeOnly(parse5) {
  return (text, scope) => {
    if (scope === void 0) return void 0;
    const url = parse5(text, scope);
    return url !== void 0 && url !== parse5(text, void 0) ? url : void 0;
  };
}
function isBunProject(ctx) {
  return ctx.command?.manager === "bun" && !ctx.command.global;
}
function registryFiles(ctx) {
  const base2 = npmConfigFiles(ctx);
  const cmd = ctx.command;
  const bun = isBunProject(ctx);
  const noDefault = cmd?.global === true && cmd.registryForm === "bun add";
  if (!bun && !noDefault) return base2;
  const plan = bun ? bunEnvPlan(ctx) : void 0;
  const out = [];
  for (const f of base2) {
    const name = basename2(f.path);
    if (f.user) {
      out.push(f);
    } else if (noDefault && (name === ".npmrc" || name === "bunfig.toml")) {
      out.push({ ...f, parse: scopeOnly(f.parse) });
    } else if (bun && name === "bunfig.toml") {
      out.push({ ...f, found: bunfigFound });
    } else {
      if (plan !== void 0 && name === ".npmrc" && plan.dirs.some((d) => samePath(d, dirname3(f.path)))) {
        for (const envName of bunEnvNames(bunMode(ctx))) {
          out.push({ path: join4(dirname3(f.path), envName), parse: () => void 0, user: false, env: true, found: (text) => envFound(text, plan.explains) });
        }
      }
      out.push(f);
    }
  }
  return out;
}
function npmRegistry(name, ctx) {
  const scope = npmScope(name);
  const fromEnv = envRegistry("npm", ctx);
  if (fromEnv !== null) return fromEnv;
  let authSource;
  let userAuth;
  let first = null;
  for (const file of registryFiles(ctx)) {
    const text = file.env === true ? readEnvFile(file.path, ctx) : read(file.path, ctx);
    if (text === void 0) continue;
    const url = file.found === void 0 ? file.parse(text, scope) : void 0;
    const hit = file.found === void 0 ? url === void 0 ? void 0 : { url, explains: true } : file.found(text, scope);
    if (hit !== void 0 && hit.explains && !isPublic("npm", hit.url)) {
      first = first ?? { kind: "registry", source: file.path, url: hit.url, from: file.user ? "user" : "project" };
      if (file.user) return first.from === "user" ? first : { ...first, from: "user" };
      continue;
    }
    if (file.env !== true && NPM_AUTH.test(text)) {
      authSource = authSource ?? file.path;
      if (file.user) userAuth = userAuth ?? file.path;
    }
  }
  const credential = scope !== void 0 && userAuth !== void 0;
  if (first !== null) return credential && first.from === "project" ? { ...first, from: "user" } : first;
  if (scope !== void 0 && authSource !== void 0) return { kind: "auth", source: authSource, from: userAuth !== void 0 ? "user" : "project" };
  const local = npmWorkspacePackage(name, ctx);
  return local === void 0 ? null : { kind: "workspace", source: local, from: "project" };
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
    const envDirs = manager === "bun" ? bunEnvPlan(ctx)?.dirs : void 0;
    for (const dir of near.slice(from)) {
      const isBase = dir === near[from];
      const obeyed = isBase || manager === "yarn" || hasWorkspaces(read(join4(dir, "package.json"), ctx, void 0, "workspace manifest")) || manager === "pnpm" && present(join4(dir, "pnpm-workspace.yaml"));
      if (envDirs?.some((d) => samePath(d, dir)) === true) {
        for (const name of bunEnvNames(bunMode(ctx))) {
          const source = join4(dir, name);
          const text = readEnvFile(source, ctx);
          const url = text === void 0 ? void 0 : bunEnvValue(text);
          if (url !== void 0) found.push({ source, url });
        }
      }
      if (!obeyed) continue;
      for (const { name, parse: parse5 } of files) {
        const source = join4(dir, name);
        const text = read(source, ctx);
        const url = text === void 0 ? void 0 : manager === "bun" && name === "bunfig.toml" ? bunfigFound(text, void 0)?.url : parse5(text, void 0);
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
function arrayUrl(body) {
  return /https?:\/\/[^"'\s]+/.exec(body.join("\n"))?.[0] ?? UNREADABLE_VALUE;
}
function indexKeyValue(line, onlyIndexUrl = false) {
  const m = /^\s*(index-url|extra-index-url|find-links)\s*=\s*["']?([^"'\s\]]+)/.exec(line);
  if (m === null || onlyIndexUrl && m[1] !== "index-url") return void 0;
  return isPublic("pypi", m[2] ?? "") ? void 0 : m[2];
}
function indexEntries(text, arrays, keys, top) {
  const out = [];
  let table;
  let keyed = top === void 0 ? void 0 : { kind: top };
  const flush = () => {
    const kind = table === void 0 ? void 0 : arrays[table.name]?.(table.body);
    if (table !== void 0 && kind !== void 0) out.push({ kind, url: arrayUrl(table.body) });
    table = void 0;
  };
  for (const line of text.split(/\r?\n/)) {
    const array = /^\s*\[\[\s*([^\][]+?)\s*\]\]/.exec(line);
    const plain = array === null ? /^\s*\[\s*([^\][]+?)\s*\]/.exec(line) : null;
    if (array !== null || plain !== null) {
      flush();
      const name = (array ?? plain)?.[1] ?? "";
      if (array !== null) {
        table = { name, body: [] };
        keyed = void 0;
      } else {
        keyed = Object.hasOwn(keys, name) ? keys[name] : top === void 0 ? void 0 : { kind: top };
      }
      continue;
    }
    if (table !== void 0) {
      table.body.push(line);
      continue;
    }
    if (keyed === void 0) continue;
    const value = indexKeyValue(line, keyed.onlyIndexUrl === true);
    if (value !== void 0) out.push({ kind: keyed.kind, url: value });
  }
  flush();
  return out;
}
var hasDefault = (body) => body.some((l) => /^\s*default\s*=\s*true\b/.test(l));
function poetryKind(body) {
  const p = body.map((l) => /^\s*priority\s*=\s*["']([^"']*)["']/.exec(l)?.[1]).find((v) => v !== void 0);
  if (p === void 0) return "poetry-none";
  return p === "primary" || p === "supplemental" || p === "explicit" ? `poetry-${p}` : "poetry-other";
}
function uvTomlEntries(text) {
  return indexEntries(
    text,
    { index: (body) => hasDefault(body) ? "uv-index-default" : "uv-index" },
    { pip: { kind: "uv-pip" } },
    "uv-top"
  );
}
function pyprojectEntries(text) {
  return indexEntries(
    text,
    {
      "tool.uv.index": (body) => hasDefault(body) ? "tool-uv-index-default" : "tool-uv-index",
      "tool.poetry.source": poetryKind,
      "tool.pdm.source": () => "pdm"
    },
    { "tool.uv": { kind: "tool-uv" }, "tool.uv.pip": { kind: "tool-uv-pip", onlyIndexUrl: true } }
  );
}
var NOT_OBEYED = {
  "uv add": /* @__PURE__ */ new Set(["uv-pip", "poetry-primary"]),
  "uv pip install": /* @__PURE__ */ new Set(["poetry-primary"]),
  "pipx install": /* @__PURE__ */ new Set(["uv-top", "tool-uv", "tool-uv-index", "tool-uv-index-default", "poetry-primary"]),
  "pipx run": /* @__PURE__ */ new Set(["uv-top", "tool-uv"]),
  "poetry add": /* @__PURE__ */ new Set(["poetry-explicit", "uv-top", "tool-uv", "tool-uv-index-default"]),
  "pip install": /* @__PURE__ */ new Set(["uv-top", "tool-uv", "tool-uv-index", "tool-uv-index-default", "poetry-primary"])
};
function explainingIndex(entries, ctx) {
  const form = ctx.command?.registryForm;
  const skipped = form === void 0 ? void 0 : Object.hasOwn(NOT_OBEYED, form) ? NOT_OBEYED[form] : void 0;
  return entries.find((e) => e.kind === "tool-uv-pip" ? form === "uv pip install" : skipped?.has(e.kind) !== true)?.url;
}
function anyIndex(entries) {
  return entries.find((e) => e.kind !== "tool-uv-pip")?.url;
}
function insideProject(path, ctx) {
  return ancestors(ctx).some((dir) => isInside(dir, resolve3(path)));
}
function pypiRegistry(name, ctx) {
  const env = envOf(ctx);
  const fromEnv = envRegistry("pypi", ctx);
  if (fromEnv !== null) return fromEnv;
  const state = { first: null };
  const take = (found) => {
    state.first = state.first ?? found;
    return found.from === "user" ? { ...state.first, from: "user" } : null;
  };
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
    if (url !== void 0) {
      const done = take({ kind: "registry", source: path, url, from: insideProject(path, ctx) ? "project" : "user" });
      if (done !== null) return done;
    }
  }
  const uvConfs = [];
  const uvExplicit = envValue(env, "UV_CONFIG_FILE");
  if (uvExplicit !== void 0) uvConfs.push(uvExplicit);
  uvConfs.push(join4(xdg, "uv", "uv.toml"), join4(appdata, "uv", "uv.toml"), join4(etc, "uv", "uv.toml"));
  for (const path of uvConfs) {
    const text = read(path, ctx);
    const url = text === void 0 ? void 0 : anyIndex(uvTomlEntries(text));
    if (url !== void 0) {
      const done = take({ kind: "registry", source: path, url, from: "user" });
      if (done !== null) return done;
    }
  }
  for (const dir of ancestors(ctx)) {
    const uvToml = join4(dir, "uv.toml");
    const uvText = read(uvToml, ctx);
    const uvUrl = uvText === void 0 ? void 0 : explainingIndex(uvTomlEntries(uvText), ctx);
    if (uvUrl !== void 0) take({ kind: "registry", source: uvToml, url: uvUrl, from: "project" });
    const pyproject = join4(dir, "pyproject.toml");
    const text = read(pyproject, ctx);
    if (text === void 0) continue;
    const url = explainingIndex(pyprojectEntries(text), ctx);
    if (url !== void 0) take({ kind: "registry", source: pyproject, url, from: "project" });
    break;
  }
  if (state.first !== null) return state.first;
  const local = uvWorkspacePackage(name, ctx);
  return local === void 0 ? null : { kind: "workspace", source: local, from: "project" };
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
    if (hasRepositories(text)) return { kind: "registry", source: path, from: "project" };
    break;
  }
  const env = envOf(ctx);
  const home = homeOf(ctx);
  const composerHome = envValue(env, "COMPOSER_HOME");
  const globals = composerHome !== void 0 ? [join4(composerHome, "config.json")] : [join4(home, ".composer", "config.json"), join4(home, ".config", "composer", "config.json"), join4(envValue(env, "APPDATA") ?? join4(home, "AppData", "Roaming"), "Composer", "config.json")];
  for (const path of globals) if (hasRepositories(read(path, ctx))) return { kind: "registry", source: path, from: "user" };
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
      return { kind: "registry", source: path, url, from: insideProject(path, ctx) ? "project" : "user" };
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
    if (strayAt(url)) return void 0;
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
function onlyTheProjectExplains(eco, custom) {
  return (eco === "npm" || eco === "pypi") && (custom.kind === "registry" || custom.kind === "auth") && custom.from === "project";
}
function customFor(spec2, opts) {
  const onCommandLine = (opts.commandRegistries ?? []).find((u) => !isPublicRegistryUrl(spec2.ecosystem, u));
  if (onCommandLine !== void 0) return { kind: "registry", source: "the command line", url: onCommandLine, from: "user" };
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
    malicious = malIds.length > 0 ? custom !== null && custom.kind !== "unreadable" && custom.kind !== "unchecked" && !onlyTheProjectExplains(eco, custom) ? warn(`OSV lists this name as a malicious package (${malIds.join(", ")}) removed from ${registry}`) : fail(`OSV lists this name as a malicious package (${malIds.join(", ")}), removed from ${registry}`) : osvDown !== void 0 ? unknown(osvDown) : na();
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
    w.custom = onCommandLine !== void 0 ? { kind: "registry", source: "the command line", url: onCommandLine, from: "user" } : { kind: "unchecked", source: "the vetting deadline", cut: "time" };
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
function boundedInstalls(command, shell, isPopular, runsLocally, nested = [], cdpath = false, withManifests = (parsed) => [...parsed], pastDeadline = () => false, onDisk = (c) => c) {
  const cut = command.length > MAX_PARSED_LENGTH;
  let unassessed = 0;
  const parsed = withManifests(
    parseInstallCommands(cut ? command.slice(0, MAX_PARSED_LENGTH) : command, { shell, nested, cdpath }).map((c) => {
      if (c.localPathFirst === true) return onDisk(c);
      if (c.localFirst !== true) return c;
      if (pastDeadline()) {
        unassessed += 1;
        return c;
      }
      return { ...c, packages: c.packages.filter((p) => !runsLocally(p, c)) };
    })
  );
  const key = (pkg) => `${pkg.ecosystem}\0${pkg.name.toLowerCase()}\0${pkg.range ?? ""}`;
  const seen = /* @__PURE__ */ new Set();
  const named = [];
  const ofManifests = [];
  const certainKeys = /* @__PURE__ */ new Set();
  for (const c of parsed) {
    const candidates = new Set(c.candidates);
    for (const pkg of c.packages) {
      if (c.fromManifest === void 0 && !candidates.has(pkg)) certainKeys.add(key(pkg));
      if (seen.has(key(pkg))) continue;
      seen.add(key(pkg));
      (c.fromManifest === void 0 ? named : ofManifests).push(pkg);
    }
  }
  const firstOf = (unique, cap) => [...unique.filter((p) => !isPopular(p)), ...unique.filter(isPopular)].slice(0, cap).map(key);
  const certain = firstOf(
    named.filter((p) => certainKeys.has(key(p))),
    MAX_VETTED_PACKAGES
  );
  const candidateKeys = named.filter((p) => !certainKeys.has(key(p))).map(key).slice(0, MAX_VETTED_PACKAGES - certain.length);
  const chosen = /* @__PURE__ */ new Set([...certain, ...candidateKeys, ...firstOf(ofManifests, MAX_MANIFEST_PACKAGES)]);
  const taken = /* @__PURE__ */ new Map();
  for (const updates of [false, true]) {
    for (const c of parsed) {
      if (c.fromUpdate === true === updates) taken.set(c, c.packages.filter((pkg) => chosen.delete(key(pkg))));
    }
  }
  const commands = [];
  for (const c of parsed) {
    const packages = taken.get(c) ?? [];
    if (packages.length === 0) continue;
    const uncertain = cut ? [...c.uncertain, "the command is over 512 KB and only its start was read"] : c.uncertain;
    commands.push({ ...c, packages, uncertain });
  }
  return {
    commands,
    // The candidates the parse left out past its own ceiling count as packages not vetted.
    notVetted: Math.max(0, named.length - MAX_VETTED_PACKAGES) + parsed.reduce((n, c) => n + (c.candidatesDropped ?? 0), 0),
    manifestNotVetted: Math.max(0, ofManifests.length - MAX_MANIFEST_PACKAGES),
    cut,
    unassessed
  };
}
var NAMED_TO_UPDATE = "not denied: a package named to an update is fetched only when it is already installed";
var UPDATES_EVERY_GLOBAL = "dev-guardian: this command updates every globally installed package \u2014 none of them was vetted.";
var UPDATES_EVERY_TOOL = "dev-guardian: this command updates every tool pipx or uv installed \u2014 none of them was vetted.";
function updateCommand(c, inManifest) {
  const packages = (c.updateNames ?? []).filter((n) => n.range !== void 0 || !inManifest.has(n.name));
  if (packages.length === 0) return void 0;
  const { manifest: _manifest, update: _update, updateNames: _names, ...rest } = c;
  return { ...rest, packages, skipped: [], fromUpdate: true };
}
var NAMED_BY_MANIFEST = "it is named by a manifest, where a missing name is usually a private or a workspace package";
var plural = (n) => n === 1 ? "1 package" : `${String(n)} packages`;
var MAX_MANIFEST_MISSING_LINES = 5;
var MAX_COUNTED_FILES = 3;
function missingCountLine(counted) {
  const files = [...counted.keys()];
  const total = [...counted.values()].reduce((sum, n) => sum + n, 0);
  const shown = files.slice(0, MAX_COUNTED_FILES);
  const rest = files.length - shown.length;
  const named = rest > 0 ? `${shown.join(", ")} and ${String(rest)} more file${rest === 1 ? "" : "s"}` : shown.length > 1 ? `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1] ?? ""}` : shown[0] ?? "";
  return `dev-guardian: ${String(total)} more package${total === 1 ? "" : "s"} of ${named} ${total === 1 ? "is" : "are"} not on the public registry either (in a manifest that is usually a private or a workspace package) \u2014 not listed.`;
}
function withManifestPackages(parsed, opts, registry, notes, locked, scriptOut, pastDeadline) {
  const out = [];
  const top = opts.projectDir === void 0 ? void 0 : gitRepositoryRoot({ ...registry, projectDir: opts.projectDir });
  const lineAsked = /* @__PURE__ */ new Map();
  const world = {
    opts,
    // The root the links of a script are walked from: the repository root, else the project directory the hook was given.
    top: top ?? opts.projectDir,
    pastDeadline,
    notes,
    asks: scriptOut.asks,
    withDeny: scriptOut.withDeny,
    folders: /* @__PURE__ */ new Map(),
    probes: /* @__PURE__ */ new Map(),
    reads: /* @__PURE__ */ new Map(),
    overflow: /* @__PURE__ */ new Set(),
    asked: /* @__PURE__ */ new Set()
  };
  let userRegistries;
  const user = () => userRegistries ??= npmUserRegistries(registry);
  for (const c of parsed) {
    const scripted = scriptCommands(c, world);
    out.push(...archiveFileCommand(scripted.command), ...scripted.extra);
    const pushUpdate = (inManifest) => {
      const more = updateCommand(c, inManifest);
      if (more !== void 0) out.push(more);
    };
    if (c.global === true && c.updateNames?.length === 0 && c.skipped.length === 0) notes.push(UPDATES_EVERY_GLOBAL);
    if (c.updatesEveryTool === true) notes.push(UPDATES_EVERY_TOOL);
    const key = `${c.manager}\0${JSON.stringify(c.workdir)}\0${String(c.prefixed)}\0${String(c.registries.length > 0)}\0${String(c.global === true)}\0${String(c.envFileFlag === true)}\0${String(c.bunLauncher === true)}`;
    if (!lineAsked.has(key)) lineAsked.set(key, projectDefaultRegistryLines(c, opts, registry, user));
    notes.push(...lineAsked.get(key) ?? []);
    const manifest = c.manifest;
    if (manifest === void 0) {
      pushUpdate(/* @__PURE__ */ new Set());
      continue;
    }
    const moved2 = c.scriptDir !== void 0 || c.scriptDirUnknown === true ? folderOf(c, world) : void 0;
    const dir = c.prefixed === true ? null : moved2 === void 0 ? commandDir(c, opts) : moved2.kind === "dirs" ? moved2.dirs[0] ?? null : null;
    if (dir === null) {
      const what = manifest.kind === "package-json" ? "package.json" : "the requirements file";
      notes.push(`dev-guardian: ${what} was not read (${UNKNOWN_DIRECTORY}) \u2014 its packages were not vetted.`);
      pushUpdate(/* @__PURE__ */ new Set());
      continue;
    }
    let reads;
    let base2 = dir;
    try {
      if (manifest.kind === "package-json") {
        const nearest = readNearestManifest(c.manager, dir, opts.projectDir, top);
        base2 = nearest.dir;
        reads = [nearest.read];
      } else {
        reads = readRequirements(dir, manifest.files, c.manager);
      }
    } catch {
      notes.push("dev-guardian: the manifest was not read (could not be read) \u2014 its packages were not vetted.");
      pushUpdate(/* @__PURE__ */ new Set());
      continue;
    }
    pushUpdate(new Set(reads.flatMap((r) => r.status === "ok" ? r.names : [])));
    for (const read2 of reads) {
      if (read2.status === "absent") continue;
      const lock = c.ecosystem === "npm" && manifest.kind === "package-json" ? lockedProject(c, base2, read2, opts, top, registry, notes) : void 0;
      if (lock !== void 0) locked.push(lock);
      if (read2.status === "unreadable") {
        notes.push(`dev-guardian: ${read2.file} was not read (${read2.reason ?? "could not be read"}) \u2014 its packages were not vetted.`);
        continue;
      }
      if (read2.incomplete !== void 0) {
        notes.push(`dev-guardian: a file ${read2.file} includes was not read (${read2.incomplete}) \u2014 its packages were not vetted.`);
      }
      const inScope = c.ecosystem === "npm" ? withoutOwnRegistryScopes(read2, { ...registry, projectDir: base2, command: registryCommand(c) }, notes) : read2.packages;
      const packages = lock === void 0 || c.update === true ? inScope : withoutCovered(inScope, lock);
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
  overflowScripts(world);
  return out;
}
function registryCommand(c) {
  return {
    manager: c.manager,
    registryForm: c.registryForm,
    global: c.global === true,
    envFileFlag: c.envFileFlag === true,
    bunLauncher: c.bunLauncher === true
  };
}
function isDefaultRegistryLine(note) {
  return /^dev-guardian: the project's \S+ sets the default registry(?: \([^)]*\))? — /.test(note) || /^dev-guardian: \d+ more files? of the project sets? the default registry\.$/.test(note);
}
var MAX_REGISTRY_LINES = 3;
function projectDefaultRegistryLines(c, opts, registry, userRegistries) {
  try {
    if (c.ecosystem !== "npm" || c.registries.length > 0 || c.prefixed === true || c.global === true || npmEnvNamesDefaultRegistry(registry)) return [];
    const dir = commandDir(c, opts);
    if (dir === null) return [];
    const found = npmProjectDefaultRegistry(c.manager, { ...registry, projectDir: dir, command: registryCommand(c) }).filter((f) => !fromUserRegistry(f.url, userRegistries()));
    const lines = found.slice(0, MAX_REGISTRY_LINES).map((f) => {
      const host = registryHost("npm", f.url);
      return `dev-guardian: the project's ${basename3(f.source)} sets the default registry${host === void 0 ? "" : ` (${host})`} \u2014 packages are fetched from it, and what it serves was not vetted.`;
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
    if (source === "") source = basename3(own.source);
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
function findLockfile(manager, dir, projectDir, top) {
  const names = manager === "npm" || manager === "pnpm" || manager === "yarn" || manager === "bun" ? LOCKFILES[manager] : [];
  if (names.length === 0) return { status: "absent" };
  const { root, dirs } = climb(dir, projectDir, top);
  if (isNetworkPath(dir) || isNetworkPath(root)) return { status: "absent" };
  const candidates = manager === "bun" ? [...names, "bun.lockb"] : names;
  for (const at of dirs) {
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
  }
  return { status: "absent" };
}
function climb(dir, projectDir, top) {
  const bound = top ?? projectDir;
  const root = bound !== void 0 && projectDir !== void 0 && isWithin(bound, dir) ? resolve4(bound) : resolve4(dir);
  const dirs = [];
  let at = resolve4(dir);
  for (let i = 0; i < 64; i += 1) {
    dirs.push(at);
    const parent = dirname4(at);
    if (relative3(root, at) === "" || parent === at) break;
    at = parent;
  }
  return { root, dirs };
}
function readNearestManifest(manager, dir, projectDir, top) {
  const here = resolve4(dir);
  const absent = readNpmManifest(here, manager);
  if (absent.status !== "absent") return { read: absent, dir: here };
  for (const at of climb(dir, projectDir, top).dirs.slice(1)) {
    const read2 = readNpmManifest(at, manager);
    if (read2.status === "absent") continue;
    return { read: { ...read2, file: `${relative3(here, at).split(sep).join("/")}/${read2.file}` }, dir: at };
  }
  return { read: absent, dir: here };
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
          if (source === "") source = basename3(own.source);
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
function lockedProject(c, dir, manifest, opts, top, registry, notes) {
  try {
    const found = findLockfile(c.manager, dir, opts.projectDir, top);
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
    const ctx = { ...registry, projectDir: dir, command: registryCommand(c) };
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
  return isRegularFile(path);
}
function isRegularFile(path) {
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
var MAX_DISK_WORDS = 50;
var diskReason = (why) => `whether a file or folder of that name is in the command's folder was not looked for (${why})`;
function withoutDiskEntries(c, opts, pastDeadline, said2) {
  const why = /* @__PURE__ */ new Set();
  const lstat = opts.lstatImpl ?? ((path) => lstatSync3(path));
  const dir = isNetworkPath(opts.cwd) ? void 0 : commandDir(c, opts);
  const asked = /* @__PURE__ */ new Map();
  const packages = [];
  for (const pkg of c.packages) {
    const word = pkg.raw;
    if (word.includes("::")) {
      packages.push(pkg);
      continue;
    }
    const known = asked.get(word);
    if (known !== void 0) {
      if (!known) packages.push(pkg);
      continue;
    }
    if (pastDeadline()) why.add("vetting time budget exhausted");
    else if (dir === void 0) why.add("the folder is on the network");
    else if (dir === null) why.add("the folder is not known");
    else if (asked.size >= MAX_DISK_WORDS) why.add(`past the first ${String(MAX_DISK_WORDS)} words`);
    else {
      const path = resolve4(dir, word);
      if (isNetworkPath(path)) why.add("the folder is on the network");
      else {
        try {
          lstat(path);
          asked.set(word, true);
          continue;
        } catch (error) {
          const code = error?.code;
          asked.set(word, false);
          if (code !== "ENOENT" && code !== "ENOTDIR") why.add(`lstat failed: ${typeof code === "string" ? code : "unknown"}`);
        }
      }
    }
    packages.push(pkg);
  }
  for (const each of why) said2.add(`dev-guardian: ${diskReason(each)} \u2014 its words were vetted as package names.`);
  return { ...c, packages, uncertain: [...c.uncertain, ...[...why].map(diskReason)] };
}
function runsInstalledCopy(pkg, c, opts, memo) {
  if (pkg.range !== void 0 || pkg.raw !== pkg.name || c.prefixed === true) return false;
  const dir = commandDir(c, opts);
  if (dir === null) return false;
  const key = `${dir}\0${pkg.name}\0${String(c.byPackageFlag === true)}\0${c.manager}`;
  const known = memo.get(key);
  if (known !== void 0) return known;
  const found = installedLocally(pkg.name, dir, c.byPackageFlag === true, c.manager);
  memo.set(key, found);
  return found;
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
    const target = cdTarget(step, home, windows);
    if (target === null || real === null) return null;
    const moved2 = plainMove(dir, real, target, windows);
    if (moved2 === null) return null;
    [dir, real] = moved2;
  }
  return dir;
}
function cdTarget(step, home, windows) {
  if (step === "~" || /^~[\\/]/.test(step)) return join5(home, step.slice(1));
  if (step.startsWith("~")) return null;
  return windows ? step.replace(/^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/, (_, drive) => `${drive.toUpperCase()}:/`) : step;
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
var MAX_SCRIPT_FILES = 8;
var DEADLINE_REASON = "vetting time budget exhausted";
var NOT_LITERAL_REASON = "not a literal file name";
var NETWORK_REASON = "on a network path";
var UNREADABLE_REASON = "could not be read";
var MAX_DIR_STATES = 8;
var hasDotDot = (path) => path.split(/[\\/]+/).includes("..");
var samePath2 = (a, b) => process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
function linkOnPath(under, path) {
  const rel = relative3(resolve4(under), resolve4(path));
  if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute3(rel)) return false;
  let at = resolve4(under);
  for (const part of rel.split(/[\\/]+/)) {
    if (part === "" || part === ".") continue;
    at = join5(at, part);
    try {
      if (lstatSync3(at).isSymbolicLink()) return true;
    } catch {
      return false;
    }
  }
  return false;
}
function physicalPath(real, target, lastIsFile) {
  let at = real;
  const parts = target.split(/[\\/]+/);
  for (const [k, part] of parts.entries()) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      at = dirname4(at);
      continue;
    }
    const next = join5(at, part);
    let link = false;
    try {
      link = lstatSync3(next).isSymbolicLink();
    } catch {
      link = false;
    }
    if (link && !(lastIsFile && k === parts.length - 1)) {
      if (!walkLinksUnder(at, next).ok) return null;
      const resolved = realDir(next);
      if (resolved === null) return null;
      at = resolved;
    } else at = next;
  }
  return at;
}
function moveScriptDir(logical, real, target, windows, top) {
  const unknown2 = { ok: false, folder: { kind: "unknown" } };
  if (windows && /^[A-Za-z]:(?![\\/])/.test(target)) return unknown2;
  const next = resolve4(logical, target);
  if (isNetworkPath(next)) return { ok: false, folder: { kind: "refused", reason: NETWORK_REASON } };
  const under = top !== void 0 && isWithin(top, next) ? top : logical;
  const walked = walkLinksUnder(under, next);
  if (!walked.ok) return { ok: false, folder: { kind: "refused", reason: walked.reason === "remote-link" ? NETWORK_REASON : UNREADABLE_REASON } };
  const landed = realDir(next);
  if (landed === null) return linkOnPath(under, next) ? { ok: false, folder: { kind: "refused", reason: UNREADABLE_REASON } } : unknown2;
  const states = [[next, landed]];
  if (!isAbsolute3(target) && hasDotDot(target)) {
    const physical = physicalPath(real, target, false);
    const physicalReal = physical === null ? null : realDir(physical);
    if (physical !== null && physicalReal !== null && !samePath2(physical, next)) states.push([physical, physicalReal]);
  }
  return { ok: true, states };
}
function scriptFolder(c, w) {
  if (c.workdir === null || c.scriptDirUnknown === true) return { kind: "unknown" };
  const start = resolve4(w.opts.cwd);
  if (isNetworkPath(start)) return { kind: "unknown" };
  const steps = [...c.workdir ?? [], ...c.scriptDir === void 0 ? [] : [c.scriptDir]];
  if (steps.length === 0) return { kind: "dirs", dirs: [start] };
  const home = w.opts.homeDir ?? homedir2();
  const windows = (w.opts.platform ?? process.platform) === "win32";
  const startReal = realDir(start);
  if (startReal === null) return { kind: "unknown" };
  let states = [[start, startReal]];
  for (const step of steps) {
    if (w.pastDeadline()) return { kind: "deadline" };
    const target = cdTarget(step, home, windows);
    if (target === null) return { kind: "unknown" };
    const next = [];
    for (const [logical, real] of states) {
      const moved2 = moveScriptDir(logical, real, target, windows, w.top);
      if (!moved2.ok) return moved2.folder;
      for (const state of moved2.states) if (!next.some(([seen]) => samePath2(seen, state[0]))) next.push(state);
    }
    states = next.slice(0, MAX_DIR_STATES);
  }
  return { kind: "dirs", dirs: states.map(([logical]) => logical) };
}
function folderOf(c, w) {
  const key = JSON.stringify([c.workdir === void 0 ? "none" : c.workdir, c.scriptDir ?? null, c.scriptDirUnknown ?? null]);
  let folder = w.folders.get(key);
  if (folder === void 0) {
    try {
      folder = scriptFolder(c, w);
    } catch {
      folder = { kind: "unknown" };
    }
    w.folders.set(key, folder);
  }
  return folder;
}
function scriptPaths(dirs, written) {
  const out = [];
  const add = (path, dir, physical) => {
    if (!out.some((p) => samePath2(p.path, path))) out.push({ path, dir, physical });
  };
  for (const dir of dirs) {
    add(resolve4(dir, written), dir, false);
    if (isAbsolute3(written) || !hasDotDot(written)) continue;
    const real = realDir(dir);
    const physical = real === null ? null : physicalPath(real, written, true);
    if (physical !== null) add(physical, dir, true);
  }
  return out;
}
var scriptUnder = (w, path, dir) => w.top !== void 0 && isWithin(w.top, path) ? w.top : dir;
function probeFile(under, path) {
  const walked = walkLinksUnder(under, path);
  if (!walked.ok) return { kind: "refused", reason: walked.reason === "remote-link" ? NETWORK_REASON : UNREADABLE_REASON };
  return isRegularFile(path) ? { kind: "file" } : { kind: "none" };
}
function readScript(w, cand, written) {
  const key = process.platform === "win32" ? cand.path.toLowerCase() : cand.path;
  const known = w.reads.get(key);
  if (known !== void 0) return known;
  if (w.reads.size >= MAX_SCRIPT_FILES) {
    w.overflow.add(key);
    return void 0;
  }
  const under = scriptUnder(w, cand.path, cand.dir);
  let read2;
  try {
    read2 = cand.physical ? { ...readInlineScript(dirname4(cand.path), basename3(cand.path), "uv", under), file: said(written) } : readInlineScript(cand.dir, written, "uv", under);
  } catch {
    read2 = { file: said(written), status: "unreadable", packages: [], names: [], registries: [], reason: UNREADABLE_REASON };
  }
  w.reads.set(key, read2);
  return read2;
}
var unreadAsk = (file, why) => `the inline dependencies of ${file} could not be read (${why}) \u2014 uv or pipx installs them unvetted; allow it only if you trust this script`;
function archiveFileCommand(c) {
  const words = c.packages.filter((p) => p.malwareOnly === true);
  if (words.length === 0) return [c];
  const rest = { ...c, packages: c.packages.filter((p) => p.malwareOnly !== true) };
  return [rest, { ...withoutCandidates(c), packages: words, skipped: [], uncertain: [], fromArchiveFile: true }];
}
var runsAsFileLine = (word) => `dev-guardian: pipx run reads ${word} as a file, not a package \u2014 if the file is there, pipx runs it as a script and installs the packages its \`# /// script\` block names; they were not vetted.`;
function withoutCandidates(c) {
  const { candidates: _candidates, candidatesDropped: _dropped, inlineScripts: _scripts, ...rest } = c;
  return rest;
}
function scriptCommands(c, w) {
  const scripts = c.inlineScripts;
  if (scripts === void 0) return { command: c, extra: [] };
  const extra = [];
  const base2 = withoutCandidates(c);
  const local = /* @__PURE__ */ new Set();
  const maybeLocal = [];
  let ran = false;
  const unread = (file, why, ask) => {
    w.notes.push(notReadLine(file, why));
    if (ask) w.asks.push(unreadAsk(file, why));
  };
  const askable = (why) => why !== DEADLINE_REASON && why !== UNKNOWN_DIRECTORY && why !== NOT_LITERAL_REASON;
  for (const s of scripts) {
    const file = said(s.file);
    const asked = s.ifFile === true;
    if (!asked) ran = true;
    if (s.literal === false) {
      w.notes.push(notReadLine(file, NOT_LITERAL_REASON));
      continue;
    }
    if (isNetworkPath(s.file)) {
      unread(file, NETWORK_REASON, true);
      if (asked) local.add(s.file);
      continue;
    }
    const folder = w.pastDeadline() ? { kind: "deadline" } : folderOf(c, w);
    if (folder.kind === "refused") {
      unread(file, folder.reason, true);
      if (asked) local.add(s.file);
      continue;
    }
    if (folder.kind !== "dirs") {
      if (asked) maybeLocal.push(s.file);
      else w.notes.push(notReadLine(file, folder.kind === "deadline" ? DEADLINE_REASON : UNKNOWN_DIRECTORY));
      continue;
    }
    if (asked) {
      const key = `${folder.dirs.join("|")}|${s.file}`;
      if (!w.asked.has(key)) {
        if (w.asked.size >= MAX_VETTED_PACKAGES) {
          maybeLocal.push(s.file);
          continue;
        }
        w.asked.add(key);
      }
    }
    for (const cand of scriptPaths(folder.dirs, s.file)) {
      if (asked) {
        const under = scriptUnder(w, cand.path, cand.dir);
        const probeKey = `${under}|${cand.path}`;
        let probe = w.probes.get(probeKey);
        if (probe === void 0) {
          probe = probeFile(under, cand.path);
          w.probes.set(probeKey, probe);
        }
        if (probe.kind === "none") continue;
        local.add(s.file);
        ran = true;
        if (probe.kind === "refused") {
          unread(file, probe.reason, true);
          continue;
        }
      }
      const read2 = readScript(w, cand, s.file);
      if (read2 === void 0 || read2.status === "absent") continue;
      if (read2.status === "unreadable") {
        const why = read2.reason ?? UNREADABLE_REASON;
        unread(read2.file, why, askable(why));
        continue;
      }
      if (read2.incomplete !== void 0) unread(read2.file, read2.incomplete, true);
      if (read2.toolUv === true) {
        w.notes.push(`dev-guardian: ${read2.file} may name its own index or sources ([tool.uv]) \u2014 what they serve was not verified.`);
        w.asks.push(`the inline dependencies of ${read2.file} may come from its own index or sources ([tool.uv]) \u2014 what they serve was not vetted; allow it only if you trust this script`);
      }
      if (read2.otherSource === true) {
        w.notes.push(`dev-guardian: ${read2.file} names packages from a URL, a path or a VCS \u2014 they were not vetted.`);
        w.asks.push(`${read2.file} names packages from a URL, a path or a VCS \u2014 they were not vetted; allow it only if you trust this script`);
      }
      if (read2.packages.length === 0) continue;
      const custom = c.customRegistry ?? void 0;
      extra.push({
        ...base2,
        packages: read2.packages,
        skipped: [],
        uncertain: [NAMED_BY_MANIFEST],
        registries: c.registries,
        ...custom !== void 0 ? { customRegistry: custom } : {},
        fromManifest: read2.file
      });
    }
  }
  if (c.sourced !== void 0 && ran) {
    const line = `dev-guardian: ${said(c.sourced)} was run with source before the script and may have changed the directory or the environment \u2014 not checked.`;
    w.notes.push(line);
    w.withDeny.push(line);
  }
  if (local.size === 0 && maybeLocal.length === 0) return { command: c, extra };
  const here = c.packages.filter((p) => local.has(p.raw));
  const reasons = [];
  for (const word of maybeLocal) {
    if (word === c.runsAsScript) w.notes.push(runsAsFileLine(said(word)));
    else reasons.push(`\`${said(word)}\` may be a local script that pipx runs instead \u2014 not checked`);
  }
  const command = { ...c, packages: c.packages.filter((p) => !local.has(p.raw)), uncertain: [...c.uncertain, ...reasons] };
  if (here.length > 0) extra.unshift({ ...base2, packages: here, skipped: [], uncertain: [], fromLocalScript: true });
  return { command, extra };
}
function overflowScripts(w) {
  const n = w.overflow.size;
  if (n === 0) return;
  w.notes.push(`dev-guardian: ${String(n)} more script file${n === 1 ? "" : "s"} of this command ${n === 1 ? "was" : "were"} not read (only the first ${String(MAX_SCRIPT_FILES)} are) \u2014 their packages were not vetted.`);
  w.asks.push(`this command runs more scripts than the hook reads \u2014 ${String(n)} ${n === 1 ? "was" : "were"} not read (only the first ${String(MAX_SCRIPT_FILES)} are); allow it only if you expected that`);
}
var COULD_NOT_VET = "dev-guardian could not vet ";
var NOT_VERIFIED = " \u2014 not verified.";
function askReason(signals, scripts = []) {
  const verb = (n) => n === 1 ? "1 was" : `${String(n)} were`;
  const reasons = [];
  if (signals.notVetted > 0) {
    reasons.push(
      `this command names more packages than the hook vets \u2014 ${verb(signals.notVetted)} not vetted (only the first ${String(MAX_VETTED_PACKAGES)} are); allow it only if you expected a command this long`
    );
  }
  if (signals.manifestNotVetted > 0) {
    reasons.push(
      `the manifests this command installs name more dependencies than the hook vets \u2014 ${verb(signals.manifestNotVetted)} not vetted (only the first ${String(MAX_MANIFEST_PACKAGES)} are); allow it only if you expected that`
    );
  }
  if (signals.cut) {
    reasons.push("this command is longer than the hook reads \u2014 installs past the first 512 KB were not looked for; allow it only if you expected a command this long");
  }
  reasons.push(...new Set(scripts));
  return reasons.length > 0 ? reasons.join("; ") : void 0;
}
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
  const scriptAsks = [];
  const scriptDenyLines = [];
  const locked = [];
  const isPopular = popularTest(opts);
  const deadlineAt = opts.deadlineAt ?? (opts.startedAt ?? Date.now()) + vetDeadlineMs(env);
  const localCopies = /* @__PURE__ */ new Map();
  const diskNotes = /* @__PURE__ */ new Set();
  const { commands, notVetted, manifestNotVetted, cut, unassessed } = boundedInstalls(
    command,
    shell,
    isPopular,
    (pkg, c) => runsInstalledCopy(pkg, c, opts, localCopies),
    opts.nested,
    cdpath,
    (parsed) => withManifestPackages(parsed, opts, registry, manifestNotes, locked, { asks: scriptAsks, withDeny: scriptDenyLines }, () => Date.now() > deadlineAt),
    () => Date.now() > deadlineAt,
    (c) => withoutDiskEntries(c, opts, () => Date.now() > deadlineAt, diskNotes)
  );
  if (commands.length === 0 && locked.length === 0) {
    const said2 = [...manifestNotes, ...cut ? [CUT_NOTE] : []];
    if (said2.length === 0) return null;
    const question2 = askReason({ notVetted, manifestNotVetted, cut }, scriptAsks);
    return question2 === void 0 ? { context: said2.join("\n") } : { context: said2.join("\n"), ask: question2 };
  }
  const offline = env["GUARDIAN_OFFLINE"] === "1";
  const budgetMs = opts.budgetMs ?? HOOK_BUDGET_MS;
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
          registry: { ...registry, command: registryCommand(c) },
          commandRegistries: c.registries,
          // A manifest's packages are told neither of a fresh version nor of install scripts (`decideManifestOne`):
          // what only those two checks need is not asked of the registry.
          // The names given to an update are told neither of them: an update repeats them at every run.
          ...c.fromManifest !== void 0 || c.fromUpdate === true ? { unreported: MANIFEST_UNREPORTED } : {},
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
  let missingListed = 0;
  const missingCounted = /* @__PURE__ */ new Map();
  const warnOfManifest = (d, file) => {
    if (d.warn === void 0) return;
    if (d.plainMissing === true) {
      if (missingListed >= MAX_MANIFEST_MISSING_LINES) {
        missingCounted.set(file, (missingCounted.get(file) ?? 0) + 1);
        return;
      }
      missingListed += 1;
    }
    warnings.push(d.warn);
  };
  for (const lock of locked) {
    try {
      const covered = lock.covered.filter((pkg) => !warnedCovered.has(`${lock.manifestFile}\0${pkg.name}\0${pkg.range ?? ""}`));
      for (const pkg of covered) warnedCovered.add(`${lock.manifestFile}\0${pkg.name}\0${pkg.range ?? ""}`);
      for (const r of vetTyposquatOnly(covered, {
        ...opts.popularDir !== void 0 ? { popularDir: opts.popularDir } : {},
        ...opts.popular !== void 0 ? { popular: opts.popular } : {}
      })) {
        warnOfManifest(decideManifestOne(r, lock.manifestFile), lock.manifestFile);
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
        warnOfManifest(d2, cmd.fromManifest);
        if (d2.unverified !== void 0) {
          const sofar = unverifiedIn.get(cmd.fromManifest);
          unverifiedIn.set(cmd.fromManifest, { count: (sofar?.count ?? 0) + 1, why: sofar?.why ?? d2.unverified });
        }
        continue;
      }
      if (cmd.fromLocalScript === true || cmd.fromArchiveFile === true) {
        if (r.checks.malicious.status === "fail") {
          denies.push(cmd.fromLocalScript === true ? localScriptDeny(r) : archiveFileDeny(r));
          malicious = true;
        }
        continue;
      }
      const d = cmd.fromUpdate === true ? decideUpdateOne(r) : decideOne(r, cmd.uncertain);
      if (d.deny !== void 0) denies.push(d.deny);
      if (d.malicious === true) malicious = true;
      else if (d.deny !== void 0) missingIn = missingIn ?? cmd;
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
        (malicious ? "If this package is genuinely intended, ask the user to install it themselves." : escapeHatch(missingIn?.manager ?? "", shell, missingIn?.sourceFlag))
      );
    }
    if (manifestDenies.length > 0) {
      parts.push(
        `${manifestDenies.join(" ")} Installing it or removing the dependency is the user's decision: tell them which file names it, and install nothing from that manifest until they have decided.`
      );
    }
    const counts = [.../* @__PURE__ */ new Set([...lockCounts, ...scriptDenyLines])];
    const registryLines = malicious ? [] : [...new Set(manifestNotes.filter(isDefaultRegistryLine))];
    const tail = [...counts, ...registryLines];
    return { deny: `dev-guardian blocked this install: ${parts.join(" ")}${tail.length > 0 ? `
${tail.join("\n")}` : ""}` };
  }
  const lines = [];
  if (warnings.length > 0) {
    lines.push("\u26A0\uFE0F dev-guardian package vetting \u2014 review before relying on these:");
    for (const w of warnings) lines.push(`  \u2022 ${w}`);
  }
  if (missingCounted.size > 0) lines.push(missingCountLine(missingCounted));
  if (unverified.length > 0) lines.push(`${COULD_NOT_VET}${unverified.join(", ")}${NOT_VERIFIED}`);
  for (const [file, { count, why }] of unverifiedIn) {
    lines.push(`${COULD_NOT_VET}${plural(count)} of ${file} (${why})${NOT_VERIFIED}`);
  }
  lines.push(.../* @__PURE__ */ new Set([...lockLines, ...manifestNotes, ...diskNotes]));
  if (unassessed > 0) {
    lines.push(
      `dev-guardian: ${unassessed} launcher commands of this line were not checked for a copy in the project (vetting time budget exhausted) \u2014 their packages were vetted as if fetched.`
    );
  }
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
  if (lines.length === 0) return null;
  const question = askReason({ notVetted, manifestNotVetted, cut }, scriptAsks);
  return question === void 0 ? { context: lines.join("\n") } : { context: lines.join("\n"), ask: question };
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
function escapeHatch(manager, shell = "bash", sourceFlag) {
  const prefix = shell === "powershell" ? "run `$env:GUARDIAN_PKG_VET = '0'` before it, in the same command" : "prefix the command with `GUARDIAN_PKG_VET=0`";
  const flag = sourceFlag ?? REGISTRY_FLAG[manager];
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
    return {
      warn: `${file}: '${label2(r)}': ${NOT_FOUND}${didYouMean} (${why})`,
      ...r.similar_to === void 0 ? { plainMissing: true } : {}
    };
  }
  const out = {};
  const typo = r.checks.typosquat;
  if (typo.status === "warn" && typo.detail !== void 0) out.warn = `${file}: ${label2(r)}: ${typo.detail}`;
  const unknown2 = [r.checks.exists, r.checks.malicious].find((c) => c.status === "unknown" && c.detail !== void 0);
  if (unknown2 !== void 0) out.unverified = unknown2.detail ?? "";
  return out;
}
function maliciousFileDeny(lead, r) {
  const why = Object.values(r.checks).filter((c) => c.status === "fail" && c.detail !== void 0).map((c) => c.detail ?? "").join("; ");
  return `${lead} a package of that name is malicious: '${label2(r)}': ${sentence(why)}`;
}
var localScriptDeny = (r) => maliciousFileDeny(`pipx runs the local file '${r.name}' here, and`, r);
var archiveFileDeny = (r) => maliciousFileDeny(`pipx reads '${r.name}' as a file here, not as a package, and`, r);
function decideUpdateOne(r) {
  if (r.checks.malicious.status === "fail") {
    const why = Object.values(r.checks).filter((c) => c.status === "fail" && c.detail !== void 0).map((c) => c.detail ?? "").join("; ");
    return { deny: `'${label2(r)}': ${sentence(why)}`, malicious: true };
  }
  if (r.not_on_public_registry === true) {
    const didYouMean = r.similar_to !== void 0 ? ` Did you mean '${r.similar_to}'?` : "";
    return { warn: `'${label2(r)}': ${NOT_FOUND}${didYouMean} (${NAMED_TO_UPDATE})` };
  }
  const out = {};
  const typo = r.checks.typosquat;
  if (typo.status === "warn" && typo.detail !== void 0) out.warn = `${label2(r)}: ${typo.detail}`;
  const unknown2 = [r.checks.exists, r.checks.malicious].find((c) => c.status === "unknown" && c.detail !== void 0);
  if (unknown2 !== void 0) out.unverified = `${label2(r)} (${unknown2.detail ?? ""})`;
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
