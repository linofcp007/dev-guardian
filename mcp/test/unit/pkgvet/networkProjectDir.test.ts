/**
 * install-vet-network-project-dir-probe: the paths install-vet asks the disk for.
 *
 * `privateRegistry.ts`, `configFile.ts` and `hookDecision.ts` import `node:fs` directly, so `opts.diskImpl` sees none of
 * their calls. A recording `node:fs` does: a path with the documentation host `198.51.100.7` in it is listed and fails
 * at once with ENOENT, never touching the disk or the network; every other path goes to the real `node:fs`.
 *
 * T-02 is the protection (green before and after the fix): a local project still reads up to its repository root, a
 * local installed copy is still looked for, and a `cd` into a network path still reaches no network path.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const NETWORK_HOST = "198.51.100.7";
// `owners[i]` is the source module (`hookDecision`, `configFile`, `privateRegistry`, `folderSpelling`) that asked for `paths[i]` (from the stack), or '' for any other.
const seen = vi.hoisted(() => ({
  paths: [] as string[],
  owners: [] as string[],
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  type P = import("node:fs").PathLike;
  type Any = (p: P, ...rest: unknown[]) => unknown;
  const ownerOf = (): string =>
    /(hookDecision|configFile|privateRegistry|folderSpelling)\.ts/.exec(
      new Error("stack").stack ?? "",
    )?.[1] ?? "";
  const record = (p: P): void => {
    const text = String(p);
    seen.paths.push(text);
    seen.owners.push(ownerOf());
    if (text.includes("198.51.100.7")) {
      throw Object.assign(
        new Error(`ENOENT: no such file or directory, '${text}'`),
        { code: "ENOENT", path: text },
      );
    }
  };
  // The first argument is the path in every wrapped call; the rest goes to the real function untouched.
  const wrap =
    (fn: Any) =>
    (p: P, ...rest: unknown[]): unknown => {
      record(p);
      return fn(p, ...rest);
    };
  const lstatSync = wrap(actual.lstatSync as Any) as typeof actual.lstatSync;
  const statSync = wrap(actual.statSync as Any) as typeof actual.statSync;
  const existsSync = (p: P): boolean => {
    seen.paths.push(String(p));
    seen.owners.push(ownerOf());
    return String(p).includes("198.51.100.7") ? false : actual.existsSync(p);
  };
  const native = wrap(
    actual.realpathSync.native as Any,
  ) as typeof actual.realpathSync.native;
  const realpathSync = Object.assign(wrap(actual.realpathSync as Any), {
    native,
  }) as typeof actual.realpathSync;
  const readdirSync = wrap(
    actual.readdirSync as Any,
  ) as typeof actual.readdirSync;
  const openSync = wrap(actual.openSync as Any) as typeof actual.openSync;
  const readFileSync = ((p: P | number, ...rest: unknown[]) => {
    if (typeof p !== "number") record(p);
    return (
      actual.readFileSync as (p: P | number, ...rest: unknown[]) => unknown
    )(p, ...rest);
  }) as typeof actual.readFileSync;
  const wrapped = {
    lstatSync,
    statSync,
    existsSync,
    realpathSync,
    readdirSync,
    openSync,
    readFileSync,
  };
  return { ...actual, ...wrapped, default: { ...actual, ...wrapped } };
});

import {
  decideInstallCommand,
  type HookVetOptions,
} from "../../../src/pkgvet/hookDecision.js";
import { hangBound } from "../../helpers/timing.js";

const NOW = Date.parse("2026-09-25T12:00:00Z");
const OSV = "https://api.osv.dev/v1/querybatch";
const EVIL = "dgprobe-zzq7731-evil";
const TOOL = "dgprobe-zzq7731-tool";
const NET = "\\\\198.51.100.7\\share\\proj";
const REASON =
  "(not denied: it runs in a folder on a network path, where an installed copy was not looked for)";
const NOTREAD =
  "dev-guardian: the project's registry settings were not read (on a network path) — if they set the default registry, what it serves was not vetted.";

/**
 * The registries and OSV, mocked: EVIL and TOOL exist on npm and PyPI, EVIL has a MAL advisory, every other name
 * (`dgprobe-zzq7731-missing` included) is a 404. Any other URL throws.
 */
function registries(): {
  fetchImpl: typeof fetch;
  calls: string[];
  pathsBeforeFirstRequest: () => number;
} {
  const calls: string[] = [];
  let firstRequestAt: number | null = null;
  const known = [EVIL, TOOL];
  const json = (body: unknown, status = 200): Response =>
    new Response(JSON.stringify(body), { status });
  const fetchImpl = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    firstRequestAt ??= seen.paths.length;
    if (url === OSV) {
      const body = JSON.parse(String(init?.body)) as {
        queries: { package?: { name?: string } }[];
      };
      return json({
        results: body.queries.map((q) =>
          q.package?.name === EVIL ? { vulns: [{ id: "MAL-2026-77" }] } : {},
        ),
      });
    }
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    if (pypi !== null) {
      return known.includes(decodeURIComponent(pypi[1] ?? ""))
        ? json({
            info: { version: "1.0.0" },
            releases: {
              "1.0.0": [{ upload_time_iso_8601: "2020-01-01T00:00:00Z" }],
            },
          })
        : json({}, 404);
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)$/.exec(url);
    if (npm !== null) {
      return known.includes(decodeURIComponent(npm[1] ?? ""))
        ? json({
            "dist-tags": { latest: "1.0.0" },
            modified: "2020-01-01T00:00:00.000Z",
            versions: { "1.0.0": {} },
          })
        : json({}, 404);
    }
    throw new Error(`unexpected network call: ${url}`);
  }) as typeof fetch;
  return {
    fetchImpl,
    calls,
    pathsBeforeFirstRequest: () => firstRequestAt ?? seen.paths.length,
  };
}

const made: string[] = [];
let home: string;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

function put(root: string, rel: string, text: string): void {
  const file = join(root, rel);
  mkdirSync(join(file, ".."), { recursive: true });
  writeFileSync(file, text);
}

beforeEach(() => {
  seen.paths.length = 0;
  seen.owners.length = 0;
  home = tempDir("dg-netdir-home-");
});
afterEach(() => {
  for (const dir of made.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

function opts(
  fetchImpl: typeof fetch,
  cwd: string,
  extra: Partial<HookVetOptions> = {},
): HookVetOptions {
  return {
    cwd,
    projectDir: cwd,
    homeDir: home,
    env: { GUARDIAN_OFFLINE: "0" },
    etcDir: join(home, "no-etc"),
    nodeExecPath: join(home, "no-node", "bin", "node"),
    systemLibraryDir: join(home, "no-library"),
    fetchImpl,
    now: NOW,
    popular: {},
    ...extra,
  };
}

/** Every path of the network host the recording saw (from index `upTo` back), as `module path`: the diff names the asker. */
const networkPaths = (upTo = seen.paths.length): string[] =>
  seen.paths
    .slice(0, upTo)
    .flatMap((p, i) =>
      p.includes(NETWORK_HOST) ? [`${seen.owners[i] || "?"} ${p}`] : [],
    );
const norm = (p: string): string => p.replaceAll("\\", "/");
/** True when `owner` asked the disk for exactly `path` (compared with forward slashes). */
const askedBy = (owner: string, path: string): boolean =>
  seen.paths.some((p, i) => seen.owners[i] === owner && norm(p) === norm(path));

describe("install-vet-network-project-dir-probe", () => {
  it("T-02 (a) a local repository: the manifest is read up to the repository root, and the mock sees privateRegistry.ts", async () => {
    const root = tempDir("dg-netdir-repo-");
    mkdirSync(join(root, ".git"));
    mkdirSync(join(root, "app"));
    put(
      root,
      "package.json",
      JSON.stringify({ name: "proj", dependencies: { [EVIL]: "1.0.0" } }),
    );
    const f = registries();
    const d = await decideInstallCommand(
      "npm install",
      opts(f.fetchImpl, join(root, "app")),
    );
    // Today's refusal names the repository root's manifest: the climb from `app` reaches the root.
    expect(d?.deny).toBe(
      "dev-guardian blocked this install: ../package.json names 'dgprobe-zzq7731-evil@1.0.0': OSV malicious-package advisory for 1.0.0: MAL-2026-77. Installing it or removing the dependency is the user's decision: tell them which file names it, and install nothing from that manifest until they have decided.",
    );
    // The recording sees privateRegistry.ts's `.git` lstat, so a fix that stopped it would turn this red.
    expect(
      askedBy("privateRegistry", join(root, "app", ".git")) ||
        askedBy("privateRegistry", join(root, ".git")),
    ).toBe(true);
  });

  it("T-02 (b) an npx in a local folder with the installed copy: no request for the name, and the mock sees hookDecision.ts and configFile.ts", async () => {
    const dir = tempDir("dg-netdir-copy-");
    put(dir, "package.json", JSON.stringify({ name: "proj" }));
    put(
      dir,
      `node_modules/${TOOL}/package.json`,
      JSON.stringify({ name: TOOL, version: "1.0.0" }),
    );
    put(dir, `node_modules/.bin/${TOOL}`, "#!/usr/bin/env node\n");
    const f = registries();
    const d = await decideInstallCommand(`npx ${TOOL}`, opts(f.fetchImpl, dir));
    // Today's decision: none (null), and no request for the name: the installed copy is found on disk.
    expect(d).toBeNull();
    expect(f.calls.filter((u) => u.includes(TOOL))).toEqual([]);
    // The recording sees the two modules that look for the installed copy.
    expect(askedBy("hookDecision", join(dir, "package.json"))).toBe(true);
    expect(
      askedBy("configFile", join(dir, "node_modules", TOOL, "package.json")),
    ).toBe(true);
  });

  it.skipIf(process.platform !== "win32")(
    "T-02 (c) a cd into a network path with local cwd and projectDir (Windows; skipped otherwise): today's decision, no network path",
    async () => {
      const dir = tempDir("dg-netdir-local-");
      const f = registries();
      const d = await decideInstallCommand(
        `cd '${NET}' && npm install ${TOOL}`,
        opts(f.fetchImpl, dir),
      );
      // Today's decision: a warning (no deny, no ask) that the manifest was not read; the name itself is vetted and clean.
      expect(d).toEqual({
        context:
          "dev-guardian: package.json was not read (where the command runs could not be determined) — its packages were not vetted.",
      });
      expect(f.calls).toContain(`https://registry.npmjs.org/${TOOL}`);
      expect(seen.paths.filter((p) => p.includes(NETWORK_HOST))).toEqual([]);
    },
  );

  const win = it.skipIf(process.platform !== "win32");
  const WIN = " (Windows; skipped otherwise)";
  const PY = 'python -c "print(1)"';
  const EVIL_DENY =
    "dev-guardian blocked this install: 'dgprobe-zzq7731-evil@1.0.0': OSV malicious-package advisory for 1.0.0: MAL-2026-77.";

  win(
    `T-01 (a) pip install of a malicious name, project dir on a network path: the deny, no network path asked${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand(
        `pip install ${EVIL}`,
        opts(f.fetchImpl, tempDir("dg-netdir-local-"), { projectDir: NET }),
      );
      expect(networkPaths()).toEqual([]);
      expect(d?.deny ?? String(d?.context)).toContain(EVIL_DENY);
    },
  );

  win(
    `T-01 (b) uv run --with-requirements, cwd and project dir on a network path: the r.txt note, no network path asked${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand(
        `uv run --with-requirements r.txt ${PY}`,
        opts(f.fetchImpl, NET),
      );
      expect(networkPaths()).toEqual([]);
      expect(d?.deny).toBeUndefined();
      expect(d?.ask).toBeUndefined();
      expect(d?.context).toContain(
        "dev-guardian: r.txt was not read (on a network path) — its packages were not vetted.",
      );
    },
  );

  win(
    `T-01 (c) npx of a clean name, cwd on a network path, no project dir: the name is asked, NOTREAD, no network path${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand(
        `npx ${TOOL}`,
        opts(f.fetchImpl, NET, { projectDir: undefined }),
      );
      expect(networkPaths()).toEqual([]);
      expect(f.calls).toContain(`https://registry.npmjs.org/${TOOL}`);
      expect(d?.context).toContain(NOTREAD);
    },
  );

  win(
    `T-01 (d) npx of a malicious name, cwd on a network path: the deny, no network path asked${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand(
        `npx ${EVIL}`,
        opts(f.fetchImpl, NET, { projectDir: undefined }),
      );
      expect(networkPaths()).toEqual([]);
      expect(d?.deny ?? String(d?.context)).toContain(
        "OSV malicious-package advisory for 1.0.0: MAL-2026-77",
      );
    },
  );

  win(
    `T-01 (e) npx of a missing name, cwd on a network path: a warning with REASON, not a deny${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand(
        "npx dgprobe-zzq7731-missing",
        opts(f.fetchImpl, NET, { projectDir: undefined }),
      );
      expect(d?.deny).toBeUndefined();
      expect(d?.context).toMatch(
        /dgprobe-zzq7731-missing.*not found on the public registry/s,
      );
      expect(d?.context).toContain(REASON);
    },
  );

  win(
    `T-01 (f) npm install of a clean name, cwd and project dir on a network path: no network path before the first request, NOTREAD${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand(
        `npm install ${TOOL}`,
        opts(f.fetchImpl, NET),
      );
      expect(networkPaths(f.pathsBeforeFirstRequest())).toEqual([]);
      expect(d?.context).toContain(NOTREAD);
    },
  );

  win(
    `T-01 (g) npm install of a missing name, cwd and project dir on a network path: the deny carries NOTREAD${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand("npm install dgprobe-zzq7731-missing", opts(f.fetchImpl, NET));
      expect(d?.deny ?? String(d?.context)).toContain(NOTREAD);
    },
  );

  // Every system: the project directory text is read before any `resolve`, and `isNetworkPath` catches `//` anywhere.
  it("T-01 (a) Linux variant: pip install of a malicious name, project dir //198.51.100.7/share/proj: the deny, no network path asked", async () => {
    const f = registries();
    const d = await decideInstallCommand(
      `pip install ${EVIL}`,
      opts(f.fetchImpl, tempDir("dg-netdir-local-"), { projectDir: "//198.51.100.7/share/proj" }),
    );
    expect(networkPaths()).toEqual([]);
    expect(d?.deny ?? String(d?.context)).toContain(EVIL_DENY);
  });

  win(
    `T-02 (d) npx of a missing name with a version, cwd on a network path: today's deny, without REASON${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand("npx dgprobe-zzq7731-missing@1.0.0", opts(f.fetchImpl, NET, { projectDir: undefined }));
      // EC-4: a version never looked for the installed copy, so a 404 nothing explains stays refused.
      expect(d?.deny ?? String(d?.context)).toContain("dgprobe-zzq7731-missing");
      expect(d?.deny).toBeDefined();
      expect(`${d?.deny ?? ""}${d?.context ?? ""}`).not.toContain(REASON);
    },
  );

  // The real disk: `203.0.113.N` is a documentation address that does not answer, so the mock lets it through. A fresh N
  // per run (172 and 204 are the M-0's) because Windows remembers a host that did not answer. 90 s, so today's ~42 s is an
  // AssertionError and not a timeout.
  win(
    `T-03 pip install of a malicious name with the project dir on a silent share: the deny, within the hang bound${WIN}`,
    async () => {
      const hosts = Array.from({ length: 254 }, (_, i) => i + 1).filter(
        (n) => n !== 172 && n !== 204,
      );
      const host = `203.0.113.${hosts[Math.floor(Math.random() * hosts.length)] ?? 1}`;
      const f = registries();
      const start = Date.now();
      const d = await decideInstallCommand(
        `pip install ${EVIL}`,
        opts(f.fetchImpl, tempDir("dg-netdir-local-"), {
          projectDir: `\\\\${host}\\share\\proj`,
        }),
      );
      const elapsed = Date.now() - start;
      expect(d?.deny ?? String(d?.context)).toContain(EVIL_DENY);
      expect(elapsed).toBeLessThan(hangBound(2000));
    },
    90_000,
  );
});

import { symlinkSync } from "node:fs";

describe("install-vet-uv-run-project-index", () => {
  const MISSING = "dgprobe-zzq7731-missing";
  const win = it.skipIf(process.platform !== "win32");
  const WIN = " (Windows; skipped otherwise)";
  /** Whether this account may make a folder link to a network path: without the privilege the link test is skipped, with its label saying so. */
  const CAN_LINK = ((): boolean => {
    if (process.platform !== "win32") return false;
    const probe = mkdtempSync(join(tmpdir(), "dg-uvproj-probe-"));
    try {
      symlinkSync(NET, join(probe, "l"), "dir");
      return true;
    } catch {
      return false;
    } finally {
      rmSync(probe, { recursive: true, force: true });
    }
  })();
  const ifLink = it.skipIf(process.platform !== "win32" || !CAN_LINK);

  /** The text of the answer, and what a name missing from the PyPI says about why it is not refused. */
  const expectNoProjectFile = (d: Awaited<ReturnType<typeof decideInstallCommand>>): void => {
    const text = `${d?.deny ?? ""}\n${d?.context ?? ""}`;
    expect(text).not.toContain("sets the package index");
    expect(text).not.toContain("a custom registry is configured (");
    expect(d?.context ?? "(no context)").toContain(`'${MISSING}': not found on the public registry`);
  };

  win(
    `T-08 (a) \`uv run --project '<a network path>' --with <a missing name>\`, the folder of the command local: the share is asked of the disk for nothing, no line, no project file as the reason${WIN}`,
    async () => {
      const f = registries();
      const d = await decideInstallCommand(
        `uv run --project '${NET}' --with ${MISSING} python -c "print(1)"`,
        opts(f.fetchImpl, tempDir("dg-uvproj-cwd-")),
      );
      expect(networkPaths()).toEqual([]);
      expectNoProjectFile(d);
    },
    90_000,
  );

  ifLink(
    `T-08 (b) \`uv run --project netproj --with <a missing name>\`, netproj a local link to a network path: nothing below the link is asked of the disk, no line, no project file as the reason${WIN}`,
    async () => {
      const dir = tempDir("dg-uvproj-link-");
      const link = join(dir, "netproj");
      symlinkSync(NET, link, "dir");
      const f = registries();
      const d = await decideInstallCommand(
        `uv run --project netproj --with ${MISSING} python -c "print(1)"`,
        opts(f.fetchImpl, dir),
      );
      const below = seen.paths.filter((p) => norm(p).startsWith(`${norm(link)}/`));
      expect(below).toEqual([]);
      expect(networkPaths()).toEqual([]);
      expectNoProjectFile(d);
    },
    90_000,
  );
});
