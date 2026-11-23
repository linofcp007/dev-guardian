# Lockfile fixtures: where each one comes from

Real lockfiles of public repositories, one per format version the readers of
`mcp/src/pkgvet/lockfile.ts` take (install-vet-lockfile-pins), and the lockfiles bun 1.4.4 wrote in a measurement
(`bun-v2/`, below). The files of public repositories were read through the GitHub API on
2026-11-17 (`gh api repos/<repository>/contents/<path>?ref=<ref>` with `Accept: application/vnd.github.raw`) and
are the files of the readers' prototype (`.specs/install-vet-lockfile-pins/measurements/README.md`).

They are **data**: `mcp/test/unit/pkgvet/lockfile.test.ts` reads them as text and nothing runs them.

| Fixture | Repository | Ref | Path | Format | Cut: entries kept of the original |
|---|---|---|---|---|---|
| `package-lock.v1.json` | mochajs/mocha | v8.0.0 (612fa312) | `package-lock.json` | package-lock v1 | 67 of 2 142 |
| `package-lock.v2.json` | mochajs/mocha | v10.0.0 (023f5482) | `package-lock.json` | package-lock v2 | 33 of 2 150, the same ones in `packages` and in `dependencies` |
| `package-lock.v3.json` | danny-avila/LibreChat | c8c5478c | `package-lock.json` | package-lock v3 | 44 of 3 171 (3 workspace members, 6 links, 35 packages), and the root |
| `pnpm-lock.v5-workspace.yaml` | vitejs/vite | v3.0.0 (b8c625ce) | `pnpm-lock.yaml` | pnpm 5.4, workspace | 33 of 1 105 packages; 7 of the importers |
| `pnpm-lock.v5-single.yaml` | ai/nanoid | 4.0.0 (fd80ce3f) | `pnpm-lock.yaml` | pnpm 5.4, one project | 27 of 388 packages |
| `pnpm-lock.v6-workspace.yaml` | vitejs/vite | v4.4.0 (3b47e34a) | `pnpm-lock.yaml` | pnpm 6.0, workspace | 30 of 1 268 packages; 7 of the importers |
| `pnpm-lock.v6-single.yaml` | ai/nanoid | 5.0.0 (cf151a74) | `pnpm-lock.yaml` | pnpm 6.0, one project | 25 of 442 packages |
| `pnpm-lock.v9.yaml` | FlowiseAI/Flowise | 9291856d | `pnpm-lock.yaml` | pnpm 9.0 | 30 of 4 201 packages, with their 31 snapshots; 2 of the 7 importers |
| `yarn.v1.lock` | ChatGPTNextWeb/NextChat | defdcdb5 | `yarn.lock` | yarn v1 | 30 of 1 145 blocks |
| `yarn.berry.lock` | jestjs/jest | v29.7.0 (4e569916) | `yarn.lock` | Yarn 2+ (`__metadata` version 6) | 36 of 2 089 blocks |
| `bun.v1.lock` | danny-avila/LibreChat | c8c5478c | `bun.lock` | bun.lock 1 | 45 of 3 971 entries; 4 of the 7 workspaces |

## `bun-v2/`: the bun.lock bun 1.4.4 writes

The 24 files of `bun-v2/` are not cut from a repository: each is the whole `bun.lock` that bun 1.4.4 wrote for one
made-up project of a measurement (lockfile-bun-lock-v2), in a Linux container with no network (`--network none`) and a
stand-in registry of made-up packages, on 2026-11-20. Each is named `bun.v2-<case>.lock` after its case: `alias`,
`catalog`, `default-registry-tarball`, `dev-optional-peer`, `file-folder`, `file-outside`, `file-tarball-noslash`,
`file-tarball`, `git-file`, `link`, `linker-isolated`, `lockfile-only-plain`, `migrated-from-package-lock`,
`min-release-age`, `nested`, `overrides`, `patched`, `path-tarball`, `plain`, `scoped`, `trusted`, `url-tarball`,
`workspace`, `workspace-nested`. They all say `"lockfileVersion": 2`.

- **One edit:** the stand-in registry's address, `http://127.0.0.1:4873`, is written `https://packages.example.invalid`
  wherever bun wrote it. Not the public registry's address: on its hosts the reader counts a tarball URL without the
  shape of a registry path as not recognised, and the `url-tarball` case has one. No other character was changed: the
  integrities are the ones bun wrote, and every name is the measurement's own made-up one (`dgprobe-zzq7731-…`).
- The line ends are LF, as bun writes them; the copies the measurement kept on the Windows host had CRLF.
- The measurement, its scripts and the files as they were saved are in the spec's working folder
  (`.specs/_findings-2026-11-20/measurements/registry-files/`, `bunlock-<case>.txt`), which the repository does not
  carry.

## How they were cut

- **Whole entries were removed; no kept entry was edited.** An entry is a key of `packages` or a name of the
  `dependencies` tree at any depth (package-lock), a block of `importers`, `packages` or `snapshots` (pnpm), a block
  (yarn), an entry of `workspaces` or a line of `packages` (bun). Every other section of a file is whole:
  `overrides`, `patchedDependencies`, `settings`, the root `specifiers` and `devDependencies` of a pnpm lockfile of
  one project, `__metadata`.
- Each file is still valid for its format: the cut was checked by reading the result with a complete parser
  (`JSON.parse`; the `yaml` package) and comparing every kept entry with the same entry of the original.
- What was kept on purpose: scoped names, several versions of one name, the aliases, the workspace members and
  links, the `file:` directories, the entries from `registry.npmmirror.com`, `mirrors.huaweicloud.com` and the
  GitHub release tarball of NextChat's `yarn.lock`, the `cdn.sheetjs.com` tarball of LibreChat, the bundled
  dependencies of `fsevents` (`"resolved": false`), a registry name that ends like an archive (`lodash.zip`), and
  the root / importers / workspaces sections the "covered" rule reads. An entry that references a removed one is
  left as it is: the readers do not follow references.
- The cutting was done by a script run once and kept out of the repository; the lists of what it keeps are the
  fixtures themselves.

## Why the files are not named as the managers name them

A file called `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` or `bun.lock` is picked up by name — by dependency
scanners, by a hosting service's dependency graph, by a package manager run in the wrong directory. These carry
old versions with known advisories on purpose, so each has a name no tool looks for; the readers take the format
as an argument, not from the name.

## Provenance is here, never in a fixture

A header comment inside a lockfile would make it something its manager never wrote (and JSON has no comments), so
nothing was added to any of them.
