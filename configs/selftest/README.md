# Selftest canaries

What `dev-guardian selftest` seeds into its temporary project: one small file per core control, each with one
known defect that the control has to report. A control that reads its canary and reports nothing is `silent` -
a scan of that area with 0 findings proves nothing on that machine. See [`docs/selftest.md`](../../docs/selftest.md).

**Every file here is data.** None of it is run, built, installed or imported, by the selftest or by anything
else, and every name ends in `.canary`: no scanner of this repository and no host that indexes it reads one as
code or as a manifest. The folder is in `.guardianignore` as well.

## Layout

- `project/` mirrors the seeded project. Seeding copies each file to the same relative path with `.canary`
  dropped: `project/bugfix-py/canary.py.canary` becomes `<temporary directory>/project/bugfix-py/canary.py`.
- `probe.yml.canary` is the selftest's own Semgrep rule. It is copied beside the seeded project, outside the
  scanned tree, and matches the marker `dev-guardian-selftest-canary` that every Semgrep canary carries in a
  comment. The probe run says which canaries Semgrep can read on that path; a pack that does not report a
  canary the probe read is `silent`, one the probe never read is `unverified`.

## The canaries

| Control | Seeded as | What has to be reported |
| --- | --- | --- |
| `semgrep:<pack>`, one per file of `configs/semgrep/` | `<pack>/canary.<ext>` (the mobile and routes packs: see below) | the rule of that pack pinned in `mcp/src/selftest/controls.ts` |
| `gitleaks`, `hooks:secret-warning` | `secrets/app.properties` | any secret in that file |
| `trivy:deps` | `deps/package-lock.json` | any vulnerability of `minimist` in that file |
| `trivy:iac` | `iac/Dockerfile.selftest` | any failed check in that file |

- The mobile pack's rule has a `paths:` filter, so its canary is seeded as
  `mobile/res/xml/network_security_config.xml`; the routes pack's is a one-route Express file, `routes/server.js`.
- `secrets/app.properties.canary` is a template: `@@SELFTEST_TOKEN@@` is replaced at run time by a synthetic
  value in the format of an AWS access key id, put together from two halves in `mcp/src/selftest/canaries.ts`.
  The whole string is in no file of the repository and in no bundle (`mcp/test/unit/selftest/canaries.test.ts`),
  and it is no key anyone was issued.
- The Dockerfile is stored as `Dockerfile.selftest.canary`, not `Dockerfile.canary`: Trivy reads
  `Dockerfile.<anything>` as a Dockerfile, and it would have been a finding of this repository.
- The lockfile has no `resolved` or `integrity` field and no file here holds a URL.

## Changing one

Each canary was chosen by measurement with the pinned scanners (Semgrep 1.182.0, gitleaks 8.30.1, Trivy 0.74.0):
its pack alone, over the whole seeded tree, reports the pinned rule on it, and the probe rule reads it.

- A new rule pack in `configs/semgrep/` needs a canary here and an entry in `PACK_CANARIES`
  (`mcp/src/selftest/controls.ts`); `mcp/test/unit/selftest/controls.test.ts` fails, naming the pack, until it has both.
- Keep a canary minimal, valid in its language and ASCII only, with the marker once, in a comment.
- Prefer a plain pattern rule that is unlikely to be renamed. The dependency and IaC canaries accept any finding
  on their file on purpose: an advisory id or a check id is the scanner's to rename.
- After a change, run `node cli/dev-guardian.mjs selftest` with the three scanners installed: every control `detected`.
