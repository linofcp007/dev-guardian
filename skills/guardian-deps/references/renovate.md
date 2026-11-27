# Renovate — installing it, or moving from Dependabot

Read this before installing Renovate with `init_project`, or before answering which profile to pick or how to
leave Dependabot.

- `init_project { project_path: "<project>", apply: false }` shows the files it would install, `renovate.json`
  among them; `apply: true` installs them (never over an existing file — one identical to the shipped copy is
  adopted in the manifest).
  - profile `standard`: automerge of dev-dependency patches and of safe-tooling minors (`@types`, eslint,
    prettier), always with a **3-day** minimum release age; majors need a review;
  - profile `paranoid` (`profile: "paranoid"`): **no** automerge and a **7-day** minimum release age.
- Renovate runs as a GitHub App: `github.com/apps/renovate` → Install → pick the repository → it opens the
  "Configure Renovate" PR. Self-hosted: `renovate-runner` in CI.
- Is there a `.github/dependabot.yml` already? Ask whether to migrate (comment the file out, never delete it) or
  to run both side by side; the old Dependabot PRs are closed by hand.
