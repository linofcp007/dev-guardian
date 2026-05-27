---
description: Verify what just entered the project after a deps install. Pós-install. Tras un install.
---

Run after the user has just executed `npm install`, `pip install`, `composer require`, `cargo add`, `gem install`, `dotnet add package`, etc. The goal is to vet what just landed before it gets baked in.

The skill should:

1. Diff the lockfile (`package-lock.json`, `poetry.lock`, `composer.lock`, `Cargo.lock`, `Gemfile.lock`, `packages.lock.json`) against `HEAD` to identify newly-added packages and transitive deps.
2. For each new package, run `scan_deps` against just those packages (Trivy / npm-audit / pip-audit / etc.).
3. Check each new dep against the typosquatting / abandoned / suspicious-author heuristics in `guardian-deps`.
4. Run `license_compatibility` on the new licenses — flag copyleft or unfamiliar OSI licenses.
5. Report 🔴 if anything serious was just introduced, otherwise 🟢.

If lockfile hasn't changed (no real install happened), say so and exit cleanly.

Package or area hint (optional): $ARGUMENTS
