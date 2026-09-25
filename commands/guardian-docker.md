---
description: Docker / container focused scan (image, Dockerfile, secrets in layers). Foco Docker. Foco Docker.
---

Run the **Docker / container-focused** Guardian flow. Use when the user has `Dockerfile`, `docker-compose.yml`, or refers to an OCI image.

The skill should:

1. `scan_containers` (Trivy) — scan the Dockerfile / built image for vulnerable OS packages, vulnerable
   application deps, embedded secrets, and misconfigurations (`--scanners vuln,secret,misconfig`, not
   `vuln` alone). This single call also covers steps 3 and part of 5 below now: hadolint runs on the
   Dockerfile when it is installed, and a compose file at the project root is checked for
   `privileged: true`, `network_mode: host`, a mounted `docker.sock`, and an unpinned/`:latest` image
   tag — no separate orchestration needed for those.
2. Verify the base image — is the tag pinned (not `:latest`)? Is it from an official / trusted registry? When was it last updated?
3. Hadolint — Dockerfile linting (anti-patterns, security best practices). Covered by step 1.
4. `scan_secrets` against each layer's filesystem (Trivy + gitleaks on extracted layers when possible).
5. Compose check — `docker-compose.yml` exposed ports, mounted host paths, `privileged: true`, missing
   `read_only`. Step 1 covers privileged/host-network/docker.sock/`:latest`; exposed ports, other mounted
   host paths and missing `read_only` are not (yet) checked automatically — call these out manually if
   relevant.

Output structured by 🔴 image-level critical, 🟡 Dockerfile smells, 🟢 nice-to-have.

Dockerfile path or image reference (optional, e.g. `Dockerfile`, `myorg/myimage:1.0`): $ARGUMENTS
