---
description: Infrastructure scan — containers (Dockerfile, image, compose) and IaC (Terraform, Kubernetes, CloudFormation, Helm). Foco infra. Foco infra.
argument-hint: "[docker | iac] [Dockerfile path, image reference or IaC path]"
---

Scan the infrastructure the project ships. The first word picks `docker` or `iac`; with neither, run `detect_stack { project_path: "<project>" }` and do both where they apply — `docker` when `has_docker` or `has_compose` is true, `iac` when `has_iac` is (`has_terraform`, `has_kubernetes`, `has_ansible`) or when CloudFormation templates or Helm charts are present, which `detect_stack` does not flag but `scan_iac` does scan.

Arguments: $ARGUMENTS

## `docker` — containers

1. `scan_containers { project_path: "<project>", dockerfile_path: "<Dockerfile>" }` for the Dockerfile, and `scan_containers { project_path: "<project>", image: "<image reference>" }` when an image is named or built. With neither argument it scans `./Dockerfile`. One call covers:
   - Trivy — a Dockerfile config check, or an image's vulnerable OS and application packages, embedded secrets and misconfigurations;
   - hadolint on the Dockerfile, when it is installed (`install_toolchain { tools: ["hadolint"], dry_run: true }` shows how to add it);
   - a compose file at the project root: `privileged: true`, host networking, a mounted `docker.sock`, and unpinned or `:latest` image tags.
2. Checklist the tool does not automate — say so when you report them:
   - the base image: pinned by digest or at least an exact tag, from an official or trusted registry, recently rebuilt;
   - the container runs as a non-root `USER`;
   - compose: exposed ports, host bind mounts other than `docker.sock`, missing `read_only: true`.
3. Group the report as 🔴 image-level critical / 🟡 Dockerfile and compose smells / 🟢 nice-to-have.

## `iac` — infrastructure as code

1. `scan_iac { project_path: "<project>" }` — Trivy config over the whole project: Terraform, Kubernetes manifests, CloudFormation templates and Helm charts.
2. Checklist the tool does not automate — say so when you report them:
   - Terraform: no committed `terraform.tfstate` (`git ls-files "*.tfstate"`), no variable defaults that look like secrets, no `0.0.0.0/0` ingress, no public buckets, no IAM wildcards;
   - Kubernetes: a `securityContext`, no `privileged: true` or `hostNetwork: true`, resource limits set, no `:latest` tags;
   - Ansible — `scan_iac` does not cover it: `become: yes` overuse, plaintext passwords in vars, `no_log: false` on tasks that handle credentials.
3. Per file, the finding and the concrete fix (the IaC equivalent of a code snippet). When the project mixes IaC types, group by tool so the work can go to the right team.

Respond in the user's language (EN/PT/ES).
