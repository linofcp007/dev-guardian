---
description: Infrastructure-as-Code scan (Terraform, Kubernetes, Ansible, CloudFormation). Foco IaC. Foco IaC.
---

Run the **IaC-focused** Guardian flow. Use when the project has `*.tf`, `*.tf.json`, `k8s/`, `kubernetes/`, `helm/`, `ansible/`, or CloudFormation YAML.

The skill should:

1. `scan_iac` — Trivy config scan across all detected IaC artifacts.
2. Terraform-specific: state file hygiene (no committed `terraform.tfstate`), variable defaults that smell like secrets, `0.0.0.0/0` ingress rules, public S3 / GCS / Azure blob, IAM wildcards.
3. Kubernetes-specific: missing `securityContext`, `privileged: true`, `hostNetwork: true`, missing resource limits, `latest` image tags.
4. Ansible-specific: `become: yes` overuse, plaintext passwords in vars, `no_log: false` on credential tasks.
5. Render a per-file findings list with explicit fixes (the IaC equivalent of a code snippet).

When the project mixes IaC types, group findings by tooling so the user can route work to the right teams.

Path filter or specific stack hint (optional): $ARGUMENTS
