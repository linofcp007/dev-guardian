---
description: Vet an AI skill / MCP server / agent before installing it (SAFE→DO NOT INSTALL). Audita uma skill antes de instalar. Audita una skill antes de instalar.
---

Run the **AI-agent supply-chain** check: vet a third-party **skill / MCP server /
agent** BEFORE installing it. This answers *"is this safe to install?"* — not
*"is my code safe to ship?"* (that's `/guardian-scan`).

Use the **`scan_skill` MCP tool**:

1. **Resolve the target.** The argument can be a local **directory**, a single
   **file**, a **.zip**, or a **git / HTTP(S) URL**. If no argument is given,
   audit the current directory.
2. **Call `scan_skill`** with that `target` (let `check_deps` default to true so
   OSV.dev CVE lookups run; it degrades gracefully offline).
3. **Lead with the verdict** — the recommendation (SAFE / REVIEW / CAUTION /
   DO_NOT_INSTALL) and the 0-100 risk score come first.
4. **Then the evidence**, grouped by severity, citing `file_path:line`. Correlate
   signals across the 16 threat categories (prompt injection, data exfiltration,
   privilege escalation, supply chain, excessive agency, output handling, system
   prompt leakage, memory poisoning, tool misuse, rogue agent, trigger abuse,
   dangerous code, taint, signatures, MCP least-privilege, MCP tool poisoning)
   into a clear story. Don't dump raw JSON.
5. **Be honest about coverage** — note if OSV was offline (deps = "unknown, not
   clean"), if the scan was truncated, or if only one file was seen.

This is heuristic **pre-install triage**, not proof. Never auto-install anything
flagged CAUTION or worse without the user explicitly accepting the risk. Load the
`guardian-scanskill` skill for the full module logic.

Target (path / URL / .zip — leave empty to scan the current directory): $ARGUMENTS
