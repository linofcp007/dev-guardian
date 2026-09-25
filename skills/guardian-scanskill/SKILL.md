---
name: guardian-scanskill
description: Vet a third-party AI skill, MCP server, plugin or agent BEFORE installing it, with the scan_skill MCP tool — prompt injection, data exfiltration, privilege escalation, excessive agency, MCP tool poisoning, dangerous code, OSV CVEs — rolled into a 0-100 risk score and a SAFE → DO NOT INSTALL verdict. EN triggers — "is this skill safe?", "scan this skill", "audit this MCP server", "should I install this plugin?", "vet this agent", "is this plugin malicious?". PT — "esta skill é segura?", "scaneia esta skill", "audita este MCP", "devo instalar este plugin?", "este plugin é malicioso?", "verifica esta skill antes de instalar". ES — "¿esta skill es segura?", "escanea esta skill", "audita este MCP", "¿debo instalar este plugin?", "¿este plugin es malicioso?", "verifica esta skill antes de instalar". Respond in the user's language.
---

# Guardian Skill — vet AI skills / MCP servers / agents before install

Most of dev-guardian asks *"is the code I'm shipping safe?"*. This module asks the
**supply-chain** question for the agent ecosystem: **"is this third-party skill /
MCP server / agent safe to INSTALL?"** — before it ever runs in your environment.

A skill is just text + scripts the model reads and runs with your privileges. A
malicious one can carry prompt injection, exfiltrate your secrets, poison your
memory, or hide instructions inside an MCP tool description. This module finds
those before you trust them.

## Engine

This module is backed by the **`scan_skill` MCP tool** — call it directly. It
does the heavy lifting (file ingestion + analysis + scoring); you interpret and
present.

```text
scan_skill(target?, check_deps?, write_reports?, severity_min?, fail_on?)
```

- **`target`** — a local **directory**, a single **file**, a **.zip**, or a
  **git / HTTP(S) URL**. If omitted, it audits the current project directory
  (handy for "is the skill I'm standing in clean?").
- **`check_deps`** (default true) — query **OSV.dev** for known CVEs in any
  declared dependencies. Degrades gracefully offline (reports "unknown", never
  "clean").
- **`write_reports`** (default true) — writes `report.sarif` + `report.json`
  under `.guardian/reports/` for CI / IDE.
- **`fail_on`** — `REVIEW` / `CAUTION` / `DO_NOT_INSTALL`; sets the `passed`
  flag so you can gate an install.

## What it detects — 16 threat categories

| Category | What it catches |
| --- | --- |
| `prompt_injection` | Instructions that override the host / ignore prior rules / hide actions from the user |
| `data_exfiltration` | Env / secrets / SSH keys / browser data sent to a network destination |
| `privilege_escalation` | sudo, chmod 777, writing system paths, disabling AV/SIP/firewall |
| `supply_chain` | curl\|bash, fetch-and-run, unpinned/URL installs, lifecycle hooks |
| `excessive_agency` | Unattended `rm -rf`, force-push, DROP/TRUNCATE, unbounded loops, self-modify |
| `output_handling` | Untrusted output → innerHTML / document.write / eval |
| `system_prompt_leakage` | "Reveal/repeat your system prompt / instructions" |
| `memory_poisoning` | Writing durable attacker content into memory / rules / CLAUDE.md |
| `tool_misuse` | A "read-only" helper reaching for shell / spawn / network |
| `rogue_agent` | Time-bombs, "when nobody's watching", **hidden/invisible Unicode**, miners, reverse shells |
| `trigger_abuse` | "Always use this skill", "for any request" — coercive over-broad activation |
| `dangerous_code` | eval/exec/Function, shell=True, unsafe deserialise, decode-then-exec |
| `taint` | A file that **reads a secret AND has a network/exec sink** (possible exfil flow) |
| `yara` | Signature matches — encoded blobs, known C2/exfil hosts, obfuscation |
| `mcp_least_privilege` | An MCP manifest granting `*` / `all` scopes it doesn't need |
| `mcp_tool_poisoning` | Hidden directives inside MCP tool names / descriptions |

## Risk score & verdict

The tool returns a **0-100 risk score** (severity-weighted; findings in
**executable** files weigh 1.3×) and one of four recommendations:

- **SAFE** (0-20) — no significant signals.
- **REVIEW** (21-35) — minor signals, skim before installing.
- **CAUTION** (36-50) — multiple signals; trusted author + manual review only.
- **DO_NOT_INSTALL** (51-100) — high-risk; don't install unless every finding
  has a clear, benign explanation.

## Flow

1. **Get the target.** If the user pasted a URL / path / zip, pass it as
   `target`. If they're pointing at "this skill" with no path, omit `target`.
2. **Call `scan_skill`.** Let OSV run unless the user is clearly offline or asks
   to skip deps (`check_deps: false`).
3. **Lead with the verdict.** State the **recommendation** and **score** first —
   that's the decision the user actually needs.
4. **Then the evidence**, grouped by severity, newest risk first:
   - 🔴 **Critical / High** — the findings that drive a DO_NOT_INSTALL / CAUTION.
   - 🟡 **Medium** — worth a look.
   - 🟢 **Low / Info** — context.
   For each, cite `file_path:line` and the one-line message. Don't dump raw JSON.
5. **Explain, don't just list.** A single `eval()` in an example is different
   from `eval(atob(...))` + a known exfil host + hidden Unicode. Correlate the
   signals into a story ("this looks like X") and say how confident you are.
6. **Be honest about coverage.** If OSV was offline, say deps are "unknown, not
   clean". If the scan was `truncated`, say so. If you only saw a single file,
   say a full-repo scan would see more.

## Important framing

- This is **heuristic pre-install triage**, not proof. A finding is a "look
  here", not a conviction. Say so. The goal is to stop the obvious-bad and
  surface the suspicious for human judgement.
- **Never auto-install** something you flagged CAUTION or worse without the user
  explicitly accepting the risk.
- A clean result means "no signals matched", not "provably safe". Encourage a
  quick human skim for anything that will run with real privileges.

## When NOT to use this

- For auditing the user's **own application code** → the `guardian-security`
  skill or `/guardian-scan`.
- For AI features *inside* the user's app (the prompt-injection surface of their
  own RAG or chatbot) → there is no dedicated module: `/guardian-scan` finds
  exposed keys and dangerous sinks, and the rest is a manual review with the
  `guardian-review` checklist. Say so rather than running `scan_skill` on it.
- For the AI-agent **workspace configuration** of this project (`.mcp.json`,
  `.claude/settings.json`: unpinned MCP servers, inline secrets, wildcard Bash
  permissions) → `audit_agent_config { project_path: "<project>" }`.
- This module is specifically for **third-party agent artifacts you're deciding
  whether to trust**.
