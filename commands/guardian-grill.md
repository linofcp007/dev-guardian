---
description: Understanding gate — the AI grills you on the domain decisions in a diff before merge. Sabatina ao diff antes do merge. Interrogatorio del diff antes del merge.
argument-hint: "[branch, PR, or scope hint]"
---

Invoke the `guardian-grill` skill: an understanding gate on the pending changes. Where
`guardian-review` checks the code, this checks that **you** still understand the domain decisions the
diff introduced — for the loops where you no longer read every line.

Steps:

1. Determine the diff (vs `main`, `--staged`, or last tag).
2. Extract the domain-significant decisions from it (business-rule branches, validation & failure
   paths, state changes, error handling, thresholds) — ignore style.
3. Grill, ONE question at a time, on what each decision does and why.
4. End with the Shared Understanding summary and a merge verdict: 🟢 Understood / 🟡 Understood with
   gaps / 🔴 Not understood. Offer to save the summary to the PR description or
   `docs/understanding/<branch>.md`.

Run alongside `/guardian-review` for a full pre-merge gate (code + understanding).

Branch, PR number, or scope hint (optional): $ARGUMENTS

Respond in the user's language (EN/PT/ES).
