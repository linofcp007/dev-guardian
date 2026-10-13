---
name: 'A code smell is not a security scan'
tags:
  - negative
  - near-miss
  - en
runs: 3
max_turns: 4
allowed_tools:
  - Skill
---
This smells bad — rename the variables in src/utils.ts to something clearer.
