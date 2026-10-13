---
name: 'A reported bug in a .specs/ project goes to dev-spec-driven'
description: 'Both plugins loaded (dev-spec-driven from the sibling checkout ../dev-spec-driven). shop-app has .specs/ with a checkout feature on its branch; the user reports a TypeError and asks for a fix. The bug belongs to dev-spec-driven''s bugfix flow (root cause, bug.md approval, a failing regression test); src/cart.js is not edited in this run.'
tags:
  - routing
  - two-plugins
  - bugfix
  - en
runs: 2
max_turns: 12
timeout_seconds: 420
allowed_tools: [Read, Glob, Grep, Skill, TodoWrite, Write, Edit]
plugins: ["../..", "../../../dev-spec-driven"]
---
orderTotal in src/cart.js throws a TypeError when the cart is empty. Fix this bug.
