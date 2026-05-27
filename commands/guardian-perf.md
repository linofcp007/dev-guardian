---
description: Performance budgets + load testing. Performance e carga. Rendimiento y carga.
---

Invoke the `guardian-performance` skill for performance work.

Coverage:

- Performance budgets (Lighthouse CI for frontends, custom budgets for backends)
- Load and stress testing (k6 or Artillery)
- Profiling hints (Node clinic, py-spy, pprof, etc. based on stack)
- Hot-path analysis: N+1 queries, missing indexes, blocking I/O, slow regexes

Report bottlenecks with measured numbers, not vibes.

Hint (optional, e.g. "load test the /api/checkout endpoint at 500 rps"): $ARGUMENTS
