---
description: Assess whether a rollback is safe — DB migrations, breaking schema, irreversible ops. Rollback seguro? ¿Es seguro hacer rollback?
---

Decide whether rolling back is **safe** before you actually do it. Rollbacks of code are easy; rollbacks of data and migrations are not.

The skill should:

1. Identify the rollback target — `$ARGUMENTS` or the previous tag / previous deployment SHA.
2. Diff the file tree between `HEAD` and the target.
3. **Database migrations** — list every migration file added since the target. For each, decide if it is reversible:
   - Schema-only and reversible → safe to rollback.
   - Adds a column with `NOT NULL` default → safe forward, **broken** if rolled back (column still in DB but app no longer expects it).
   - Drops a column / table → **destructive**, rolling back loses data.
4. **Lockfiles** — flag major-version dep upgrades that may have changed API shape.
5. **Configuration / env vars** — flag new required env vars that production may not have yet.
6. **API contracts** — diff OpenAPI / GraphQL / gRPC schemas if present; warn on removed fields.

Verdict: ✅ safe rollback / ⚠️ rollback possible with caveats (listed) / 🔴 do not rollback without [data migration | manual schema fix | …].

Rollback target (tag, SHA, or "previous deploy"): $ARGUMENTS
