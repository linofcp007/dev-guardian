# When the project's database is not used

If `health_status` returns `storage_warning`, or a scan's `warnings` say the project's `.guardian/guardian.db` is
not used, history is going to a per-user fallback database: a database dev-guardian did not create for this very
path — copied from elsewhere, or older than its registry — is never trusted automatically.

Tell the user, and give them the command the warning names to run **themselves, in a terminal**, if the database
is theirs — `node "<plugin root>/cli/dev-guardian.mjs" db adopt --project <project>` shows what it holds; the same
with `--yes` registers it. **Never run it yourself**, with or without `--yes`: it decides whose data dev-guardian
trusts, and that is not an assistant's decision.

Point them first at what to weigh, in the same `health_status`: `suppressions.all_projects` (suppressions with no
project hide findings in every project) and `storage.future_dated_scans_ignored`.
