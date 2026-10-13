# History

> Maintainer notes, moved from `CLAUDE.md` (the index). Not loaded into sessions: read this file before you
> change its area.

## Where the design docs went

`docs/superpowers/` — thirteen implementation plans and fourteen designs of
record — was removed from the tree on 2026-08-22. It is **not lost**: 97 commits
touch those files (the removal included), so any of them is one command away.

```bash
git log --oneline --diff-filter=D -- docs/superpowers   # find the removal
git show <commit>^:docs/superpowers/specs/<name>.md     # read one
git checkout <commit>^ -- docs/superpowers              # restore the tree
```

Code comments that used to cite a section by path, or a "design doc §N", now
say "the design of record" instead. The measurements those documents held — why a rule was
deleted, which tier moved and against what corpus, which clause was measured
inert — were written into the rule packs' own comments and into `CHANGELOG.md`
as they were made, so the reasoning survives in the tree even though the
documents do not.
