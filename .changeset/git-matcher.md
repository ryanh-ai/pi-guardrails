---
"@aliou/pi-guardrails": minor
---

Add a built-in matcher for destructive git operations. It covers force pushes (including `+refspec`, quoted, and abbreviated flags), remote ref deletion, `--mirror`/`--prune` pushes, branch force-delete/rename/reset, `reset --hard`, `clean -f`, `worktree remove --force`, path checkout/restore, `switch --discard-changes`, and `stash drop/clear`.
