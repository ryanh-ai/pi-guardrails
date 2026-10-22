---
"@aliou/pi-guardrails": minor
---

Add a structural git matcher to the built-in dangerous-command checks. It covers force pushes (including `+refspec`, quoted, and abbreviated flags), remote ref deletion, `--mirror`/`--prune` pushes, branch force-delete, `reset --hard`, `clean -f`, path checkout/restore, `stash drop/clear`, and options that run commands (`-c`, `--upload-pack`, `--receive-pack`, `--exec`).

Harden config loading: values with the wrong type are dropped with a warning, a config that breaks loading is skipped instead of disabling guardrails, and fail-closed mode also enforces the home-secret file rules. Exact persistent grants are anchored, project grants are keyed by the git root, and a corrupt grants store is never overwritten.
