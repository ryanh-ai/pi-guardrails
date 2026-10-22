---
"@aliou/pi-guardrails": minor
---

Harden the permission gate and config loading:

- Auto-deny patterns now always win. `allowedPatterns` and saved grants only skip the confirmation prompt.
- Text submitted to an existing `interactive_shell` session is checked like a `bash` command.
- An unreadable global config (dangling symlink, permission error, invalid JSON) is reported at session start. Guardrails then uses the last good snapshot, or confirms every shell command if there is none, and refuses to save over the broken file.
- Project config can no longer weaken protection. "Allow for project" grants are stored outside the project.
