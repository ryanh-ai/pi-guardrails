---
"@aliou/pi-guardrails": patch
---

Report a settings file that exists but can't be read, such as a dangling symlink, a permission error, or invalid JSON. Previously it silently fell back to defaults. Guardrails now shows an error at session start and refuses to save over the file. Path-access "always" grants fall back to the current session.
