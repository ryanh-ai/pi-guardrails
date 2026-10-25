---
"@aliou/pi-guardrails": patch
---

Evaluate `autoDenyPatterns` before `allowedPatterns` and session grants. An allow rule or grant now only skips the confirmation prompt, so a broad or unanchored allow rule can no longer let an auto-denied command through.
