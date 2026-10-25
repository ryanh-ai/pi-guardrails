---
"@aliou/pi-guardrails": patch
---

Check settings file shapes before merging. Wrong-typed values are dropped or fixed toward the stricter setting, and reported at session start. Previously `"enabled": 0` silently disabled guardrails, and a malformed value such as a non-array `pathAccess.allowedPaths` could break config loading.
