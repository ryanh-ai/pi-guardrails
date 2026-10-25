---
"@aliou/pi-guardrails": minor
---

Respect pi's project trust for the project settings file. A trusted project's `.pi/extensions/guardrails.json` is honored as before. In an untrusted project, settings that would loosen protection are ignored and listed at session start: disabling features or confirmation, `customPatterns`, `allowedPatterns`, overriding built-in or global rule ids, and loosening path access. Settings that add protection still apply. Requires pi >= 0.84.3 (`ctx.isProjectTrusted()`); older pi keeps the previous behavior.
