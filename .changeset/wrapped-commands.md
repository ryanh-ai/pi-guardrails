---
"@aliou/pi-guardrails": patch
---

Built-in dangerous-command matchers now see through common wrappers (`env`, `command`, `exec`, `nice`, `nohup`, `timeout`, `xargs`, `stdbuf`) and path-qualified commands (`/bin/rm`, `/usr/bin/git`). Previously `env FOO=1 rm -rf build` or `/bin/rm -rf build` was not matched.
