---
description: Activate or manage the CLM safety guardrail for the current session on all commands and tool actions
---

[[agent-guardrail:on]]
Activate the safety guardrail for this session.
The guardrail is now active in the background via lifecycle hooks: do not run manual Python scripts to check every action. Proceed normally with user requests—checks will run automatically to block destructive commands or request confirmation.
