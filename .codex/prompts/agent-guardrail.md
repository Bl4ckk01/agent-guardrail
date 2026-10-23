---
description: Activate or manage the Agent Safety Guardrail (/agent-guardrail on, off, status, reload, check, why, doctor) for the current session
---

[[agent-guardrail:on]]
Activate the safety guardrail for this session.
The guardrail is now active in the background via lifecycle hooks: do not run manual Python scripts to check every action. Proceed normally with user requests — checks will run automatically to block destructive commands or request confirmation.
