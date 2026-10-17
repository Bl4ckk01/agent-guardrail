# 🛡️ Agent Security Guardrail (AGENTS.md)

This project is protected by the **Agent Guardrail** multi-tier safety architecture.
All AI coding agents (Claude Code, OpenAI Codex / ChatGPT, Google Antigravity, Cursor, and Grok Build) MUST adhere to the security boundaries specified in `policy.yaml`.

---

## 1. Safety Principles & Decision Hierarchy

Whenever evaluating or executing any action, adhere to the three decisions:

### 🚫 1. BLOCK (Strictly Denied)
Refuse immediately and explain why the action is blocked:
- **Destructive Deletion**: Any recursive file removal (`rm -rf`, `rmdir /s`, `Remove-Item -Recurse -Force`, `del /s`).
- **Remote Git Destruction**: Force pushes (`git push --force`, `git push -f`), deleting remote branches or tags (`git push :main`, `git push --delete main`), or hard resets (`git reset --hard`).
- **Database Dropping**: `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE`, unbounded `DELETE FROM` or `UPDATE` statements without a `WHERE` clause.
- **Disk / System Format**: Unit formatting (`format c:`, `mkfs`), raw device overwrites (`dd if=... of=/dev/...`), `chmod 777`, fork bombs.
- **Secret Leaks**: Committing, publishing, printing, or exporting `.env` files, API keys, SSH private keys (`id_rsa`, `id_ed25519`), `.pem` certificates, or credentials.
- **Security Bypasses**: Disabling firewall (`ufw disable`, `iptables -F`), antivirus, audit logs, or safety guardrails.

### ⚠️ 2. ASK USER (Human Approval Required)
Pause and request explicit user confirmation in chat before proceeding:
- Modifying configuration files: `.env`, `docker-compose.yml`, `Dockerfile`, `requirements.txt`, `package.json`.
- Running container operations: `docker run`, `docker exec`, `docker compose up/down`.
- Cloud and infrastructure modifications: `kubectl apply/delete`, `terraform apply`, `aws s3`.
- Installing global dependencies: `npm i -g`, `pip install --user`.
- Modifying system privileges or services: `systemctl`, `service`, `sudo`.

### ⚡ 3. PROCEED (Permitted Silently)
Routine safe developer workflows proceed with zero friction:
- Read-only queries: `ls`, `dir`, `cat`, `grep`, `git status`, `git diff`, `git log`, `find`.
- Running test suites and linters: `pytest`, `npm test`, `cargo test`, `ruff check`, `mypy`, `eslint`.
- Normal source code creation, edits, refactoring, and adding unit tests within the workspace.

---

## 2. Programmatic Verification

Agents can programmatically verify whether an action is permitted under the active policy by executing:
```bash
python check_action.py "<command or natural language intent>"
```
The output JSON returns:
```json
{
  "decision": "proceed | ask_user | block",
  "backend": "rules | d1 | clm | jev",
  "matched_rules": [...]
}
```

---

## 3. Session Control

In chat with any supported agent, users can manage the guardrail using:
- `/guardrail` or `/guardrail on`: Enable active monitoring.
- `/guardrail start`: Automatically launch background daemon and enable protection.
- `/guardrail off`: Temporarily disable monitoring for administrative maintenance.
- `/guardrail stop`: Stop background daemons managed by the guardrail.
- `/guardrail status`: View active status and live daemon connectivity.
- `/guardrail reload`: Reload `policy.yaml` configuration dynamically without restart.

---

## 4. Native Model Context Protocol (MCP) Integration

Any MCP-compliant client (Claude Desktop, Cursor, Antigravity, Zed, VS Code) can mount Agent Guardrail directly:

### Server Command
```bash
python mcp_server.py
# or
python check_action.py --mcp
```

### Export Configuration Snippets
```bash
python mcp_server.py --export-config
```

### Exposed MCP Tools & Resources
- **Tool `check_action`**: Verify any command or natural language intent.
- **Tool `check_batch_actions`**: Evaluate multiple commands in batch and return overall verdict.
- **Tool `get_guardrail_status`**: Inspect active backend, daemons, and rule count.
- **Tool `reload_policy`**: Reload `policy.yaml` dynamically without server restart.
- **Resources**: `guardrail://policy`, `guardrail://status`, `guardrail://rules`.
- **Prompts**: `guardrail-pre-execution-check`, `guardrail-safety-guidelines`.

