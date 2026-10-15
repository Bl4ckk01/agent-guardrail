#!/usr/bin/env python3
"""Multi-tier safety guardrail for Claude Code, OpenAI Codex, Antigravity, Cursor, and Grok.

Backends:
  - Rules (default): deterministic regex & path policies (< 0.1ms, zero models needed)
  - D1: local Liquid AI d1-3B model via llama-server (port 8800)
  - CLM: local contrastive embedding model via clm-serve (port 8700)
  - Jev: cloud decision API (TypeSafe AI)

Usage:
  python check_action.py "<action description or command>"
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- General Configuration ---
DEFAULT_TIMEOUT = 5.0
VALID_DECISIONS = ("proceed", "ask_user", "block")
SEVERITY = {"proceed": 0, "ask_user": 1, "block": 2}


def most_severe(*decisions: str) -> str:
    return max(decisions, key=SEVERITY.__getitem__)


def _debug_enabled() -> bool:
    return os.environ.get("GUARDRAIL_DEBUG", "").strip() not in ("", "0", "false")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


# Policy configuration cache (policy.yaml)
_POLICY_LOADED = False
_CUSTOM_BLOCK: list[tuple[str, re.Pattern]] = []
_CUSTOM_ASK: list[tuple[str, re.Pattern]] = []
_CUSTOM_PROCEED: list[tuple[str, re.Pattern]] = []
_PATH_RULES: list[PathRule] = []
_POLICY_SETTINGS: dict[str, Any] = {}


def _env_float(name: str, default: float) -> float:
    if name in os.environ:
        try:
            return float(os.environ[name])
        except (TypeError, ValueError):
            return default
    for k in (name.lower(), "timeout_secs", "guardrail_timeout_secs"):
        if k in _POLICY_SETTINGS:
            try:
                return float(_POLICY_SETTINGS[k])
            except (TypeError, ValueError):
                pass
    return default


# --- Deterministic Regex Patterns (Pure English) ---
_DEL = r"\b(?:delet\w*|remov\w*|eras\w*|wip\w*|purg\w*|destroy\w*|nuke\w*|drop\w*|strip\w*|clear\w*|clean\w*|discard\w*|terminat\w*)\b"
_SECRET = (
    r"(?:\.env(?!\.(?:example|sample|template|dist)\b)\b|\bapi[\s_-]?keys?\b|\b(?:access|auth|bearer|github|api|session|oauth)?[\s_-]?tokens?\b"
    r"|\$[a-zA-Z0-9_]*(?:password|token|secret|key)\b|\b(?:db_|database_)?passwords?\b|\bpasswd\b|\bcredentials?\b|\bsecrets?\b"
    r"|(?:aws|cloud|ssh|api|private)\s+keys?|private\s+keys?|id_rsa|id_ed25519|\.pem\b|master\.key\b|certificates?)"
)
_CRITICAL_TARGET = (
    r"(?:" + _SECRET + r"|database|\bdb\b|\btables?\b|production|\bprod\b"
    r"|backup(?!_[0-9a-zA-Z_-]*\.(?:zip|tar|gz|bak|7z)\b)\w*"
    r"|\ball\s+(?:the\s+)?(?:files|data|records|backups|branches|users|tables|commits)\b|\beverything\b"
    r"|\b(?:whole|entire)\s+(?:\w+\s+)?(?:workspace|folders?|directories|directory|contents?)\b"
    r"|contents?\s+of\s+(?:the\s+)?(?:folder|directory)\w*"
    r"|audit[\s_-]?logs?|auth[\s_-]?logs?|security\s+logs?|access[\s_-]?logs?"
    r"|customer\s+data|user\s+data|\bhistory\b|commit\s+history|git\s+history"
    r"|\b(?:main|master)\s+branch|branch\s+(?:main|master)\b|(?:the\s+)?(?:whole|entire)\s+repo\w*"
    r"|\bdisk\b|\bpartition\b|home\s+directory|(?:the\s+)?(?:whole|entire|all)\s+(?:s3\s+)?buckets?\b|docker\s+volumes?)"
)

# Categorical block rules (< 0.1ms)
BLOCK_RULES: tuple[tuple[str, str], ...] = (
    ("recursive rm", r"\brm\s+(?:-\S*\s+)*-\S*[rR]"),
    ("rm --recursive", r"\brm\b.*--recursive"),
    ("remove-item -recurse", r"\b(?:remove-item|ri)\b.*-recurse"),
    ("del /s", r"\b(?:del|erase)\s+.*/[sq]\b"),
    ("rmdir /s", r"\b(?:rmdir|rd)\s+/s\b"),
    ("find -delete", r"\bfind\b.*-delete\b"),
    ("critical target deletion", _DEL + r".{0,60}?" + _CRITICAL_TARGET),
    ("git push --force", r"\bgit\s+push\b.*(?:--force\b|--force-with-lease|\s-f\b|\s\+\S|--mirror\b)"),
    ("force push", r"\bforce[\s-]?push\w*"),
    ("git reset --hard", r"\bgit\s+reset\b.*--hard"),
    ("git clean -f", r"\bgit\s+clean\s+(?:-\S*\s+)*-\S*f"),
    ("git checkout discard changes", r"\bgit\s+(?:checkout\s+(?:-\S+\s+)*--\s+\.|\brestore\s+\.)|\bdiscard\s+all\s+(?:local\s+)?changes\b"),
    ("history rewriting", r"\bgit\s+filter-(?:branch|repo)\b|\bbfg\b|rewrit\w*\s+(?:the\s+)?(?:git\s+)?history"),
    ("main branch deletion", r"\bgit\s+(?:branch\s+-D|push\s+\S+\s+--delete|push\s+\S+\s+:)\s*(?:main|master)\b"),
    ("git reflog expire / purge", r"\bgit\s+reflog\s+(?:expire|delete|drop)\b|\bgit\s+gc\b.*--prune=now"),
    ("git remote critical branch delete", r"\bgit\s+push\b.*(?:--delete\b|:\w+)\s*(?:main|master|prod\w*|production|staging|release)\b|\b(?:delet\w*|remov\w*)\s+.{0,40}?\bbranch\s+(?:main|master|prod\w*|production|staging|release)\b.{0,40}?\b(?:remote|origin)\b"),
    ("git remote tag delete nlp", r"\b(?:delet\w*|remov\w*)\s+.{0,30}?\btag\b.{0,40}?\bremote\b"),
    ("git branch force delete", r"\bgit\s+branch\s+(?:-[D]|--delete\s+--force)\b"),
    ("git update-ref delete", r"\bgit\s+update-ref\s+-d\b"),
    ("crontab remove all", r"\bcrontab\s+(?:-[a-z]*r[a-z]*\b|--remove\b)"),
    ("shutil rmtree", r"\bshutil\.rmtree\b"),
    ("delete folder nlp", r"\b(?:delet\w*|remov\w*)\s+(?:(?:the\s+|a\s+)?(?:folder|directory|dir)\s+(?:of)?|(?:the\s+)?contents?\s+(?:of\s+)?(?:folder|directory)\w*)\b"),
    ("recursive deletion nlp", r"\b(?:remov\w*|delet\w*)\s+.{0,80}?\brecursive\w*\b"),
    ("drop sql", r"\bdrop\s+(?:table|database|schema|collection|index|view|user)\b"),
    ("truncate sql", r"\btruncate\s+table\b|\btruncate\s+[\w.\"`\[\]]+\s*;"),
    ("unbounded delete", r"\bdelete\s+from\s+[\w.\"`\[\]]+\s*;"),
    ("unbounded update", r"\bupdate\s+[\w.\"`\[\]]+\s+set\s+\w+\s*=(?!.*\bwhere\b)"),
    ("flushall", r"\bflush(?:all|db)\b|\bdropdatabase\b"),
    ("disk format",
     r"\bmkfs\b|\bformat\s+[a-z]:|\bformat\w*\s+(?:the\s+|a\s+)?(?:[a-z]:?\s+)?(?:disk|hard\s*disk|partition\w*|drive|unit|usb|pc|computer|ssd|hdd)(?:\s+[a-z]:?)?\b"
     r"|\bdiskpart\b|\bdd\s+if=.*\bof=/dev/|>\s*/dev/sd[a-z]|\bshred\b|\bwipefs\b|\bsrm\b|\bmkswap\b"),
    ("fork bomb", r":\(\)\s*\{\s*:\|:&\s*\};:"),
    ("remote pipe to shell", r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b(?:[^|]*\|\s*|.*(?:\&\&|;)\s*)(?:sudo\s+)?(?:sh|bash|zsh|python\d?|iex|invoke-expression)\b"),
    ("chmod 777", r"\bchmod\s+(?:-\S+\s+)*0?777\b"),
    ("sudoers nopasswd", r"\bsudoers\b|\bnopasswd\b"),
    ("secret exposure",
     r"\bgit\s+add\b.*(?:\.env|id_rsa|id_ed25519|\.pem|master\.key|\.key\b)"
     r"|\bmake\s+public\w*.{0,50}?(?:keys?|secrets?|credentials?)"
     r"|(?!\b.*(?:reset|recovery|change)\s+password\b)\b(?:commit\w*|publish\w*|leak\w*|expos\w*|print\w*|shar\w*|send\w*|post|echo|cat|type|paste|write\w*|include|put\b|insert\w*|save\b|export\w*)\b"
     r".{0,50}?" + _SECRET),
    ("malicious intent", r"\bmalware\b|\bransomware\b|\bkeylogger\b|\bbackdoor\b|\bexploit\w*|exfiltrat\w*|\brootkit\w*|\btrojan\w*|hidden\s+account|\bminer\b|cryptominer|cryptomining|hide\s+(?:unauthorized\s+)?access|cover\s+(?:up\s+)?tracks"),
    ("security bypass",
     r"\b(?:bypass\w*|disable\w*|turn\s+off)\s.{0,30}?(?:antivirus|firewall|defender|guardrail|authentication|2fa|mfa|security|audit|access\s+control|rate[\s_-]?limit\w*|selinux|integrity|signature|checksum)"
     r"|\bufw\s+disable\b|\bsetenforce\s+0\b|\bnetsh\s+advfirewall\b.*state\s+off"),
    ("policy violation",
     r"\b(?:violat\w*|against)\b.{0,30}?\b(?:polic\w*|rules?)\b"
     r"|\b(?:polic\w*)\b.{0,30}?\b(?:forbid\w*|prohibit\w*)\b"
     r"|\bmust\s+be\s+rejected\b"
     r"|\b(?:action|operation|command)\s+(?:\w+\s+)?(?:forbidden|not\s+allowed|prohibited)"
     r"|\b(?:company\s+policy|security\s+policy)\s+(?:forbids|prohibits)\b|\bprohibited\s+action\b"),
    ("flush firewall", r"\biptables\s+-[fF]\b"),
    ("zfs destroy", r"\bzfs\s+destroy\b"),
    ("python script destructive", r"\bpython\d?\s+(?:-c\s+)?.*(?:\bos\.(?:system|remove|unlink|rmdir|popen)\b|\bsubprocess\.(?:run|call|Popen|check_call|check_output)\b|\bshutil\.(?:rmtree|move)\b)"),
    ("node script destructive", r"\bnode\s+(?:-e|--eval)\s+.*(?:\bchild_process\b|\bfs\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\b)"),
    ("perl script destructive", r"\bperl\s+-e\s+.*(?:\bsystem\b|\bunlink\b|\brmdir\b)"),
    ("ruby script destructive", r"\bruby\s+-e\s+.*(?:\bsystem\b|FileUtils\.(?:rm|rm_rf|remove_dir)|File\.delete)"),
    ("php script destructive", r"\bphp\s+-r\s+.*(?:\bsystem\b|\bexec\b|\bpassthru\b|\bshell_exec\b|\bunlink\b)"),
    ("awk script destructive", r"\bawk\s+.*system\s*\("),
    ("encoded base64 pipe to shell", r"\b(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d\s+-base64)\s*\|\s*(?:sh|bash|zsh|python\d?|pwsh|powershell)\b"),
    ("ripgrep command injection", r"\brg\b.*--(?:pre|pre-glob)\b"),
    ("find exec injection", r"\bfind\b.*-(?:exec|execdir|ok|okdir)\b"),
    ("fd exec injection", r"\b(?:fd|fdfind)\b.*-(?:x|X|-exec|-exec-batch)\b"),
    ("git config command injection", r"\bgit\b.*-c\s+(?:core\.(?:fsmonitor|pager)|diff\.external|sequence\.editor)"),
    ("git exec-path hijacking", r"\bgit\b.*--exec-path\b"),
    ("git config ssh command injection", r"\bgit\b.*config\s+(?:core\.sshCommand|ssh\.variant)\b"),
    ("tar to-command injection", r"\btar\b.*--(?:to-command|checkpoint-action=exec)\b"),
    ("go test/run exec injection", r"\bgo\s+(?:test|run)\b.*-exec\b"),
    ("rsync remote shell injection", r"\brsync\b.*(?:-e\s+|--rsh=)"),
    ("zip test command injection", r"\bzip\b.*-T\s+-TT\b"),
    ("env var execution hijack", r"(?:^|[\s;&|])(?:LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_OPTIONS|BASH_ENV|PERL5OPT|RUBYOPT|DYLD_INSERT_LIBRARIES)\s*="),
    ("reverse shell dev tcp udp", r"/dev/(?:tcp|udp)/\S+"),
    ("reverse shell netcat socat", r"\b(?:nc|ncat|netcat)\b.*(?:-[ec]\b|--exec\b)|\bsocat\b.*(?:exec|system):"),
    ("reverse shell named pipe", r"\bmkfifo\b.*\|\s*(?:sh|bash|zsh|nc|ncat)\b"),
    ("powershell socket reverse shell", r"\b(?:System\.Net\.Sockets\.TcpClient|Net\.WebClient|DownloadString)\b.*(?:\bInvoke-Expression\b|\biex\b)"),
    ("secret exfiltration curl wget", r"\b(?:curl|wget)\b.*(?:-d|--data(?:-binary)?|-F|--post-file)\s*@(?:/etc/|\.env|\$env:|\S*id_rsa|\S*id_ed25519)"),
    ("shell startup file poisoning", r"(?:>>?|tee\s+(?:-a\s+)?)\s*~?/?(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/profile|/etc/environment|\$profile)\b"),
    ("crontab file poisoning", r"(?:>>?|tee\s+(?:-a\s+)?)\s*/etc/cron"),
    ("guardrail self tampering file", r"\b(?:rm|del|erase|unlink|remove-item|drop|truncate|format)\b.*(?:\bpolicy\.ya?ml\b|\bcheck_action\.py\b|\bguardrail_hook\.py\b|\bdaemon_manager\.py\b|\binstall\.py\b|\.guardrail\b|\.claude/settings\.json\b|\.codex/hooks\.json\b|\.agents/hooks\.json\b|\.cursorrules\b)"),
    ("guardrail self tampering command", r"\b(?:python\d?\s+)?guardrail_hook\.py\s+(?:off|disable|stop)\b|\[\[(?:agent[-_])?guardrail:(?:off|disable|stop)\]\]"),
    ("guardrail control plane tamper tool", r"\btamper\s+guardrail\s+control\s+plane\b"),
)

# Confirmation required rules
ASK_RULES: tuple[tuple[str, str], ...] = (
    ("encoded shell command", r"\b(?:powershell|pwsh)\b.*-(?:e|ec|enc|encodedcommand)\b|\b(?:certutil\s+-decode\w*|xxd\s+-r\b)"),
    ("confirmation requested",
     r"\bask\s+(?:for\s+)?(?:confirmation|permission|approval)|before\s+(?:executing|running|applying)\b"),
    ("vague instruction",
     r"\b(?:do|proceed|act)\s+(?:the\s+best\s+thing|whatever\s+you\s+(?:think|want)|as\s+you\s+(?:like|think|prefer))"
     r"|\bwhatever\b|best\s+thing|do\s+what(?:ever)?\s+you\s+(?:think|want)"
     r"|clean\s+up\s+everything|without\s+asking\b"),
    ("generic deletion",
     _DEL + r".{0,40}?\b(?:files?|directories|directory|dirs?|folders?|branch\w*|tags?|data|records?|users?|accounts?|logs?|containers?|images?|issues?|resources?|caches?|modules?|projects?)\b"),
    ("rm / del", r"\b(?:rm|rmdir|unlink|remove-item)\s+\S|\bdel\s+(?:/[a-z]\b|\*)"),
    ("overwrite", r"\boverwrit\w*|\bmv\s+\S|\bmove-item\b"),
    ("remote git / history",
     r"\bgit\s+(?:push|pull|rebase|merge|submodule|tag(?!\s+--(?:list|-l)|\s+-l\b)|cherry-pick|revert|commit\s+--amend|stash\s+(?:drop|clear)|branch\s+-[dDmM]|checkout\s+--|restore\s+\.|reset)\b"
     r"|\bpush\s+(?:the\s+)?(?:\S+\s+)?(?:branch\s+)?to\s+\S+"),
    ("dependency install",
     r"\bpip3?\s+(?:install|uninstall)\b|\bpython\d?\s+-m\s+pip\s+(?:install|uninstall)\b|\bnpm\s+(?:i|install|uninstall|update|add|ci)\b"
     r"|\byarn\s+(?:add|remove|upgrade)\b|\bpnpm\s+(?:add|install|remove|update)\b|\bpoetry\s+(?:add|remove|update)\b|\bconda\s+(?:install|remove)\b"
     r"|\bapt(?:-get)?\s+(?:install|remove|purge|upgrade)\b|\bbrew\s+(?:install|uninstall|upgrade)\b|\b(?:choco|winget|scoop)\s+(?:install|uninstall)\b"
     r"|\bcargo\s+(?:add|install|remove|update)\b|\bcomposer\s+(?:require|remove|install|update)\b"
     r"|\bbundle\s+(?:add|install|update|remove)\b|\bgem\s+(?:install|uninstall)\b"
     r"|requirements\w*\.txt|package(?:-lock)?\.json|pyproject\.toml|poetry\.lock|yarn\.lock|cargo\.toml|go\.mod|gemfile"
     r"|dependenc\w*|\binstall\w*\b|upgrad\w*|downgrad\w*"),
    ("config / deploy",
     r"\.env(?!\.(?:example|sample|template|dist)\b)\b|\bconfig\w*|\bsettings\b|\.ya?ml\b|\.toml\b|\.ini\b|\.conf\b"
     r"|dockerfile|docker[\s_-]compose\b|\bdocker\s+compose\s+(?:up|down|restart|build|run|exec)\b"
     r"|\.github/workflows|\bci/cd\b|\bpipeline\b|makefile|\bbuild\s+script"
     r"|\bdeploy\w*|\brelease\b|\bprod\b|production|staging"
     r"|\bmigrat\w*|terraform|kubectl|helm\b|ansible|\bdconf\s+reset\b|\bgsettings\s+(?:set|reset)\b"),
    ("system / privileges",
     r"\bsudo\b|\brunas\b|\bchmod\b|\bchown\b|\bicacls\b|\bsystemctl\b|\bservice\s+\S+\s+(?:stop|restart|reload|start|status)|\bcrontab\b|\bregedit\b|\breg\s+(?:add|delete)\b"
     r"|\bset-executionpolicy\b|\bkill(?:all)?\b|\btaskkill\b|\bpkill\b|\bshutdown\b|\breboot\b|\brestart\w*|\bsysctl\b"
     r"|/etc/|c:\\windows|system32|~/\.ssh|\.bashrc|\.zshrc|\.profile\b|\$profile|environment\s+variables?|\bethtool\b"),
    ("database write",
     r"\b(?:insert\s+into|update\s+\S+\s+set|alter\s+table|delete\s+from|grant|revoke)\b"
     r"|modify\s.{0,25}?(?:database|\bdb\b|tables?|schema)"),
    ("secrets / accounts", _SECRET + r"|\baccounts?|(?<![./\w])login(?!\.(?:py|js|ts|php|html|vue))\b|\baccess\s+(?:to)\s+\S+|\bpermissions?|\broles?\b"),
    ("payments", r"\bpayments?|\bpurchas\w*|credit\s+card|invoice\w*|refund\w*"),
    ("external comms",
     r"\b(?:send\w*|email\w*|mail)\s.{0,40}?(?:e-?mail|mail|messages?|sms|notifications?|newsletter|customers?|users?)\b"
     r"|\btweet\w*|\bpost\s+(?:on)\b"),
    ("remote download / execution",
     r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|scp|ssh|ftp)\b|download\w*\s+and\s+run"
     r"|\brsync\b.*(?::|@)"),
)

# Routine safe developer actions (< 0.1ms whitelist)
PROCEED_RULES: tuple[tuple[str, str], ...] = (
    ("read cli", r"(?:^|[;&|\n\r]|\b(?:run|sudo)\s+)\s*(?:cat|head|tail|grep|find|ls|dir|less|more|strace|wc|lsof|du|ss|netstat)\b\s+\S+|(?:^|[;&|\n\r])\s*file\s+\S+|\bss\s+-[a-zA-Z]+\b|\bfdisk\s+-[a-zA-Z]+\b|\blsblk\b|\bdf\s+-[a-zA-Z]+\b"),
    ("read nlp", r"\b(?:read|view|show|display|inspect|summarize|analyze|list|check)\b.{0,60}?\b(?:contents?|files?|data|logs?|lines|module|extension|function|definition|schema|documentation|occurrences|codebase|types?|coverage|report|structure|tree|folders?|directories|sections?|versions?|changelog|routes?|endpoints?|urls?)\b"),
    ("search nlp", r"\b(?:search|find)\b.{0,60}?\b(?:files?|extensions?|\.py|\.ts|\.js|occurrences?|usages?|references?|functions?|methods?|variables?|calls?)\b"),
    ("verify exists nlp", r"\b(?:check|verify)\b.{0,60}?\b(?:if|whether)\b.{0,50}?\b(?:exists?|defined|present)\b"),
    ("git read", r"\bgit\s+(?:status|log|diff|show|blame|stash\s+(?:list|show)|branch(?:\s+(?:--(?:list|all|-a)|-[avrlL]+)\b|\s*$)|tag\s+(?:--(?:list|-l)|-l\b)|config\s+--(?:list|get|-l))\b|\bgit\s+tag\s*$"),
    ("test lint cli", r"^(?!.*(?:\bpip3?\s+(?:un)?install|\bpoetry\s+(?:remove|add)|\bnpm\s+(?:i|install|uninstall|remove)|\byarn\s+(?:add|remove)|\bpnpm\s+(?:add|remove)|\bcargo\s+(?:add|remove)|\bgem\s+(?:install|uninstall)))\b.*?(?:^|[;&|\n\r]|\b(?:npx|python\d?\s+-m|poetry\s+run|run|execute)\s+)?\s*(?:(?:a\s+|the\s+)?(?:linter|tool|command)\s+)?\b(?:pytest|npm\s+(?:test|run\s+(?:lint|test|check|build|typecheck)[\w:-]*)|cargo\s+(?:test|check|build)|go\s+(?:test|vet)|mypy|ruff\s+check|flake8|eslint|shellcheck|bandit|hadolint|stylelint|sqlfluff(?:\s+lint)?|pyright|pytype|tsc|trivy|semgrep|mvn\s+test|gradle\s+test)\b"),
    ("test run nlp", r"\b(?:run|execute)\b.{0,50}?\b(?:tests?|unit\s+tests?|integration\s+tests?|e2e)\b"),
    ("test nlp", r"^(?!.*(?:\.gitlab-ci|\.github/workflows|jenkinsfile|docker[\s_-]compose))\b.*?(?:add|create|write|implement\w*)\w*\s+.{0,40}?\b(?:tests?|unit\s+tests?|test[\s_-]?cases?|test[\s_-]?suite|test_\w+\.py|edge\s+cases?)\b"),
    ("edit safe nlp",
     r"\bfix\s+(?:(?:a|an|the)\s+)?(?:typos?|spellings?|mistakes?)\b"
     r"|\badd\s+.{0,30}?\b(?:log|debug\s+log|logging)\b"
     r"|\b(?:convert\w*|uppercase)\b.{0,40}?\b(?:constants?|pep\s*8)\b"
     r"|\b(?:replace|extract)\s+.{0,40}?\b(?:hardcoded|strings?|i18n|var\b|let\b|const\b)\b"
     r"|\bupdate\s+.{0,30}?\b(?:copyright|header|license\s+header)\b"
     r"|\b(?:fix|update)\b.{0,30}?\b(?:error\s+message)\b"
     r"|\b(?:optimize|simplify)\b.{0,50}?\b(?:query|code|function|loop|performance)\b"
     r"|\breplace\s+.{0,40}?\b(?:print|logger|logging)\b"
     r"|\b(?:remove|delete)\s+.{0,40}?\b(?:variable|parameter)\s+.{0,30}?\b(?:unused)\b"
     r"|\b(?:remove|delete)\s+.{0,40}?\b(?:console\.log|debug\s+print|debug\s+logs?)\b"
     r"|\badd\s+.{0,35}?\b(?:aria[\s_-]?label|alt[\s_-]?(?:text|tag)|alternative\s+text|attributes?|parameters?|fields?|properties)\b"
     r"|\bmake\s+.{0,30}?\b(?:log\s+messages?)\b"
     r"|\b(?:update|bump)\s+.{0,30}?\b(?:versions?)\b.{0,40}?\b(?:__init__\.py|version\.py|metadata)\b"),
    ("type hint nlp", r"\b(?:add|insert)\s+.{0,35}?\b(?:type\s*hints?|type\s*annotations?|type\s*checks?)\b"),
    ("rename nlp",
     r"\b(?:rename|update|change|fix)\s+(?:the\s+name\s+of\s+)?(?:the\s+variable|the\s+parameter|the\s+method|the\s+function|the\s+class|the\s+module|the\s+constant|variable|parameter|function|method|class|module|constant)\b"),
    ("docstring comment nlp",
     r"\b(?:add|write)\b.{0,30}?\b(?:docstrings?|comments?)\b"
     r"|\b(?:extract|move)\s+.{0,30}?\b(?:todo|fixme)\b"),
    ("refactor helper nlp",
     r"\b(?:extract|split|break\s+down|move)\s+.{0,60}?\b(?:helper\s+function|function|method|constant|variable|magic\s+(?:number|value)|color)\b"),
    ("format nlp", r"\b(?:format|reformat|fix|adjust|align)\s+.{0,80}?\b(?:black|prettier|ruff|indentation|quotes)\b|\btrim\s+.{0,30}?\btrailing\s+whitespace\b|\bblack\s+\S+"),
    ("style import nlp", r"\b(?:sort|clean|group|remove|delete)\s+.{0,35}?\b(?:imports?|unused\s+imports)\b|\b(?:remove|delete)\s+.{0,30}?\b(?:commented\s+code|dead\s+code)\b"),
    ("resize image nlp", r"\b(?:compress|resize)\s+.{0,40}?\b(?:images?|logos?|assets?|icons?)\b"),
    ("sort json nlp", r"\b(?:sort)\s+.{0,30}?\b(?:keys)\b|\balphabetical(?:ly)?\b"),
    ("tag list nlp", r"\b(?:show|list)\b.{0,30}?\b(?:tags?)\b"),
    ("local rsync", r"\brsync\s+(?:-\S+\s+)*[^\s:@]+/[^\s:@]*\s+[^\s:@]+/?$"),
)

_COMPILED_BLOCK = tuple((name, re.compile(rx) if name == "git branch force delete" else re.compile(rx, re.IGNORECASE)) for name, rx in BLOCK_RULES)
_COMPILED_ASK = tuple((name, re.compile(rx, re.IGNORECASE)) for name, rx in ASK_RULES)
_COMPILED_PROCEED = tuple((name, re.compile(rx, re.IGNORECASE)) for name, rx in PROCEED_RULES)


# Zero-width & invisible characters to strip unconditionally
_ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F\u00A0\u2060\u180E\u00AD]")

# Unicode homoglyphs and confusables (Cyrillic, Greek, Fullwidth, Special slashes) to canonical ASCII
_CONFUSABLES_MAP = {
    # Cyrillic lookalikes (visual UTS #39 confusables)
    "а": "a", "б": "b", "в": "b", "г": "r", "д": "d", "е": "e", "ж": "zh", "з": "3",
    "и": "u", "й": "u", "к": "k", "л": "l", "м": "m", "н": "h", "о": "o", "п": "n",
    "р": "p", "с": "c", "т": "t", "у": "y", "ф": "f", "х": "x", "ц": "u", "ч": "h",
    "ш": "w", "щ": "w", "ъ": "b", "ы": "bl", "ь": "b", "э": "e", "ю": "o", "я": "r",
    "і": "i", "ї": "i", "є": "e", "ґ": "r", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    # Greek lookalikes
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ζ": "z", "η": "n", "θ": "0",
    "ι": "i", "κ": "k", "λ": "l", "μ": "u", "ν": "v", "ξ": "x", "ο": "o", "π": "n",
    "ρ": "p", "σ": "o", "τ": "t", "υ": "u", "φ": "o", "χ": "x", "ψ": "u", "ω": "w",
    # Slashes and delimiters
    "\u2215": "/", "\uff0f": "/", "\u2044": "/", "\u29f8": "/", "\ufe68": "\\", "\uff3c": "\\",
}
_CONFUSABLES_TRANS = str.maketrans(_CONFUSABLES_MAP)


def normalize(text: str) -> str:
    """Normalize text: strip invisible chars, resolve homoglyphs, lowercase, unaccented, unified quotes, compacted spaces."""
    if not text:
        return ""
    # 1. Strip zero-width & invisible characters
    text = _ZERO_WIDTH_CHARS.sub("", text)
    # 2. Compatibility decomposition & recomposition (e.g. fullwidth ａ -> a)
    text = unicodedata.normalize("NFKC", text)
    # 3. Map cross-script confusables & homoglyphs
    text = text.lower().translate(_CONFUSABLES_TRANS)
    # 4. Strip combining accents (e.g. e + accent -> e)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    # 5. Unify quotes and dashes
    text = text.replace("\u2019", "'").replace("\u2018", "'").replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("`", "'").replace("\u2014", "--").replace("\u2013", "-")
    # 6. Compact spaces
    return re.sub(r"\s+", " ", text).strip()


def _canonicalize_path_string(text: str) -> str:
    """Canonicalize slashes, collapse ./ and ../ relative sequences in text."""
    if not text:
        return ""
    t = text.replace("\\", "/")
    t = re.sub(r"/+", "/", t)
    t = re.sub(r"(?:^|(?<=[\s\'\"=]))\./+", "", t)
    prev = None
    while prev != t:
        prev = t
        t = re.sub(r"[a-zA-Z0-9_.-]+/+\.\./+", "", t)
    return t


def deobfuscate_shell_syntax(text: str) -> str:
    """Strip shell obfuscation: quote-splicing, backslash escapes, $IFS, hex/octal escapes, reversed text."""
    if not text:
        return ""
    s = text

    # 1. Expand $IFS and ${IFS} (case-insensitive) to space
    s = re.sub(r"(?i)\$(?:ifs|\{ifs\})", " ", s)

    # 2. Decode ANSI-C hex and octal escapes: $'\x72\x6d' or \x72\x6d or $'\162\155'
    def _decode_hex(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)

    s = re.sub(r"(?:\$')?\\x([0-9a-fA-F]{2})'?", _decode_hex, s)

    def _decode_octal(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 8))
        except ValueError:
            return m.group(0)

    s = re.sub(r"(?:\$')?\\([0-3][0-7]{2})'?", _decode_octal, s)

    # 3. Remove escaping backslashes from all characters (including spaces): \r\m\ \-\r\f -> rm -rf
    s = re.sub(r"\\(.)", r"\1", s)

    # 4. Collapse quote splicing: remove quotes within word tokens
    # E.g. r""m -> rm, 'r''m' -> rm, "r""m" -> rm, 'r'm -> rm, r'm' -> rm
    s = re.sub(r'""|\'\'', '', s)
    s = re.sub(r"(?<=[a-zA-Z0-9_./-])['\"]+|['\"]+(?=[a-zA-Z0-9_./-])", "", s)
    s = re.sub(r"(^|[\s;&|])['\"]([a-zA-Z0-9_./-]+)['\"](?=[\s;&|]|$)", r"\1\2", s)

    # 5. Simple brace expansion: {rm,-rf,/} -> rm -rf /
    def _expand_braces(m: re.Match) -> str:
        parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
        return " ".join(parts)

    s = re.sub(r"\{([^{}]+,[^{}]+)\}", _expand_braces, s)

    # 6. Inline subshell expansions: $(rev <<< '...'), $(echo '...'), `echo '...'`
    def _expand_rev_subshell(m: re.Match) -> str:
        return m.group(1)[::-1]

    s = re.sub(r"\$\(\s*rev\s*<<<\s*['\"]?([^'\"\)\n]+?)['\"]?\s*\)", _expand_rev_subshell, s)
    s = re.sub(r"\$\(\s*(?:echo|printf)\s+['\"]?([^'\"\)\n]+)['\"]?\s*\)", r"\1", s)
    s = re.sub(r"`\s*(?:echo|printf)\s+['\"]?([^'\"`\n]+)['\"]?\s*`", r"\1", s)

    m_rev = re.search(r"rev\s*<<<\s*['\"]?([^'\"\)\n]+?)['\"]?", s)
    if m_rev:
        s += " " + m_rev.group(1).strip()[::-1]
    m_rev_pipe = re.search(r"(?:echo|printf)\s+['\"]?([^'\"\|\n]+)['\"]?\s*\|\s*rev", s)
    if m_rev_pipe:
        s += " " + m_rev_pipe.group(1).strip()[::-1]

    return re.sub(r"\s+", " ", s).strip()


def decode_encoded_payloads(text: str) -> list[str]:
    """Extract and decode Base64 and hex payloads from PowerShell and Unix pipelines."""
    decoded_payloads: list[str] = []
    if not text:
        return decoded_payloads

    # 1. PowerShell -EncodedCommand / -enc / -ec / -e
    ps_enc_matches = re.finditer(
        r"(?:-|/)(?:encodedcommand|enc|ec|e)\s+[\"']?([A-Za-z0-9+/=]{8,})[\"']?",
        text,
        re.IGNORECASE,
    )
    for m in ps_enc_matches:
        raw_b64 = m.group(1)
        pad = (4 - len(raw_b64) % 4) % 4
        padded = raw_b64 + ("=" * pad)
        try:
            b = base64.b64decode(padded)
            decoded_utf16 = b.decode("utf-16le", errors="ignore").strip()
            if decoded_utf16:
                decoded_payloads.append(decoded_utf16)
            decoded_utf8 = b.decode("utf-8", errors="ignore").strip()
            if decoded_utf8 and decoded_utf8 != decoded_utf16:
                decoded_payloads.append(decoded_utf8)
        except Exception:
            pass

    # 2. Unix base64 decode pipelines: echo "<b64>" | base64 -d
    b64_pipe_matches = re.finditer(
        r"(?:echo|printf)\s+[\"']?([A-Za-z0-9+/=]{8,})[\"']?\s*\|\s*(?:base64\s+-(?:d|-decode)|openssl\s+enc\s+-d\s+-base64)",
        text,
        re.IGNORECASE,
    )
    for m in b64_pipe_matches:
        raw_b64 = m.group(1)
        pad = (4 - len(raw_b64) % 4) % 4
        padded = raw_b64 + ("=" * pad)
        try:
            b = base64.b64decode(padded)
            decoded_str = b.decode("utf-8", errors="ignore").strip()
            if decoded_str:
                decoded_payloads.append(decoded_str)
        except Exception:
            pass

    # 3. Certutil -decode blocks
    certutil_matches = re.finditer(
        r"certutil\s+-decode\w*\s+[\"']?([A-Za-z0-9+/=]{8,})[\"']?",
        text,
        re.IGNORECASE,
    )
    for m in certutil_matches:
        raw_b64 = m.group(1)
        pad = (4 - len(raw_b64) % 4) % 4
        padded = raw_b64 + ("=" * pad)
        try:
            b = base64.b64decode(padded)
            decoded_str = b.decode("utf-8", errors="ignore").strip()
            if decoded_str:
                decoded_payloads.append(decoded_str)
        except Exception:
            pass

    return decoded_payloads


_SHELL_NAMES = {"bash", "sh", "zsh", "dash", "ksh", "busybox", "csh", "tcsh"}
_PRIV_WRAPPERS = {"sudo", "doas", "runuser", "chroot", "nsenter"}
_UTIL_WRAPPERS = {"nohup", "timeout", "time", "nice", "ionice", "stdbuf", "xargs"}
_LANG_RUNNERS = {"python", "python3", "python2", "py", "node", "perl", "ruby", "php"}


def _split_tokens(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError:
        return [t.strip("\"'") for t in cmd.split() if t.strip()]


def unwrap_command_wrappers(text: str, max_depth: int = 5) -> list[str]:
    """Recursively peel wrapper commands (bash -c, eval, sudo, env, xargs, etc.) to extract all inner commands."""
    discovered: list[str] = [text]
    seen: set[str] = {text}

    def _add(cand: str, depth: int) -> None:
        cand = cand.strip()
        if not cand or cand in seen or depth > max_depth:
            return
        seen.add(cand)
        discovered.append(cand)
        _recurse(cand, depth + 1)

    def _recurse(curr: str, depth: int) -> None:
        if depth > max_depth:
            return

        # 1. Extract subshell contents: $(...) and `...`
        for sub in re.findall(r"\$\(([^()]+)\)", curr):
            _add(sub, depth)
        for sub in re.findall(r"`([^`]+)`", curr):
            _add(sub, depth)

        # 2. Extract process substitution: <(...) and >(...)
        for sub in re.findall(r"[<>]\(([^()]+)\)", curr):
            _add(sub, depth)

        # 3. Extract here-strings: bash <<< "..."
        for hs in re.findall(r"<<<\s*['\"]?([^'\"\n]+)['\"]?", curr):
            _add(hs, depth)

        # 4. Token-based unwrapping
        tokens = _split_tokens(curr)
        if not tokens:
            return

        # Skip leading environment variable assignments: e.g. FOO=bar BAZ=1 cmd ...
        idx = 0
        while idx < len(tokens) and re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*=.*$", tokens[idx]):
            idx += 1
        if idx > 0 and idx < len(tokens):
            _add(" ".join(tokens[idx:]), depth)
            tokens = tokens[idx:]

        if not tokens:
            return

        prog = os.path.basename(tokens[0]).lower()
        if prog.endswith(".exe"):
            prog = prog[:-4]

        # A. env command: env [-i] [VAR=VAL...] cmd
        if prog == "env" and len(tokens) > 1:
            sub_tokens = tokens[1:]
            while sub_tokens and (sub_tokens[0].startswith("-") or "=" in sub_tokens[0]):
                sub_tokens = sub_tokens[1:]
            if sub_tokens:
                _add(" ".join(sub_tokens), depth)

        # B. sudo / doas / privilege wrappers
        elif prog in _PRIV_WRAPPERS and len(tokens) > 1:
            sub_tokens = tokens[1:]
            i = 0
            while i < len(sub_tokens) and sub_tokens[i].startswith("-"):
                if sub_tokens[i] in ("-u", "-g", "--user", "--group") and i + 1 < len(sub_tokens):
                    i += 2
                else:
                    i += 1
            if i < len(sub_tokens):
                _add(" ".join(sub_tokens[i:]), depth)

        # C. Utility wrappers: nohup, timeout 10s, nice -n 19, time, etc.
        elif prog in _UTIL_WRAPPERS and len(tokens) > 1:
            sub_tokens = tokens[1:]
            i = 0
            while i < len(sub_tokens) and sub_tokens[i].startswith("-"):
                if sub_tokens[i] in ("-n", "-s", "-k", "-I", "-i", "-o", "-e", "-t") and i + 1 < len(sub_tokens):
                    i += 2
                else:
                    i += 1
            if prog == "timeout" and i < len(sub_tokens) and re.match(r"^\d+[smhd]?$", sub_tokens[i]):
                i += 1
            if i < len(sub_tokens):
                _add(" ".join(sub_tokens[i:]), depth)

        # D. Shell -c: bash -c "...", sh -c '...'
        elif prog in _SHELL_NAMES and len(tokens) >= 2:
            if "-c" in tokens:
                c_idx = tokens.index("-c")
                if c_idx + 1 < len(tokens):
                    _add(tokens[c_idx + 1], depth)
            elif len(tokens) >= 2 and not tokens[1].startswith("-"):
                _add(" ".join(tokens[1:]), depth)

        # E. PowerShell wrappers: powershell -c "...", pwsh -command "..."
        elif prog in ("powershell", "pwsh") and len(tokens) >= 2:
            for flag in ("-c", "-command", "/c", "/command"):
                for t_i, t in enumerate(tokens):
                    if t.lower() == flag and t_i + 1 < len(tokens):
                        _add(tokens[t_i + 1], depth)
                        break

        # F. CMD wrappers: cmd /c "...", cmd.exe /c "..."
        elif prog == "cmd" and len(tokens) >= 2:
            for flag in ("/c", "/k", "-c"):
                for t_i, t in enumerate(tokens):
                    if t.lower() == flag and t_i + 1 < len(tokens):
                        _add(" ".join(tokens[t_i + 1:]), depth)
                        break

        # G. eval and exec
        elif prog in ("eval", "exec") and len(tokens) > 1:
            _add(" ".join(tokens[1:]), depth)

        # H. Script interpreters: python -c "...", node -e "...", etc.
        elif prog in _LANG_RUNNERS and len(tokens) >= 2:
            for flag in ("-c", "-e", "-r", "--eval"):
                for t_i, t in enumerate(tokens):
                    if t.lower() == flag and t_i + 1 < len(tokens):
                        _add(tokens[t_i + 1], depth)
                        break

        # I. Chained / piped commands: split on &&, ||, ;, |
        if any(sep in curr for sep in ("&&", "||", ";", "|", "\n")):
            for seg in re.split(r"&&|\|\||;|\||\n", curr):
                seg = seg.strip()
                if seg and seg != curr:
                    _add(seg, depth)

        # J. Script file execution peeking (e.g. bash script.sh, sh ./test.sh, python run.py, ./script.sh)
        for cand in tokens:
            clean_sc = cand.strip("'\"`")
            if clean_sc and not clean_sc.startswith("-") and ("." in clean_sc or "/" in clean_sc or "\\" in clean_sc):
                try:
                    sc_path = Path(clean_sc)
                    if sc_path.is_file() and sc_path.stat().st_size <= 65536:
                        content = sc_path.read_text(encoding="utf-8", errors="ignore")
                        for line in content.splitlines():
                            line_s = line.strip()
                            if line_s and not line_s.startswith(("#", "//", ";", "rem", "::")):
                                _add(line_s, depth)
                except Exception:
                    pass

    _recurse(text, 1)
    return discovered


@dataclass
class RuleResult:
    decision: str
    matched: list[str] = field(default_factory=list)


@dataclass
class PathRule:
    """Policy rule bound to a directory path or file pattern."""
    name: str
    path: str
    decision: str
    all_commands: bool = True
    commands: list[str] = field(default_factory=list)
    path_regex: re.Pattern = field(init=False)
    command_regexes: list[re.Pattern] = field(default_factory=list, init=False)

    def __post_init__(self):
        p_raw = self.path.strip()
        is_complex = bool(re.search(r"[()|?*+^$]", p_raw))
        if is_complex:
            pattern_str = p_raw.replace(r"\/", r"[/\\]").replace(r"\\", r"[/\\]")
        else:
            clean_tail = p_raw.lstrip("/\\")
            if p_raw.startswith(("/", "\\")):
                pattern_str = r"(?:^|[a-zA-Z]:|[/\\])" + re.escape(clean_tail)
            else:
                escaped = re.escape(p_raw).replace(r"\/", r"[/\\]").replace(r"\\", r"[/\\]")
                pattern_str = r"\b" + escaped + r"\b" if p_raw.replace("-", "").replace("_", "").isalnum() else escaped
        self.path_regex = re.compile(pattern_str, re.IGNORECASE)

        self.command_regexes = []
        if not self.all_commands:
            for cmd in self.commands:
                cmd_raw = cmd.strip()
                if not cmd_raw:
                    continue
                if bool(re.search(r"[()|?*+^$]", cmd_raw)):
                    self.command_regexes.append(re.compile(cmd_raw, re.IGNORECASE))
                else:
                    rx = r"\b" + re.escape(cmd_raw) + r"\b" if cmd_raw.replace("-", "").replace("_", "").isalnum() else re.escape(cmd_raw)
                    self.command_regexes.append(re.compile(rx, re.IGNORECASE))

    def matches(self, text: str) -> bool:
        norm_text = _canonicalize_path_string(text)
        matched_path = bool(self.path_regex.search(text) or self.path_regex.search(norm_text))
        if not matched_path:
            for token in text.split():
                clean_tok = token.strip("'\"`")
                if ("/" in clean_tok or "\\" in clean_tok or "." in clean_tok) and not clean_tok.startswith("-"):
                    try:
                        p_obj = Path(clean_tok)
                        if p_obj.exists():
                            resolved = str(p_obj.resolve()).replace("\\", "/")
                            if self.path_regex.search(resolved):
                                matched_path = True
                                break
                    except Exception:
                        pass
        if not matched_path:
            return False
        if self.all_commands:
            return True
        return any(rx.search(text) or rx.search(norm_text) for rx in self.command_regexes) if self.command_regexes else False


# --- External Policy Configuration (policy.yaml) ---

def load_policy(file_path: str | Path | None = None) -> dict:
    """Load customized rules and settings from policy.yaml."""
    global _POLICY_LOADED, _CUSTOM_BLOCK, _CUSTOM_ASK, _CUSTOM_PROCEED, _PATH_RULES, _POLICY_SETTINGS
    p = Path(file_path or os.environ.get("GUARDRAIL_POLICY_FILE", Path(__file__).resolve().parent / "policy.yaml"))
    if not p.is_file():
        _POLICY_LOADED = True
        return {}

    try:
        import yaml
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        if _debug_enabled():
            _log(f"[guardrail:policy] Error reading {p}: {exc}")
        _POLICY_LOADED = True
        return {}

    _CUSTOM_BLOCK = [
        (r.get("name", "custom_block"), re.compile(r.get("pattern", ""), re.IGNORECASE))
        for r in data.get("custom_block_rules", []) if r.get("pattern")
    ]
    _CUSTOM_ASK = [
        (r.get("name", "custom_ask"), re.compile(r.get("pattern", ""), re.IGNORECASE))
        for r in data.get("custom_ask_rules", []) if r.get("pattern")
    ]
    _CUSTOM_PROCEED = [
        (r.get("name", "custom_proceed"), re.compile(r.get("pattern", ""), re.IGNORECASE))
        for r in data.get("custom_proceed_rules", []) if r.get("pattern")
    ]

    raw_path_rules = data.get("path_rules", []) or data.get("custom_path_rules", [])
    _PATH_RULES = []
    for pr in raw_path_rules:
        if not pr.get("path"):
            continue
        p_name = pr.get("name", f"path:{pr.get('path')}")
        p_decision = str(pr.get("decision", "ask_user")).lower()
        if p_decision not in VALID_DECISIONS:
            p_decision = "ask_user"
        p_commands = pr.get("commands", [])
        if isinstance(p_commands, str):
            p_commands = [p_commands]
        try:
            _PATH_RULES.append(PathRule(
                name=p_name,
                path=pr.get("path", ""),
                decision=p_decision,
                all_commands=bool(pr.get("all_commands", True)),
                commands=p_commands,
            ))
        except Exception as exc:
            if _debug_enabled():
                _log(f"[guardrail:policy] Error compiling path rule '{p_name}': {exc}")

    _POLICY_SETTINGS = data.get("settings", {})
    _POLICY_LOADED = True
    return data


def evaluate_rules(description: str) -> RuleResult:
    """Evaluate deterministic rules, path rules, and policy.yaml with recursive unwrapping."""
    if not _POLICY_LOADED:
        load_policy()

    # 1. Base normalization (homoglyphs, invisible chars, quotes, lower)
    base_text = normalize(description)
    if not base_text:
        return RuleResult("proceed", [])

    # 2. De-obfuscate shell syntax (quote splicing, backslashes, IFS, hex/octal)
    deobf_text = deobfuscate_shell_syntax(base_text)

    # 3. Extract decoded payloads (PowerShell Base64 UTF-16LE, Unix base64 pipes)
    decoded_payloads = decode_encoded_payloads(description) + decode_encoded_payloads(base_text)

    # 4. Recursively unwrap all command wrappers
    unwrapped_layers: list[str] = []
    candidates = [description, base_text, deobf_text] + decoded_payloads
    for cand in candidates:
        if not cand:
            continue
        for unwrapped in unwrap_command_wrappers(cand):
            unwrapped_norm = normalize(unwrapped)
            unwrapped_deobf = deobfuscate_shell_syntax(unwrapped_norm)
            for item in (unwrapped, unwrapped_norm, unwrapped_deobf):
                if item and item not in unwrapped_layers:
                    unwrapped_layers.append(item)

    if not unwrapped_layers:
        unwrapped_layers = [base_text]

    # 5. Evaluate all layers: most severe takes absolute priority
    # Check block rules first across ALL layers
    all_blocks = list(_COMPILED_BLOCK) + _CUSTOM_BLOCK
    blocked_matches: list[str] = []
    for layer in unwrapped_layers:
        for name, rx in all_blocks:
            match_found = rx.search(description) if name == "git branch force delete" else rx.search(layer)
            if match_found:
                tag = f"block:{name}"
                if tag not in blocked_matches:
                    blocked_matches.append(tag)

    if blocked_matches:
        return RuleResult("block", blocked_matches)

    # Check path block rules across ALL layers
    path_blocks: list[str] = []
    for layer in unwrapped_layers:
        for r in _PATH_RULES:
            if r.decision == "block" and r.matches(layer):
                tag = f"block:path:{r.name}"
                if tag not in path_blocks:
                    path_blocks.append(tag)

    if path_blocks:
        return RuleResult("block", path_blocks)

    # Check path ask rules across ALL layers
    path_asks: list[str] = []
    for layer in unwrapped_layers:
        for r in _PATH_RULES:
            if r.decision == "ask_user" and r.matches(layer):
                tag = f"ask_user:path:{r.name}"
                if tag not in path_asks:
                    path_asks.append(tag)

    if path_asks:
        return RuleResult("ask_user", path_asks)

    # Check whitelist (proceed rules) across outer text
    all_proceed_rules = list(_COMPILED_PROCEED) + _CUSTOM_PROCEED
    whitelist_matches = [name for name, rx in all_proceed_rules if rx.search(base_text) or rx.search(deobf_text)]
    path_proceeds = [r.name for r in _PATH_RULES if r.decision == "proceed" and (r.matches(base_text) or r.matches(deobf_text))]
    all_proceeds = [f"proceed:whitelist:{n}" for n in whitelist_matches] + [f"proceed:path:{n}" for n in path_proceeds]
    if all_proceeds:
        return RuleResult("proceed", all_proceeds)

    # Check command ask rules across ALL layers
    all_asks = list(_COMPILED_ASK) + _CUSTOM_ASK
    asked_matches: list[str] = []
    for layer in unwrapped_layers:
        for name, rx in all_asks:
            if rx.search(layer):
                tag = f"ask_user:{name}"
                if tag not in asked_matches:
                    asked_matches.append(tag)

    if asked_matches:
        return RuleResult("ask_user", asked_matches)

    return RuleResult("proceed", [])


class GuardrailError(Exception):
    pass


# --- Jev Backend (Cloud) ---
JEV_DEFAULT_ENDPOINT = "https://api.jev.typesafe.ai/v1/decide"


def ask_jev(description: str) -> str:
    """Query Jev Choice API. Returns proceed, block, or ask_user."""
    api_key = os.environ.get("JEV_API_KEY")
    if not api_key:
        raise GuardrailError("JEV_API_KEY is not set")

    endpoint = os.environ.get("JEV_ENDPOINT", JEV_DEFAULT_ENDPOINT)
    timeout = _env_float("GUARDRAIL_TIMEOUT_SECS", DEFAULT_TIMEOUT)

    payload = {
        "type": "choice",
        "options": list(VALID_DECISIONS),
        "context": description,
        "instructions": (
            "Evaluate action risk for an AI coding assistant. Choose 'block' for destructive, "
            "irreversible actions or secrets exposure; 'ask_user' for configs, deps, remote git, "
            "or ambiguous requests; 'proceed' ONLY for clearly safe, local actions. When in doubt: 'ask_user'."
        ),
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    decision = body.get("decision") if isinstance(body, dict) else None
    if decision not in VALID_DECISIONS:
        raise GuardrailError(f"Invalid Jev response: {body!r}")
    return decision


# --- CLM Backend (Local clm-serve) ---
CLM_DEFAULT_BASE_URL = "http://127.0.0.1:8700"
CLM_INSTRUCTIONS = "How risky is this coding agent action? Safe (proceed), confirm (ask_user), or dangerous (block)?"

CLM_DECISION_CRITERIA = {
    "proceed": (
        "Safe, local, and reversible action that only reads or modifies project source code "
        "or documentation with no external impact. Examples: read or summarize a file, analyze data, "
        "fix a typo, add a comment or unit test, rename a variable, refactor a function, run tests."
    ),
    "ask_user": (
        "Action with notable side effects requiring user confirmation: modifies configs, dependencies, "
        "build or deploy scripts, .env, database, permissions; git push; installs packages; sends "
        "emails; deletes a file; or vague request. Examples: update requirements.txt, pip install, "
        "modify docker-compose, git push, do the best thing with this account."
    ),
    "block": (
        "Destructive, irreversible, dangerous, or prohibited action to block: deletes data, directories, "
        "or database; rm -rf, git push --force, git reset --hard, DROP TABLE, delete or leak credentials, "
        "API keys, passwords, or .env; modify production without rollback, disable security or guardrails, "
        "policy violations."
    ),
}

# --- Liquid AI d1-3B Backend ---
LIQUID_DEFAULT_ENDPOINT = "http://127.0.0.1:8800/v1"
LIQUID_DEFAULT_MODEL = "d1-3b"

LIQUID_DECISION_CRITERIA: dict[str, str] = {
    "proceed": "Safe, local, and reversible developer actions (code reads, edits, unit tests, linting, git status).",
    "ask_user": "Actions modifying configs, dependencies, git remote push, production environments, or ambiguous instructions.",
    "block": "Destructive system or database deletion, disk format, secret exposure, or disabling security/guardrails.",
}


def _get_liquid_endpoint() -> str:
    if "LIQUID_ENDPOINT" in os.environ:
        return os.environ["LIQUID_ENDPOINT"]
    if "liquid_endpoint" in _POLICY_SETTINGS and _POLICY_SETTINGS["liquid_endpoint"]:
        return str(_POLICY_SETTINGS["liquid_endpoint"])
    return LIQUID_DEFAULT_ENDPOINT


def _get_liquid_model() -> str:
    if "LIQUID_MODEL" in os.environ:
        return os.environ["LIQUID_MODEL"]
    if "liquid_model" in _POLICY_SETTINGS and _POLICY_SETTINGS["liquid_model"]:
        return str(_POLICY_SETTINGS["liquid_model"])
    return LIQUID_DEFAULT_MODEL


@dataclass
class ModelResult:
    decision: str
    raw_choice: str | None = None
    confidence: float | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    note: str = ""
    used_qwen: bool = False
    qwen_explanation: str | None = None


# --- Qwen Semantic Knowledge (System 2 fallback for esoteric CLI) ---
QWEN_DEFAULT_BASE_URL = "http://127.0.0.1:8090/v1"

OFFLINE_ESOTERIC_KNOWLEDGE: dict[str, str] = {
    "shred": "Destructive file shredding operation, permanently overwriting and deleting data.",
    "wipefs": "Destructive partition table and filesystem signature erasure.",
    "strace": "Read-only system call tracing and debugging tool. Does not modify files.",
    "tar": "Creates or extracts local compressed archives. Safe file packaging.",
    "iptables -f": "Flushes all firewall rules, exposing network or severing connections.",
    "dconf reset": "Resets user configuration values to defaults.",
    "ethtool": "Configures network interface hardware and link parameters.",
    "zfs destroy": "Permanently destroys a ZFS filesystem dataset or snapshot.",
    "chroot": "Changes process root directory, privileged system operation.",
    "setenforce 0": "Disables SELinux enforcement putting system in permissive mode.",
    "ss -tulpn": "Displays listening sockets and network connections, read-only diagnostic.",
}

_QWEN_SERVER_AVAILABLE: bool | None = None
_QWEN_LAST_CHECK_TIME: float = 0.0
_QWEN_RETRY_INTERVAL: float = 15.0


def _get_qwen_base_url() -> str:
    if "QWEN_BASE_URL" in os.environ:
        return os.environ["QWEN_BASE_URL"]
    if "qwen_base_url" in _POLICY_SETTINGS and _POLICY_SETTINGS["qwen_base_url"]:
        return str(_POLICY_SETTINGS["qwen_base_url"])
    return QWEN_DEFAULT_BASE_URL


def _get_qwen_timeout() -> float:
    if "GUARDRAIL_QWEN_TIMEOUT_SECS" in os.environ:
        try:
            return float(os.environ["GUARDRAIL_QWEN_TIMEOUT_SECS"])
        except (TypeError, ValueError):
            pass
    for k in ("qwen_timeout_secs", "guardrail_qwen_timeout_secs"):
        if k in _POLICY_SETTINGS:
            try:
                return float(_POLICY_SETTINGS[k])
            except (TypeError, ValueError):
                pass
    return 3.5


def _is_qwen_enabled() -> bool:
    env_val = os.environ.get("GUARDRAIL_USE_QWEN")
    if env_val is not None:
        return env_val.strip().lower() not in ("0", "false", "no")
    if "use_qwen" in _POLICY_SETTINGS:
        val = _POLICY_SETTINGS["use_qwen"]
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() not in ("0", "false", "no")
    return True


def ask_qwen_explain(description: str) -> str | None:
    """Query Qwen 3.8B System 2 to explain unknown or esoteric CLI commands."""
    global _QWEN_SERVER_AVAILABLE, _QWEN_LAST_CHECK_TIME

    # Check offline esoteric knowledge first for instant (< 0.1ms) resolution
    lower_desc = description.lower()
    for k, expl in OFFLINE_ESOTERIC_KNOWLEDGE.items():
        if k in lower_desc:
            return expl

    if not _is_qwen_enabled():
        return None

    now = time.monotonic()
    if _QWEN_SERVER_AVAILABLE is False:
        if (now - _QWEN_LAST_CHECK_TIME) < _QWEN_RETRY_INTERVAL and "QWEN_BASE_URL" not in os.environ:
            return None

    base_url = _get_qwen_base_url().rstrip("/")
    if "localhost" in base_url:
        base_url = base_url.replace("localhost", "127.0.0.1")
    endpoint = f"{base_url}/chat/completions"
    timeout = _get_qwen_timeout()

    payload = {
        "model": "qwen",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity expert analyzing shell commands. "
                    "In 2 concise sentences, state: 1) What this command does. "
                    "2) What resources it modifies/deletes. 3) Whether it is destructive, "
                    "requires authorization, or is safe read-only."
                ),
            },
            {"role": "user", "content": f"Command: {description}"},
        ],
        "max_tokens": 80,
        "temperature": 0.1,
    }

    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices", [])
            if choices and "message" in choices[0]:
                msg = choices[0]["message"]
                content = (msg.get("content") or "").strip()
                if not content:
                    content = (msg.get("reasoning_content") or "").strip()
                content = re.sub(r"</?think>", "", content).strip()
                if content:
                    _QWEN_SERVER_AVAILABLE = True
                    return content
    except Exception as exc:
        _QWEN_SERVER_AVAILABLE = False
        _QWEN_LAST_CHECK_TIME = now
        if _debug_enabled():
            _log(f"[guardrail:qwen] Server call failed: {exc}")
        return None

    return None


def interpret_clm_answer(choice: str, confidence: float, probabilities: dict[str, float]) -> ModelResult:
    """Interpret CLM probabilities: block when indicated, proceed with reasonable confidence, else ask_user."""
    if choice not in VALID_DECISIONS:
        raise GuardrailError(f"Invalid CLM choice: {choice!r}")

    min_conf = _env_float("CLM_MIN_CONFIDENCE", 0.50)
    proceed_min_prob = _env_float("CLM_PROCEED_MIN_PROB", 0.50)
    block_alert = _env_float("CLM_BLOCK_ALERT_PROB", 0.20)

    p_proceed = float(probabilities.get("proceed", 0.0))
    p_block = float(probabilities.get("block", 0.0))

    if choice == "block":
        if confidence >= min_conf:
            return ModelResult("block", choice, confidence, probabilities, "block with sufficient confidence")
        return ModelResult("ask_user", choice, confidence, probabilities, "low confidence block -> ask_user")

    if choice == "proceed":
        reasons = []
        if confidence < min_conf:
            reasons.append(f"confidence {confidence:.2f} < {min_conf}")
        if p_proceed < proceed_min_prob:
            reasons.append(f"P(proceed) {p_proceed:.2f} < {proceed_min_prob}")
        if p_block >= block_alert:
            reasons.append(f"P(block) {p_block:.2f} >= {block_alert}")
        if reasons:
            return ModelResult("ask_user", choice, confidence, probabilities,
                               "unreliable proceed (" + ", ".join(reasons) + ") -> ask_user")
        return ModelResult("proceed", choice, confidence, probabilities, "proceed with strong evidence")

    return ModelResult("ask_user", choice, confidence, probabilities, "ask_user from model")


def ask_clm(description: str) -> ModelResult:
    """Query local CLM embedding model; escalate to Qwen on low confidence."""
    try:
        from clm import CLMClient, Choice
    except ImportError as exc:
        raise GuardrailError("clm package not installed: pip install -r requirements.txt from clm repo") from exc

    base_url = os.environ.get("CLM_BASE_URL", _POLICY_SETTINGS.get("clm_base_url", CLM_DEFAULT_BASE_URL))
    if "localhost" in base_url:
        base_url = base_url.replace("localhost", "127.0.0.1")
    timeout = _env_float("GUARDRAIL_TIMEOUT_SECS", DEFAULT_TIMEOUT)

    try:
        client = CLMClient(base_url=base_url, timeout=timeout)
        result = client.system_one(
            state=f"Action: {description}",
            questions={
                "decision": Choice(instructions=CLM_INSTRUCTIONS, criteria=dict(CLM_DECISION_CRITERIA)),
            },
        )
    except Exception as exc:
        err_msg = str(exc)
        if any(c in err_msg for c in ("10061", "Connection refused", "Failed to connect", "Max retries exceeded", "ConnectionRefusedError", "ConnectError")):
            raise GuardrailError(
                "CLM backend is unavailable.\n"
                "  - Ensure Qwen 3.8B is running on port 8090: llama-server -m <qwen.gguf> --embedding --port 8090\n"
                "  - Ensure clm-serve is running on port 8700: clm-serve --emb-url http://127.0.0.1:8090/v1/embeddings\n"
                "  - Or switch backend in policy.yaml to 'd1', 'jev', or 'rules'."
            ) from exc
        raise GuardrailError(f"CLM error: {exc}") from exc

    try:
        answer = result.answers["decision"]
        choice = answer.choice
        confidence = float(answer.confidence)
        probabilities = {k: float(v) for k, v in dict(answer.probabilities).items()}
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise GuardrailError(f"Unexpected clm-serve response: {result!r}") from exc

    res = interpret_clm_answer(choice, confidence, probabilities)

    # Qwen System 2 escalation on low confidence
    min_conf = _env_float("CLM_MIN_CONFIDENCE", 0.6)
    if confidence < min_conf:
        explanation = ask_qwen_explain(description)
        if explanation:
            enriched_state = f"Action: {description}\nTechnical explanation: {explanation}"
            try:
                enr_res = client.system_one(
                    state=enriched_state,
                    questions={
                        "decision": Choice(instructions=CLM_INSTRUCTIONS, criteria=dict(CLM_DECISION_CRITERIA)),
                    },
                )
                enr_ans = enr_res.answers["decision"]
                enr_choice = enr_ans.choice
                enr_conf = float(enr_ans.confidence)
                enr_probs = {k: float(v) for k, v in dict(enr_ans.probabilities).items()}
                res_enriched = interpret_clm_answer(enr_choice, enr_conf, enr_probs)
                res_enriched.used_qwen = True
                res_enriched.qwen_explanation = explanation
                res_enriched.note += " (resolved via Qwen semantic analysis)"
                return res_enriched
            except Exception as e:
                if _debug_enabled():
                    _log(f"[guardrail:clm] Failed Qwen re-inference: {e}")

    return res


def _call_liquid_api(endpoint: str, model_name: str, description: str, timeout: float) -> tuple[str, float, dict[str, float]]:
    """Query Liquid AI d1-3B either via native llama-server systemone, decide endpoint, or chat completions."""
    api_key = os.environ.get("LIQUID_API_KEY", "")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    base_url = endpoint.rstrip("/")
    if "localhost" in base_url:
        base_url = base_url.replace("localhost", "127.0.0.1")

    # llama.cpp decision models natively expose /v1/systemone
    is_systemone = base_url.endswith("/systemone") or not any(base_url.endswith(sub) for sub in ("/chat/completions", "/decide", "/decision", "/choice"))
    is_native_decide = any(base_url.endswith(sub) for sub in ("/decide", "/decision", "/choice"))

    def _try_request(url: str, payload: dict) -> dict:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    data = None
    last_exc = None

    if is_systemone:
        url_sys = f"{base_url}/systemone" if not base_url.endswith("/systemone") else base_url
        payload_sys = {
            "state": f"Action: {description}",
            "questions": {
                "decision": {
                    "type": "choice",
                    "instructions": "Evaluate action risk for an AI coding assistant: proceed (safe), ask_user (confirm), block (dangerous).",
                    "options": list(VALID_DECISIONS),
                    "criteria": LIQUID_DECISION_CRITERIA,
                }
            },
        }
        try:
            data = _try_request(url_sys, payload_sys)
        except Exception as exc:
            last_exc = exc
            # If 404 Not Found, try /chat/completions fallback
            if "404" in str(exc) or "HTTP Error 404" in str(exc):
                url_chat = f"{base_url}/chat/completions"
                payload_chat = {
                    "model": model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a cybersecurity safety classifier for AI coding actions. "
                                "Evaluate the action risk and respond ONLY with JSON containing: "
                                '{"decision": "proceed"|"ask_user"|"block", "confidence": <float 0-1>, '
                                '"probabilities": {"proceed": <float>, "ask_user": <float>, "block": <float>}}.\n'
                                "Criteria:\n"
                                "- proceed: Safe local read, unit tests, code edits, git status.\n"
                                "- ask_user: Configs, dependency installs, git push, ambiguous or broad actions.\n"
                                "- block: Destructive deletions, secret leaks, disk formats, disabling security."
                            ),
                        },
                        {"role": "user", "content": f"Action: {description}"},
                    ],
                    "temperature": 0.0,
                    "max_tokens": 100,
                }
                try:
                    data = _try_request(url_chat, payload_chat)
                except Exception as exc2:
                    last_exc = exc2
    elif is_native_decide:
        payload_decide = {
            "model": model_name,
            "task": "choice",
            "context": f"Action: {description}",
            "options": list(VALID_DECISIONS),
            "criteria": LIQUID_DECISION_CRITERIA,
        }
        try:
            data = _try_request(base_url, payload_decide)
        except Exception as exc:
            last_exc = exc
    else:
        url_chat = f"{base_url}/chat/completions" if not base_url.endswith("/chat/completions") else base_url
        payload_chat = {
            "model": model_name,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity safety classifier for AI coding actions. "
                        "Evaluate the action risk and respond ONLY with JSON containing: "
                        '{"decision": "proceed"|"ask_user"|"block", "confidence": <float 0-1>, '
                        '"probabilities": {"proceed": <float>, "ask_user": <float>, "block": <float>}}.\n'
                        "Criteria:\n"
                        "- proceed: Safe local read, unit tests, code edits, git status.\n"
                        "- ask_user: Configs, dependency installs, git push, ambiguous or broad actions.\n"
                        "- block: Destructive deletions, secret leaks, disk formats, disabling security."
                    ),
                },
                {"role": "user", "content": f"Action: {description}"},
            ],
            "temperature": 0.0,
            "max_tokens": 100,
        }
        try:
            data = _try_request(url_chat, payload_chat)
        except Exception as exc:
            last_exc = exc

    if data is None:
        err_msg = str(last_exc)
        if any(c in err_msg for c in ("10061", "Connection refused", "Failed to connect", "URLError", "timed out", "Timeout")):
            raise GuardrailError(
                f"Liquid AI d1-3B backend is unreachable at {base_url}.\n"
                "  - Start d1-3B locally (e.g., llama-server -m <d1-3b.gguf> --port 8800)\n"
                "  - Or configure liquid_endpoint in policy.yaml\n"
                "  - Or switch backend in policy.yaml to 'clm', 'jev', or 'rules'."
            ) from last_exc
        raise GuardrailError(f"Liquid AI d1-3B query error: {last_exc}") from last_exc

    # Parse response: 1. systemone format (data["answers"]["decision"])
    if "answers" in data and isinstance(data["answers"], dict):
        ans = data["answers"].get("decision") or next(iter(data["answers"].values()))
        choice = str(ans.get("choice") or ans.get("decision") or "ask_user").lower()
        confidence = float(ans.get("confidence", 0.5))
        probabilities = {k: float(v) for k, v in ans.get("probabilities", {}).items()}
    # 2. native decide format (data["decision"] or data["choice"])
    elif "decision" in data or "choice" in data:
        choice = str(data.get("decision") or data.get("choice") or "ask_user").lower()
        confidence = float(data.get("confidence", 0.5))
        probabilities = {k: float(v) for k, v in data.get("probabilities", {}).items()}
    # 3. OpenAI chat completion format (data["choices"][0]["message"]["content"])
    else:
        choices = data.get("choices", [])
        if not choices or "message" not in choices[0]:
            raise GuardrailError(f"Unexpected response structure from d1-3B: {data!r}")
        raw_text = (choices[0]["message"].get("content") or "").strip()
        match = re.search(r"\{.*\}", raw_text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                choice = str(parsed.get("decision", "ask_user")).lower()
                confidence = float(parsed.get("confidence", 0.5))
                probabilities = {k: float(v) for k, v in parsed.get("probabilities", {}).items()}
            except Exception:
                choice = "ask_user"
                confidence = 0.5
                probabilities = {}
        else:
            lower_text = raw_text.lower()
            if "block" in lower_text:
                choice = "block"
            elif "proceed" in lower_text:
                choice = "proceed"
            else:
                choice = "ask_user"
            confidence = 0.5
            probabilities = {}

    if choice not in VALID_DECISIONS:
        choice = "ask_user"

    return choice, confidence, probabilities


def ask_liquid_d1(description: str) -> ModelResult:
    """Query Liquid AI d1-3B model; escalate to Qwen if enabled and confidence is low."""
    endpoint = _get_liquid_endpoint()
    model_name = _get_liquid_model()
    timeout = _env_float("GUARDRAIL_TIMEOUT_SECS", DEFAULT_TIMEOUT)

    choice, confidence, probabilities = _call_liquid_api(endpoint, model_name, description, timeout)
    res = interpret_clm_answer(choice, confidence, probabilities)

    # Qwen System 2 escalation on low confidence (ONLY when use_qwen is true)
    min_conf = _env_float("LIQUID_MIN_CONFIDENCE", 0.55)
    if _is_qwen_enabled() and confidence < min_conf:
        explanation = ask_qwen_explain(description)
        if explanation:
            enriched_desc = f"{description}\nTechnical context: {explanation}"
            try:
                enr_choice, enr_conf, enr_probs = _call_liquid_api(endpoint, model_name, enriched_desc, timeout)
                res_enriched = interpret_clm_answer(enr_choice, enr_conf, enr_probs)
                res_enriched.used_qwen = True
                res_enriched.qwen_explanation = explanation
                res_enriched.note += " (resolved via Qwen System 2 + d1-3B)"
                return res_enriched
            except Exception as e:
                if _debug_enabled():
                    _log(f"[guardrail:liquid] Qwen escalation re-inference failed: {e}")

    return res


def _ask_jev_result(description: str) -> ModelResult:
    try:
        decision = ask_jev(description)
    except Exception as exc:
        err_msg = str(exc)
        if "JEV_API_KEY" in err_msg:
            raise GuardrailError(
                "JEV backend requires JEV_API_KEY environment variable. "
                "Set it or switch backend in policy.yaml to 'clm', 'd1', or 'rules'."
            ) from exc
        raise
    res = ModelResult(decision, decision, note="Jev decision")
    if _is_qwen_enabled() and decision == "ask_user":
        explanation = ask_qwen_explain(description)
        if explanation:
            res.used_qwen = True
            res.qwen_explanation = explanation
    return res


BACKENDS = {
    "jev": _ask_jev_result,
    "clm": ask_clm,
    "d1": ask_liquid_d1,
    "liquid": ask_liquid_d1,
    "rules": lambda desc: ModelResult("proceed", note="rules-only backend"),
}


@dataclass
class Decision:
    decision: str
    backend: str
    rules: RuleResult
    model: ModelResult | None = None
    error: str | None = None

    def explain(self) -> str:
        parts = [f"final={self.decision}", f"backend={self.backend}"]
        parts.append(f"rules={self.rules.decision}" + (f" {self.rules.matched}" if self.rules.matched else ""))
        if self.model is not None:
            m = self.model
            probs = ", ".join(f"{k}={v:.3f}" for k, v in m.probabilities.items())
            conf = f"{m.confidence:.3f}" if m.confidence is not None else "N/A"
            parts.append(f"model={m.decision} (choice={m.raw_choice}, conf={conf}{', ' + probs if probs else ''}; {m.note})")
            if m.qwen_explanation:
                parts.append(f'qwen_reasoning="{m.qwen_explanation}"')
        if self.error:
            parts.append(f"backend_error={self.error}")
        return " | ".join(parts)


def fallback_decision(description: str) -> str:
    """Model failure fallback: use rules, never silent proceed."""
    return most_severe(evaluate_rules(description).decision, "ask_user")


def decide(description: str, backend_name: str | None = None) -> Decision:
    """Main decision function: rules -> backend -> most severe."""
    if not _POLICY_LOADED:
        load_policy()
    if backend_name is None:
        backend_name = os.environ.get("GUARDRAIL_BACKEND") or _POLICY_SETTINGS.get("backend", "clm")
    backend_name = backend_name.strip().lower()
    rules = evaluate_rules(description)

    if not description.strip():
        return Decision("ask_user", backend_name, rules, error="empty description")

    # Zero-tolerance: immediate block bypasses model
    if rules.decision == "block":
        return Decision("block", backend_name, rules)

    # Pure rules-only backend
    if backend_name == "rules":
        return Decision(rules.decision, "rules", rules, model=ModelResult(rules.decision, note="rules only"))

    backend_fn = BACKENDS.get(backend_name)
    if backend_fn is None:
        return Decision(fallback_decision(description), backend_name, rules, error=f"unknown backend '{backend_name}'")

    try:
        model = backend_fn(description)
    except Exception as exc:  # noqa: BLE001
        return Decision(fallback_decision(description), backend_name, rules, error=f"{type(exc).__name__}: {exc}")

    if rules.decision == "proceed" and rules.matched:
        # Coreutils read CLI commands (wc, cat, ls, grep, etc.) and safe test/lint tools are inspection: prevent embedding hallucinations from blocking them
        if any(w in rules.matched for w in ("proceed:whitelist:read cli", "proceed:whitelist:test lint cli")) and not re.search(_SECRET, normalize(description)):
            final_decision = "proceed"
        else:
            final_decision = "block" if model.decision == "block" else "proceed"
    elif rules.decision == "ask_user" and rules.matched:
        # Explicit confirmation or ambiguous instructions must ask user, never escalate to block
        if any("vague instruction" in m or "confirmation requested" in m for m in rules.matched):
            final_decision = "ask_user"
        elif model.decision == "block":
            is_pkg_rule = any("dependency install" in m for m in rules.matched)
            min_block_conf = 0.70 if is_pkg_rule else 0.60
            final_decision = "block" if (model.confidence or 0.0) >= min_block_conf else "ask_user"
        else:
            final_decision = "ask_user"
    else:
        final_decision = most_severe(rules.decision, model.decision)

    return Decision(final_decision, backend_name, rules, model)


def main() -> int:
    if len(sys.argv) < 2:
        _log('Usage: check_action.py "<action description>" [--backend <clm|d1|jev|rules>] [--explain]')
        _log('       check_action.py --start | --stop | --status')
        return 2

    raw_args = sys.argv[1:]
    first_arg = raw_args[0].lower()

    if first_arg in ("--start", "start"):
        try:
            import daemon_manager
            ok, msg = daemon_manager.start_daemon()
            print(msg)
            return 0 if ok else 1
        except Exception as exc:
            _log(f"Error starting daemon: {exc}")
            return 1

    if first_arg in ("--stop", "stop"):
        try:
            import daemon_manager
            ok, msg = daemon_manager.stop_daemon()
            print(msg)
            return 0 if ok else 1
        except Exception as exc:
            _log(f"Error stopping daemon: {exc}")
            return 1

    if first_arg in ("--status", "status"):
        try:
            import daemon_manager
            print(daemon_manager.format_status_report())
            return 0
        except Exception as exc:
            _log(f"Error checking status: {exc}")
            return 1

    show_explain = False
    cli_backend = None
    cleaned_args = []
    skip_next = False
    for i, arg in enumerate(raw_args):
        if skip_next:
            skip_next = False
            continue
        if arg in ("--explain", "-e", "--verbose", "-v"):
            show_explain = True
        elif arg in ("--backend", "-b") and i + 1 < len(raw_args):
            cli_backend = raw_args[i + 1]
            skip_next = True
        elif arg.startswith("--backend="):
            cli_backend = arg.split("=", 1)[1]
        else:
            cleaned_args.append(arg)

    if not cleaned_args:
        _log('Usage: check_action.py "<action description>" [--backend <clm|d1|jev|rules>] [--explain]')
        return 2

    description = " ".join(cleaned_args)
    result = decide(description, backend_name=cli_backend)

    if result.error:
        _log(f"[guardrail:{result.backend}] fallback active: {result.error}")
    if _debug_enabled() or show_explain:
        _log(f"[guardrail] {result.explain()}")

    print(result.decision)
    return 0


if __name__ == "__main__":
    sys.exit(main())