#!/usr/bin/env python3
"""Read-only session mode (`/guardrail readonly`).

Best-effort detection of shell commands that change files, repositories, packages, containers or
the system, so a session can explore or review code without modifying anything. It looks at the command
word of every link of a chain (and at what wrappers, `bash -c` and `$(...)` run), at output
redirections and at the sub-commands of git, package managers, docker and kubectl.

It cannot see what a script does once it runs (`python build.py`, `make`): those are allowed. File-edit
tools (Write, Edit, apply_patch...) are refused by the hook before they get here.
"""

from __future__ import annotations

import os
import re

import check_action as ca

_WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "timeout", "nice", "ionice", "stdbuf", "command",
             "builtin", "exec", "xargs", "setsid"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "powershell", "pwsh", "cmd"}
_INTERPRETERS = {"python", "python2", "python3", "py", "node", "perl", "ruby", "php", "lua"}

# Commands whose whole purpose is to change something
_ALWAYS_WRITE = {
    "rm", "rmdir", "del", "erase", "rd", "mv", "move", "cp", "copy", "xcopy", "robocopy", "ren", "rename", "mkdir",
    "md", "touch", "ln", "mklink", "chmod", "chown", "chgrp", "icacls", "takeown", "attrib", "tee", "truncate", "dd",
    "shred", "wipefs", "mkfs", "format", "diskpart", "fdisk", "mount", "umount", "install", "patch", "unzip", "zip",
    "7z", "gzip", "gunzip", "bzip2", "rsync", "scp", "sftp", "kill", "pkill", "killall", "taskkill", "shutdown",
    "reboot", "halt", "poweroff", "crontab", "schtasks", "setx", "useradd", "userdel", "usermod", "passwd",
    # PowerShell
    "set-content", "add-content", "out-file", "clear-content", "new-item", "remove-item", "move-item", "copy-item",
    "rename-item", "set-item", "set-itemproperty", "new-itemproperty", "remove-itemproperty", "start-process",
    "stop-process", "install-module", "install-package", "set-executionpolicy", "expand-archive", "compress-archive",
}
_GIT_READ = {
    "status", "log", "diff", "show", "blame", "grep", "ls-files", "ls-tree", "ls-remote", "rev-parse", "rev-list",
    "describe", "shortlog", "cat-file", "show-ref", "show-branch", "for-each-ref", "name-rev", "whatchanged",
    "count-objects", "check-ignore", "check-attr", "diff-tree", "diff-index", "diff-files", "merge-base", "help",
    "version", "var", "verify-commit", "verify-tag",
}
_PKG_MANAGERS = {"pip", "pip3", "pipx", "uv", "poetry", "pipenv", "conda", "mamba", "npm", "yarn", "pnpm", "bun",
                 "cargo", "gem", "composer", "apt", "apt-get", "apk", "yum", "dnf", "pacman", "brew", "choco",
                 "winget", "scoop", "go", "dotnet"}
_PKG_WRITE = {"install", "i", "add", "remove", "rm", "uninstall", "update", "upgrade", "ci", "publish", "get",
              "require", "init", "create", "lock", "sync", "tidy", "restore", "download", "autoremove", "purge",
              "dist-upgrade", "uninstall-all", "unlink", "link", "dedupe", "prune", "rebuild"}
_DOCKER_READ = {"ps", "images", "image", "logs", "inspect", "info", "version", "top", "stats", "port", "history",
                "diff", "search", "events", "ls", "context", "network", "volume", "container", "manifest"}
_DOCKER_READ_SUB = {"ls", "list", "inspect", "ps", "logs", "images", "config", "top", "version", "stats", "history"}
_KUBECTL_READ = {"get", "describe", "logs", "top", "version", "cluster-info", "explain", "api-resources",
                 "api-versions", "diff", "events", "auth"}
_SYSTEMCTL_READ = {"status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "show", "cat",
                   "list-timers", "list-sockets", "list-dependencies"}
_FD_RE = re.compile(r"\d*>&\d+|\d*>&-|&?\d*>>?\s*/dev/null\b|\d*>>?\s*nul\b", re.IGNORECASE)
_REDIRECT_RE = re.compile(r"(?<![-=<>])>{1,2}(?!\()|&>")


def _basename(tok: str) -> str:
    name = os.path.basename(tok.replace("\\", "/")).lower()
    return name[:-4] if name.endswith(".exe") else name


def _tokens(link: str) -> list[str]:
    toks = [t.strip("'\"") for t in ca._split_tokens(link)]
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", toks[0]):
        toks = toks[1:]
    return toks


def _git_violation(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        if args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            break
    if i >= len(args):
        return None
    sub = args[i].lower()
    rest = [a.lower() for a in args[i + 1:]]
    plain = [a for a in rest if not a.startswith("-")]
    if sub in _GIT_READ:
        return None
    if sub == "branch":
        write_flags = {"-d", "-m", "-c", "-u", "-f", "--delete", "--move", "--copy", "--force", "--set-upstream-to", "--unset-upstream"}
        return None if not plain and not (write_flags & set(rest)) else "git branch"
    if sub == "tag":
        listing = {"-l", "--list", "-n"} & set(rest)
        return None if listing or not plain and not ({"-d", "--delete", "-f"} & set(rest)) else "git tag"
    if sub == "stash":
        return None if rest[:1] in (["list"], ["show"]) else "git stash"
    if sub == "config":
        return None if {"--get", "--get-all", "--list", "-l", "--get-regexp", "--show-origin"} & set(rest) else "git config"
    if sub == "remote":
        return None if rest[:1] in ([], ["-v"], ["show"], ["get-url"]) else "git remote"
    if sub in ("submodule", "worktree"):
        return None if rest[:1] in (["status"], ["list"]) else f"git {sub}"
    if sub == "reflog":
        return "git reflog" if {"expire", "delete"} & set(rest) else None
    return f"git {sub}"


def _link_violations(link: str, depth: int) -> list[str]:
    out: list[str] = []
    if depth > 4:
        return out
    plain = _FD_RE.sub(" ", ca._blank_quoted(link))
    if _REDIRECT_RE.search(plain):
        out.append("output redirection")
    for inner in ca.embedded_commands(link):
        out += readonly_violations(inner, depth + 1)

    toks = _tokens(link)
    while toks and _basename(toks[0]) in _WRAPPERS:
        name = _basename(toks[0])
        rest = toks[1:]
        i = 0
        while i < len(rest) and (
            rest[i].startswith("-")
            or (name == "env" and "=" in rest[i])
            or (name == "timeout" and re.fullmatch(r"\d+[smhd]?", rest[i]))
        ):
            i += 1
        toks = rest[i:]
    if not toks:
        return out

    name = _basename(toks[0])
    args = toks[1:]
    low = [a.lower() for a in args]

    if name == "eval":
        out += readonly_violations(" ".join(args), depth + 1)
    elif name in _SHELLS:
        for idx, a in enumerate(low):
            if a in ("-c", "-lc", "-ic", "-command", "-c", "/c", "/k") and idx + 1 < len(args):
                out += readonly_violations(" ".join(args[idx + 1:]) if name == "cmd" else args[idx + 1], depth + 1)
                break
    elif name in _INTERPRETERS:
        if args[:2] == ["-m", "pip"] or args[:2] == ["-m", "pip3"]:
            out += [f"pip {low[2]}"] if len(low) > 2 and low[2] in _PKG_WRITE else []
        elif any(a in ("-c", "-e", "-r", "--eval", "-pe", "-pi", "-ne", "-i") or a.startswith("-pi") for a in low):
            out.append(f"{name} inline code")
    elif name in _ALWAYS_WRITE:
        out.append(name)
    elif name == "sed":
        if any(a.startswith("-i") or a == "--in-place" for a in low):
            out.append("sed -i")
    elif name == "tar":
        if not any(a in ("-t", "--list") or (a.startswith("-") and "t" in a and not a.startswith("--")) for a in low):
            out.append("tar")
    elif name == "git":
        v = _git_violation(args)
        if v:
            out.append(v)
    elif name in _PKG_MANAGERS:
        sub = low[1] if name == "uv" and low[:1] == ["pip"] and len(low) > 1 else (low[0] if low else "")
        if name in ("yarn", "pnpm") and not low:
            out.append(f"{name} install")
        elif name == "go" and low[:1] in (["mod"], ["get"], ["install"], ["generate"]):
            out.append(f"go {low[0]}")
        elif sub in _PKG_WRITE:
            out.append(f"{name} {sub}")
    elif name == "curl":
        # -o/-O (and the long forms) save to a file, -T uploads one; plain GET/POST to stdout is fine
        if any(a in ("-o", "-O", "--output", "--remote-name", "-T", "--upload-file") or (a.startswith("-o") and not a.startswith("--")) for a in args):
            out.append("curl download to file")
    elif name == "wget":
        to_stdout = "-o-" in low or ("-o" in low and low[low.index("-o") + 1:low.index("-o") + 2] == ["-"])
        if not to_stdout and "--spider" not in low:
            out.append("wget")
    elif name in ("iwr", "invoke-webrequest", "irm", "invoke-restmethod"):
        if any(a == "-outfile" for a in low):
            out.append(f"{name} -OutFile")
    elif name in ("docker", "podman"):
        sub = low[0] if low else ""
        if sub == "compose":
            if len(low) < 2 or low[1] not in _DOCKER_READ_SUB:
                out.append("docker compose " + (low[1] if len(low) > 1 else ""))
        elif sub in ("network", "volume", "container", "image", "context", "manifest"):
            if len(low) < 2 or low[1] not in _DOCKER_READ_SUB:
                out.append(f"{name} {sub} {low[1] if len(low) > 1 else ''}".strip())
        elif sub not in _DOCKER_READ:
            out.append(f"{name} {sub}".strip())
    elif name in ("kubectl", "oc", "helm"):
        sub = low[0] if low else ""
        read = _KUBECTL_READ | ({"list", "status", "show", "search", "get", "history", "template", "lint"} if name == "helm" else set())
        if sub not in read and not (sub == "config" and low[1:2] in (["view"], ["get-contexts"], ["current-context"])):
            out.append(f"{name} {sub}".strip())
    elif name in ("systemctl", "service", "sc"):
        sub = low[0] if low else ""
        if name == "systemctl" and sub in _SYSTEMCTL_READ:
            pass
        elif name == "service" and low[1:2] == ["status"]:
            pass
        elif name == "sc" and sub in ("query", "queryex", "qc"):
            pass
        else:
            out.append(f"{name} {sub}".strip())
    elif name == "reg":
        if low[:1] and low[0] != "query":
            out.append(f"reg {low[0]}")
    elif name == "terraform":
        if (low[:1] or [""])[0] not in ("plan", "show", "validate", "output", "version", "providers", "graph", "fmt"):
            out.append(f"terraform {(low[:1] or [''])[0]}".strip())
    return out


def readonly_violations(command: str, _depth: int = 0) -> list[str]:
    """Reasons why a shell command line is not read-only ([] when it looks read-only)."""
    found: list[str] = []
    for link in ca.split_command_chain(command or ""):
        for v in _link_violations(link, _depth):
            if v not in found:
                found.append(v)
    return found
