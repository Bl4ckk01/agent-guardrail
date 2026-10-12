#!/usr/bin/env python3
"""Daemon and process manager for local guardrail backends (Liquid AI D1 and CLM).

Manages background servers (llama-server and clm-serve) based on policy.yaml.
For cloud backends ('jev') or offline deterministic rules ('rules'),
no local model or background process is required.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# --- Core Paths and Configuration Files ---
ROOT_DIR = Path(__file__).resolve().parent
POLICY_PATH = ROOT_DIR / "policy.yaml"
PID_DIR = ROOT_DIR / ".guardrail"
PID_FILE = PID_DIR / "daemons.json"
LOG_DIR = ROOT_DIR / ".guardrail" / "logs"


def _log(msg: str) -> None:
    """Print an internal diagnostic message to stderr."""
    print(msg, file=sys.stderr)


# --- Network & Port Health Check ---
def is_port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """Check if a TCP port is open and accepting connections.
    
    Performs a quick TCP socket probe to verify if a local model server
    (e.g., llama-server or clm-serve) is currently running and ready.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError, TimeoutError):
        return False


# --- Policy Configuration Loader ---
def load_policy_daemon_config() -> dict[str, Any]:
    """Read backend and daemon settings from policy.yaml.
    
    Returns a dictionary containing model paths, ports, GPU offload layers,
    and whether daemons should start automatically or manually.
    """
    config: dict[str, Any] = {
        "backend": "clm",
        "manual_start": False,
        "d1_model_path": "",
        "qwen_model_path": "",
        "d1_gpu_layers": 20,
        "qwen_gpu_layers": 0,
        "d1_port": 8800,
        "qwen_port": 8090,
        "clm_port": 8700,
        "qwen_base_url": "http://127.0.0.1:8090/v1",
        "clm_base_url": "http://127.0.0.1:8700",
        "liquid_endpoint": "http://127.0.0.1:8800/v1",
    }

    # Return defaults if policy.yaml does not exist
    if not POLICY_PATH.is_file():
        return config

    try:
        import yaml
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        _log(f"[guardrail:daemon] Error parsing policy.yaml: {exc}")
        return config

    settings = data.get("settings", {})
    if not isinstance(settings, dict):
        return config

    # Parse backend selection and manual start flag
    config["backend"] = str(settings.get("backend", config["backend"])).strip().lower()
    config["manual_start"] = bool(settings.get("manual_start", config["manual_start"]))

    # Parse model paths, ports, and GPU layer settings
    for key in (
        "d1_model_path", "qwen_model_path",
        "d1_gpu_layers", "qwen_gpu_layers",
        "d1_port", "qwen_port", "clm_port",
        "qwen_base_url", "clm_base_url", "liquid_endpoint",
    ):
        if key in settings:
            config[key] = settings[key]

    return config


# --- Process ID (PID) Management ---
def _load_pids() -> dict[str, int]:
    """Load running daemon process IDs from the local JSON tracking file."""
    if not PID_FILE.is_file():
        return {}
    try:
        with open(PID_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_pids(pids: dict[str, int]) -> None:
    """Save active daemon process IDs to the local JSON tracking file."""
    PID_DIR.mkdir(parents=True, exist_ok=True)
    with open(PID_FILE, "w", encoding="utf-8") as f:
        json.dump(pids, f, indent=2)


def _is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is currently running.
    
    Uses 'tasklist' on Windows and signal 0 (os.kill) on Unix/Linux/macOS.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return str(pid) in out
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def _kill_pid(pid: int) -> bool:
    """Force terminate a running process by its PID.
    
    Uses 'taskkill /F /T' on Windows to kill the process tree,
    and SIGKILL (signal 9) on Unix/Linux/macOS.
    """
    if not _is_pid_alive(pid):
        return True
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            os.kill(pid, 9)
        return True
    except Exception:
        return False


# --- Backend Status Inspection ---
def get_status() -> dict[str, Any]:
    """Retrieve current live status for all guardrail backends and background servers.
    
    Inspects TCP ports for D1 and CLM, verifies JEV API keys, and checks
    offline deterministic rules readiness.
    """
    cfg = load_policy_daemon_config()
    active_backend = cfg["backend"]

    # Probe network ports for active local servers
    d1_up = is_port_listening(int(cfg["d1_port"]))
    qwen_up = is_port_listening(int(cfg["qwen_port"]))
    clm_up = is_port_listening(int(cfg["clm_port"]))

    # Verify cloud API key presence
    jev_configured = bool(os.environ.get("JEV_API_KEY"))

    status = {
        "active_backend": active_backend,
        "manual_start": cfg["manual_start"],
        "backends": {
            "d1": {
                "type": "local_neural",
                "port": cfg["d1_port"],
                "running": d1_up,
                "model_configured": bool(cfg["d1_model_path"] and Path(str(cfg["d1_model_path"])).is_file()),
            },
            "clm": {
                "type": "local_neural",
                "qwen_port": cfg["qwen_port"],
                "clm_port": cfg["clm_port"],
                "qwen_running": qwen_up,
                "clm_running": clm_up,
                "ready": (qwen_up and clm_up),
                "model_configured": bool(cfg["qwen_model_path"] and Path(str(cfg["qwen_model_path"])).is_file()),
            },
            "jev": {
                "type": "cloud_api",
                "local_daemon_needed": False,
                "api_key_configured": jev_configured,
                "ready": jev_configured,
                "note": "Cloud API (TypeSafe AI) via JEV_API_KEY. No local model or background process required.",
            },
            "rules": {
                "type": "deterministic_offline",
                "local_daemon_needed": False,
                "ready": True,
                "note": "Native in-process deterministic regex and path policies (<0.3ms). No model or daemon required.",
            },
        },
    }

    # Set overall readiness flag for the selected active backend
    if active_backend == "d1":
        status["active_ready"] = d1_up
    elif active_backend == "clm":
        status["active_ready"] = (qwen_up and clm_up)
    elif active_backend == "jev":
        status["active_ready"] = jev_configured
    elif active_backend == "rules":
        status["active_ready"] = True
    else:
        status["active_ready"] = False

    return status


# --- Detached Background Process Launcher ---
def _launch_detached(args: list[str], log_file: Path) -> int:
    """Launch a detached background daemon that survives the parent shell.
    
    On Windows, uses WMI (Win32_Process.Create) so the background server
    runs independently of short-lived agent terminal sessions. Falls back
    to subprocess.Popen with redirected stdout/stderr.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    cmd_str = subprocess.list2cmdline(args)
    
    if os.name == "nt":
        # WMI creates the process under Windows WmiPrvSE, completely detached from parent Job Objects
        escaped_cmd = cmd_str.replace("'", "''")
        escaped_root = str(ROOT_DIR).replace("'", "''")
        ps_script = (
            f"$res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
            f"-Arguments @{{CommandLine = '{escaped_cmd}'; CurrentDirectory = '{escaped_root}'}}; "
            f"$res.ProcessId"
        )
        try:
            out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_script], text=True).strip()
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    return int(line)
        except Exception as exc:
            _log(f"[guardrail:daemon] WMI launch failed: {exc}, falling back to Popen")

    out_fh = open(log_file, "a", encoding="utf-8")
    proc = subprocess.Popen(
        args,
        stdout=out_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        cwd=str(ROOT_DIR),
        close_fds=(os.name != "nt"),
    )
    return proc.pid


# --- Daemon Lifecycle Management ---
def start_daemon(force: bool = False) -> tuple[bool, str]:
    """Start the required background daemon for the configured backend.
    
    Returns (success: bool, message: str).
    """
    cfg = load_policy_daemon_config()
    backend = cfg["backend"]

    # 1. Backends that do NOT require any background daemon:
    # JEV connects directly to TypeSafe AI Cloud API via an API key,
    # and RULES evaluates deterministic regex/path policies in-process.
    if backend == "jev":
        key_status = "JEV_API_KEY is configured" if os.environ.get("JEV_API_KEY") else "WARNING: set the JEV_API_KEY environment variable"
        return True, (
            "ℹ️ [Guardrail] Active backend: JEV (TypeSafe AI Cloud API).\n"
            "   No local model or background daemon is required.\n"
            f"   API Status: {key_status}."
        )

    if backend == "rules":
        return True, (
            "ℹ️ [Guardrail] Active backend: RULES (Deterministic offline rules).\n"
            "   Operates entirely in-process with zero latency (<0.3ms).\n"
            "   No neural model or background daemon is required."
        )

    # 2. Check if manual startup mode is requested by policy.yaml
    if cfg["manual_start"] and not force:
        return False, (
            f"ℹ️ [Guardrail] 'manual_start: true' is configured in policy.yaml.\n"
            f"   The daemon for '{backend}' must be launched manually in a terminal (see README.md),\n"
            f"   or set 'manual_start: false' in policy.yaml to enable automatic startup via '/guardrail start'."
        )

    pids = _load_pids()

    # 3. Liquid AI D1 Backend
    # Launches llama-server hosting the Liquid D1-3B GGUF model on the specified port.
    if backend in ("d1", "liquid"):
        d1_port = int(cfg["d1_port"])
        # If the port is already listening, no need to spawn another server
        if is_port_listening(d1_port):
            return True, f"✅ [Guardrail] Liquid AI D1 is already running and listening on http://127.0.0.1:{d1_port}."

        model_path = cfg["d1_model_path"]
        if not model_path or not Path(model_path).is_file():
            return False, (
                f"❌ [Guardrail] D1 model file not found: '{model_path}'.\n"
                f"   Configure 'd1_model_path' in policy.yaml with the absolute path to your .gguf file."
            )

        # Build llama-server arguments with model path, context size, and GPU layers
        llama_exe = shutil.which("llama-server") or "llama-server"
        cmd = [
            llama_exe,
            "-m", str(model_path),
            "-c", "2048",
            "-ngl", str(cfg["d1_gpu_layers"]),
            "--port", str(d1_port),
        ]

        # Launch detached server process and record its PID
        log_path = LOG_DIR / "d1_server.log"
        pid = _launch_detached(cmd, log_path)
        pids["d1"] = pid
        _save_pids(pids)

        # Wait up to 18 seconds for the model weights to load into VRAM and bind the port
        for _ in range(60):
            time.sleep(0.3)
            if is_port_listening(d1_port):
                return True, (
                    f"🚀 [Guardrail] Liquid AI D1 started successfully in the background!\n"
                    f"   - Endpoint: http://127.0.0.1:{d1_port}/v1\n"
                    f"   - GPU Offload: {cfg['d1_gpu_layers']} layers\n"
                    f"   - Log: {log_path}\n"
                    f"   - PID: {pid}"
                )

        return True, (
            f"⏳ [Guardrail] D1 process launched (PID {pid}). Loading GGUF weights into VRAM...\n"
            f"   Port :{d1_port} will be available in a few seconds. Log: {log_path}"
        )

    # 4. CLM Backend (Requires Qwen embeddings on port 8090 + clm-serve reasoning on port 8700)
    if backend == "clm":
        qwen_port = int(cfg["qwen_port"])
        clm_port = int(cfg["clm_port"])

        # Stage A: Start Qwen embedding server if not already running
        qwen_ready = is_port_listening(qwen_port)
        if not qwen_ready:
            model_path = cfg["qwen_model_path"]
            if not model_path or not Path(model_path).is_file():
                return False, (
                    f"❌ [Guardrail] Qwen model file not found: '{model_path}'.\n"
                    f"   Configure 'qwen_model_path' in policy.yaml with the absolute path to your Qwen GGUF file."
                )

            llama_exe = shutil.which("llama-server") or "llama-server"
            cmd_qwen = [
                llama_exe,
                "-m", str(model_path),
                "--embedding",
                "--pooling", "last",
                "-c", "2048",
                "-ngl", str(cfg["qwen_gpu_layers"]),
                "--port", str(qwen_port),
            ]
            log_qwen = LOG_DIR / "qwen_server.log"
            pid_qwen = _launch_detached(cmd_qwen, log_qwen)
            pids["qwen"] = pid_qwen
            _save_pids(pids)

            # Wait for Qwen to bind port
            for _ in range(50):
                time.sleep(0.3)
                if is_port_listening(qwen_port):
                    qwen_ready = True
                    break

        # Stage B: Start clm-serve daemon connected to the Qwen embedding service
        clm_ready = is_port_listening(clm_port)
        if not clm_ready:
            clm_exe = shutil.which("clm-serve") or "clm-serve"
            cmd_clm = [
                clm_exe,
                "--emb-url", f"http://127.0.0.1:{qwen_port}/v1/embeddings",
                "--port", str(clm_port),
            ]
            log_clm = LOG_DIR / "clm_server.log"
            pid_clm = _launch_detached(cmd_clm, log_clm)
            pids["clm"] = pid_clm
            _save_pids(pids)

            # Wait for clm-serve to bind port
            for _ in range(25):
                time.sleep(0.2)
                if is_port_listening(clm_port):
                    clm_ready = True
                    break

        if qwen_ready and clm_ready:
            return True, (
                f"🚀 [Guardrail] CLM Stack started successfully in the background!\n"
                f"   - Qwen Embeddings: http://127.0.0.1:{qwen_port}\n"
                f"   - CLM Serve: http://127.0.0.1:{clm_port}\n"
                f"   - Logs: {LOG_DIR}"
            )

        return True, (
            f"⏳ [Guardrail] CLM daemons launched in the background.\n"
            f"   Port status: Qwen:{qwen_port}={'ONLINE' if qwen_ready else 'STARTING'}, "
            f"CLM:{clm_port}={'ONLINE' if clm_ready else 'STARTING'}."
        )

    return False, f"❌ [Guardrail] Unknown backend: '{backend}'"


# --- Daemon Termination & Cleanup ---
def stop_daemon(backend: str | None = None) -> tuple[bool, str]:
    """Stop running background daemons managed by the guardrail.
    
    Reads active PIDs from the tracking file, terminates matching processes,
    and cleans up the PID state.
    """
    pids = _load_pids()
    stopped = []

    # Iterate through recorded daemons and terminate active processes
    for name, pid in list(pids.items()):
        if _is_pid_alive(pid):
            _kill_pid(pid)
            stopped.append(f"{name} (PID {pid})")
        pids.pop(name, None)

    # Save the updated empty/cleaned PID file
    _save_pids(pids)

    if stopped:
        return True, f"🛑 [Guardrail] Daemons stopped successfully: {', '.join(stopped)}."
    return True, "ℹ️ [Guardrail] No active daemons managed by guardrail were found running."


# --- Status Dashboard Formatting ---
def format_status_report() -> str:
    """Return a human-readable English status report for terminal or chat.
    
    Inspects all configured backends (D1, CLM, JEV, Rules) and builds
    a clear summary table indicating port readiness, model status, and health.
    """
    st = get_status()
    b = st["active_backend"].upper()
    manual = "Yes (manual_start: true)" if st["manual_start"] else "No (automatic launch via /guardrail start)"

    lines = [
        f"🛡️  GUARDRAIL STATUS - ACTIVE BACKEND: [{b}]",
        f"⚙️  Startup Mode: {manual}",
        "─" * 60,
    ]

    # Format status for each backend
    for name, info in st["backends"].items():
        tag = f"[{name.upper()}]"
        if info["type"] == "cloud_api":
            k_st = "Configured" if info["api_key_configured"] else "NOT set"
            lines.append(f"• {tag:<8} Cloud API (TypeSafe AI) | JEV_API_KEY: {k_st}")
            lines.append(f"           -> {info['note']}")
        elif info["type"] == "deterministic_offline":
            lines.append(f"• {tag:<8} Offline Regex & Path Rules (<0.3ms) | Ready to use")
            lines.append(f"           -> {info['note']}")
        elif name == "d1":
            p_st = f"ACTIVE (port {info['port']})" if info["running"] else f"INACTIVE (port {info['port']})"
            m_st = "Found" if info["model_configured"] else "File missing or path not found"
            lines.append(f"• {tag:<8} Liquid AI D1-3B | Server: {p_st} | GGUF Model: {m_st}")
        elif name == "clm":
            q_st = "ON" if info["qwen_running"] else "OFF"
            c_st = "ON" if info["clm_running"] else "OFF"
            m_st = "Found" if info["model_configured"] else "File missing or path not found"
            lines.append(f"• {tag:<8} CLM Stack | Qwen Embeddings ({info['qwen_port']}): {q_st} | clm-serve ({info['clm_port']}): {c_st} | Model: {m_st}")

    lines.append("─" * 60)
    # Overall active backend evaluation
    if st["active_ready"]:
        lines.append(f"✅ Backend '{b}' is ready to protect sessions.")
    else:
        lines.append(f"⚠️  Backend '{b}' is NOT ready. Use '/guardrail start' or 'python check_action.py --start' to launch it.")

    return "\n".join(lines)


# --- CLI Entry Point ---
# Allows managing daemons directly from the command line:
#   python daemon_manager.py start   -> Launches the configured background daemon
#   python daemon_manager.py stop    -> Stops running background daemons
#   python daemon_manager.py status  -> Displays real-time health dashboard
if __name__ == "__main__":
    action = sys.argv[1].lower() if len(sys.argv) > 1 else "status"
    if action in ("--start", "-s", "start"):
        ok, msg = start_daemon()
        print(msg)
        sys.exit(0 if ok else 1)
    elif action in ("--stop", "stop"):
        ok, msg = stop_daemon()
        print(msg)
        sys.exit(0 if ok else 1)
    elif action in ("--status", "status"):
        print(format_status_report())
        sys.exit(0)
    else:
        print("Usage: python daemon_manager.py [start | stop | status]")
        sys.exit(2)
