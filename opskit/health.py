from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile


@dataclass
class Check:
    name: str
    status: str
    message: str


EXIT_CODES = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}


def usage_status(percent: float, warning: float, critical: float) -> str:
    if not 0 <= warning < critical <= 100:
        raise ValueError("Thresholds must satisfy 0 <= warning < critical <= 100")
    return "CRITICAL" if percent >= critical else "WARNING" if percent >= warning else "OK"


def disk_check(path: Path, warning: float = 85, critical: float = 95) -> Check:
    try:
        usage = shutil.disk_usage(path)
        used = usage.used / usage.total * 100
        return Check("disk", usage_status(used, warning, critical), f"{used:.1f}% used at {path}")
    except OSError as exc:
        return Check("disk", "UNKNOWN", f"Cannot read disk usage: {exc.strerror or type(exc).__name__}")


def parse_meminfo(text: str) -> float:
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"MemTotal", "MemAvailable"}:
            number, unit = value.strip().split()
            if unit != "kB":
                raise ValueError("Unexpected memory unit")
            values[key] = int(number)
    total, available = values["MemTotal"], values["MemAvailable"]
    if not 0 <= available <= total or total <= 0:
        raise ValueError("Invalid memory values")
    return (total - available) / total * 100


def memory_check(path: Path = Path("/proc/meminfo"), warning: float = 85, critical: float = 95) -> Check:
    try:
        used = parse_meminfo(path.read_text(encoding="ascii"))
        return Check("memory", usage_status(used, warning, critical), f"{used:.1f}% used excluding available memory")
    except (OSError, ValueError, KeyError):
        return Check("memory", "UNKNOWN", "Cannot read Linux MemTotal/MemAvailable; use --skip-memory on other OSes")


def service_check(unit: str, timeout: float = 3) -> Check:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", unit):
        raise ValueError("Invalid systemd unit name")
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--", unit], capture_output=True,
            text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return Check(f"service:{unit}", "UNKNOWN", "systemctl unavailable or timed out")
    state = result.stdout.strip()
    if result.returncode == 0 and state == "active":
        return Check(f"service:{unit}", "OK", "active")
    if state in {"inactive", "failed", "activating", "deactivating", "reloading"}:
        return Check(f"service:{unit}", "CRITICAL", state)
    return Check(f"service:{unit}", "UNKNOWN", "Unit missing or systemd is unavailable")


def tcp_check(host: str, port: int, timeout: float = 2) -> Check:
    if not host or not 1 <= port <= 65535:
        raise ValueError("TCP target requires a hostname and port 1..65535")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return Check(f"tcp:{host}:{port}", "OK", "connection established")
    except OSError:
        return Check(f"tcp:{host}:{port}", "CRITICAL", "connection failed")


def report(checks: list[Check]) -> dict:
    return {
        "schema_version": 1,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "exit_code": max((EXIT_CODES[c.status] for c in checks), default=0),
        "checks": [asdict(c) for c in checks],
    }


def write_report(path: Path, value: dict) -> None:
    path = path.resolve()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        except BaseException:
            stream.close()
            temp.unlink(missing_ok=True)
            raise
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
