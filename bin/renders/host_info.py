#!/usr/bin/env python3
"""Consistent host metadata for locally generated HTML reports."""
import os
import platform
import subprocess

FIELDS = (
    "hostname", "system", "release", "machine", "processor",
    "cpu_frequency", "cpu_count", "python",
)


def _sysctl(name):
    try:
        return subprocess.check_output(
            ["/usr/sbin/sysctl", "-n", name], text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def collect_host_info():
    frequency = "not reported by OS (dynamic frequency)"
    for name in ("hw.cpufrequency_max", "hw.cpufrequency"):
        value = _sysctl(name)
        if value.isdigit() and int(value) > 0:
            frequency = f"{int(value) / 1_000_000_000:.2f} GHz"
            break
    return {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": _sysctl("machdep.cpu.brand_string") or platform.processor(),
        "cpu_frequency": frequency,
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
    }


def host_rows(recorded=None):
    host = recorded or {}
    return [(f"host.{field}", host.get(field, "not recorded")) for field in FIELDS]
