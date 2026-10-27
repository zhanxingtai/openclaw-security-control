#!/usr/bin/env python3
"""
OpenClaw system process monitor.

Runs as a child process of the OpenClaw security plugin. Reads NDJSON
commands from stdin and emits NDJSON security events to stdout.

Commands:
    {"type": "config", "data": {"scanIntervalMs": 5000, ...}}
    {"type": "bind_context", "data": {"root_pid": 1234, "session_id": "...", ...}}
    {"type": "unbind_context", "data": {"root_pid": 1234}}
    {"type": "shutdown"}

Events:
    process_start   - a process belonging to a bound context is discovered
    x_openclaw_process_change - an already tracked process changed state
    process_exit    - a tracked process disappeared
    x_openclaw_process_snapshot - periodic full snapshot of all tracked processes

    event_type 带 x_openclaw_ 前缀：平台 validate_batch 对未登记且无
    x_<project>_ 前缀的类型直接 UnsupportedEventType 并整批拒绝 NDJSON。
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import threading
import time
import uuid
from queue import Queue
from typing import Any, Callable, Dict, List, Optional, Set, Union

try:
    import psutil
except ImportError as _import_err:  # pragma: no cover - exercised at runtime only
    _err = {
        "type": "error",
        "message": "psutil is required. Install with: pip install psutil",
    }
    print(json.dumps(_err), file=sys.stderr)
    sys.exit(1)


# Defaults
# cmdline 风险模式与 autokill 默认名单的唯一数据源是
# policies/security-policy.spl.yaml（monitorPatterns / metadata.flagRegistry），
# 构建期生成同目录 generated-patterns.json。下方 _FALLBACK_* 常量只在产物
# 缺失/损坏时兜底（打 WARN），正常部署不再双写漂移。

# Risk flag patterns matched against the redacted command line.
# Keep patterns simple and maintainable; each matched flag contributes 1.0 to
# risk_score. The default riskThreshold is 1.0, so a single default flag match
# is enough to trigger auto-kill when enabled.
_FALLBACK_RISK_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    (
        "reverse_shell",
        re.compile(
            r"(/dev/tcp/|/dev/udp/|bash\s+-i\s+>&|sh\s+-i\s+>&|"
            r"nc\s+.*-e\s+/(?:bin|usr)/(?:sh|bash|zsh)|python.*socket.*connect)",
            re.IGNORECASE,
        ),
    ),
    (
        "download_execute",
        re.compile(
            r"(?:curl|wget|fetch).*\|.*\b(?:sh|bash|zsh)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "mass_deletion",
        re.compile(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive|--no-preserve-root)",
            re.IGNORECASE,
        ),
    ),
    (
        "privilege_escalation",
        re.compile(
            r"\bsudo\b|\bsu\s+-|\bchmod\b.*\+s|\bsetuid\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "data_exfiltration",
        re.compile(
            r"\bscp\b|\brsync\b|\btar\s+.*-c\b|\bzip\s+.*-r\b",
            re.IGNORECASE,
        ),
    ),
    (
        "token_in_command",
        re.compile(
            r"(?i)(?:Authorization\s*[:=]\s*|Bearer\s+[A-Za-z0-9_\-\.~+/=]{8,}|"
            r"(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*\S+)"
        ),
    ),
    (
        "sensitive_file_access",
        re.compile(
            r"(?:^|\s|[\"'<>])"
            r"(?:/etc/(?:passwd|shadow|gshadow|sudoers|hosts|ssh/\S*)|"
            r"/root/\S*|/proc/self/environ|"
            r"(?:.*/)?\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|config))"
            r"\b|\bgetent\s+(?:passwd|shadow|group)\b",
            re.IGNORECASE,
        ),
    ),
]

_FALLBACK_AUTOKILL_FLAGS: List[str] = [
    "reverse_shell",
    "skill_binary_execution",
]

_GENERATED_PATTERNS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "generated-patterns.json"
)

_PY_FLAG_MAP = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def _load_generated_patterns(
    path: str = _GENERATED_PATTERNS_PATH,
) -> Optional[tuple[List[tuple[str, "re.Pattern[str]"]], List[str]]]:
    """Load build-time generated risk patterns.

    Returns (patterns, autoKillFlags) on success, None on any failure —
    callers fall back to the built-in constants. Never raises: a partial
    deployment bundle must not crash the monitor.
    """
    try:
        with open(path, encoding="utf-8") as f:
            spec = json.load(f)
        raw_patterns = spec["patterns"]
        if not isinstance(raw_patterns, list) or not raw_patterns:
            raise ValueError("empty or missing patterns list")
        patterns: List[tuple[str, re.Pattern[str]]] = []
        for entry in raw_patterns:
            flags = 0
            for ch in entry.get("flags") or "":
                if ch not in _PY_FLAG_MAP:
                    raise ValueError(f"unsupported regex flag {ch!r}")
                flags |= _PY_FLAG_MAP[ch]
            patterns.append((str(entry["flag"]), re.compile(str(entry["pattern"]), flags)))
        auto_kill = [str(f) for f in spec.get("autoKillFlags") or []]
        return patterns, auto_kill or list(_FALLBACK_AUTOKILL_FLAGS)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(
            json.dumps(
                {
                    "type": "log",
                    "level": "warn",
                    "message": (
                        f"generated-patterns.json unavailable ({exc}); "
                        "using built-in fallback risk patterns"
                    ),
                }
            ),
            file=sys.stderr,
        )
        return None


_loaded_patterns = _load_generated_patterns()

# Active pattern table / autokill defaults: generated artifact when present,
# built-in fallback otherwise.
RISK_PATTERNS: List[tuple[str, re.Pattern[str]]] = (
    _loaded_patterns[0] if _loaded_patterns else _FALLBACK_RISK_PATTERNS
)
_DEFAULT_AUTOKILL_FLAGS: List[str] = (
    _loaded_patterns[1] if _loaded_patterns else list(_FALLBACK_AUTOKILL_FLAGS)
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "scanIntervalMs": 5000,
    "snapshotIntervalMs": 0,  # 0 disables periodic process_snapshot events
    "processNames": ["openclaw", "node", "python", "hermes"],
    "excludeCommandLines": ["process_monitor.py"],
    "collectOpenFiles": False,
    "collectConnections": False,
    "collectChildren": True,
    "collectCpuPercent": False,
    "changeDetectionFields": ["cmdline", "cwd", "process_status", "ppid", "exe_path"],
    "memoryRssChangeThresholdBytes": 1024 * 1024,  # 1 MB
    # Burst mode defaults: only scan the bound tool-call tree by default.
    "burstScanEnabled": True,
    "burstScanIntervalMs": 100,
    "burstScanDurationMs": 3000,
    "burstMode": False,  # dynamic flag pushed by the JS side on every config command
    "burstScanGlobal": False,  # do not scan/kill processes outside the tool tree
    # Cgroup monitoring configuration
    "cgroupsEnabled": False,
    "cgroupsScanIntervalMs": 5000,
    "cgroupsBurstScanIntervalMs": 200,
    "cgroupsCpuChangeThresholdPercent": 5.0,
    "cgroupsMemoryChangeThresholdPercent": 5.0,
    "cgroupsIoChangeThresholdBytes": 1024 * 1024,
    "cgroupsAnomalyCpuSpikeThresholdPercent": 50.0,
    "cgroupsAnomalyMemoryThresholdPercent": 80.0,
    "cgroupsFullFieldsInBurstOnly": True,
    "cgroupsHeartbeatEnabled": False,
    "cgroupsAggregateWindowSeconds": 60,
    # Process auto-kill configuration (opt-in, defaults disabled).
    # Default riskFlags are intentionally narrow to minimize false positives.
    # 缺省值来自构建期产物的 monitorAutoKillFlags，缺失时回退
    # _FALLBACK_AUTOKILL_FLAGS。
    "autoKill": False,
    "riskFlags": _DEFAULT_AUTOKILL_FLAGS,
    "riskThreshold": 1.0,
    "protectedPids": [],
    "killSignal": "SIGTERM",
}

# Flag name used for a skill-shipped binary. The executable path is checked
# separately because it is not part of the command-line string.
SKILL_BINARY_FLAG = "skill_binary_execution"

# A node process whose environment lacks the runtime-hook marker is running
# WITHOUT the preloaded child_process hook (e.g. its parent stripped
# NODE_OPTIONS before spawning it). Such processes bypass the entire runtime
# layer, so they are flagged as unpatched engines.
HOOK_MARKER_ENV = "OPENCLAW_RUNTIME_HOOK_ACTIVE"
UNPATCHED_ENGINE_FLAG = "unpatched_engine"

SENSITIVE_REGEXES: List[tuple[str, str]] = [
    # Authorization: Bearer <token>
    (
        r"(?i)(authorization[:\s]+bearer\s+)\S+",
        r"\1***",
    ),
    # -H Authorization: <value> (up to next flag or end of string)
    (
        r"(?i)(-[Hh]\s+authorization[:\s]+).*?(?=(\s+-|\s*$))",
        r"\1***\2",
    ),
    # token=..., api_key=..., key=..., secret=..., password=...
    (
        r"(?i)\b(token|api_key|apikey|key|secret|password)=[^\s&\"']+",
        r"\1=***",
    ),
]


# Helpers


def safe_get(func: Callable[[], Any], default: Any = None) -> Any:
    """Call a psutil accessor and return default on expected exceptions."""
    try:
        return func()
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        AttributeError,
    ):
        return default


def redact_command_line(command_line: str) -> str:
    """Remove obvious sensitive tokens from a command-line string."""
    result = command_line
    for pattern, repl in SENSITIVE_REGEXES:
        result = re.sub(pattern, repl, result)
    return result.strip()


def is_skill_binary_execution(exe_path: Optional[str]) -> bool:
    """Detect whether the executable is a skill-shipped binary.

    OpenClaw skills are normally JS/TS/Python packages; a compiled or shell
    binary hidden under <skill>/bin/ is a common bypass vector used by
    malicious skills to hide the real command lines.
    """
    if not exe_path:
        return False
    normalized = exe_path.replace("\\", "/")
    return bool(re.search(r"/skills/[^/]+/bin/[^/]+$", normalized, re.IGNORECASE))


_NODE_PROCESS_NAMES = frozenset({"node", "node.exe", "nodejs", "nodejs.exe"})


def is_node_process(process_name: Optional[str], exe_path: Optional[str]) -> bool:
    """Return True when the process looks like a Node.js runtime."""
    for candidate in (process_name, exe_path):
        if not candidate:
            continue
        base = candidate.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base in _NODE_PROCESS_NAMES:
            return True
    return False


def read_process_environ(proc: psutil.Process) -> Optional[Dict[str, str]]:
    """Best-effort read of a process environment.

    Returns None when the environment cannot be read: insufficient
    privileges (psutil.AccessDenied), the platform does not support
    environ() (NotImplementedError / AttributeError), or the process exited
    between listing and read. Callers must treat None as "unknown" and skip
    silently — never as "marker absent".

    Note: this runs on the polling path, so there is an inherent race
    window — a short-lived node process may start and exit between scans and
    never be inspected. That residual gap is accepted and documented.
    """
    try:
        return proc.environ()
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        NotImplementedError,
        AttributeError,
        OSError,
    ):
        return None


def score_command_line(command_line: str, exe_path: Optional[str] = None) -> tuple[List[str], float]:
    """Score a process command line for risky behavior.

    Returns (risk_flags, risk_score). Each matched flag adds 1.0 to the
    score. The skill_binary_execution flag is derived from exe_path when it
    is provided.
    """
    flags: List[str] = []
    text = command_line.lower()
    for flag_name, pattern in RISK_PATTERNS:
        if pattern.search(text):
            flags.append(flag_name)
    if exe_path and is_skill_binary_execution(exe_path):
        flags.append(SKILL_BINARY_FLAG)
    return flags, float(len(flags))


def format_addr(addr: Optional[Any]) -> Optional[str]:
    if addr is None:
        return None
    return f"{addr.ip}:{addr.port}"


def get_container_id(pid: int) -> Optional[str]:
    """Extract a short container id from /proc/<pid>/cgroup, if available."""
    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("/")
                last = parts[-1] if parts else ""
                if "docker" in line or "containerd" in line or len(last) >= 64:
                    return last[:12] if len(last) >= 12 else last or None
    except (OSError, IOError):
        pass
    return None


def host_id() -> str:
    return os.environ.get("HOSTNAME") or os.environ.get("HOST") or ""


# Cgroup helpers


def read_file_int(path: str, default: int = 0) -> int:
    """Read an integer from a cgroup pseudo-file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
            if value == "max":
                return -1
            return int(value)
    except (OSError, IOError, ValueError):
        return default


def read_file_str(path: str, default: str = "") -> str:
    """Read a string from a cgroup pseudo-file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except (OSError, IOError):
        return default


def parse_kv_file(path: str) -> Dict[str, int]:
    """Parse a key-value cgroup stat file into a dictionary of integers."""
    result: Dict[str, int] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        result[parts[0]] = int(parts[1])
                    except ValueError:
                        pass
    except (OSError, IOError):
        pass
    return result


class CgroupReader:
    """Read cgroup metrics for a process or cgroup path.

    Supports both cgroup v1 and v2. In v1 the controllers are split into
    separate hierarchies; in v2 they are unified under a single path.
    """

    def __init__(self) -> None:
        self.version = self._detect_version()
        self.base_path = "/sys/fs/cgroup"

    def _detect_version(self) -> str:
        """Detect whether the host uses cgroup v1 or v2."""
        if os.path.isfile("/sys/fs/cgroup/cgroup.controllers"):
            return "v2"
        return "v1"

    def get_cgroup_path(self, pid: int) -> Optional[str]:
        """Return the cgroup path for a process from /proc/<pid>/cgroup.

        In cgroup v1 there are multiple controller-specific paths; we prefer a
        path that looks like a container slice (docker/containerd/kubepods) and
        avoid the root "/" hierarchy when possible.  In cgroup v2 there is only
        one path.
        """
        try:
            with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
        except (OSError, IOError):
            return None

        candidates: List[str] = []
        for line in lines:
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            path = parts[2]
            if not path:
                continue
            candidates.append(path)

        if not candidates:
            return None

        # Prefer container-like paths and avoid the root "/" hierarchy.
        for path in candidates:
            lowered = path.lower()
            if "/" in lowered and any(
                marker in lowered for marker in ("docker", "containerd", "kubepods", "lxc", "libvirt")
            ):
                return path

        non_root = [p for p in candidates if p != "/"]
        if non_root:
            return non_root[0]

        return candidates[0]

    def resolve_cpu_path(self, cgroup_path: str) -> Optional[str]:
        """Resolve the filesystem path for the cpu controller."""
        if self.version == "v2":
            return self.base_path + cgroup_path
        # v1: try cpuacct first, then cpu
        for controller in ("cpuacct", "cpu"):
            candidate = f"{self.base_path}/{controller}{cgroup_path}"
            if os.path.isdir(candidate):
                return candidate
        return None

    def resolve_memory_path(self, cgroup_path: str) -> Optional[str]:
        """Resolve the filesystem path for the memory controller."""
        if self.version == "v2":
            return self.base_path + cgroup_path
        candidate = f"{self.base_path}/memory{cgroup_path}"
        if os.path.isdir(candidate):
            return candidate
        return None

    def resolve_blkio_path(self, cgroup_path: str) -> Optional[str]:
        """Resolve the filesystem path for the blkio controller."""
        if self.version == "v2":
            return self.base_path + cgroup_path
        candidate = f"{self.base_path}/blkio{cgroup_path}"
        if os.path.isdir(candidate):
            return candidate
        return None

    def resolve_pids_path(self, cgroup_path: str) -> Optional[str]:
        """Resolve the filesystem path for the pids controller."""
        if self.version == "v2":
            return self.base_path + cgroup_path
        candidate = f"{self.base_path}/pids{cgroup_path}"
        if os.path.isdir(candidate):
            return candidate
        return None

    def read_cpu(self, cgroup_path: str) -> Dict[str, Any]:
        """Read CPU metrics for the cgroup."""
        result: Dict[str, Any] = {}
        cpu_path = self.resolve_cpu_path(cgroup_path)
        if not cpu_path:
            return result

        if self.version == "v2":
            stat = parse_kv_file(os.path.join(cpu_path, "cpu.stat"))
            result["usage_nanos"] = stat.get("usage_usec", 0) * 1000
            result["user_nanos"] = stat.get("user_usec", 0) * 1000
            result["system_nanos"] = stat.get("system_usec", 0) * 1000
            cpu_max = read_file_str(os.path.join(cpu_path, "cpu.max"), "max 100000")
            parts = cpu_max.split()
            if len(parts) >= 2:
                quota = parts[0]
                period = parts[1]
                result["cfs_quota_us"] = -1 if quota == "max" else int(quota)
                result["cfs_period_us"] = int(period)
        else:
            result["usage_nanos"] = read_file_int(os.path.join(cpu_path, "cpuacct.usage"))
            stat = parse_kv_file(os.path.join(cpu_path, "cpuacct.stat"))
            # user/system are in USER_HZ (usually 100 ticks/sec)
            try:
                ticks_per_sec = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
            except (KeyError, ValueError):
                ticks_per_sec = 100
            result["user_nanos"] = stat.get("user", 0) * 1_000_000_000 // ticks_per_sec
            result["system_nanos"] = stat.get("system", 0) * 1_000_000_000 // ticks_per_sec
            result["cfs_period_us"] = read_file_int(os.path.join(cpu_path, "cpu.cfs_period_us"))
            result["cfs_quota_us"] = read_file_int(os.path.join(cpu_path, "cpu.cfs_quota_us"))

        return result

    def read_memory(self, cgroup_path: str) -> Dict[str, Any]:
        """Read memory metrics for the cgroup."""
        result: Dict[str, Any] = {}
        mem_path = self.resolve_memory_path(cgroup_path)
        if not mem_path:
            return result

        if self.version == "v2":
            result["current_bytes"] = read_file_int(os.path.join(mem_path, "memory.current"))
            limit = read_file_str(os.path.join(mem_path, "memory.max"), "max")
            result["limit_bytes"] = -1 if limit == "max" else int(limit)
            stat = parse_kv_file(os.path.join(mem_path, "memory.stat"))
            result["rss_bytes"] = stat.get("anon", 0)
            result["swap_bytes"] = stat.get("swap", 0)
        else:
            result["current_bytes"] = read_file_int(os.path.join(mem_path, "memory.usage_in_bytes"))
            result["limit_bytes"] = read_file_int(os.path.join(mem_path, "memory.limit_in_bytes"))
            stat = parse_kv_file(os.path.join(mem_path, "memory.stat"))
            result["rss_bytes"] = stat.get("rss", 0)
            result["swap_bytes"] = stat.get("swap", 0)

        return result

    def read_blkio(self, cgroup_path: str) -> Dict[str, Any]:
        """Read block I/O metrics for the cgroup."""
        result: Dict[str, Any] = {}
        blkio_path = self.resolve_blkio_path(cgroup_path)
        if not blkio_path:
            return result

        if self.version == "v2":
            # io.stat format: major:minor rbytes=... wbytes=...
            read_bytes = 0
            write_bytes = 0
            try:
                with open(os.path.join(blkio_path, "io.stat"), "r", encoding="utf-8") as f:
                    for line in f:
                        for token in line.split():
                            if token.startswith("rbytes="):
                                try:
                                    read_bytes += int(token.split("=", 1)[1])
                                except ValueError:
                                    pass
                            elif token.startswith("wbytes="):
                                try:
                                    write_bytes += int(token.split("=", 1)[1])
                                except ValueError:
                                    pass
            except (OSError, IOError):
                pass
            result["read_bytes"] = read_bytes
            result["write_bytes"] = write_bytes
        else:
            stat = parse_kv_file(os.path.join(blkio_path, "blkio.throttle.io_service_bytes"))
            result["read_bytes"] = stat.get("Read", 0)
            result["write_bytes"] = stat.get("Write", 0)

        return result

    def read_pids(self, cgroup_path: str) -> Dict[str, Any]:
        """Read PID metrics for the cgroup."""
        result: Dict[str, Any] = {}
        pids_path = self.resolve_pids_path(cgroup_path)
        if not pids_path:
            return result

        result["current"] = read_file_int(os.path.join(pids_path, "pids.current"))
        max_val = read_file_str(os.path.join(pids_path, "pids.max"), "max")
        result["max"] = -1 if max_val == "max" else int(max_val)
        return result


# Cgroup monitor


class CgroupMonitor:
    """Monitor cgroup metrics for bound contexts and emit snapshot/anomaly events."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.reader = CgroupReader()
        self.last_states: Dict[str, Dict[str, Any]] = {}
        self.last_scan_times: Dict[str, float] = {}
        # Heartbeat clock is tracked separately from last_scan_times (which is
        # refreshed on every scan) so cgroupsAggregateWindowSeconds actually
        # spaces heartbeat snapshots apart.
        self.last_heartbeat_emit: Dict[str, float] = {}
        self._last_debug: Optional[str] = None

    def is_enabled(self) -> bool:
        return bool(self.config.get("cgroupsEnabled", False))

    def _log(self, level: str, message: str) -> None:
        payload = {"type": "log", "level": level, "message": message}
        print(json.dumps(payload), file=sys.stderr)
        sys.stderr.flush()

    def scan(self, contexts: Dict[int, Dict[str, Any]], burst_mode: bool) -> List[Dict[str, Any]]:
        """Scan cgroups for all bound contexts and return enriched events."""
        if not self.is_enabled():
            return []

        events: List[Dict[str, Any]] = []
        now = time.time()

        # Collect cgroup paths to monitor, mapped to their context
        paths_to_monitor: Dict[str, Dict[str, Any]] = {}
        for root_pid, context in list(contexts.items()):
            if not psutil.pid_exists(root_pid):
                continue
            cgroup_path = self.reader.get_cgroup_path(root_pid)
            if not cgroup_path:
                continue
            if cgroup_path not in paths_to_monitor:
                paths_to_monitor[cgroup_path] = dict(context)
                paths_to_monitor[cgroup_path]["root_pid"] = root_pid

        # Fallback: if no contexts bound, monitor own cgroup (useful for testing)
        fallback = False
        if not paths_to_monitor:
            fallback = True
            own_path = self.reader.get_cgroup_path(os.getpid())
            if own_path:
                paths_to_monitor[own_path] = {}

        debug_key = f"ctx={len(contexts)} paths={sorted(paths_to_monitor)} fallback={fallback}"
        if debug_key != self._last_debug:
            self._last_debug = debug_key
            self._log("debug", f"cgroup scan contexts: {debug_key}")

        for cgroup_path, context in paths_to_monitor.items():
            try:
                cgroup_events = self._scan_cgroup(cgroup_path, context, now, burst_mode)
                events.extend(cgroup_events)
            except Exception:
                # Never let cgroup scanning crash the monitor
                continue

        return events

    def _scan_cgroup(
        self, cgroup_path: str, context: Dict[str, Any], now: float, burst_mode: bool
    ) -> List[Dict[str, Any]]:
        """Scan a single cgroup and emit enriched events."""
        events: List[Dict[str, Any]] = []

        cpu = self.reader.read_cpu(cgroup_path)
        memory = self.reader.read_memory(cgroup_path)
        blkio = self.reader.read_blkio(cgroup_path)
        pids = self.reader.read_pids(cgroup_path)

        if not cpu and not memory and not pids:
            return events

        # Compute usage percentages
        current = self._build_snapshot(cgroup_path, cpu, memory, blkio, pids)
        self._enrich_with_context(current, context)

        prev = self.last_states.get(cgroup_path)
        prev_time = self.last_scan_times.get(cgroup_path, now)
        elapsed = now - prev_time

        if prev and elapsed > 0:
            cpu_delta = current.get("cpu", {}).get("usage_nanos", 0) - prev.get("cpu", {}).get("usage_nanos", 0)
            cfs_quota = current.get("cpu", {}).get("cfs_quota_us", 0)
            cfs_period = current.get("cpu", {}).get("cfs_period_us", 0)
            cpu_limit = 1.0
            if cfs_quota > 0 and cfs_period > 0:
                cpu_limit = cfs_quota / cfs_period

            cpu_percent = (cpu_delta / 1_000_000_000) / elapsed * 100 / cpu_limit if cpu_limit > 0 else 0.0
            cpu_percent = max(0.0, min(cpu_percent, 100.0 * max(cpu_limit, 1.0)))
            current["cpu"]["usage_percent"] = round(cpu_percent, 2)

            mem_current = current.get("memory", {}).get("current_bytes", 0)
            mem_limit = current.get("memory", {}).get("limit_bytes", 0)
            if mem_limit and mem_limit > 0:
                current["memory"]["usage_percent"] = round((mem_current / mem_limit) * 100, 2)

            # Check anomaly conditions
            anomaly = self._detect_anomaly(cgroup_path, context, prev, current, elapsed)
            if anomaly:
                events.append(anomaly)

        # Decide whether to emit snapshot based on change thresholds
        if self._should_emit_snapshot(cgroup_path, prev, current, burst_mode, now):
            # Field cropping in non-burst mode: keep full state internally,
            # emit only the cropped version.
            if not burst_mode and self.config.get("cgroupsFullFieldsInBurstOnly", True):
                events.append(self._crop_snapshot(current))
            else:
                events.append(current)

        self.last_states[cgroup_path] = current
        self.last_scan_times[cgroup_path] = now
        return events

    def _enrich_with_context(self, event: Dict[str, Any], context: Dict[str, Any]) -> None:
        """Add session/run/agent/tool metadata from the bound context."""
        for key in ("session_id", "run_id", "agent_id", "tool_name", "tool_call_id"):
            if context.get(key):
                event[key] = context[key]

    def _build_snapshot(
        self,
        cgroup_path: str,
        cpu: Dict[str, Any],
        memory: Dict[str, Any],
        blkio: Dict[str, Any],
        pids: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a cgroup_snapshot event.

        event_type 带 x_openclaw_ 前缀：平台 validate_batch 对未登记且无
        x_<project>_ 前缀的类型直接 UnsupportedEventType 并整批拒绝 NDJSON。
        """
        now = int(time.time() * 1000)
        snapshot: Dict[str, Any] = {
            "comm": "openclaw-process-monitor",
            "event_id": str(uuid.uuid4()),
            "event_type": "x_openclaw_cgroup_snapshot",
            "layer": "system",
            "ts": now,
            "cgroup_version": self.reader.version,
            "cgroup_path": cgroup_path,
            "host_id": host_id(),
        }
        if cpu:
            snapshot["cpu"] = cpu
        if memory:
            snapshot["memory"] = memory
        if blkio:
            snapshot["blkio"] = blkio
        if pids:
            snapshot["pids"] = pids
        return snapshot

    def _crop_snapshot(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Return a cropped snapshot with only core fields for normal mode."""
        cropped = {
            k: v
            for k, v in snapshot.items()
            if k not in ("cpu", "memory", "blkio", "pids")
        }
        if "cpu" in snapshot:
            cropped["cpu"] = {"usage_percent": snapshot["cpu"].get("usage_percent")}
        if "memory" in snapshot:
            cropped["memory"] = {"usage_percent": snapshot["memory"].get("usage_percent")}
        if "pids" in snapshot:
            cropped["pids"] = {"current": snapshot["pids"].get("current")}
        return cropped

    def _should_emit_snapshot(
        self,
        cgroup_path: str,
        prev: Optional[Dict[str, Any]],
        current: Dict[str, Any],
        burst_mode: bool,
        now: float,
    ) -> bool:
        """Determine if a snapshot should be emitted based on redundancy controls."""
        if prev is None:
            return True

        if burst_mode:
            return True

        # Change threshold checks
        cpu_threshold = float(self.config.get("cgroupsCpuChangeThresholdPercent", 5.0))
        memory_threshold = float(self.config.get("cgroupsMemoryChangeThresholdPercent", 5.0))
        io_threshold = int(self.config.get("cgroupsIoChangeThresholdBytes", 1024 * 1024))

        prev_cpu_pct = prev.get("cpu", {}).get("usage_percent", 0) or 0
        curr_cpu_pct = current.get("cpu", {}).get("usage_percent", 0) or 0
        if abs(curr_cpu_pct - prev_cpu_pct) >= cpu_threshold:
            return True

        prev_mem_pct = prev.get("memory", {}).get("usage_percent", 0) or 0
        curr_mem_pct = current.get("memory", {}).get("usage_percent", 0) or 0
        if abs(curr_mem_pct - prev_mem_pct) >= memory_threshold:
            return True

        prev_read = prev.get("blkio", {}).get("read_bytes", 0) or 0
        curr_read = current.get("blkio", {}).get("read_bytes", 0) or 0
        prev_write = prev.get("blkio", {}).get("write_bytes", 0) or 0
        curr_write = current.get("blkio", {}).get("write_bytes", 0) or 0
        if abs(curr_read - prev_read) >= io_threshold or abs(curr_write - prev_write) >= io_threshold:
            return True

        prev_pids = prev.get("pids", {}).get("current", 0) or 0
        curr_pids = current.get("pids", {}).get("current", 0) or 0
        if curr_pids != prev_pids:
            return True

        # Aggregation window: emit a periodic heartbeat only when enabled and
        # no threshold has been crossed. This avoids redundant snapshots in
        # steady-state deployments.
        if not self.config.get("cgroupsHeartbeatEnabled", False):
            return False
        window_seconds = int(self.config.get("cgroupsAggregateWindowSeconds", 60))
        last_emit = self.last_heartbeat_emit.get(cgroup_path, 0)
        if window_seconds > 0 and (now - last_emit) >= window_seconds:
            self.last_heartbeat_emit[cgroup_path] = now
            return True

        return False

    def _detect_anomaly(
        self,
        cgroup_path: str,
        context: Dict[str, Any],
        prev: Dict[str, Any],
        current: Dict[str, Any],
        elapsed: float,
    ) -> Optional[Dict[str, Any]]:
        """Detect anomalies and return an anomaly event if found."""
        cpu_spike_threshold = float(self.config.get("cgroupsAnomalyCpuSpikeThresholdPercent", 50.0))
        memory_threshold = float(self.config.get("cgroupsAnomalyMemoryThresholdPercent", 80.0))

        prev_cpu_pct = prev.get("cpu", {}).get("usage_percent", 0) or 0
        curr_cpu_pct = current.get("cpu", {}).get("usage_percent", 0) or 0
        cpu_jump = curr_cpu_pct - prev_cpu_pct

        anomaly: Optional[Dict[str, Any]] = None
        if cpu_jump >= cpu_spike_threshold:
            anomaly = self._build_anomaly_event(
                cgroup_path,
                "cpu_spike",
                "high",
                f"CPU usage_percent jumped from {prev_cpu_pct}% to {curr_cpu_pct}% within {elapsed:.1f} seconds",
                {"cpu_usage_percent": prev_cpu_pct},
                {"cpu_usage_percent": curr_cpu_pct},
            )
        else:
            curr_mem_pct = current.get("memory", {}).get("usage_percent", 0) or 0
            if curr_mem_pct >= memory_threshold:
                anomaly = self._build_anomaly_event(
                    cgroup_path,
                    "memory_high",
                    "medium",
                    f"Memory usage_percent reached {curr_mem_pct}%",
                    {"memory_usage_percent": prev.get("memory", {}).get("usage_percent", 0)},
                    {"memory_usage_percent": curr_mem_pct},
                )

        if anomaly:
            self._enrich_with_context(anomaly, context)
        return anomaly

    def _build_anomaly_event(
        self,
        cgroup_path: str,
        anomaly_type: str,
        severity: str,
        description: str,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
    ) -> Dict[str, Any]:
        now = int(time.time() * 1000)
        return {
            "comm": "openclaw-process-monitor",
            "event_id": str(uuid.uuid4()),
            "event_type": "x_openclaw_cgroup_anomaly",
            "layer": "system",
            "ts": now,
            "cgroup_version": self.reader.version,
            "cgroup_path": cgroup_path,
            "host_id": host_id(),
            "anomaly_type": anomaly_type,
            "severity": severity,
            "description": description,
            "baseline": baseline,
            "current": current,
        }


# Monitor


class ProcessMonitor:
    """psutil-based process tree monitor for OpenClaw security events."""

    # I-C2-04: signals this monitor is allowed to forward to other processes.
    # Anything outside this set (SIGKILL, SIGSTOP, raw integers that happen to
    # map to other signals, …) is rejected at kill_process() entry. The
    # previous implementation passed whatever the caller supplied, which let
    # a hostile caller send SIGKILL to PID 1 or otherwise wedge the host.
    # SIGHUP is POSIX-only: on Windows use the SIGTERM fallback.
    _sighup = getattr(signal, "SIGHUP", signal.SIGTERM)
    ALLOWED_SIGNALS = frozenset({
        signal.SIGTERM, signal.SIGINT, _sighup,
        "SIGTERM", "SIGINT", "SIGHUP", 15, 2, 1,
    })
    KILL_RATE_LIMIT_S = 60.0  # one kill per PID per window

    def __init__(self) -> None:
        self.config = dict(DEFAULT_CONFIG)
        self.contexts: Dict[int, Dict[str, Any]] = {}
        self.last_states: Dict[int, Dict[str, Any]] = {}
        self.command_queue: Queue[Dict[str, Any]] = Queue()
        self.running = True
        self.scan_counter = 0
        self.own_pid = os.getpid()
        self.cgroup_monitor = CgroupMonitor(self.config)
        self.last_cgroup_scan = 0.0
        # I-C2-04: per-PID last-kill timestamp for rate limiting.
        self.last_kill_at: Dict[int, float] = {}

    # -----------------------------------------------------------------------
    # Logging / output
    # -----------------------------------------------------------------------

    def log(self, level: str, message: str) -> None:
        payload = {"type": "log", "level": level, "message": message}
        print(json.dumps(payload), file=sys.stderr)
        sys.stderr.flush()

    def emit(self, event: Dict[str, Any]) -> None:
        print(json.dumps(event, ensure_ascii=False))
        sys.stdout.flush()

    # -----------------------------------------------------------------------
    # Command handling
    # -----------------------------------------------------------------------

    def enqueue_command(self, command: Dict[str, Any]) -> None:
        self.command_queue.put(command)

    def process_pending_commands(self) -> None:
        while not self.command_queue.empty():
            try:
                cmd = self.command_queue.get_nowait()
            except Exception:
                break
            self.handle_command(cmd)

    def handle_command(self, cmd: Dict[str, Any]) -> None:
        cmd_type = cmd.get("type")
        data = cmd.get("data", {})

        if cmd_type == "config":
            self.update_config(data)
        elif cmd_type == "bind_context":
            self.bind_context(
                root_pid=data.get("root_pid"),
                session_id=data.get("session_id"),
                run_id=data.get("run_id"),
                agent_id=data.get("agent_id"),
                tool_name=data.get("tool_name"),
                tool_call_id=data.get("tool_call_id"),
            )
        elif cmd_type == "unbind_context":
            self.unbind_context(data.get("root_pid"))
        elif cmd_type == "kill_pid":
            self.kill_process(data.get("pid"), data.get("signal"))
        elif cmd_type == "shutdown":
            self.running = False
        else:
            self.log("warn", f"Unknown command type: {cmd_type}")

    def kill_process(
        self,
        pid: Optional[int],
        signal: Optional[Union[int, str]] = None,
    ) -> bool:
        """Kill a process by PID using the configured or supplied signal.

        Safety rules (I-C2-04):
          - never kill the monitor itself, PID 0/1, or protected PIDs
          - only signals in ALLOWED_SIGNALS (SIGTERM/SIGINT/SIGHUP)
          - only PIDs the monitor has previously observed via scan()
          - rate-limited to one kill per PID per 60s window
          - Windows: only SIGTERM is reliably supported by psutil
        """
        if pid is None or not isinstance(pid, int):
            self.log("warn", f"kill_process called with invalid pid: {pid}")
            return False

        if pid == self.own_pid:
            self.log("warn", f"Refusing to kill monitor's own PID {pid}")
            return False
        if pid in (0, 1):
            self.log("warn", f"Refusing to kill special PID {pid}")
            return False

        protected = self.config.get("protectedPids") or []
        if isinstance(protected, list) and pid in protected:
            self.log("warn", f"Refusing to kill protected PID {pid}")
            return False

        # PID allowlist: only kill processes we have actually observed.
        # Without this guard, the IPC channel could be used to terminate
        # arbitrary host processes (e.g. another container's init).
        if pid not in self.contexts and pid not in self.last_states:
            self.log("warn", f"Refusing to kill unobserved PID {pid}")
            return False

        # Signal whitelist.
        sig = signal if signal is not None else self.config.get("killSignal", "SIGTERM")
        if sig not in self.ALLOWED_SIGNALS:
            self.log("warn", f"Refusing to send disallowed signal {sig!r} to PID {pid}")
            return False

        # Per-PID rate limit.
        now = time.monotonic()
        last = self.last_kill_at.get(pid)
        if last is not None and now - last < self.KILL_RATE_LIMIT_S:
            self.log(
                "warn",
                f"Rate-limited kill on PID {pid} (last={last:.1f}, now={now:.1f})"
            )
            return False
        self.last_kill_at[pid] = now

        try:
            psutil.Process(pid).send_signal(sig)
            self.log("info", f"Sent signal {sig} to PID {pid}")
            return True
        except psutil.NoSuchProcess:
            self.log("warn", f"Failed to kill PID {pid}: process does not exist")
        except psutil.AccessDenied:
            self.log("warn", f"Failed to kill PID {pid}: access denied")
        except Exception as e:
            self.log("error", f"Failed to kill PID {pid}: {e}")
        return False

    def update_config(self, config: Dict[str, Any]) -> None:
        for key, value in config.items():
            if key in self.config:
                self.config[key] = value
        self.cgroup_monitor.config = self.config
        self.log("info", f"Config updated: {self.config}")

    def bind_context(
        self,
        root_pid: Optional[int],
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_call_id: Optional[str] = None,
    ) -> None:
        if root_pid is None or not isinstance(root_pid, int):
            self.log("warn", f"bind_context called without valid root_pid: {root_pid}")
            return
        self.contexts[root_pid] = {
            "session_id": session_id,
            "run_id": run_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "tool_call_id": tool_call_id,
        }
        self.log("info", f"Bound context to root_pid={root_pid}")

    def unbind_context(self, root_pid: Optional[int]) -> None:
        if root_pid is None:
            return
        if root_pid in self.contexts:
            del self.contexts[root_pid]
            self.log("info", f"Unbound context for root_pid={root_pid}")

    # -----------------------------------------------------------------------
    # Main loop
    # -----------------------------------------------------------------------

    def scan_interval_ms(self) -> int:
        """Current scan interval, with a safe fallback for malformed config.

        The JS side drops non-finite numbers, but a hand-edited or third-party
        command could still push a non-numeric scanIntervalMs; int(None) /
        int("abc") must not kill the monitor loop.
        """
        try:
            return int(self.config["scanIntervalMs"])
        except (TypeError, ValueError):
            return 5000

    def run(self) -> None:
        self.log("info", "OpenClaw process monitor started")
        try:
            while self.running:
                try:
                    self.process_pending_commands()
                    self.scan()
                    self.scan_counter += 1
                    # Short sleep loop so shutdown commands and scan-interval changes
                    # (e.g. entering/leaving burst mode) are handled promptly.
                    target_interval = self.scan_interval_ms()
                    for _ in range(max(1, int(target_interval / 100))):
                        if not self.running:
                            break
                        # If the interval was reconfigured, finish this mini-sleep early
                        # so the next scan can use the new interval.
                        if self.scan_interval_ms() != target_interval:
                            break
                        time.sleep(0.1)
                except Exception as e:
                    # A single bad scan (TypeError from poisoned config, psutil
                    # hiccup, ...) must not take the whole monitor down — the
                    # gateway side restarts are expensive and lose state.
                    self.log("error", f"Monitor scan iteration failed, continuing: {e}")
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.log("info", "Interrupted by signal")
        finally:
            self.log("info", "Monitor exiting")

    # -----------------------------------------------------------------------
    # Scanning
    # -----------------------------------------------------------------------

    def scan(self) -> None:
        current_pids: Set[int] = set()

        if self.contexts:
            # Normal mode: monitor the process trees of all bound contexts.
            for root_pid, context in list(self.contexts.items()):
                if not psutil.pid_exists(root_pid):
                    self.log("info", f"Root process {root_pid} gone, removing context")
                    del self.contexts[root_pid]
                    continue

                try:
                    root = psutil.Process(root_pid)
                    processes: List[psutil.Process] = [root]
                    if self.config.get("collectChildren", True):
                        processes.extend(root.children(recursive=True))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                for proc in processes:
                    try:
                        if self.should_exclude_process(proc):
                            continue
                        snapshot = self.build_snapshot(proc, context)
                        pid = snapshot["pid"]
                        current_pids.add(pid)
                        self.handle_snapshot(pid, snapshot)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        else:
            # Fallback mode: no context bound yet, discover agent-related processes
            # by name so monitoring starts before the first tool call.
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    if self.should_exclude_process(proc):
                        continue
                    if not self.matches_process_names(proc):
                        continue
                    snapshot = self.build_snapshot(proc, {})
                    pid = snapshot["pid"]
                    current_pids.add(pid)
                    self.handle_snapshot(pid, snapshot)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        # Global burst scan: during active tool execution, also observe all
        # processes system-wide. This catches commands spawned outside the
        # bound process tree (e.g. by a worker with a separate process group).
        if self.contexts and self.config.get("burstMode") and self.config.get("burstScanGlobal"):
            active_context = list(self.contexts.values())[-1]
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    if proc.pid in current_pids:
                        continue
                    if self.should_exclude_process(proc):
                        continue
                    snapshot = self.build_snapshot(proc, active_context)
                    pid = snapshot["pid"]
                    current_pids.add(pid)
                    self.handle_snapshot(pid, snapshot)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        # Detect exits. build_snapshot() stores session/run/agent/tool context
        # at the snapshot top level, so pass the last state itself — reading a
        # nonexistent "context" sub-key would silently null out attribution.
        for pid in list(self.last_states.keys()):
            if pid not in current_pids:
                self.emit_exit_event(pid, self.last_states[pid])
                del self.last_states[pid]

        # Cgroup monitoring
        self.scan_cgroups()

    def scan_cgroups(self) -> None:
        """Run cgroup monitoring if enabled and the scan interval has elapsed."""
        if not self.cgroup_monitor.is_enabled():
            return

        now = time.time()
        burst_mode = bool(self.config.get("burstMode"))
        interval_ms = (
            self.config.get("cgroupsBurstScanIntervalMs", 200)
            if burst_mode
            else self.config.get("cgroupsScanIntervalMs", 5000)
        )
        if (now - self.last_cgroup_scan) * 1000 < interval_ms:
            return

        events = self.cgroup_monitor.scan(self.contexts, burst_mode)
        for event in events:
            self.emit(event)

        self.last_cgroup_scan = now

    def matches_process_names(self, proc: psutil.Process) -> bool:
        """Return True if the process name or command line matches any configured name."""
        names = self.config.get("processNames", [])
        if not isinstance(names, list) or not names:
            return False

        process_name = safe_get(proc.name, "")
        cmdline = safe_get(lambda: " ".join(proc.cmdline() or []), "")
        text = f"{process_name} {cmdline}".lower()

        return any(str(name).lower() in text for name in names)

    def score_snapshot(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Score the snapshot command line and attach risk fields."""
        command_line = snapshot.get("cmdline") or ""
        exe_path = snapshot.get("exe_path") or snapshot.get("exe")
        flags, score = score_command_line(command_line, exe_path)
        # A node process whose environ was readable AND lacks the runtime-hook
        # marker runs without the preloaded child_process hook. Unreadable
        # environ (permissions / platform / race) skips silently.
        if snapshot.get("runtime_hook_loaded") is False:
            flags.append(UNPATCHED_ENGINE_FLAG)
            score = float(len(flags))
        snapshot["risk_flags"] = flags
        snapshot["risk_score"] = score
        return snapshot

    def _should_autokill(self, pid: int, snapshot: Dict[str, Any]) -> Optional[str]:
        """Return the matched flag that triggers auto-kill, or None."""
        if not self.config.get("autoKill", False):
            return None
        if pid == self.own_pid:
            return None
        if pid in (0, 1):
            return None
        protected = self.config.get("protectedPids") or []
        if isinstance(protected, list) and pid in protected:
            return None

        score = snapshot.get("risk_score", 0.0) or 0.0
        try:
            threshold = float(self.config.get("riskThreshold", 1.0))
        except (TypeError, ValueError):
            threshold = 1.0
        if score < threshold:
            return None

        flags = snapshot.get("risk_flags") or []
        if not flags:
            return None

        allowed_flags = self.config.get("riskFlags") or []
        if not isinstance(allowed_flags, list):
            allowed_flags = []
        # If riskFlags is empty, treat that as "any matched flag" for safety.
        if not allowed_flags:
            return flags[0]
        for flag in flags:
            if flag in allowed_flags:
                return flag
        return None

    def handle_snapshot(self, pid: int, snapshot: Dict[str, Any]) -> None:
        snapshot = self.score_snapshot(snapshot)
        trigger_flag = self._should_autokill(pid, snapshot)
        killed = False
        kill_signal: Optional[Union[int, str]] = None
        kill_reason: Optional[str] = None

        if trigger_flag:
            kill_signal = self.config.get("killSignal", "SIGTERM")
            kill_reason = f"auto-kill triggered by risk flag: {trigger_flag}"
            killed = self.kill_process(pid, kill_signal)
            snapshot["killed"] = killed
            snapshot["kill_signal"] = kill_signal
            snapshot["kill_reason"] = kill_reason

        prev = self.last_states.get(pid)
        emit_snapshot = False
        snapshot_interval = self.config.get("snapshotIntervalMs", 0)
        if snapshot_interval and snapshot_interval > 0:
            emit_snapshot = (self.scan_counter * self.config["scanIntervalMs"]) % snapshot_interval < self.config["scanIntervalMs"]

        if prev is None:
            snapshot["event_type"] = "process_start"
            self.emit(snapshot)
        elif self.has_changed(prev, snapshot):
            snapshot["event_type"] = "x_openclaw_process_change"
            snapshot["changed_fields"] = self.changed_fields(prev, snapshot)
            self.emit(snapshot)
        elif emit_snapshot:
            snapshot["event_type"] = "x_openclaw_process_snapshot"
            self.emit(snapshot)

        self.last_states[pid] = snapshot

    # -----------------------------------------------------------------------
    # Exclusion logic
    # -----------------------------------------------------------------------

    def should_exclude_process(self, proc: psutil.Process) -> bool:
        """Return True if the process should not be reported.

        Excludes:
        - the monitor process itself (by PID)
        - processes whose command line matches configured exclude patterns

        Audit H10: 默认配置里的 ``"process_monitor.py"`` 是子串匹配，
        任意进程在 argv 里塞这个字样（``bash -c 'evil # process_monitor.py'``）
        即被整体跳过 — 不产事件、不 autokill。改为精确匹配自身可执行路径
        （解析 ``sys.argv[0]`` 为绝对路径后与 cmdline 首词比较）。
        """
        if proc.pid == self.own_pid:
            return True

        cmdline = safe_get(lambda: " ".join(proc.cmdline() or []), "")
        exclude_patterns = self.config.get("excludeCommandLines", [])
        if isinstance(exclude_patterns, list):
            for pattern in exclude_patterns:
                if not pattern:
                    continue
                if pattern == "process_monitor.py":
                    # 哨兵：精确匹配自身可执行路径
                    own = self._own_executable
                    if own and cmdline.split(" ", 1)[0] == own:
                        return True
                    continue
                if pattern in cmdline:
                    return True
        return False

    @property
    def _own_executable(self) -> str:
        """自身可执行文件的绝对路径（缓存于实例）。"""
        cached = getattr(self, "_own_executable_cached", None)
        if cached is not None:
            return cached
        try:
            own = os.path.realpath(sys.argv[0])
        except Exception:
            own = ""
        self._own_executable_cached = own
        return own

    # -----------------------------------------------------------------------
    # Snapshot construction
    # -----------------------------------------------------------------------

    def build_snapshot(self, proc: psutil.Process, context: Dict[str, Any]) -> Dict[str, Any]:
        with proc.oneshot():
            cmdline = safe_get(lambda: proc.cmdline(), [])
            process_name = safe_get(proc.name, "")
            now = int(time.time() * 1000)
            snapshot: Dict[str, Any] = {
                "comm": process_name or "openclaw-process-monitor",
                "event_id": str(uuid.uuid4()),
                "event_type": "x_openclaw_process_snapshot",
                "layer": "system",
                "ts": now,
                "session_id": context.get("session_id"),
                "run_id": context.get("run_id"),
                "agent_id": context.get("agent_id"),
                "tool_name": context.get("tool_name"),
                "tool_call_id": context.get("tool_call_id"),
                "host_id": host_id(),
                "container_id": get_container_id(proc.pid),
                "pid": proc.pid,
                "ppid": safe_get(proc.ppid),
                "pgid": safe_get(lambda: proc.pgid()),
                "sid": safe_get(lambda: proc.sid()),
                "process_name": process_name,
                "cmdline": redact_command_line(" ".join(cmdline)),
                "exe_path": safe_get(proc.exe),
                "exe": safe_get(proc.exe),
                "cwd": safe_get(proc.cwd),
                "username": safe_get(proc.username),
                "uid": safe_get(lambda: proc.uids().real),
                "gid": safe_get(lambda: proc.gids().real),
                "create_time": safe_get(lambda: int(proc.create_time() * 1000)),
                "process_status": safe_get(proc.status),
                "memory_rss": safe_get(lambda: proc.memory_info().rss),
            }

            if self.config.get("collectChildren", True):
                snapshot["child_pids"] = safe_get(
                    lambda: [c.pid for c in proc.children(recursive=False)], []
                )

            if self.config.get("collectOpenFiles", False):
                snapshot["open_files"] = safe_get(
                    lambda: [{"path": f.path, "fd": f.fd} for f in proc.open_files()],
                    [],
                )

            if self.config.get("collectConnections", False):
                conns: List[Dict[str, Any]] = []
                raw = safe_get(lambda: proc.connections("inet"), [])
                for c in raw:
                    conns.append({
                        "local_ip": format_addr(c.laddr),
                        "remote_ip": format_addr(c.raddr),
                        "status": c.status,
                    })
                snapshot["connections"] = conns

            if self.config.get("collectCpuPercent", False):
                snapshot["cpu_percent"] = safe_get(lambda: proc.cpu_percent(interval=0.1))

            # For node processes, record whether the runtime-hook marker env
            # is present so score_snapshot() can flag engines that run WITHOUT
            # the preloaded hook (e.g. parent stripped NODE_OPTIONS). None
            # (unreadable env) means "unknown" and is never treated as a
            # bypass.
            if is_node_process(process_name, snapshot.get("exe_path")):
                environ = read_process_environ(proc)
                if environ is not None:
                    snapshot["runtime_hook_loaded"] = HOOK_MARKER_ENV in environ

        return snapshot

    # -----------------------------------------------------------------------
    # Change detection
    # -----------------------------------------------------------------------

    def change_detection_keys(self) -> List[str]:
        fields = self.config.get("changeDetectionFields") or []
        if not isinstance(fields, list) or not fields:
            return ["cmdline", "cwd", "process_status", "memory_rss", "ppid", "exe_path"]
        return [str(f) for f in fields]

    def _field_changed(self, key: str, prev: Dict[str, Any], curr: Dict[str, Any]) -> bool:
        prev_val = prev.get(key)
        curr_val = curr.get(key)
        if prev_val == curr_val:
            return False

        if key == "memory_rss":
            threshold = self.config.get("memoryRssChangeThresholdBytes", 0)
            try:
                threshold = int(threshold)
            except (TypeError, ValueError):
                threshold = 0
            if threshold > 0:
                try:
                    diff = abs(int(curr_val) - int(prev_val))
                    if diff < threshold:
                        return False
                except (TypeError, ValueError):
                    pass

        return True

    def has_changed(self, prev: Dict[str, Any], curr: Dict[str, Any]) -> bool:
        return any(self._field_changed(k, prev, curr) for k in self.change_detection_keys())

    def changed_fields(self, prev: Dict[str, Any], curr: Dict[str, Any]) -> List[str]:
        return [k for k in self.change_detection_keys() if self._field_changed(k, prev, curr)]

    # -----------------------------------------------------------------------
    # Exit event
    # -----------------------------------------------------------------------

    def emit_exit_event(self, pid: int, context: Dict[str, Any]) -> None:
        # Best-effort: recover process info from last state if available
        last_state = self.last_states.get(pid, {})
        exe = last_state.get("exe") or last_state.get("exe_path")
        create_time = last_state.get("create_time")
        duration: Optional[int] = None
        if create_time and isinstance(create_time, (int, float)):
            duration = int(time.time() * 1000) - int(create_time)
        now = int(time.time() * 1000)
        self.emit({
            "comm": last_state.get("process_name") or "openclaw-process-monitor",
            "event_id": str(uuid.uuid4()),
            "event_type": "process_exit",
            "layer": "system",
            "ts": now,
            "session_id": context.get("session_id"),
            "run_id": context.get("run_id"),
            "agent_id": context.get("agent_id"),
            "tool_name": context.get("tool_name"),
            "tool_call_id": context.get("tool_call_id"),
            "host_id": host_id(),
            "container_id": get_container_id(pid),
            "pid": pid,
            "exe": exe,
            "exit_code": None,  # psutil does not provide exit code without waiting
            "duration": duration,
        })


# I/O threads


def read_stdin(monitor: ProcessMonitor) -> None:
    """Read NDJSON commands from stdin and enqueue them."""
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
                monitor.enqueue_command(cmd)
            except json.JSONDecodeError as e:
                monitor.log("error", f"Invalid JSON command: {e}")
    except Exception as e:
        monitor.log("error", f"stdin reader error: {e}")


# Entry point


def main() -> None:
    monitor = ProcessMonitor()

    # Start stdin reader thread so commands are handled asynchronously.
    reader = threading.Thread(target=read_stdin, args=(monitor,), daemon=True)
    reader.start()

    try:
        monitor.run()
    finally:
        # Give the reader thread a moment to drain any pending input.
        time.sleep(0.2)


if __name__ == "__main__":
    main()
