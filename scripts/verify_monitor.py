#!/usr/bin/env python3
"""
验证 OpenClaw 系统进程采集逻辑。

用法（在 Linux 目标容器/主机上执行）：
    cd ~/.openclaw/plugins/openclaw-security-monitor
    python3 scripts/verify_monitor.py

脚本会：
1. 启动 Python Monitor 子进程
2. 发送高频扫描配置（100ms）
3. 绑定当前 shell 进程作为上下文根
4. 模拟短生命周期命令（sleep 0.02 / whoami / echo）
5. 启动一个存活 2 秒的 long-running 子进程
6. 输出 Monitor 捕获到的事件，供人工判断逻辑是否正确
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def log(msg: str) -> None:
    print(f"[verify] {msg}", file=sys.stderr)


def main() -> int:
    base = Path(__file__).resolve().parent.parent
    # Install layout: system/process_monitor.py
    monitor_path = base / "system" / "process_monitor.py"
    if not monitor_path.exists():
        # Development layout fallback: monitor/process_monitor.py
        monitor_path = base / "monitor" / "process_monitor.py"
    if not monitor_path.exists():
        log(f"未找到 monitor 脚本: {monitor_path}")
        return 1

    log(f"启动 monitor: {monitor_path}")
    proc = subprocess.Popen(
        [sys.executable, str(monitor_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    events: list[dict] = []
    stderr_lines: list[str] = []

    def read_stdout() -> None:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                log(f"stdout 解析失败: {line}")

    def read_stderr() -> None:
        for line in proc.stderr:
            line = line.strip()
            if line:
                stderr_lines.append(line)
                log(f"monitor stderr: {line}")

    t_out = threading.Thread(target=read_stdout, daemon=True)
    t_err = threading.Thread(target=read_stderr, daemon=True)
    t_out.start()
    t_err.start()

    def send(cmd: dict) -> None:
        proc.stdin.write(json.dumps(cmd) + "\n")
        proc.stdin.flush()

    # 1. 配置高频扫描
    send({
        "type": "config",
        "data": {
            "scanIntervalMs": 100,
            "snapshotIntervalMs": 0,
            "processNames": ["openclaw", "node", "python", "hermes"],
            "excludeCommandLines": ["process_monitor.py"],
            "collectChildren": True,
            "collectOpenFiles": False,
            "collectConnections": False,
            "collectCpuPercent": False,
        },
    })
    time.sleep(0.3)

    # 2. 绑定当前 shell 作为上下文根
    root_pid = os.getpid()
    session_id = "verify-session-001"
    run_id = "verify-run-001"
    agent_id = "verify-agent-001"
    tool_name = "exec"
    send({
        "type": "bind_context",
        "data": {
            "root_pid": root_pid,
            "session_id": session_id,
            "run_id": run_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
        },
    })
    time.sleep(0.3)

    # 3. 模拟短生命周期子进程
    log("模拟短生命周期子进程: whoami / echo / sleep 0.02")
    subprocess.run(["whoami"], capture_output=True, text=True)
    subprocess.run(["echo", "hello"], capture_output=True, text=True)
    subprocess.run(["sleep", "0.02"], capture_output=True, text=True)
    time.sleep(0.3)

    # 4. 模拟一个存活 2 秒的 long-running 子进程
    log("模拟长生命周期子进程: sleep 2")
    long_proc = subprocess.Popen(["sleep", "2"])
    time.sleep(0.5)

    # 5. 结束 Monitor
    send({"type": "shutdown"})
    proc.wait(timeout=5)
    t_out.join(timeout=2)
    t_err.join(timeout=2)

    # 6. 输出事件汇总
    print("\n===== 采集到的事件汇总 =====")
    for ev in events:
        et = ev.get("event_type")
        pid = ev.get("pid")
        cmd = ev.get("cmdline", "")
        name = ev.get("process_name", "")
        sid = ev.get("session_id")
        aid = ev.get("agent_id")
        changed = ev.get("changed_fields", [])
        print(f"[{et:15}] pid={pid:6} name={name:20} cmd='{cmd}' session={sid} agent={aid} changed={changed}")

    long_pid = long_proc.pid
    long_proc.wait()

    captured_short = any("whoami" in (e.get("cmdline") or "") for e in events)
    captured_long_start = any(e.get("pid") == long_pid and e.get("event_type") == "process_start" for e in events)
    captured_long_exit = any(e.get("pid") == long_pid and e.get("event_type") == "process_exit" for e in events)
    context_bound = any(e.get("session_id") == session_id and e.get("agent_id") == agent_id for e in events)

    print("\n===== 验证结论 =====")
    print(f"上下文绑定正确: {'是' if context_bound else '否'}")
    print(f"捕获到 whoami 短进程: {'是' if captured_short else '否'}")
    print(f"捕获到 long-running 进程启动 (pid={long_pid}): {'是' if captured_long_start else '否'}")
    print(f"捕获到 long-running 进程退出 (pid={long_pid}): {'是' if captured_long_exit else '否'}")

    if captured_short:
        print("\n[提示] 即使 100ms 扫描也能捕获 whoami，说明命令执行窗口和扫描窗口重叠了。")
    else:
        print("\n[提示] 100ms 扫描仍未捕获 whoami，符合预期：whoami 实际执行时间通常 < 10ms，仍可能落在扫描间隙。")

    if not captured_long_start:
        print("[警告] 连 sleep 2 都没捕获到，说明 Monitor 进程树扫描逻辑可能有问题，需检查配置或 root_pid。")

    return 0


if __name__ == "__main__":
    sys.exit(main())
