"""macOS 系统级 IPv6 关闭与恢复。

只改 Wi-Fi 网络服务的 IPv6 配置（与原文一致），以太网、VPN 等其它服务不动；
关闭前把服务名单写进 ~/.ccclean/ipv6-state.json，恢复时按名单还原为 Automatic。
提权命令固定为 networksetup，服务名只来自本机枚举，不接受前端传入。
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from . import compat

STATE = Path.home() / ".ccclean/ipv6-state.json"
LOCK = threading.Lock()
NETWORKSETUP = "/usr/sbin/networksetup"
MODE_AUTO = "Automatic"

IMPACT = ("关闭后，Wi-Fi 上的 IPv6 将不可用，只提供 IPv6 的热点或服务可能无法连接；"
          "已建立的连接可能保持到断开为止。改动可能要在重新连接 Wi-Fi 后才完全生效，"
          "恢复为 Automatic 后 IPv6 会重新可用。")
LIMITS = ("只修改 Wi-Fi 网络服务的 IPv6 配置，不动以太网、VPN、USB 网络等其它服务；"
          "也不改代理软件内的 ipv6 开关，不验证代理远端解析是否仍走 IPv6。")


def _run(args, timeout=8):
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _services():
    """已启用的网络服务名。首行是说明，带 * 的是已停用服务。"""
    out = _run([NETWORKSETUP, "-listallnetworkservices"])
    lines = [line.strip() for line in out.splitlines()]
    return [line for i, line in enumerate(lines)
            if i > 0 and line and not line.startswith("*")]


def _mode(service):
    out = _run([NETWORKSETUP, "-getinfo", service])
    for line in out.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == "ipv6":
            return value.strip()
    return ""


def _snapshot():
    return [{"name": name, "mode": _mode(name)} for name in _services()]


# 原文关的是 Wi-Fi。networksetup 的服务名通常是 "Wi-Fi"，旧系统叫 "AirPort"，
# 统一按小写匹配，不做模糊猜测——多关一个 VPN 服务的代价比少关一个高得多。
_WIFI_NAMES = ("wi-fi", "wifi", "airport")


def _wifi_service(rows=None):
    rows = _snapshot() if rows is None else rows
    for row in rows:
        name = (row.get("name") or "").strip().lower()
        if name in _WIFI_NAMES or name.startswith("wi-fi"):
            return row
    return None


def _is_off(mode):
    return (mode or "").strip().lower() in ("off", "关闭")


def _is_auto(mode):
    return (mode or "").strip().lower() in ("automatic", "自动")


def _read_state():
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError) as exc:
        return None, f"IPv6 恢复记录无法读取：{exc}"
    services = data.get("services") if isinstance(data, dict) else None
    if (not isinstance(data, dict) or data.get("version") != 1
            or not isinstance(services, dict)
            or not all(isinstance(k, str) and isinstance(v, str)
                       for k, v in services.items())):
        return None, "IPv6 恢复记录格式不正确"
    return data, ""


def _state(strict=False):
    data, error = _read_state()
    if error and strict:
        raise ValueError(error + "，未修改系统设置")
    return data, error


def _write_state(data):
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".ipv6-", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _guard_paths():
    if STATE.is_symlink() or STATE.parent.is_symlink():
        raise ValueError("状态路径是符号链接，未修改")


def _script(jobs):
    lines = ["set -eu"]
    for name, flag in jobs:
        lines.append(f"{shlex.quote(NETWORKSETUP)} {flag} {shlex.quote(name)}")
    return "\n".join(lines) + "\n"


def _run_privileged(script):
    # 密码由 macOS 原生授权窗口处理，应用不收集密码。
    command = ("do shell script " + json.dumps(script, ensure_ascii=False)
               + " with administrator privileges")
    result = subprocess.run(["/usr/bin/osascript", "-e", command],
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError("系统未完成 IPv6 修改（可能取消授权或网络服务已变化）。可重试或恢复。")


def _set_modes(jobs):
    _run_privileged(_script(jobs))


def _modes(names):
    table = {row["name"]: row["mode"] for row in _snapshot()}
    return {name: table.get(name) for name in names}


def status():
    supported = compat.IS_MAC
    saved, state_error = _state()
    rows = _snapshot() if supported else []
    wifi = _wifi_service(rows) if rows else None
    wifi_name = wifi["name"] if wifi else ""
    wifi_mode = wifi["mode"] if wifi else ""
    automatic = [wifi_name] if wifi_name and _is_auto(wifi_mode) else []
    disabled = [wifi_name] if wifi_name and _is_off(wifi_mode) else []
    recorded = list(saved["services"]) if saved else []
    current = {r["name"]: r["mode"] for r in rows}
    changed = [name for name in recorded
               if name in current and _is_off(current[name])]
    return {
        "supported": supported,
        "services": rows,
        "wifi": wifi_name,
        "wifiMode": wifi_mode,
        "readError": "" if not supported or rows else "读不到已启用的网络服务",
        "wifiError": ("" if not supported or not rows or wifi_name
                      else "没有已启用的 Wi-Fi 网络服务"),
        "automatic": automatic,
        "disabled": disabled,
        "recorded": recorded,
        "changed": changed,
        "applied": bool(changed),
        "restoreAvailable": bool(saved),
        "savedAt": (saved or {}).get("createdAt") or 0,
        "statePath": str(STATE),
        "stateError": state_error,
        "exposure": compat.ipv6_exposure() if supported else {},
        "impact": IMPACT,
        "limits": LIMITS,
    }


def _off():
    saved, _ = _state(strict=True)
    if saved:
        raise ValueError("已有未恢复的 IPv6 改动，请先恢复为 Automatic")
    rows = _snapshot()
    if not rows:
        raise ValueError("读不到已启用的网络服务，未修改")
    wifi = _wifi_service(rows)
    if not wifi:
        raise ValueError("没有已启用的 Wi-Fi 网络服务，未修改")
    name = wifi["name"]
    if not _is_auto(wifi["mode"]):
        raise ValueError(f"{name} 的 IPv6 当前不是 Automatic（{wifi['mode'] or '未知'}），未修改")
    _write_state({"version": 1, "createdAt": time.time(),
                  "services": {name: MODE_AUTO}})
    try:
        _set_modes([(name, "-setv6off")])
    except Exception:
        # 授权取消时一个都没改，删掉空记录；已生效时保留记录供恢复。
        # 读不到状态时不能假定「没改过」，保留记录更安全。
        current = _modes([name])
        known = [mode for mode in current.values() if mode]
        if known and not any(_is_off(mode) for mode in known):
            STATE.unlink(missing_ok=True)
        raise
    left = [n for n, mode in _modes([name]).items() if not _is_off(mode)]
    if left:
        raise RuntimeError("Wi-Fi 的 IPv6 未关闭：" + "、".join(left) + "。可重试或恢复。")
    result = status()
    result["message"] = "已关闭 Wi-Fi 的 IPv6，可随时恢复为 Automatic；其它网络服务未改动。"
    return result


def _restore():
    saved, _ = _state(strict=True)
    if not saved:
        raise ValueError("没有本工具留下的 IPv6 恢复记录")
    rows = _snapshot()
    if not rows:
        raise RuntimeError("读不到网络服务列表，未恢复；恢复记录已保留")
    names = list(saved["services"])
    current = {row["name"]: row["mode"] for row in rows}
    unknown = [name for name in names if name in current and not current[name]]
    if unknown:
        raise RuntimeError("无法确认以下服务的 IPv6 状态："
                           + "、".join(unknown) + "；恢复记录已保留")
    targets = [name for name in names
               if name in current and _is_off(current[name])]
    skipped = [name for name in names
               if name in current and not _is_off(current[name])]
    if targets:
        _set_modes([(name, "-setv6automatic") for name in targets])
        current = _modes(targets)
        left = [name for name in targets
                if name in current and not _is_auto(current[name])]
        if left:
            raise RuntimeError("部分服务未恢复为 Automatic：" + "、".join(left) + "。可重试。")
    STATE.unlink(missing_ok=True)
    result = status()
    note = f"已恢复 {len(targets)} 个网络服务为 Automatic。"
    if skipped:
        note += f"另外 {len(skipped)} 个已被手动改成其他值，未覆盖。"
    result["message"] = note
    return result


def apply(action):
    if not compat.IS_MAC:
        raise ValueError("此持久设置入口仅支持 macOS")
    with LOCK:
        _guard_paths()
        if action == "off":
            return _off()
        if action == "restore":
            return _restore()
        raise ValueError("未知操作")
