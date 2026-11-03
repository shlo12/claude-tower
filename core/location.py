"""定位服务（Location Services）总开关。

外部探针会把「本机定位」单列一项：桌面端和浏览器 API 一旦拿到定位权限，
就能读到物理坐标，而这跟出口 IP 是不是海外没有关系。开关本身写在
`/var/db/locationd/Library/Preferences/ByHost/` 下面——那是 `_locationd`
的目录，普通用户连 `ls` 都进不去。所以只能做成「点一次、授权一次」：

- 常规扫描只读 `~/.ccclean/location.json` 里的缓存，**不弹密码框**。为了一个
  检测项每次体检都拦一道管理员授权，比不检测更烦人。
- 用户点「授权读取」才跑一次 `osascript ... with administrator privileges`。
- 结果连时间一起存。超过 `STALE` 就降级成「未确认」——一周前的开关状态不能
  当现状用，用户完全可能在这中间打开过。

**只读不写。** 关定位服务要用户自己去系统设置点：那是隐私开关，本工具不碰。
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from . import compat

STATE = Path.home() / ".ccclean/location.json"
# 一周。开关不常变，但也不能永远拿旧值下结论。
STALE = 7 * 86400
TIMEOUT = 90

# 一段写死的 shell：找出 locationd 的 ByHost plist，读出 LocationServicesEnabled。
# 全程不用双引号，这样可以原样嵌进 AppleScript 的字符串里，不必再套一层转义。
_SCRIPT = (
    "P=$(/bin/ls /var/db/locationd/Library/Preferences/ByHost/"
    "com.apple.locationd.*.plist 2>/dev/null | /usr/bin/head -1); "
    "[ -n $P ] || { echo MISSING; exit 0; }; "
    "D=${P%.plist}; "
    "V=$(/usr/bin/defaults read $D LocationServicesEnabled 2>/dev/null); "
    "[ -n $V ] || V=$(/usr/bin/plutil -extract LocationServicesEnabled raw $P 2>/dev/null); "
    "echo ${V:-UNKNOWN}"
)


def _parse(value: str):
    """把 shell 的输出变成 True / False / None（None = 读不出来）。"""
    text = (value or "").strip().lower()
    if text in ("1", "true", "yes"):
        return True
    if text in ("0", "false", "no"):
        return False
    return None


def read() -> dict:
    """跑一次带管理员权限的读取。用户取消时 checked=False，不当作「关着」。"""
    out = {"checked": False, "enabled": None, "error": ""}
    if not compat.IS_MAC:
        out["error"] = "定位服务开关只在 macOS 上可读"
        return out
    script = 'do shell script "' + _SCRIPT + '" with administrator privileges'
    try:
        res = subprocess.run(["/usr/bin/osascript", "-e", script],
                             capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        out["error"] = f"调用系统授权失败：{exc}"
        return out
    text = (res.stdout or "").strip()
    if res.returncode != 0:
        err = (res.stderr or "").strip()
        # osascript 被用户取消时返回 -128，报错里通常带 "User canceled"
        if "User canceled" in err or "-128" in err:
            out["error"] = "取消了管理员授权，没有读取"
        else:
            out["error"] = (err.splitlines()[-1][:160] if err else "读取失败")
        return out
    if text == "MISSING":
        out["error"] = "没找到定位服务的配置文件（这台机器可能从未启用过定位）"
        return out
    enabled = _parse(text)
    if enabled is None:
        out["error"] = "读到的值无法识别，未记录"
        return out
    out.update(checked=True, enabled=enabled)
    return out


def _read_state() -> dict:
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("version") != 1:
        return {}
    if not isinstance(data.get("enabled"), bool):
        return {}
    return data


def _write_state(enabled: bool) -> None:
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".location-", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "at": time.time(), "enabled": enabled},
                      stream, ensure_ascii=False)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def status() -> dict:
    """缓存状态。`checked=False` 表示还没读过或已经过期。"""
    saved = _read_state()
    at = float(saved.get("at") or 0)
    age = int(time.time() - at) if at else None
    fresh = age is not None and age <= STALE
    return {
        "supported": compat.IS_MAC,
        "checked": bool(saved) and fresh,
        "enabled": saved.get("enabled") if (saved and fresh) else None,
        "at": at,
        "age": age,
        "stale": bool(saved) and not fresh,
        "path": str(STATE),
        "error": "",
    }


def refresh() -> dict:
    """用户点了「授权读取」：读一次、存起来、把状态回给页面。"""
    got = read()
    if not got.get("checked"):
        return {**status(), "error": got.get("error") or "读取失败"}
    _write_state(bool(got["enabled"]))
    state = status()
    state["message"] = ("定位服务总开关是开着的。" if got["enabled"]
                        else "定位服务总开关是关闭的。")
    return state
