"""与 Claude Shield 共用的状态文件。

基线（时区、出口国家、打码后的出口 IP）两边都会写：塔在扫描后写一次，
哨兵每天用 Claude 边缘的 trace 结果自己续期——不开塔也不会过期。
所以写入必须是「先读、只改自己那几个键、再原子写回」，直接覆盖会把
用户的开关、暂停时间和命中记录一起抹掉。

字段归属：
    塔写    baselineTz / ruleGuard
    两边写  country / egressIP / egressAt / egressSeen*
    Shield 写 enabled / level / pausedUntil / hits / interval / loginIntent
    谁都不该动对方的键；出口那一组按时间戳取新的那份。

egressIP 存的是打码后的地址（`1.2.*.4`），不是完整 IP。Shield 拿它跟 STUN
探测到的地址做掩码比对，判断 UDP 出口和 HTTP 出口是不是同一个——这是检测
WebRTC 泄漏唯一不需要联网就能做的判据，而且不必把真实 IP 落到磁盘上。

测到的出口和基线不同时，任何一方都不许直接改基线：写进 egressSeen 等用户
确认。基线是「UDP 出口该长什么样」的参照，悄悄跟着新值走的话，真泄漏会
被当成正常。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
STATE_FILE = STATE_DIR / "shield.json"
VERSION = 1

LAUNCH_LABEL = "com.ccclean.shield"
LAUNCH_PLIST = HOME / "Library" / "LaunchAgents" / f"{LAUNCH_LABEL}.plist"

# 塔可以放在 /Applications，也可以放在 ~/Applications；哨兵嵌在塔的
# Resources 里，跟着宿主一起装、一起走。
TOWER_APP_PATHS = (
    Path("/Applications/Claude Tower.app"),
    HOME / "Applications/Claude Tower.app",
)
APP_PATHS = tuple(
    p / "Contents" / "Resources" / "Claude Shield.app" for p in TOWER_APP_PATHS
)


def launch_agent_state() -> str:
    """开机自启的 LaunchAgent 状态：loaded / installed / none。

    Shield 是用户态菜单栏程序，没有 root LaunchDaemon。`launchctl print`
    查的是用户 GUI 域里的实际加载状态——plist 文件在但没加载，开机不会起来。
    """
    if sys.platform != "darwin" or not LAUNCH_PLIST.exists():
        return "none"
    try:
        r = subprocess.run(
            ["launchctl", "print", f"gui/{os.getuid()}/{LAUNCH_LABEL}"],
            capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return "installed"
    return "loaded" if r.returncode == 0 else "installed"


def running() -> bool:
    """哨兵是不是正在跑。读不到进程表就当没跑——不猜。"""
    try:
        r = subprocess.run(["/bin/ps", "-axo", "comm="], capture_output=True,
                           text=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        return False
    if r.returncode != 0:
        return False
    return any("Claude Shield.app/Contents/MacOS/Shield" in line
               for line in r.stdout.splitlines())


def installed() -> bool:
    return any(p.exists() for p in APP_PATHS)


def read() -> dict:
    """读不到、读坏了都返回空字典——这个文件坏了不该让塔起不来。"""
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict) -> bool:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(STATE_DIR, 0o700)
        fd, tmp = tempfile.mkstemp(dir=str(STATE_DIR), prefix=".shield-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, STATE_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except (OSError, ValueError):
        return False
    return True


def _clear_seen(data: dict, at: int) -> bool:
    """撤掉待确认出口。

    清空时也写 egressSeenAt：Shield 用 max(egressAt, egressSeenAt) 判断
    哪一端写得更晚，留一个时间戳，「已清空」才能压住被撤掉的旧候选。
    """
    if not data.get("egressSeen") and not data.get("egressSeenCountry"):
        return False
    data["egressSeen"] = ""
    data["egressSeenCountry"] = ""
    data["egressSeenAt"] = at
    return True


def write_baseline(scan: dict | None) -> bool:
    """把这一轮检测到的时区、出口国家与出口 IP 写给 Shield。没有变化就不写盘。

    出口和已有基线对不上时不改基线，只写 egressSeen 等用户确认——基线是
    「UDP 出口该长什么样」的参照，塔自己跟着换等于把真泄漏洗成正常。
    """
    if not isinstance(scan, dict):
        return False
    tz = ((scan.get("system") or {}).get("timezone") or "").strip()
    net = scan.get("network") or {}
    country = ((net.get("country")) or "").strip().upper()
    # 打码后的地址（`1.2.*.4`）。塔从不把完整 IP 交给别人，包括自己的另一个程序。
    egress = ((net.get("ip")) or "").strip()
    if not tz and not country and not egress:
        return False

    data = read()
    now = int(time.time())
    changed = False
    if data.get("version") != VERSION:
        data["version"] = VERSION
        changed = True
    # 时区比对是 Shield 的主要用途之一：只要这次读到了就记下来，
    # 哪怕和上次一样也写一遍 version，保证老文件能升上来
    if tz and data.get("baselineTz") != tz:
        data["baselineTz"] = tz
        changed = True

    current = (data.get("egressIP") or "").strip()
    if egress and not current:
        # 第一次测到出口：没有参照可用，只能采用。
        data["egressIP"] = egress
        data["egressAt"] = now
        _clear_seen(data, now)
        changed = True
    elif egress and data.get("egressSeen") != egress:
        if egress == current:
            # 回到基线：撤掉待确认，时间戳隔一分钟以上才续期——Shield 只在
            # 基线够新时才比对出口，但打开页面就会扫，不该每次都写盘。
            if _clear_seen(data, now):
                changed = True
            if now - int(data.get("egressAt") or 0) >= 60:
                data["egressAt"] = now
                changed = True
        else:
            # 出口变了：不动基线，只记候选，等用户点「是我换的」。
            data["egressSeen"] = egress
            data["egressSeenAt"] = now
            data["egressSeenCountry"] = country
            changed = True
    if country and data.get("country") != country and not data.get("egressSeen"):
        data["country"] = country
        changed = True
    if not changed:
        return False
    return _write(data)


def clear_rule_guard() -> bool:
    """撤销分流修复时把规则清单一起删掉。

    留着旧清单会让哨兵一直报「规则不见了」——用户明明是主动撤销的。
    """
    data = read()
    if "ruleGuard" not in data:
        return False
    data.pop("ruleGuard", None)
    return _write(data)


def record_rule_guard(client: str, name: str, path, rules) -> bool:
    """把这次分流修复写下的规则记给哨兵。

    只记规则对（`TYPE,payload`），不记整份文件哈希：三个客户端都会在
    日常运行里重写配置的其它部分（FlClash 重启后按数据库重新生成配置、
    ClashX 订阅更新会整份重写 YAML），整文件哈希一改就报「配置被改过」，
    等于每轮巡检都在喊狼来了。规则对消失或被改名才是真正的漂移，
    而且和塔自己核对运行时配置的口径一致。
    """
    pairs = []
    for rule in rules or []:
        parts = [p.strip() for p in str(rule).split(",")]
        if len(parts) >= 2 and parts[0] and parts[1]:
            pairs.append(f"{parts[0].upper()},{parts[1].lower()}")
    if not pairs or not path:
        return False
    data = read()
    data["ruleGuard"] = {
        "client": client,
        "name": name,
        "path": str(path),
        "rules": sorted(set(pairs)),
        "at": int(time.time()),
    }
    return _write(data)


def status() -> dict:
    """给界面用：哨兵装没装、在不在跑、基线写的是什么。"""
    data = read()
    egress_at = int(data.get("egressAt") or 0)
    return {
        "baseline": {
            "tz": data.get("baselineTz") or "",
            "country": data.get("country") or "",
            "ip": data.get("egressIP") or "",
            # 塔多久以前记的。Shield 只认 24 小时以内的出口，过期的只展示不比对。
            "ipAge": max(0, int(time.time()) - egress_at) if egress_at else None,
        },
        "app": {
            "installed": installed(),
            "running": running(),
            "enabled": bool(data.get("enabled", True)),
            "level": 2 if data.get("level") in (2, 3) else 1,
            "launchAgent": launch_agent_state(),
        },
        "file": str(STATE_FILE).replace(str(HOME), "~"),
    }
