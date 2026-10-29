"""卸载器：把本工具自己留下的东西清干净。

检测类工具最怕「装完删不干净」。用户把 .app 拖进废纸篓之后，开机自启
还在、看门狗还在拉起一个已经不存在的哨兵、`~/.ccclean` 里还留着上一次
的检测记录和备份。所以卸载必须比安装更周到。

五条规矩，每一条都对应一次真实的踩坑：

1. **先列清单再动手。** 每一项都要说清路径、体积、留着它的后果。
   不列清单的「一键卸载」等于让用户签一张空白支票。

2. **先撤改动，再删记录。** proxyfix 把「写过哪几行」记在
   `~/.ccclean/proxyfix.json` 里。先删记录，代理客户端里那几行就再也
   撤不掉了——用户会以为卸载干净了，其实配置已经被永久改写。

3. **先停看门狗，再停哨兵。** 反过来做，哨兵刚被 kill 就会被
   看门狗拉起来，循环到用户放弃为止。

4. **一律进废纸篓，不 rm。** 误删一个 .app 可以重下，误删 `backups/`
   里那份被清理前的配置就回不来了。

5. **自己最后一个删。** 应用包没了，这个页面也就没了，后面的步骤
   全部无法执行。
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import compat, ipv6cfg, privacy, proxyfix, shield

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
# app.py 的 RUNTIME_DIR：打包后解出来的临时运行目录（图标缓存等）
RUNTIME_DIR = (HOME / "Library" / "Application Support" / "CCclean") if compat.IS_MAC \
    else (HOME / ".ccclean" / "runtime")

TOWER_APP_PATHS = (
    Path("/Applications/Claude Tower.app"),
    HOME / "Applications" / "Claude Tower.app",
)

WATCHDOG_NAME = "ShieldWatchdog"
SHIELD_NAME = "Shield"

# 确认串。卸载是不可逆的（虽然进了废纸篓，但 .app 删了就打不开这个页面了），
# 所以要一个和清理一样的「打字确认」。
CONFIRM_WORD = "UNINSTALL"


def _display(path) -> str:
    text = str(path)
    return "~" + text[len(str(HOME)):] if text.startswith(str(HOME)) else text


def _size(path: Path, cap: int = 4000) -> int:
    """目录体积。数到 cap 个文件就停——卸载面板不需要精确到字节，
    但也不能为了一个数字让页面卡十秒。"""
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    seen = 0
    for root, _dirs, files in os.walk(path, onerror=lambda e: None):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
            seen += 1
            if seen >= cap:
                return total
    return total


def _size_text(n: int) -> str:
    if n <= 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB")
    value = float(n)
    i = 0
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    return f"{round(value)} {units[i]}" if i <= 1 else f"{value:.1f} {units[i]}"


def _app_path(candidates) -> Path | None:
    for path in candidates:
        if path.exists():
            return path
    return None


def _bundle_of_running_app() -> Path | None:
    """当前这个进程是从哪个 .app 里跑起来的。从源码直接跑时返回 None。"""
    try:
        exe = Path(sys.executable).resolve()
    except OSError:
        return None
    for parent in exe.parents:
        if parent.suffix == ".app":
            return parent
    return None


def _exec_path(pid: int) -> str:
    """进程真正的可执行文件路径。

    `pgrep -f` 匹配的是命令行，一个把 "Shield" 写在参数里的脚本也会命中。
    kill 之前必须再看一眼它是谁。
    """
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")
        buf = ctypes.create_string_buffer(4096)
        n = lib.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(len(buf)))
        if n > 0:
            return buf.value.decode("utf-8", "replace")
    except (OSError, AttributeError):
        pass
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        r = subprocess.run(["ps", "-p", str(pid), "-o", "comm="],
                           capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return ""
    return (r.stdout or "").strip()


def _is_watchdog(path: str) -> bool:
    return (os.path.basename(path) == WATCHDOG_NAME
            and "Claude Shield.app" in path)


def _is_shield(path: str) -> bool:
    """只认应用包里的那个可执行文件，不认命令行里带 "Shield" 的别的进程。"""
    return os.path.basename(path) == SHIELD_NAME and "Claude Shield.app" in path


def _pids(pattern: str, accept=None) -> list[int]:
    """按命令行匹配进程，再用可执行文件路径确认身份。

    accept 为空表示不校验；实际 kill 的调用点都必须传。
    """
    try:
        r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in (r.stdout or "").split():
        try:
            out.append(int(line))
        except ValueError:
            pass
    if accept is not None:
        out = [p for p in out if accept(_exec_path(p))]
    return out


def _running(pattern: str, accept=None) -> bool:
    return bool(_pids(pattern, accept))


def _stop(patterns: list[str], accept=None) -> tuple[int, list[str]]:
    """先 TERM，等一会儿再 KILL。返回 (停掉的进程数, 说明)。

    accept 是身份校验：清单里说「有进程在跑」和执行时「杀谁」必须用
    同一套判据，否则会出现「显示在跑、点下去却一个都没杀」。
    """
    stopped = 0
    notes = []
    targets: list[int] = []
    for pattern in patterns:
        targets.extend(_pids(pattern, accept))
    targets = [p for p in dict.fromkeys(targets) if p != os.getpid()]
    if not targets:
        return 0, notes

    for pid in targets:
        try:
            os.kill(pid, 15)
            stopped += 1
        except OSError:
            pass
    deadline = time.time() + 3.0
    while time.time() < deadline:
        alive = [p for p in targets if _alive(p)]
        if not alive:
            break
        time.sleep(0.15)
    for pid in targets:
        if _alive(pid):
            try:
                os.kill(pid, 9)
                notes.append(f"{pid} 没有响应 TERM，已强制结束")
            except OSError:
                notes.append(f"{pid} 仍在运行")
    return stopped, notes


def _alive(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


# ---------------------------------------------------------------- 清单


def plan() -> dict:
    """列出所有能清的东西。不改动任何文件。"""
    items: list[dict] = []

    # ---- 1. 先撤系统改动（顺序在前，因为撤销依据记在 ~/.ccclean 里） ----
    try:
        pf = proxyfix.status()
        applied = bool(pf.get("canUndo"))
    except Exception:
        applied = False
    items.append({
        "id": "proxyfix",
        "title": "撤销写入代理客户端的规则",
        "paths": [pf.get("configPath") or "代理客户端配置"] if applied else [],
        "size": 0,
        "sizeText": "已写入" if applied else "未写入",
        "default": applied,
        "available": applied,
        "kind": "module",
        "why": "分流规则是直接写进客户端配置的。不撤销的话，卸载之后那几行还在，"
               "而记录「写过什么」的 ~/.ccclean/proxyfix.json 已经被删掉，再也撤不掉。",
        "danger": "只删除本工具记录的那几行，不动其它规则。客户端会重启一次。",
    })

    try:
        pv = privacy.status()
        privacy_on = bool(pv.get("restoreAvailable"))
    except Exception:
        privacy_on = False
    privacy_paths = []
    if privacy_on:
        # 这一项同时改 hosts 和 Claude Code 的配置，两个都得列出来。
        privacy_paths = [pv.get("configPath") or "~/.claude/settings.json", "/etc/hosts"]
    items.append({
        "id": "privacy",
        "title": "恢复 hosts 与 Claude Code 配置",
        "paths": privacy_paths,
        "size": 0,
        "sizeText": "已修改" if privacy_on else "未修改",
        "default": privacy_on,
        "available": privacy_on,
        "kind": "module",
        "why": "遥测封缄改的是系统 hosts 和 Claude Code 的配置。卸载后这些改动会一直留着，"
               "而做出改动的工具已经不在了。",
        "danger": "会请求管理员授权；只恢复本工具写过的那几条。",
    })

    try:
        v6 = ipv6cfg.status()
        ipv6_off = bool(v6.get("restoreAvailable"))
    except Exception:
        ipv6_off = False
    items.append({
        "id": "ipv6",
        "title": "把 Wi-Fi 的 IPv6 恢复为 Automatic",
        "paths": ["网络服务（Wi-Fi）"] if ipv6_off else [],
        "size": 0,
        "sizeText": "已关闭" if ipv6_off else "未改动",
        "default": ipv6_off,
        "available": ipv6_off,
        "kind": "module",
        "why": "IPv6 是系统级设置，和本工具是否安装无关。卸载前恢复，"
               "免得日后想不起来是谁把它关的。",
        "danger": "会请求管理员授权；只改 Wi-Fi 这一个网络服务。",
    })

    # ---- 2. 停进程 ----
    procs = []
    if compat.IS_MAC:
        if _running(WATCHDOG_NAME, _is_watchdog):
            procs.append("看门狗")
        if _running("Claude Shield.app/Contents/MacOS/Shield", _is_shield):
            procs.append("哨兵")
    items.append({
        "id": "stop",
        "title": "停止看门狗与哨兵",
        "paths": procs,
        "size": 0,
        "sizeText": "运行中" if procs else "未运行",
        "default": bool(procs),
        "available": bool(procs),
        "kind": "process",
        "why": "看门狗会在哨兵退出后把它拉起来。先删文件的话，哨兵会被拉起一次、"
               "再写一遍状态文件，最后留下一个删了一半的目录。",
        "danger": "只结束这两个进程，不碰其它任何程序。",
    })

    # ---- 3. 开机自启 ----
    plist = shield.LAUNCH_PLIST
    items.append({
        "id": "launchagent",
        "title": "移除开机自启",
        "paths": [_display(plist)] if plist.exists() else [],
        "size": _size(plist),
        "sizeText": _size_text(_size(plist)) if plist.exists() else "未安装",
        "default": plist.exists(),
        "available": plist.exists(),
        "kind": "trash",
        "why": "plist 留着的话，下次登录 launchd 还会去启动一个已经不存在的哨兵，"
               "控制台里会一直刷 failed to spawn 的报错。",
        "danger": "先 bootout 再从 LaunchAgents 移走，移进废纸篓。",
    })

    # ---- 4. 状态与备份 ----
    state_size = _size(STATE_DIR)
    items.append({
        "id": "state",
        "title": "本工具的记录与备份",
        "paths": [_display(STATE_DIR)],
        "size": state_size,
        "sizeText": _size_text(state_size),
        "default": STATE_DIR.exists(),
        "available": STATE_DIR.exists(),
        "kind": "trash",
        "why": "里面有历次检测记录、排行榜、挑战历史，还有清理前的备份；"
               "自动更新的配置、已下载的暂存包和回滚备份也在里面。"
               "留着它，下次重装会接着上一份历史；删掉就彻底从头开始。",
        "danger": "整个目录移入废纸篓，可以在废纸篓里找回。",
    })

    runtime_size = _size(RUNTIME_DIR)
    items.append({
        "id": "runtime",
        "title": "运行时目录",
        "paths": [_display(RUNTIME_DIR)],
        "size": runtime_size,
        "sizeText": _size_text(runtime_size),
        "default": RUNTIME_DIR.exists(),
        "available": RUNTIME_DIR.exists(),
        "kind": "trash",
        "why": "打包运行时解出来的临时文件。留着不占多少空间，但重装后可能读到旧版本残留。",
        "danger": "移入废纸篓。",
    })

    # ---- 5. 应用包 ----
    tower_app = _bundle_of_running_app() or _app_path(TOWER_APP_PATHS)
    t_size = _size(tower_app) if tower_app else 0
    items.append({
        "id": "tower_app",
        "title": "Claude Tower 应用（本程序）",
        "paths": [_display(tower_app)] if tower_app else ["从源码运行，没有应用包"],
        "size": t_size,
        "sizeText": _size_text(t_size) if tower_app else "—",
        "default": bool(tower_app),
        "available": bool(tower_app),
        "kind": "trash",
        "why": "塔和哨兵装在同一个应用包里（哨兵在 Resources 里），删掉它"
               "等于两个都删了。这是你自己，删完之后这个页面就没了，所以放在最后一步。",
        "danger": "移入废纸篓，随后本程序退出。",
    })

    total = sum(i["size"] for i in items)
    return {
        "items": items,
        "confirmWord": CONFIRM_WORD,
        "totalBytes": total,
        "totalText": _size_text(total),
        "warnings": _warnings(),
    }


def _warnings() -> list[str]:
    out = []
    if compat.IS_WIN:
        out.append("Windows 上的开机自启在注册表和启动文件夹里，本清单不处理；"
                   "需要的话请在「任务管理器 → 启动」里关掉。")
    if not compat.IS_MAC:
        out.append("非 macOS 平台不处理 LaunchAgent 与哨兵进程，只清理目录。")
    out.append("卸载会撤销本工具对 hosts、Claude Code 配置和代理客户端分流的修改；"
               "不会删除你的 Claude Code 本身，也不会动 ~/.claude 里本工具没改过的内容，"
               "不动代理客户端里的节点。")
    return out


# ---------------------------------------------------------------- 执行


_ORDER = ["proxyfix", "privacy", "ipv6", "stop", "launchagent",
          "state", "runtime", "tower_app"]

# 执行时只需要标题，不需要重新扫一遍磁盘。plan() 会去量应用包的体积，
# 在真正动手之前再跑一遍纯属浪费——而且那会儿状态可能已经变了。
_TITLES = {
    "proxyfix": "撤销写入代理客户端的规则",
    "privacy": "恢复 hosts 与 Claude Code 配置",
    "ipv6": "把 Wi-Fi 的 IPv6 恢复为 Automatic",
    "stop": "停止看门狗与哨兵",
    "launchagent": "移除开机自启",
    "state": "本工具的记录与备份",
    "runtime": "运行时目录",
    "tower_app": "Claude Tower 应用（本程序）",
}


def execute(ids: list[str], confirm: str) -> dict:
    """按固定顺序执行。顺序是这个模块最重要的部分，见文件头第 2、3、5 条。"""
    if (confirm or "").strip().upper() != CONFIRM_WORD:
        raise ValueError(f"请输入 {CONFIRM_WORD} 确认")
    wanted = [i for i in _ORDER if i in set(ids or [])]
    if not wanted:
        raise ValueError("没有勾选任何项目")

    results = []
    for item_id in wanted:
        try:
            results.append(_run_one(item_id, {"title": _TITLES.get(item_id, item_id)}))
        except Exception as exc:  # noqa: BLE001 - 单项失败不能拖垮整轮
            results.append({"id": item_id, "title": _TITLES.get(item_id, item_id),
                            "ok": False, "message": str(exc)[:200]})
    return {
        "results": results,
        "quit": "tower_app" in wanted,
        "trash": str(compat.trash_root()).replace(str(HOME), "~"),
    }


def _run_one(item_id: str, item: dict) -> dict:
    title = item.get("title", item_id)

    if item_id == "proxyfix":
        res = proxyfix.apply("undo")
        return {"id": item_id, "title": title, "ok": bool(res.get("ok", True)),
                "message": str(res.get("message") or "已撤销写入的规则")}

    if item_id == "privacy":
        res = privacy.apply(False)
        return {"id": item_id, "title": title, "ok": bool(res.get("ok", True)),
                "message": str(res.get("message") or "已恢复本工具的修改")}

    if item_id == "ipv6":
        res = ipv6cfg.apply("restore")
        return {"id": item_id, "title": title, "ok": bool(res.get("ok", True)),
                "message": str(res.get("message") or "已恢复为 Automatic")}

    if item_id == "stop":
        # 顺序：看门狗先，哨兵后。反过来会被立刻拉起。
        notes: list[str] = []
        count = 0
        if compat.IS_MAC:
            n1, m1 = _stop([WATCHDOG_NAME], _is_watchdog)
            n2, m2 = _stop(["Claude Shield.app/Contents/MacOS/Shield"], _is_shield)
            count = n1 + n2
            notes.extend(m1 + m2)
        msg = f"已停止 {count} 个进程" if count else "没有在运行的进程"
        if notes:
            msg += "；" + "；".join(notes)
        return {"id": item_id, "title": title, "ok": True, "message": msg}

    if item_id == "launchagent":
        plist = shield.LAUNCH_PLIST
        notes = []
        if plist.exists():
            # 先 bootout：只删文件的话，launchd 内存里那份还活着
            try:
                subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{shield.LAUNCH_LABEL}"],
                               capture_output=True, text=True, timeout=8, check=False)
            except (OSError, subprocess.SubprocessError) as exc:
                notes.append(f"bootout 失败：{exc}")
            ok, dest = compat.send_to_trash(plist)
            if not ok:
                return {"id": item_id, "title": title, "ok": False,
                        "message": "移入废纸篓失败，请手动删除"}
            notes.append(f"plist 已移入废纸篓（{dest}）")
        return {"id": item_id, "title": title, "ok": True, "message": "；".join(notes) or "没有可移除的项"}

    if item_id in ("state", "runtime"):
        target = STATE_DIR if item_id == "state" else RUNTIME_DIR
        if not target.exists():
            return {"id": item_id, "title": title, "ok": True, "message": "目录不存在，跳过"}
        ok, dest = compat.send_to_trash(target)
        return {"id": item_id, "title": title, "ok": ok,
                "message": f"已移入废纸篓（{dest}）" if ok else "移入废纸篓失败，请手动删除"}

    if item_id == "tower_app":
        target = _bundle_of_running_app() or _app_path(TOWER_APP_PATHS)
        if not target or not target.exists():
            return {"id": item_id, "title": title, "ok": True, "message": "应用包不存在，跳过"}
        # 应用包里可能有一堆只读的签名文件，rename 整个目录比逐个删快得多。
        # 哨兵就在这个包里，跟着一起进废纸篓。
        ok, dest = compat.send_to_trash(target)
        return {"id": item_id, "title": title, "ok": ok,
                "message": f"已移入废纸篓（{dest}）" if ok else "移入废纸篓失败，请手动拖进废纸篓"}

    return {"id": item_id, "title": title, "ok": False, "message": "未知项目"}


def leftovers() -> list[str]:
    """卸载后复查：还剩下什么。给页面显示「已清干净」用，不做任何删除。"""
    left = []
    for label, path in (("状态目录", STATE_DIR), ("运行时目录", RUNTIME_DIR)):
        if path.exists():
            left.append(f"{label}仍在：{_display(path)}")
    if compat.IS_MAC:
        if shield.LAUNCH_PLIST.exists():
            left.append(f"开机自启仍在：{_display(shield.LAUNCH_PLIST)}")
        if _running(WATCHDOG_NAME, _is_watchdog) or \
                _running("Claude Shield.app/Contents/MacOS/Shield", _is_shield):
            left.append("哨兵相关进程仍在运行")
        for path in TOWER_APP_PATHS:
            if path.exists():
                left.append(f"应用包仍在：{_display(path)}")
    return left
