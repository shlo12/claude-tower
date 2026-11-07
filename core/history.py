"""操作日志：每次真的写盘的动作记一条。

写入类动作散在六个地方——`proxyfix`（分流规则、DNS 解析器）、`align`（出口
对齐）、`regioncfg`（区域格式）、`shellenv`（终端环境变量）、`shellproxy`（终端代理变量）、`privacy`
（遥测屏蔽）。各写各的日志，格式一定会漂，最后没人能一眼看出「昨天下午到底
改了哪几样」。这里只做一件事：把「谁、什么时候、改了什么、成没成」追加进
一个 jsonl。

三条边界：

1. **只记动作，不记内容。** 不写完整 IP、不写密钥、不写文件正文。记录是给
   自己回溯用的，不是取证材料——真需要细节，那几处各自有状态文件。
2. **写失败不影响主流程。** 日志是旁路。磁盘满、权限不对、目录被删，都只
   让这一条日志丢掉，不能把已经成功的修复带崩。
3. **追加式。** 只追加不重写；超过上限时整份重写一次，保留最近 N 条。
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

LOG = Path.home() / ".ccclean/history.jsonl"
KEEP = 200          # 超过这个数的两倍就压缩一次
MAX_READ = 500
_LOCK = threading.Lock()

# 动作名用 `模块.对象.动词`。写的时候统一，读的时候才能按前缀过滤。
ACTIONS = {
    "sessionapi.apply": "启用本机节点监测接口",
    "sessionapi.undo": "恢复本机节点监测接口",
    "proxyfix.rules.apply": "写入分流规则",
    "proxyfix.rules.undo": "撤销分流规则",
    "proxyfix.dns.apply": "统一 DNS 解析器",
    "proxyfix.dns.undo": "恢复 DNS 解析器",
    "align.apply": "按出口对齐",
    "align.restore": "恢复对齐前设置",
    "region.apply": "改区域格式",
    "region.restore": "恢复区域格式",
    "shellproxy.apply": "写入终端代理变量",
    "shellproxy.undo": "撤销终端代理变量",
    "shellenv.apply": "写入终端环境变量",
    "shellenv.undo": "撤销终端环境变量",
    "shellenv.wrapper": "生成启动器",
    "privacy.apply": "切换遥测屏蔽",
}


def label(action: str) -> str:
    return ACTIONS.get(action, action)


def _ensure() -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)


def log(action: str, target: str = "", ok: bool = True,
        detail: str = "", extra: dict | None = None) -> bool:
    """追加一条。返回是否写成——调用方不该依赖这个返回值。"""
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "epoch": int(time.time()),
        "action": action,
        "target": (target or "")[:80],
        "ok": bool(ok),
        "detail": (detail or "")[:300],
    }
    if extra:
        # 只留短标量，嵌套结构会让这份日志变成第二个状态文件
        flat = {k: v for k, v in extra.items()
                if isinstance(v, (str, int, float, bool)) and len(str(v)) <= 60}
        if flat:
            row["extra"] = flat
    try:
        with _LOCK:
            _ensure()
            if not LOG.exists():
                # 先按 0600 建出来再追加。open(..., "a") 会用 umask，
                # 在默认 umask 022 下变成 0644——日志里虽然不写密钥，
                # 但「谁在什么时候改过什么」也不该让同机其他用户读到。
                fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            line = json.dumps(row, ensure_ascii=False)
            with open(LOG, "a", encoding="utf-8") as stream:
                stream.write(line + "\n")
            _rotate()
        return True
    except Exception:
        # 旁路失败不能把主流程带崩
        return False


def _rotate() -> None:
    """行数超过两倍上限时压缩一次。调用方已持锁。"""
    try:
        if LOG.stat().st_size < 4096:
            return
        lines = LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    if len(lines) <= KEEP * 2:
        return
    kept = lines[-KEEP:]
    fd, name = tempfile.mkstemp(prefix=".history-", dir=str(LOG.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(kept) + "\n")
        os.replace(name, LOG)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def tail(n: int = 20) -> list[dict]:
    """最近 n 条，新的在前。坏行跳过，不让一行脏数据把整份日志读废。"""
    limit = max(1, min(int(n or 20), MAX_READ))
    try:
        raw = LOG.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    except OSError:
        return []
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or not row.get("action"):
            continue
        rows.append(row)
    rows.reverse()
    return rows[:limit]


def clear() -> dict:
    try:
        LOG.unlink(missing_ok=True)
    except OSError as exc:
        raise ValueError(f"清不掉日志：{exc}") from exc
    return {"ok": True, "message": "操作日志已清空"}
