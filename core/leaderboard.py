"""Claude 勇士榜 · 本地排行榜。

不联网、不上传，榜单存在 ~/.ccclean/leaderboard.json。
排序规则：存活天数优先，其次通关血量，最后比用时（越短越靠前）。

榜单里有一条常驻的「作者」记录，存活天数 35 天。它只在第一次读榜单时
写入一次（用 data["seed"] 记账），之后就算被删掉也不会自己长回来——
否则每次清榜都会被自己的幽灵记录找上门。
"""

from __future__ import annotations

import json
import time
from pathlib import Path

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
BOARD_FILE = STATE_DIR / "leaderboard.json"
MAX_ENTRIES = 100

# 改了种子内容就把版本 +1，老机器上的记录会被替换成新的
SEED_VERSION = 4

# 作者提供的个人战绩；固定展示，不由账号接口自动验证。
AUTHOR_ENTRY = {
    "name": "shlo",
    "days": 35,
    "hp": 100,
    "level": 99,
    "exp": 0,
    "durationSec": 0,
    "title": "塔的建造者",
    "note": "这座塔是他写的，所以他知道每一层守卫的弱点。",
    "clearedAt": "",
    "ts": 0.5,
    "author": True,
}


def _read() -> dict:
    try:
        if BOARD_FILE.exists():
            data = json.loads(BOARD_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("entries"), list):
                return data
    except Exception:
        pass
    return {"entries": []}


def _write(data: dict) -> None:
    BOARD_FILE.parent.mkdir(parents=True, exist_ok=True)
    BOARD_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _seeded(data: dict) -> dict:
    """把作者榜位补进去，只补一次。"""
    if data.get("seed") == SEED_VERSION:
        return data
    data["entries"] = [e for e in data["entries"] if not e.get("author")]
    data["entries"].insert(0, dict(AUTHOR_ENTRY))
    data["seed"] = SEED_VERSION
    _write(data)
    return data


def _load() -> dict:
    return _seeded(_read())



def _days(e) -> int:
    v = e.get("days")
    return v if isinstance(v, int) else 0


def list_entries() -> list[dict]:
    entries = _load()["entries"]
    entries.sort(key=lambda e: (-_days(e), -(e.get("hp") or 0), e.get("durationSec") or 0))
    for i, e in enumerate(entries, 1):
        e["rank"] = i
    return entries


def stats() -> dict:
    entries = _load()["entries"]
    if not entries:
        return {"count": 0, "bestDays": None, "avgDays": None, "bestHp": None}
    days = [_days(e) for e in entries]
    return {
        "count": len(entries),
        "bestDays": max(days),
        "avgDays": round(sum(days) / len(days)),
        "bestHp": max((e.get("hp") or 0) for e in entries),
    }


def add(name: str, days=None, hp: int = 0, level: int = 1, exp: int = 0,
        duration_sec: int = 0, title: str = "", note: str = "") -> dict:
    name = (name or "").strip()[:24] or "无名勇者"
    data = _load()
    entry = {
        "name": name,
        "days": days if isinstance(days, int) else None,
        "hp": int(hp or 0),
        "level": int(level or 1),
        "exp": int(exp or 0),
        "durationSec": int(duration_sec or 0),
        "title": title or "",
        "note": (note or "")[:60],
        "clearedAt": time.strftime("%Y-%m-%d %H:%M"),
        "ts": time.time(),
    }
    data["entries"].append(entry)
    entries = data["entries"]
    if len(entries) > MAX_ENTRIES:
        # 作者榜位不参与「先进先出」淘汰，否则第 101 位勇士会把他挤掉
        pinned = [e for e in entries if e.get("author")]
        rest = [e for e in entries if not e.get("author")]
        data["entries"] = rest[-(MAX_ENTRIES - len(pinned)):] + pinned
    _write(data)
    return entry


def remove(ts: float) -> bool:
    data = _load()
    before = len(data["entries"])
    data["entries"] = [e for e in data["entries"] if abs((e.get("ts") or 0) - float(ts)) > 0.001]
    _write(data)
    return len(data["entries"]) != before


def clear() -> None:
    # 保留 seed 记账：清空之后作者也不该自己冒出来
    _write({"entries": [], "seed": SEED_VERSION})


def export_md(entry: dict | None = None) -> str:
    entries = list_entries()
    now = time.strftime("%Y-%m-%d %H:%M")
    lines = ["# Claude 勇士榜", "", f"- 导出时间：{now}", f"- 在册勇士：{len(entries)} 位", ""]

    if entry:
        lines += [
            "## 本次战绩",
            "",
            f"- 勇士：**{entry['name']}**",
            f"- 称号：{entry.get('title') or '—'}（Lv.{entry.get('level')}）",
            f"- 存活时长：**{entry.get('days')} 天**" if entry.get("days") is not None else "- 存活时长：未记录",
            f"- 通关血量：**{entry.get('hp')} / 100**",
            f"- 通关用时：{_fmt_dur(entry.get('durationSec'))}",
            f"- 通关时间：{entry.get('clearedAt')}",
            "",
        ]

    if entries:
        lines += ["## 榜单", "", "| # | 勇士 | 存活天数 | 血量 | 等级 | 用时 | 通关时间 |", "| --- | --- | --- | --- | --- | --- | --- |"]
        for e in entries:
            days = f"{e['days']}" if e.get("days") is not None else "—"
            name = f"{e['name']}（作者）" if e.get("author") else e["name"]
            lines.append(
                f"| {e['rank']} | {name} | {days} | {e.get('hp', 0)} | "
                f"Lv.{e.get('level', 1)} | {_fmt_dur(e.get('durationSec'))} | {e.get('clearedAt') or '—'} |"
            )
    else:
        lines += ["## 榜单", "", "还没有勇士登榜。"]

    lines += [
        "",
        "---",
        "",
        "榜单只存在本机 `~/.ccclean/leaderboard.json`，不上传任何数据。",
        "存活时长按本地最早痕迹推算，可在录入时手动改成你知道的首次使用日期。",
        "",
    ]
    return "\n".join(lines)


def _fmt_dur(sec) -> str:
    try:
        sec = int(sec or 0)
    except Exception:
        return "—"
    if sec <= 0:
        return "—"
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"
