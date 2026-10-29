"""闯关进度的本机存储。

原来的「12 关流程」已经退休：结论统一由 core/tower.py 出，前端只认那一套。
留着两套判定最麻烦的地方不是多写代码，而是**同一台机器会拿到两个不一样的结论**——
旧流程说「第 7 关通过」，新塔说「第 3 层还卡着」，用户不知道该信谁。

所以这里只剩「读过哪些声明、勾过哪些清单项、点过哪些直达链接」的持久化，
不含任何判定逻辑。tower 与 app 都读它，progress.json 的老字段原样保留，
不需要迁移。
"""

from __future__ import annotations

import json
from pathlib import Path

HOME = Path.home()
STATE = HOME / ".ccclean"
PROGRESS_FILE = STATE / "progress.json"

DEFAULT_PROGRESS = {
    "ip": {"opened": False, "at": None},
    "checklist": [],
    "ack": [],
    "report": None,
    "isolation": None,
}


def load_progress() -> dict:
    if not PROGRESS_FILE.exists():
        return json.loads(json.dumps(DEFAULT_PROGRESS))
    try:
        data = json.loads(PROGRESS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return json.loads(json.dumps(DEFAULT_PROGRESS))
    merged = json.loads(json.dumps(DEFAULT_PROGRESS))
    merged.update(data or {})
    return merged


def save_progress(data: dict) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    PROGRESS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
