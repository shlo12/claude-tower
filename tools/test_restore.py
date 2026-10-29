#!/usr/bin/env python3
"""备份还原的回归测试。

把 HOME 指到一个临时目录，造一份假的备份，看 restore() 能不能
既把内容盖回去、又在该拒绝的时候拒绝。

    python3 tools/test_restore.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import cleaner  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}" + (f"  —— {detail}" if detail else ""))


def make_backup(home: Path, bid: str, entries: list[dict], files: dict[str, str]) -> Path:
    """在临时 HOME 里造一份备份：manifest + files/ 下的副本。"""
    d = home / ".ccclean" / "backups" / bid
    (d / "files").mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        target = d / "files" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    (d / "manifest.json").write_text(
        json.dumps({"createdAt": "2025-01-01T12:00:00", "backupDir": str(d), "entries": entries},
                   ensure_ascii=False),
        encoding="utf-8",
    )
    return d


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="ccclean-restore-")).resolve()
    real = (cleaner.HOME, cleaner.BACKUP_DIR)
    try:
        cleaner.HOME = tmp
        cleaner.BACKUP_DIR = tmp / ".ccclean" / "backups"
        settings = tmp / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text('{"cleaned": true}\n', encoding="utf-8")

        bid = "20250101-120000"
        make_backup(
            tmp, bid,
            [
                {"id": "cfg.keys", "kind": "json_keys", "path": str(settings), "detail": {}},
                {"id": "kc.claude", "kind": "keychain", "path": "", "detail": {"service": "Claude"}},
                {"id": "env.anthropic", "kind": "envvar", "path": "", "detail": {"var": "X"}},
            ],
            {".claude/settings.json": '{"original": true}\n'},
        )

        print("\n[1] 口令与编号")
        for bad_confirm in ("", "clean", "RESTORE "):
            try:
                cleaner.restore(bid, bad_confirm)
                check(f"口令 {bad_confirm!r} 被拒", False, "居然放行了")
            except cleaner.CleanError:
                check(f"口令 {bad_confirm!r} 被拒", True)

        for bad_id in ("", "../../etc", "20250101-120000/../../x", "notadate"):
            try:
                cleaner.restore(bad_id, "RESTORE")
                check(f"编号 {bad_id!r} 被拒", False, "居然放行了")
            except cleaner.CleanError:
                check(f"编号 {bad_id!r} 被拒", True)

        print("\n[2] 还原配置文件")
        r = cleaner.restore(bid, "RESTORE")
        check("返回 ok", r["ok"] is True, str(r.get("message")))
        check("内容回到清理前", settings.read_text(encoding="utf-8") == '{"original": true}\n',
              settings.read_text(encoding="utf-8"))
        check("报出还原了 1 项", len(r["restored"]) == 1, str(r["restored"]))

        print("\n[3] 还原不了的必须明说，不能假装成功")
        reasons = {s["id"]: s["reason"] for s in r["skipped"]}
        check("钥匙串列为跳过", "kc.claude" in reasons)
        check("环境变量列为跳过", "env.anthropic" in reasons)
        check("跳过原因不是空话", all(len(v) > 6 for v in reasons.values()), str(reasons))

        print("\n[4] 覆盖前留底")
        pre = cleaner.restore(bid, "RESTORE")
        check("第二次还原也成功", pre["ok"] is True)
        check("留下 pre-restore 快照", bool(pre["preRestoreDir"]), pre.get("preRestoreDir", ""))
        pre_root = tmp / pre["preRestoreDir"][2:]
        snaps = list(pre_root.rglob("settings.json")) if pre_root.exists() else []
        check("快照里有被覆盖的那份", bool(snaps), str(snaps))
        check("快照内容是被覆盖的那份", bool(snaps) and snaps[0].read_text(encoding="utf-8") == '{"original": true}\n')

        print("\n[5] 从废纸篓还原")
        trash = tmp / ".Trash" / "CCclean-test"
        trash.mkdir(parents=True, exist_ok=True)
        moved = trash / "old.txt"
        moved.write_text("hello", encoding="utf-8")
        dest = tmp / ".claude" / "old.txt"
        bid2 = "20250102-090000"
        make_backup(
            tmp, bid2,
            [{"id": "trash.log", "kind": "trash", "path": str(dest),
              "detail": {"from": str(dest), "to": str(moved)}}],
            {},
        )
        r2 = cleaner.restore(bid2, "RESTORE")
        check("废纸篓里的文件被移回", dest.exists() and dest.read_text(encoding="utf-8") == "hello")
        check("移回后废纸篓不再有", not moved.exists())

        print("\n[6] 原位置已有同名文件时不覆盖")
        moved.write_text("again", encoding="utf-8")
        r3 = cleaner.restore(bid2, "RESTORE")
        check("不覆盖已存在的文件", dest.read_text(encoding="utf-8") == "hello",
              dest.read_text(encoding="utf-8"))
        check("并说明原因", any("已有同名" in s["reason"] for s in r3["skipped"]),
              str(r3["skipped"]))

        print("\n[7] 备份里缺文件")
        bid3 = "20250103-090000"
        make_backup(tmp, bid3,
                    [{"id": "cfg.x", "kind": "json_keys", "path": str(settings), "detail": {}}], {})
        r4 = cleaner.restore(bid3, "RESTORE")
        check("缺文件时不报成功", r4["ok"] is False, str(r4))
        check("并说明缺什么", any("没有这个文件" in s["reason"] for s in r4["skipped"]),
              str(r4["skipped"]))

        print("\n[8] 越界路径拒绝")
        outside = Path("/tmp/ccclean-should-not-write.txt")
        bid4 = "20250104-090000"
        # 把副本放在 restore 真正会去找的位置，确认守卫而不是「找不到文件」把它挡下来
        make_backup(tmp, bid4,
                    [{"id": "evil", "kind": "json_keys", "path": str(outside), "detail": {}}],
                    {cleaner._rel(outside): "pwned"})
        r5 = cleaner.restore(bid4, "RESTORE")
        check("家目录之外的文件不写", not outside.exists())
        check("并说明被拒绝", any("家目录之外" in s["reason"] or "白名单" in s["reason"]
                                  for s in r5["skipped"]), str(r5["skipped"]))

        print("\n[9] 列表接口")
        listing = cleaner.list_backups()
        check("列出全部备份", len(listing) >= 4, str(len(listing)))
        check("带条目数", all("entries" in b for b in listing))
        check("带可还原项数", all("restorable" in b for b in listing))
        one = next((b for b in listing if b["id"] == bid), None)
        check("可还原项数只数能还原的", one and one["restorable"] == 1, str(one))

    finally:
        cleaner.HOME, cleaner.BACKUP_DIR = real
        shutil.rmtree(tmp, ignore_errors=True)
        if Path("/tmp/ccclean-should-not-write.txt").exists():
            Path("/tmp/ccclean-should-not-write.txt").unlink()

    print(f"\n{'='*46}\n  通过 {PASS} 项，失败 {FAIL} 项\n{'='*46}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
