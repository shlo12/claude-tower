"""清理引擎：敏感内容不留副本；其他配置备份，其他文件移入废纸篓。"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from . import compat, retention

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
BACKUP_DIR = STATE_DIR / "backups"
TRASH_DIR = compat.trash_root()

# 只允许操作这些前缀下的路径，避免任何越界删除
ALLOWED_PREFIXES = (
    ".claude",
    ".claude.json",
    ".claude-env-inspector",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".bash_profile",
    ".bashrc",
    ".profile",
    ".config/fish/config.fish",
    "Library/Application Support/Claude",
    "Library/Application Support/Claude-3p",
    "Library/Caches/com.anthropic.claudefordesktop",
    "Library/Caches/claude-cli-nodejs",
    "Library/HTTPStorages/com.anthropic.claudefordesktop",
    "Library/Preferences/com.anthropic.claudefordesktop.plist",
    "Library/Saved Application State/com.anthropic.claudefordesktop.savedState",
    "Library/WebKit/com.anthropic.claudefordesktop",
    "Library/Logs/Claude",
    ".vscode/extensions",
    ".cursor/extensions",
)

# 文件名前缀匹配（glob 出来的文件，目录规则覆盖不到）
ALLOWED_FILE_PREFIXES = (
    "Library/Preferences/ByHost/com.anthropic.claudefordesktop",
    "Library/Logs/DiagnosticReports/Claude",
    "Library/Application Support/CrashReporter/Claude",
)

# 用户资产操作后复查；debug / session-env 属于明确选择后不留副本的日志与环境快照。
PROTECTED_CLAUDE = (
    "CLAUDE.md", "agents", "backups", "commands", "file-history",
    "history.jsonl", "hooks", "mcp-servers", "plans", "plugins", "projects",
    "scripts", "sessions", "settings.json", "settings.local.json",
    "skills", "tasks", "todos",
)
if compat.IS_WIN:
    ALLOWED_PREFIXES += (
        "AppData/Local/AnthropicClaude",
        "AppData/Roaming/Claude",
        "AppData/Local/claude",
        "AppData/Local/Programs/claude-desktop",
        "AppData/Roaming/npm/node_modules/@anthropic-ai",
        "Documents/PowerShell",
        "Documents/WindowsPowerShell",
    )

MANUAL_HINT = "该项需要手动执行（涉及系统权限），工具不会代跑。"


class CleanError(Exception):
    pass


def _private_action(op: dict) -> str:
    kind = op["kind"]
    if kind == "purge":
        return op.get("privateAction", "cache")
    if kind == "keychain":
        return "credential"
    if kind == "envvar" and retention.secret_name(op["var"]):
        return "credential"
    if kind == "startup":
        path = Path(op["item"].get("path", ""))
        if path.is_file() and not retention.copy_allowed(path, HOME):
            op["item"] = {**op["item"], "noCopy": True}
            return "sensitive_config"
    if kind in ("json_keys", "rotate_ids"):
        if any(retention.secret_name(k.split(".")[-1]) for k in op.get("keys", [])):
            return "credential"
    if kind == "json_patch":
        if any(retention.secret_name(p[-1]) for p in op["patch"].get("delete", []) if p):
            return "credential"
    if kind in ("json_keys", "json_patch", "rotate_ids", "shellrc"):
        path = Path(op["path"])
        if path.exists() and not retention.copy_allowed(path, HOME):
            return "shell_secret" if kind == "shellrc" else "sensitive_config"
    return ""


def _display(path: Path) -> str:
    """把路径显示成 ~/xxx，使用未解析符号链接的原始路径。"""
    try:
        rel = path.relative_to(HOME)
        return "~/" + str(rel)
    except ValueError:
        return str(path)


def _rel(path: Path) -> str:
    for base in (HOME, HOME.resolve()):
        try:
            return str(path.relative_to(base))
        except ValueError:
            continue
    return str(path).lstrip("/")


def _guard(path: Path) -> Path:
    p = path.expanduser().resolve()
    try:
        rel = p.relative_to(HOME.resolve())
    except ValueError as exc:
        raise CleanError(f"拒绝操作家目录之外的路径：{p}") from exc
    if str(rel) == ".":
        raise CleanError("拒绝操作家目录本身")
    norm = str(rel).replace(os.sep, "/")
    if not (any(norm == pre or norm.startswith(pre + "/") for pre in ALLOWED_PREFIXES)
            or any(norm.startswith(pre) for pre in ALLOWED_FILE_PREFIXES)):
        raise CleanError(f"路径不在白名单内：{rel}")
    return p


def _expand(file_str: str) -> Path:
    return Path(os.path.expanduser(file_str))


def build_plan(items: list[dict], ids: list[str]) -> dict:
    """把选中的检测项翻译成可执行的操作清单。"""
    by_id = {it["id"]: it for it in items}
    ops: list[dict] = []
    skipped: list[dict] = []

    for item_id in ids:
        item = by_id.get(item_id)
        if not item:
            skipped.append({"id": item_id, "reason": "检测项已失效，请重新扫描"})
            continue
        fix = item.get("fix")
        if not fix:
            skipped.append({"id": item_id, "title": item["title"], "reason": "该项不支持自动清理"})
            continue
        kind = fix.get("kind")

        if kind == "json_keys":
            path = _expand(fix["file"])
            try:
                safe = _guard(path)
            except CleanError as exc:
                skipped.append({"id": item_id, "title": item["title"], "reason": str(exc)})
                continue
            ops.append(
                {
                    "id": item_id,
                    "kind": "json_keys",
                    "title": f"清空 {path.name} 中的 {len(fix['keys'])} 个字段",
                    "path": str(safe),
                    "display": _display(path),
                    "keys": fix["keys"],
                    "bytes": safe.stat().st_size if safe.exists() else 0,
                    "files": 1,
                    "severity": item["severity"],
                    "risk": fix.get("risk", "会删除 JSON 里对应字段，字段下的数据一并移除"),
                    "manual": fix.get("manual", "手动：文本编辑器打开文件，删除同名键后保存"),
                }
            )

        elif kind == "trash":
            raw_paths = fix.get("paths") or [fix["path"]]
            for raw in raw_paths:
                path = _expand(raw)
                try:
                    safe = _guard(path)
                except CleanError as exc:
                    skipped.append({"id": item_id, "title": item["title"], "reason": str(exc)})
                    continue
                if not safe.exists():
                    continue
                ops.append(
                    {
                        "id": item_id,
                        "kind": "trash",
                        "title": f"移入废纸篓：{safe.name}" if compat.IS_MAC else f"移入回收站：{safe.name}",
                        "path": str(safe),
                        "display": _display(path),
                        "bytes": fix.get("size", 0),
                        "files": fix.get("count", 1),
                        "severity": item["severity"],
                        "risk": fix.get("risk", "移入回收区而非永久删除；对应功能/登录态会随之消失，从回收区还原可恢复"),
                        "manual": fix.get("manual", "手动：把该目录/文件拖到回收站"),
                    }
                )

        elif kind == "keychain":
            store = "钥匙串" if compat.IS_MAC else "凭据管理器"
            ops.append(
                {
                    "id": item_id,
                    "kind": "keychain",
                    "title": f"删除{store}条目「{fix['service']}」",
                    "path": f"keychain:{fix['service']}",
                    "display": f"{store} · {fix['service']}",
                    "service": fix["service"],
                    "bytes": 0,
                    "files": 0,
                    "severity": item["severity"],
                    "risk": fix.get("risk", "凭据删除后需要重新登录"),
                    "manual": fix.get("manual", f"手动：{store}里找到同名条目删除"),
                }
            )

        elif kind == "shellrc":
            path = _expand(fix["file"])
            try:
                safe = _guard(path)
            except CleanError as exc:
                skipped.append({"id": item_id, "title": item["title"], "reason": str(exc)})
                continue
            ops.append(
                {
                    "id": item_id,
                    "kind": "shellrc",
                    "title": f"注释 {safe.name} 中的 {len(fix['lines'])} 行配置",
                    "path": str(safe),
                    "display": f"{_display(path)} · 第 {', '.join(map(str, fix['lines'][:5]))} 行",
                    "lines": fix["lines"],
                    "bytes": safe.stat().st_size if safe.exists() else 0,
                    "files": 1,
                    "severity": item["severity"],
                    "risk": fix.get("risk", "行被注释而非删除，取消注释即可恢复"),
                    "manual": fix.get("manual", "手动：文本编辑器打开文件，给对应行加 # 注释"),
                }
            )

        elif kind == "envvar":
            vars_ = fix.get("vars") or [{"name": fix.get("name"), "scope": fix.get("scope", "")}]
            for v in vars_:
                if not v.get("name"):
                    continue
                ops.append(
                    {
                        "id": item_id,
                        "kind": "envvar",
                        "title": f"删除环境变量 {v['name']}",
                        "path": f"env:{v['name']}",
                        "display": f"{v.get('scope') or '持久层'} · {v['name']}",
                        "var": v["name"],
                        "scope": v.get("scope", ""),
                        "bytes": 0,
                        "files": 0,
                        "severity": item["severity"],
                        "risk": fix.get("risk", "删除后新启动的进程读不到该变量；正在运行的进程不受影响"),
                        "manual": fix.get("manual",
                                          "手动：launchctl unsetenv " + v["name"] if compat.IS_MAC
                                          else "手动：系统属性 → 环境变量里删除 " + v["name"]),
                    }
                )

        elif kind == "startup":
            for it in fix.get("items") or []:
                ops.append(
                    {
                        "id": item_id,
                        "kind": "startup",
                        "title": f"移除启动项「{it['name']}」",
                        "path": f"startup:{it['name']}",
                        "display": it.get("path", it["name"]),
                        "item": it,
                        "bytes": 0,
                        "files": 1,
                        "severity": item["severity"],
                        "risk": fix.get("risk", "开机不再自启；文件本身会进回收站可还原"),
                        "manual": fix.get("manual",
                                          "手动：launchctl bootout + 删 plist" if compat.IS_MAC
                                          else "手动：任务管理器 → 启动 里禁用"),
                    }
                )

        elif kind == "json_patch":
            path = _expand(fix["file"])
            try:
                safe = _guard(path)
            except CleanError as exc:
                skipped.append({"id": item_id, "title": item["title"], "reason": str(exc)})
                continue
            if not safe.exists() and not fix.get("create"):
                skipped.append({"id": item_id, "title": item["title"], "reason": "目标文件不存在"})
                continue
            ops.append(
                {
                    "id": item_id,
                    "kind": "json_patch",
                    "title": fix.get("title", f"修改 {path.name} 的 {len(fix.get('delete') or [])} 处字段"),
                    "path": str(safe),
                    "display": _display(path),
                    "patch": fix,
                    "bytes": safe.stat().st_size if safe.exists() else 0,
                    "files": 1,
                    "severity": item["severity"],
                    "risk": fix.get("risk", ""),
                    "manual": fix.get("manual", "手动：文本编辑器打开文件删除对应字段"),
                }
            )

        elif kind == "rotate_ids":
            path = _expand(fix["file"])
            try:
                safe = _guard(path)
            except CleanError as exc:
                skipped.append({"id": item_id, "title": item["title"], "reason": str(exc)})
                continue
            if not safe.exists():
                skipped.append({"id": item_id, "title": item["title"], "reason": "目标文件不存在"})
                continue
            ops.append(
                {
                    "id": item_id,
                    "kind": "rotate_ids",
                    "title": f"重置 {path.name} 的设备指纹",
                    "path": str(safe),
                    "display": _display(path),
                    "rotate": fix.get("rotate") or [],
                    "keys": fix.get("keys") or [],
                    "bytes": safe.stat().st_size,
                    "files": 1,
                    "severity": item["severity"],
                    "risk": fix.get("risk", "指纹换成全新随机值后，服务端会把它当成一台新设备"),
                    "manual": fix.get("manual", "手动：备份后把 machineID/userID 改成随机 64 位十六进制"),
                }
            )

        elif kind == "manual":
            skipped.append(
                {
                    "id": item_id,
                    "title": item["title"],
                    "reason": MANUAL_HINT,
                    "command": fix.get("command", ""),
                }
            )
        else:
            skipped.append({"id": item_id, "title": item["title"], "reason": "未知操作类型"})

    # 同一个文件的多个操作合并，避免重复备份与重复写盘
    merged: dict[tuple, dict] = {}
    for op in ops:
        key = (op["kind"], op["path"])
        if key in merged and op["kind"] in ("json_keys", "shellrc", "rotate_ids", "json_patch"):
            tgt = merged[key]
            if op["kind"] == "json_keys":
                for k in op["keys"]:
                    if k not in tgt["keys"]:
                        tgt["keys"].append(k)
                tgt["title"] = f"清空 {Path(op['path']).name} 中的 {len(tgt['keys'])} 个字段"
            elif op["kind"] == "json_patch":
                p = tgt["patch"]
                np_ = op["patch"]
                p["delete"] = (p.get("delete") or []) + [d for d in (np_.get("delete") or []) if d not in (p.get("delete") or [])]
                p["set"] = {**(p.get("set") or {}), **(np_.get("set") or {})}
                p["filter"] = {**(p.get("filter") or {}), **(np_.get("filter") or {})}
                tgt["title"] = f"修改 {Path(op['path']).name}（{tgt.get('_patchn', 1) + 1} 项调整）"
                tgt["_patchn"] = tgt.get("_patchn", 1) + 1
                for extra in ("risk", "manual"):
                    if np_.get(extra) and np_[extra] not in (tgt.get(extra) or ""):
                        tgt[extra] = ((tgt.get(extra) or "") + " " + np_[extra]).strip()
            elif op["kind"] == "rotate_ids":
                for k in op.get("rotate") or []:
                    if k not in tgt["rotate"]:
                        tgt["rotate"].append(k)
                for k in op.get("keys") or []:
                    if k not in tgt["keys"]:
                        tgt["keys"].append(k)
            else:
                for ln in op["lines"]:
                    if ln not in tgt["lines"]:
                        tgt["lines"].append(ln)
                tgt["lines"].sort()
                tgt["title"] = f"注释 {Path(op['path']).name} 中的 {len(tgt['lines'])} 行配置"
            continue
        clone = dict(op)
        if "patch" in clone:
            clone["patch"] = dict(clone["patch"])
        if "keys" in clone:
            clone["keys"] = list(clone["keys"])
        if "lines" in clone:
            clone["lines"] = list(clone["lines"])
        if "rotate" in clone:
            clone["rotate"] = list(clone["rotate"])
        merged[key] = clone
    ops = list(merged.values())

    for op in ops:
        if op["kind"] == "trash":
            path = Path(op["path"])
            category = retention.path_category(path, HOME)
            if not category and path.is_file() and not retention.copy_allowed(path, HOME):
                category = "credential"
            if category:
                op.update(kind="purge", privateAction=category,
                          title=f"直接删除（不留副本）：{Path(op['path']).name}",
                          risk="不备份、不进废纸篓，删除后无法还原；凭据需重新登录，旧日志无法用于排障。",
                          manual="手动处理时同样不要保留凭据、缓存或日志副本。")
        private = _private_action(op)
        op["retention"] = "no-copy" if private or op["kind"] == "envvar" else "recoverable"
        if op["kind"] == "trash" and Path(op["path"]).is_dir():
            op["retention"] = "filtered"
            op["risk"] = (op.get("risk", "") + " 目录中的缓存、日志、凭据、含密钥或无法安全复制的文件直接删除；"
                          "其他内容移入废纸篓，无法完整还原。")
        if private:
            op["privateAction"] = private
            if op["kind"] not in ("purge", "keychain", "envvar"):
                op["risk"] = "该文件含密钥或令牌，不保留配置副本，无法通过本工具还原。"
            if op["kind"] == "shellrc":
                op["title"] = f"清理 {Path(op['path']).name}（密钥行删除，不留副本）"
                op["risk"] += " 密钥赋值行会真正移除；其他选中配置行仍只注释。"
                op["manual"] = "手动：移除密钥赋值行；非敏感配置可按需注释。"

    total_bytes = sum(o["bytes"] for o in ops)
    total_files = sum(o["files"] for o in ops)
    warnings = []
    if any(n in ("claude", "claude-code") for n in compat.ancestor_names()):
        warnings.append("当前工具进程是由 Claude Code 拉起的——清理它正在使用的 ~/.claude "
                        "风险很高（可能回写或崩溃）。建议换普通终端或 Codex 里运行本工具。")
    return {
        "ops": ops,
        "skipped": skipped,
        "totalBytes": total_bytes,
        "totalFiles": total_files,
        "backupDir": _display(BACKUP_DIR / "<时间戳>"),
        "warnings": warnings,
    }


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _unique_dir(base: Path) -> Path:
    if not base.exists():
        return base
    i = 2
    while True:
        cand = base.with_name(f"{base.name}-{i}")
        if not cand.exists():
            return cand
        i += 1


def execute(items: list[dict], ids: list[str], confirm: str) -> dict:
    if confirm != "CLEAN":
        raise CleanError("确认口令不正确，未执行任何操作")

    plan = build_plan(items, ids)
    if not plan["ops"]:
        return {"ok": False, "message": "没有可执行的操作", "results": [], "skipped": plan["skipped"]}

    stamp = _stamp()
    backup = _unique_dir(BACKUP_DIR / stamp)
    backup.mkdir(parents=True, exist_ok=True, mode=0o700)
    trash_bin = _unique_dir(TRASH_DIR / f"CCclean-{stamp}")
    manifest = {"createdAt": time.strftime("%Y-%m-%dT%H:%M:%S"), "backupDir": str(backup), "entries": []}
    results: list[dict] = []

    # 受保护路径快照：执行后逐项复查，确保对话/配置/技能等资产一个没少
    claude_dir = HOME / ".claude"
    protected_before = [claude_dir / name for name in PROTECTED_CLAUDE
                        if (claude_dir / name).exists() or (claude_dir / name).is_symlink()]

    for op in plan["ops"]:
        try:
            if op["kind"] == "json_keys":
                res = _apply_json_keys(op, backup)
            elif op["kind"] in ("trash", "purge"):
                res = _apply_trash(op, trash_bin)
            elif op["kind"] == "keychain":
                res = _apply_keychain(op, backup)
            elif op["kind"] == "shellrc":
                res = _apply_shellrc(op, backup)
            elif op["kind"] == "rotate_ids":
                res = _apply_rotate_ids(op, backup)
            elif op["kind"] == "envvar":
                res = _apply_envvar(op)
            elif op["kind"] == "startup":
                res = _apply_startup(op)
            elif op["kind"] == "json_patch":
                res = _apply_json_patch(op, backup)
            else:
                res = {"ok": False, "message": "未知操作"}
            results.append({"id": op["id"], "title": op["title"], "ok": res["ok"], "message": res["message"]})
            private = op.get("privateAction") or ("sensitive_config" if res.get("noCopy") else "")
            if private:
                manifest["entries"].append({"kind": "no_copy", "action": private, "ok": bool(res["ok"])})
            else:
                manifest["entries"].append(
                    {"id": op["id"], "kind": op["kind"], "path": op["path"], "detail": res.get("detail", {})})
        except Exception as exc:
            private = op.get("privateAction")
            message = ("操作未完成；未保留敏感内容副本。请检查文件权限，Shell 密钥须使用独立赋值行。"
                       if private else str(exc))
            results.append({"id": op["id"], "title": op["title"], "ok": False, "message": message})
            if private:
                manifest["entries"].append({"kind": "no_copy", "action": private, "ok": False})

    _write_private(backup / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode())
    prune_backups(protect=backup)

    protected_missing = [str(p).replace(str(HOME), "~") for p in protected_before
                         if not (p.exists() or p.is_symlink())]

    ok_count = sum(1 for r in results if r["ok"])
    skip_note = f"，{len(plan['skipped'])} 项需手动处理" if plan["skipped"] else ""
    warn_note = f"；⚠ {len(protected_missing)} 个受保护路径缺失" if protected_missing else ""
    return {
        "ok": ok_count > 0 and not protected_missing,
        "message": f"完成 {ok_count}/{len(results)} 项{skip_note}{warn_note}",
        "results": results,
        "skipped": plan["skipped"],
        "backupDir": str(backup).replace(str(HOME), "~"),
        "trashDir": str(trash_bin).replace(str(HOME), "~") if trash_bin.exists() else None,
        "protectedMissing": protected_missing,
        "restoreHint": "缓存、诊断日志、密钥及含凭据的配置不留副本，无法还原；其余项目按清单恢复。",
    }


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)


def _rewrite(path: Path, data: bytes, mode: int | None = None) -> None:
    """原子改写；失败时也不留下可能含未清理凭据的临时文件。"""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = mode if mode is not None else path.stat().st_mode if path.exists() else 0o600
    fd, name = tempfile.mkstemp(prefix=".ccclean-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _safe_copy(path: Path, target: Path) -> bool:
    """先在内存检查同一份内容再落盘，避免检查后 copy2 再读到新写入的密钥。"""
    if path.is_symlink() or retention.path_category(path, HOME):
        return False
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            return False
        data = stream.read()
    if not retention.copy_allowed(path, HOME, data):
        return False
    _write_private(target, data)
    return True


def _backup_file(path: Path, backup: Path) -> Path | None:
    target = backup / "files" / _rel(path)
    if target.exists():
        return target  # 同一批次只保存第一次改动之前的版本。
    return target if _safe_copy(path, target) else None


def _apply_json_keys(op: dict, backup: Path) -> dict:
    path = Path(op["path"])
    if not path.exists():
        return {"ok": False, "message": "文件不存在"}
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    saved = _backup_file(path, backup)
    removed = []
    for dotted in op["keys"]:
        parts = dotted.split(".")
        node = data
        for p in parts[:-1]:
            node = node.get(p) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, dict) and parts[-1] in node:
            del node[parts[-1]]
            removed.append(dotted)

    # 去掉被清空的容器，避免留下 "env": {}
    for container in ("env", "permissions"):
        if isinstance(data.get(container), dict) and not data[container]:
            data.pop(container, None)

    _rewrite(path, json.dumps(data, ensure_ascii=False, indent=2).encode())
    return {
        "ok": True,
        "message": f"已清空 {len(removed)} 个字段（{'已备份原文件' if saved else '不留副本，不可还原'}）",
        "noCopy": not bool(saved),
        "detail": {"removed": removed},
    }


def _apply_rotate_ids(op: dict, backup: Path) -> dict:
    """重置设备指纹：machineID/userID 写全新随机值，其余标识字段删除。

    比直接删除更彻底——有些字段删掉后客户端会按硬件特征算回原值，
    换成随机值才真正换了张脸。项目路径与偏好设置保留。
    """
    path = Path(op["path"])
    if not path.exists():
        return {"ok": False, "message": "文件不存在"}
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    saved = _backup_file(path, backup)

    # 新指纹只生成一次：主文件与客户端的内部备份要写同一组值，
    # 否则客户端从内部备份恢复时旧指纹原地复活
    new_ids = {k: secrets.token_hex(32) for k in op.get("rotate") or []}
    rotated = []
    for k, v in new_ids.items():
        if k in data:
            data[k] = v
            rotated.append(k)
    removed = []
    for dotted in op.get("keys") or []:
        parts = dotted.split(".")
        node = data
        for p in parts[:-1]:
            node = node.get(p) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, dict) and parts[-1] in node:
            del node[parts[-1]]
            removed.append(dotted)
    for container in ("env", "permissions"):
        if isinstance(data.get(container), dict) and not data[container]:
            data.pop(container, None)

    _rewrite(path, json.dumps(data, ensure_ascii=False, indent=2).encode())
    # 客户端内部备份 ~/.claude/backups/.claude.json.backup.* 里存着同一组旧指纹，
    # 同步写新值 + 清同样的缓存字段，堵死「从备份恢复回旧脸」这条路
    synced = 0
    for bpath in sorted((HOME / ".claude" / "backups").glob(".claude.json.backup.*")):
        try:
            if not bpath.is_file() or bpath.is_symlink():
                continue
            bdata = json.loads(bpath.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(bdata, dict):
                continue
            _backup_file(bpath, backup)
            bdata.update(new_ids)
            for dotted in op.get("keys") or []:
                parts = dotted.split(".")
                node = bdata
                for p in parts[:-1]:
                    node = node.get(p) if isinstance(node, dict) else None
                    if node is None:
                        break
                if isinstance(node, dict):
                    node.pop(parts[-1], None)
            _rewrite(bpath, json.dumps(bdata, ensure_ascii=False, indent=2).encode())
            synced += 1
        except (OSError, ValueError):
            continue

    msg = []
    if rotated:
        msg.append(f"{', '.join(rotated)} 已重置为全新随机值")
    if removed:
        msg.append(f"清空 {len(removed)} 个标识字段")
    if synced:
        msg.append(f"同步重置 {synced} 份内部备份")
    return {
        "ok": True,
        "message": "；".join(msg) + ("（原文件已备份）" if saved else "（不留副本，不可还原）") if msg else "没有可重置的字段",
        "noCopy": not bool(saved),
        "detail": {"rotated": rotated, "removed": removed, "synced": synced},
    }


def _apply_trash(op: dict, trash_bin: Path) -> dict:
    src = Path(op["path"])
    if not src.exists():
        return {"ok": False, "message": "目标已不存在"}
    if (op.get("kind") == "purge" or retention.path_category(src, HOME)
            or (src.is_file() and not retention.copy_allowed(src, HOME))):
        if src.is_dir() and not src.is_symlink():
            shutil.rmtree(src)
        else:
            src.unlink()
        return {"ok": True, "message": "已直接删除；不备份、不进废纸篓，不可还原", "noCopy": True}
    removed = _discard_private_children(src) if src.is_dir() else 0
    if compat.IS_WIN:
        # Windows 走系统回收站；失败退回本地隔离目录
        ok, note = compat.send_to_trash(src)
        if ok:
            return {"ok": True, "message": f"已移入回收站；{removed} 项敏感内容未保留",
                    "detail": {"from": str(src), "to": "回收站", "privateRemoved": removed}}
        dest = trash_bin / src.name
        if dest.exists():
            dest = _unique_dir(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        return {
            "ok": True,
            "message": f"回收站不可用，非敏感内容已移入隔离区；{removed} 项敏感内容未保留",
            "detail": {"from": str(src), "to": str(dest), "privateRemoved": removed},
        }
    dest = trash_bin / src.name
    if dest.exists():
        dest = _unique_dir(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    return {
        "ok": True,
        "message": f"非敏感内容已移入废纸篓；{removed} 项敏感内容未保留",
        "detail": {"from": str(src), "to": str(dest), "privateRemoved": removed},
    }


def _discard_private_children(root: Path) -> int:
    """整目录清理也要过滤，避免把夹带的凭据、日志随其他文件挪进废纸篓。"""
    removed = 0
    for path in root.iterdir():
        private = path.is_symlink() or bool(retention.path_category(path, HOME))
        if not private and path.is_file():
            private = not retention.copy_allowed(path, HOME)
        if private:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed += 1
        elif path.is_dir():
            removed += _discard_private_children(path)
    return removed


def _apply_envvar(op: dict) -> dict:
    ok, err = compat.unset_env(op["var"], op.get("scope") or "")
    if ok:
        return {"ok": True, "message": f"已删除 {op['var']}（新启进程生效）", "detail": {"var": op["var"]}}
    return {"ok": False, "message": err or "删除失败"}


def _apply_startup(op: dict) -> dict:
    ok, note = compat.remove_startup_item(op["item"])
    if ok:
        return {"ok": True, "message": note or "已移除", "detail": {"name": op["item"]["name"]}}
    return {"ok": False, "message": note or "移除失败"}


def _apply_json_patch(op: dict, backup: Path) -> dict:
    """嵌套键手术：delete 删路径、set 设值、filter 按正则过滤数组元素。"""
    path = Path(op["path"])
    patch = op["patch"]
    created = not path.exists()
    if created and patch.get("create"):
        data = {}
    else:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"ok": False, "message": "JSON 读不出来，跳过"}
    if not isinstance(data, dict):
        return {"ok": False, "message": "JSON 根节点不是对象，跳过"}
    saved = _backup_file(path, backup) if not created else None
    changed = 0

    for keypath in patch.get("delete") or []:
        node = data
        for k in keypath[:-1]:
            if not isinstance(node, dict) or k not in node:
                node = None
                break
            node = node[k]
        if isinstance(node, dict) and keypath[-1] in node:
            del node[keypath[-1]]
            changed += 1

    for keypath, val in (patch.get("set") or {}).items():
        keys = keypath.split(".")
        node = data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
            if not isinstance(node, dict):
                node = None
                break
        if isinstance(node, dict) and node.get(keys[-1]) != val:
            node[keys[-1]] = val
            changed += 1

    for keypath, pattern in (patch.get("filter") or {}).items():
        keys = keypath.split(".")
        node = data
        for k in keys:
            node = node.get(k) if isinstance(node, dict) else None
        if isinstance(node, list):
            kept = [x for x in node if not (isinstance(x, str) and re.search(pattern, x))]
            removed = len(node) - len(kept)
            if removed:
                node[:] = kept
                changed += removed

    if not changed:
        return {"ok": False, "message": "目标字段已不存在"}
    _rewrite(path, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode())
    note = "新建配置；撤销时删除新增字段或文件" if created else "原文件已备份" if saved else "不留副本，不可还原"
    return {"ok": True, "message": f"已修改 {changed} 处（{note}）", "noCopy": not created and not bool(saved),
            "detail": {"changed": changed, "created": created}}


def _apply_keychain(op: dict, backup: Path) -> dict:
    svc = op["service"]
    store = "钥匙串" if compat.IS_MAC else "凭据管理器"
    ok, err = compat.delete_keychain(svc)
    if ok:
        return {"ok": True, "message": f"已从{store}删除", "detail": {"service": svc}}
    return {"ok": False, "message": err or f"删除失败（可能需要解锁{store}）"}


def _apply_shellrc(op: dict, backup: Path) -> dict:
    path = Path(op["path"])
    if not path.exists():
        return {"ok": False, "message": "文件不存在"}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    targets = set(op.get("lines") or [])
    spans = retention.shell_secret_spans("".join(lines), strict=True, selected=targets)
    secret_lines = {n for start, end in spans if any(start <= n <= end for n in targets)
                    for n in range(start, end + 1)}
    saved = _backup_file(path, backup)
    removed = len(secret_lines)
    changed = 0
    for idx, line in enumerate(lines, 1):
        if idx in secret_lines:
            lines[idx - 1] = ""
        elif idx in targets and not line.lstrip().startswith("#"):
            lines[idx - 1] = "# [ccclean] " + line
            changed += 1
    _rewrite(path, "".join(lines).encode())
    return {
        "ok": True,
        "message": f"已移除 {removed} 行密钥配置，注释 {changed} 行其他配置（{'原文件已备份' if saved else '不留副本，不可还原'}）",
        "noCopy": not bool(saved),
        "detail": {"commented": changed, "removed": removed},
    }


def full_snapshot() -> dict:
    """过滤快照：缓存、日志、凭据、含密钥的文件及符号链接不复制。"""
    src = HOME / ".claude"
    if not src.is_dir() or src.is_symlink():
        raise CleanError("~/.claude 不存在，没有可备份的对象")
    dest = _unique_dir(BACKUP_DIR / f"snapshot-{_stamp()}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".partial")
    (partial / "dot-claude").mkdir(parents=True, mode=0o700)
    files, nbytes, excluded = 0, 0, 0
    for root, dirs, names in os.walk(src, followlinks=False):
        root = Path(root)
        for name in list(dirs):
            child = root / name
            if child.is_symlink() or retention.path_category(child, HOME):
                dirs.remove(name)
                excluded += 1
        for name in names:
            path = root / name
            target = partial / "dot-claude" / path.relative_to(src)
            if _safe_copy(path, target):
                files += 1
                nbytes += target.stat().st_size
            else:
                excluded += 1
    copied_json = False
    ident = HOME / ".claude.json"
    if ident.is_file():
        copied_json = _safe_copy(ident, partial / "claude.json")
        if copied_json:
            files += 1
            nbytes += (partial / "claude.json").stat().st_size
        else:
            excluded += 1
    _write_private(partial / "manifest.json",
        json.dumps({"kind": "filtered-snapshot", "files": files, "regularFileBytes": nbytes,
                    "excludedEntries": excluded, "policy": "no-cache-log-credentials-v1",
                    "claudeJsonCopied": copied_json,
                    "createdAt": time.strftime("%Y-%m-%dT%H:%M:%S")},
                   ensure_ascii=False, indent=2).encode())
    partial.rename(dest)
    return {"ok": True, "path": _display(dest), "files": files, "bytes": nbytes,
            "excludedEntries": excluded,
            "message": f"已保存 {files} 个非敏感文件（{_human_bytes(nbytes)}）；排除 {excluded} 项缓存、日志、凭据或不可安全复制的文件。"}


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n:.0f}B"
        n /= 1024
    return f"{n:.0f}B"


def running_claude() -> list[dict]:
    """还在跑的 claude 进程（CLI 与桌面端）。清理前必须确认，否则会回写指纹。"""
    return compat.claude_processes()


def quit_claude() -> dict:
    """先礼后兵：桌面端正常退出，CLI 按 pid 收；还在就强杀。"""
    compat.quit_processes(compat.claude_processes())
    left = compat.claude_processes()
    return {"ok": not left, "left": left}


def list_backups() -> list[dict]:
    if not BACKUP_DIR.exists():
        return []
    out = []
    for d in sorted(BACKUP_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        manifest = d / "manifest.json"
        count = 0
        created = ""
        kinds: dict[str, int] = {}
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                entries = data.get("entries", [])
                count = len(entries)
                created = data.get("createdAt") or ""
                for e in entries:
                    k = e.get("kind") or "?"
                    kinds[k] = kinds.get(k, 0) + 1
            except Exception:
                count = 0
        out.append({
            "id": d.name,
            "path": str(d).replace(str(HOME), "~"),
            "entries": count,
            "createdAt": created,
            "kinds": kinds,
            # 钥匙串/环境变量/登录项没有原始值可还原，界面上要说清楚
            "restorable": sum(v for k, v in kinds.items() if k in _RESTORABLE_KINDS),
        })
    return out[:20]


# 有文件备份、能原样盖回去的操作类型
_RESTORABLE_KINDS = ("json_keys", "json_patch", "shellrc", "rotate_ids", "trash")


def _manifest_entries(backup: Path) -> list[dict]:
    try:
        data = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return []
    entries = data.get("entries")
    return entries if isinstance(entries, list) else []


def restore(backup_id: str, confirm: str) -> dict:
    """把某一次清理的备份还原回去。

    能还原的：被改写/删除字段的配置文件（有整份副本）、被移入废纸篓的文件。
    还原不了的：钥匙串条目（没有副本）、环境变量与登录项（没记原值）。
    后者会明确列在 skipped 里，而不是假装成功。

    还原本身也会覆盖当前文件，所以覆盖之前先把现在的样子存进
    `pre-restore/<时间戳>/`——万一还原错了还能再回去。
    """
    if confirm != "RESTORE":
        raise CleanError("确认口令不正确，未执行任何操作")
    if not _BACKUP_NAME.match(backup_id or ""):
        raise CleanError("备份编号不合法")
    backup = BACKUP_DIR / backup_id
    if not backup.is_dir():
        raise CleanError("找不到这份备份")
    entries = _manifest_entries(backup)
    if not entries:
        raise CleanError("这份备份没有清单，不知道要还原什么")

    pre_dir = _unique_dir(backup / "pre-restore" / _stamp())
    results: list[dict] = []
    skipped: list[dict] = []

    for e in entries:
        kind = e.get("kind") or ""
        raw_path = e.get("path") or ""
        label = e.get("id") or kind

        if kind in ("keychain", "envvar", "startup", "no_copy"):
            skipped.append({"id": label, "reason": "这一类操作没有留下原始值，无法自动还原"})
            continue

        if kind == "trash":
            detail = e.get("detail") or {}
            src, dst = detail.get("from"), detail.get("to")
            if not src or not dst or dst == "回收站":
                skipped.append({"id": label, "reason": "文件在系统回收站里，请手动还原"})
                continue
            src_p, dst_p = Path(src), Path(dst)
            if not dst_p.exists():
                skipped.append({"id": label, "reason": "废纸篓里已找不到这个文件"})
                continue
            if src_p.exists():
                skipped.append({"id": label, "reason": "原位置已有同名文件，未覆盖"})
                continue
            try:
                target = _guard(src_p)
            except CleanError as exc:
                skipped.append({"id": label, "reason": str(exc)})
                continue
            if retention.path_category(target, HOME) or not _restorable_tree(dst_p, target):
                skipped.append({"id": label, "reason": "旧副本包含缓存、日志或凭据，按当前隐私策略不还原"})
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(dst_p), str(target))
                results.append({"id": label, "message": f"已从废纸篓移回 {_display(target)}"})
            except OSError as exc:
                skipped.append({"id": label, "reason": f"移回失败：{exc}"})
            continue

        if not raw_path:
            skipped.append({"id": label, "reason": "清单里没记路径"})
            continue
        target = _expand(raw_path)
        saved = backup / "files" / _rel(target)
        if not saved.exists():
            if kind == "json_patch" and (e.get("detail") or {}).get("created"):
                skipped.append({"id": label, "reason": "这个文件是清理时新建的，没有原始副本；如需删除请手动处理"})
            else:
                skipped.append({"id": label, "reason": "备份里没有这个文件"})
            continue
        try:
            target = _guard(target)
        except CleanError as exc:
            skipped.append({"id": label, "reason": str(exc)})
            continue
        if not retention.copy_allowed(target, HOME, saved.read_bytes()):
            skipped.append({"id": label, "reason": "旧副本含缓存、日志或凭据，按当前隐私策略不还原"})
            continue
        if target.exists() and not retention.copy_allowed(target, HOME):
            skipped.append({"id": label, "reason": "当前文件含密钥或令牌，未覆盖，也未保存副本"})
            continue
        try:
            if target.exists():
                snap = pre_dir / "files" / _rel(target)
                if not _safe_copy(target, snap):
                    raise CleanError("当前内容已变化，未覆盖")
            data = saved.read_bytes()
            if not retention.copy_allowed(target, HOME, data):
                raise CleanError("副本已变化，未还原")
            _rewrite(target, data)
            results.append({"id": label, "message": f"已还原 {_display(target)}"})
        except (OSError, CleanError) as exc:
            skipped.append({"id": label, "reason": f"写入失败：{exc}"})

    return {
        "ok": bool(results),
        "message": f"还原 {len(results)} 项" + (f"，{len(skipped)} 项需手动处理" if skipped else ""),
        "restored": results,
        "skipped": skipped,
        "preRestoreDir": _display(pre_dir) if pre_dir.exists() else "",
    }


def _restorable_tree(stored: Path, original: Path) -> bool:
    if stored.is_symlink() or retention.path_category(original, HOME):
        return False
    if stored.is_file():
        return retention.copy_allowed(original, HOME, stored.read_bytes())
    if not stored.is_dir():
        return False
    return all(_restorable_tree(p, original / p.name) for p in stored.iterdir())


BACKUP_KEEP = 20
_BACKUP_NAME = re.compile(r"^\d{8}-\d{6}(-\d+)?$")


def prune_backups(keep: int = BACKUP_KEEP, protect: Path | None = None) -> int:
    """只保留最近 keep 次备份，返回删掉的数量。

    三重保险，避免误删任何不是自己造的东西：
      1. 只处理名字是「日期-时间[-序号]」的目录；
      2. 目录里必须有 manifest.json（说明是本工具写的）；
      3. 正在使用的那一个（protect）永不删除。
    """
    if not BACKUP_DIR.exists():
        return 0
    cands = []
    for d in BACKUP_DIR.iterdir():
        if not d.is_dir():
            continue
        if not _BACKUP_NAME.match(d.name):
            continue
        if not (d / "manifest.json").exists():
            continue
        if protect is not None and d.resolve() == protect.resolve():
            continue
        cands.append(d)
    cands.sort(key=lambda p: p.name, reverse=True)
    removed = 0
    for d in cands[keep:]:
        try:
            shutil.rmtree(d)
            removed += 1
        except Exception:
            pass
    return removed
