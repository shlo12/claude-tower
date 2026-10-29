"""本地副本策略：已识别的缓存、诊断日志和凭据不进入备份或废纸篓。"""
from __future__ import annotations

import json
import plistlib
import re
import shlex
from pathlib import Path

CACHE_NAMES = frozenset({
    "telemetry", "statsig", "stats-cache.json", "paste-cache", "debug", "logs",
    "usage.jsonl", "usage.with-fix.jsonl", "usage-data", "cache", "caches",
    "shell-snapshots", "session-env",
})
_SECRET_NAME = re.compile(
    r"(?:api_?key|auth_?token|access_?token|refresh_?token|id_?token|client_?secret|"
    r"password|passwd|authorization|cookie|credential|secret|token)$", re.I)
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+|readonly\s+|typeset\s+-[a-zA-Z]+\s+)?(?:\$env:)?([A-Za-z_]\w*)\s*=", re.I)
_FISH = re.compile(r"^\s*set\s+(?:-[a-zA-Z]+\s+)*([A-Za-z_]\w*)\s+")
_SECRET_TEXT = re.compile(
    r"(?:\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}|\bBearer\s+[^\s\"']{8,}|"
    r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|"
    r"(?:api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|password|client[_-]?secret|authorization|cookie|secret|token)"
    r"[\"']?\s*[=:]\s*[^\s]+)", re.I)


def secret_name(name: str) -> bool:
    return bool(_SECRET_NAME.search(name.replace("-", "_")))


def path_category(path: Path, home: Path) -> str:
    """返回固定类别；不靠客户端传入的标题或 ID 决定永久删除。"""
    name = path.name.lower()
    if (name in {".credentials.json", "credentials.json", "auth.json", "tokens.json", "token.json"}
            or name.endswith((".key", ".pem"))):
        return "credential"
    parts = None
    for base in (home, home.resolve()):
        try:
            parts = path.relative_to(base).parts
            break
        except ValueError:
            continue
    if parts is None:
        return ""
    # 自定义隔离档与默认目录使用相同的 Claude 数据布局。
    for marker in (".claude", "claude", "container-claude"):
        if marker in parts:
            tail = parts[parts.index(marker) + 1:]
            if tail and tail[0].lower() in CACHE_NAMES:
                return "cache"
            if tail and tail[-1].lower().endswith(".log"):
                return "cache"
    rel = "/".join(parts)
    cache_roots = (
        "Library/Caches/com.anthropic.claudefordesktop", "Library/Caches/claude-cli-nodejs",
        "Library/Logs/Claude", "Library/Logs/DiagnosticReports/Claude",
        "Library/Application Support/CrashReporter/Claude",
    )
    if any(rel.startswith(root) for root in cache_roots):
        return "cache"
    # 这些存储容器可能包含 Cookie / 会话令牌，不能整目录挪进废纸篓。
    stores = ("Library/Application Support/Claude", "Library/Application Support/Claude-3p",
              "Library/HTTPStorages/com.anthropic.claudefordesktop",
              "Library/WebKit/com.anthropic.claudefordesktop")
    if any(rel == root or rel.startswith(root + "/") for root in stores):
        return "credential"
    return ""


def shell_secret_spans(text: str, strict: bool = False, selected: set[int] | None = None) -> list[tuple[int, int]]:
    """识别独立密钥赋值，包含旧版注释、带引号多行和反斜杠续行。行号从 1 开始。"""
    lines = text.splitlines(keepends=True)
    spans = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        candidate = re.sub(r"^\s*#\s*(?:\[ccclean\]\s*)?", "", raw)
        match = _ASSIGNMENT.match(candidate) or _FISH.match(candidate)
        if not match or not secret_name(match[1]):
            i += 1
            continue
        start = i
        statement = candidate
        while True:
            try:
                tokens = shlex.split(statement, comments=True)
                complete = not statement.rstrip("\r\n").endswith("\\")
            except ValueError:
                tokens, complete = [], False
            if complete or i + 1 >= len(lines):
                break
            i += 1
            statement += re.sub(r"^\s*# \[ccclean\] ", "", lines[i])
        if strict and (selected is None or any(start + 1 <= n <= i + 1 for n in selected)):
            # 不猜测命令替换、here-doc 或同一行混合命令的语义，避免误删其他配置。
            lexer = shlex.shlex(statement, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            if (not complete or "$(" in statement or "`" in statement
                    or any(t and all(c in ";&|<>" for c in t) for t in lexer)
                    or sum(bool(_ASSIGNMENT.match(t)) for t in tokens) > 1):
                raise ValueError("密钥赋值不是独立配置行，请先拆开混合命令或命令替换后重试；未修改文件")
        spans.append((start + 1, i + 1))
        i += 1
    return spans


def contains_secret(data: bytes) -> bool:
    """检查已识别的凭据；不能仅因文件是二进制就认定它是密钥并永久删除。"""
    text = data.decode("utf-8", errors="ignore")
    if shell_secret_spans(text) or _SECRET_TEXT.search(text):
        return True
    try:
        value = plistlib.loads(data) if data.startswith(b"bplist") or text.lstrip().startswith("<?xml") else json.loads(text)
    except (ValueError, RecursionError, plistlib.InvalidFileException):
        return False

    def visit(node):
        if isinstance(node, dict):
            return any((secret_name(str(k)) and v not in (None, "", {}, [])) or visit(v)
                       for k, v in node.items())
        if isinstance(node, list):
            return any(visit(v) for v in node)
        return False

    return visit(value)


def copy_allowed(path: Path, home: Path, data: bytes | None = None) -> bool:
    if path.is_symlink() or path_category(path, home):
        return False
    return not contains_secret(path.read_bytes() if data is None else data)
