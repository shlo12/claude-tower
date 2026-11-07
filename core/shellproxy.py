"""终端里的代理变量：看清楚、写进去、删干净。

`terminalegress` 能测出「终端里的 curl 和浏览器不是同一个出口」——最常见
的原因就是 curl **不读 macOS 的系统代理**，而 shell 里没有 `export HTTPS_PROXY`。
知道了却只能让人自己去改 `.zshrc`，这一项就永远停在红叉上，所以这里补上
写的那一半。

四条规矩：

1. **只写一个文件。** 登录 shell 真正会读的那个 rc；fish 的语法不同
   （`set -x`），不代写，直接说清楚。
2. **只写一个带标记的块。** 撤销时按标记删，块外的内容一个字都不动。
3. **已经有别人的代理变量就不写。** 两块配置打架时谁在后面谁生效，这种事
   不该由本工具替用户决定——报出行号让他自己处理。
4. **写前备份、写后回读。** 脱敏副本放 `~/.ccclean/backups/`（0600），无法安全脱敏时不留副本；回读确认
   块真的在里面，没写进去就报错且不留记录。
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.request
from pathlib import Path

from . import compat, domainegress, netprobe, retention, history

BLOCK0 = "# >>> ccclean terminal proxy >>>"
BLOCK1 = "# <<< ccclean terminal proxy <<<"
STATE = Path.home() / ".ccclean/shellproxy.json"
BACKUP_DIR = Path.home() / ".ccclean/backups"
TRACE_URL = "https://api.anthropic.com/cdn-cgi/trace"
UA = "CCTower shellproxy"
TIMEOUT = 8
MAX_BYTES = 512 * 1024

# 会自己开本地 HTTP 端口的客户端。只用来「猜候选端口」，不当作结论。
_CLIENT_HINTS = ("clash", "verge", "mihomo", "flclash", "surge",
                 "shadowrocket", "stash", "sing-box", "singbox")
# 块外已有的代理变量：`export HTTPS_PROXY=` / `http_proxy=` 都算。
_ENV_RE = re.compile(r"^\s*(?:export\s+)?(?:https?|all|no)_proxy\s*=", re.I)


def rc_path() -> tuple[Path | None, str]:
    """登录 shell 会读的那个 rc 文件；不支持时返回 (None, 原因)。"""
    shell = Path(os.environ.get("SHELL") or "/bin/zsh").name
    home = Path.home()
    if shell == "zsh":
        return home / ".zshrc", ""
    if shell == "bash":
        for name in (".bash_profile", ".bashrc"):
            if (home / name).is_file():
                return home / name, ""
        return home / ".bash_profile", ""
    if shell == "fish":
        return None, "fish 的变量语法是 set -x，本工具不代写；请手动加到 config.fish"
    return None, f"没有为 {shell or '未知 shell'} 准备写入路径"


def detect() -> list[dict]:
    """可能的本地代理端口：系统代理优先，其次是跑着的客户端监听端口。"""
    out: list[dict] = []

    def add(port, source: str) -> None:
        try:
            num = int(port)
        except (TypeError, ValueError):
            return
        if not 0 < num < 65536 or any(x["port"] == num for x in out):
            return
        out.append({"port": num, "from": source})

    server = str((compat.system_proxy() or {}).get("server") or "")
    hit = re.search(r":(\d+)$", server)
    if hit:
        add(hit.group(1), "系统代理")
    for row in compat.listening_ports() or []:
        name = str(row.get("name") or "")
        if any(k in name.lower() for k in _CLIENT_HINTS):
            add(row.get("port"), name)
    return out


def _block(port: int) -> str:
    proxy = f"http://127.0.0.1:{port}"
    return "\n".join([
        BLOCK0,
        "# 由 CC Tower 写入。删掉这两行注释之间的内容即可还原。",
        f'export http_proxy="{proxy}"',
        f'export https_proxy="{proxy}"',
        'export HTTP_PROXY="$http_proxy"',
        'export HTTPS_PROXY="$https_proxy"',
        'export NO_PROXY="127.0.0.1,localhost,::1"',
        'export no_proxy="$NO_PROXY"',
        BLOCK1,
        "",
    ])


def _span(lines: list[str]) -> tuple[int, int] | None:
    """标记块在行列表里的 [start, end) 区间；没有标记返回 None。"""
    start = end = None
    for i, line in enumerate(lines):
        text = line.strip()
        if text == BLOCK0:
            start = i
        elif text == BLOCK1 and start is not None:
            end = i + 1
            break
    if start is None or end is None:
        return None
    return start, end


def strip_block(text: str) -> str:
    """去掉标记块，块外的内容原样保留（撤销要能一字不差地还原）。"""
    lines = (text or "").splitlines(keepends=True)
    span = _span(lines)
    if not span:
        return text or ""
    start, end = span
    return "".join(lines[:start] + lines[end:])


def foreign_env(text: str) -> list[int]:
    """块外已有的代理变量行号（1 起）。这些行说明有人已经配过了。"""
    lines = (text or "").splitlines()
    span = _span(lines)
    skip = set()
    if span:
        skip = set(range(span[0], span[1]))
    return [i + 1 for i, line in enumerate(lines)
            if i not in skip and _ENV_RE.match(line)]


def probe_port(port: int) -> dict:
    """拿这个端口当 HTTP 代理发一次请求，看它是不是真的能出去。"""
    out = {"ok": False, "ipMasked": "", "loc": "", "error": ""}
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    req = urllib.request.Request(TRACE_URL, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            text = resp.read(4096).decode("utf-8", "replace")
    except Exception as exc:  # 端口没开、不是 HTTP 代理、被拦，都归到这里
        out["error"] = f"这个端口没有按 HTTP 代理回应（{type(exc).__name__}）"
        return out
    trace = domainegress.parse_trace(text)
    if not trace:
        out["error"] = "端口通了，但返回的不是 Cloudflare 的 trace，无法确认出口"
        return out
    out.update(ok=True, ipMasked=netprobe._mask_ip(trace["ip"]),
               loc=trace.get("loc") or "")
    return out


def _read_state() -> tuple[dict, str]:
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, ""
    except (OSError, ValueError) as exc:
        return {}, f"终端代理记录无法读取：{exc}"
    if not isinstance(data, dict) or data.get("version") != 1:
        return {}, "终端代理记录格式不正确"
    return data, ""


def _write_state(data: dict) -> None:
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".shellproxy-", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _backup(path: Path) -> str:
    """脱敏副本保存到 ~/.ccclean/backups/（0600）；无法安全脱敏时不留副本。"""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise RuntimeError(f"读不到 {path.name}，未修改：{exc}") from exc
    # Shell 配置可能已有 API 密钥：副本移除已识别的密钥赋值。
    lines = data.decode("utf-8", errors="replace").splitlines(keepends=True)
    spans = retention.shell_secret_spans("".join(lines))
    data = "".join(line for n, line in enumerate(lines, 1)
                   if not any(start <= n <= end for start, end in spans)).encode("utf-8")
    # 其他已识别敏感内容无法安全拆分时，不生成副本；撤销仍只移除标记块。
    if retention.contains_secret(data):
        return ""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = BACKUP_DIR / f"rc-{stamp}-{path.name}"
    # 同一秒里写一次、撤一次会撞名；撞了就加序号，不能覆盖掉前一份
    seq = 1
    while dest.exists():
        seq += 1
        dest = BACKUP_DIR / f"rc-{stamp}-{seq}-{path.name}"
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return str(dest)


def _guard(path: Path) -> None:
    for item in (path, path.parent, STATE, STATE.parent):
        if item.is_symlink():
            raise ValueError(f"{item} 是符号链接，未修改")


def _load(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise ValueError(f"{path.name} 超过 {MAX_BYTES // 1024}KB，未修改")
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise ValueError(f"读不到 {path.name}，未修改：{exc}") from exc
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"读不到 {path.name}，未修改：{exc}") from exc


def status() -> dict:
    path, why = rc_path()
    saved, error = _read_state()
    out = {
        "supported": bool(path) and compat.IS_MAC,
        "file": str(path) if path else "",
        "exists": bool(path and path.is_file()),
        "applied": False,
        "port": 0,
        "block": "",
        "foreign": [],
        "candidates": detect() if compat.IS_MAC else [],
        "canApply": False,
        "canUndo": False,
        "backup": "",
        "error": error or why,
        "path": str(STATE),
    }
    if not path:
        return out
    try:
        text = _load(path)
    except ValueError as exc:
        out["error"] = str(exc)
        return out
    lines = text.splitlines()
    span = _span(lines)
    out["applied"] = bool(span)
    if span:
        out["block"] = "".join(lines[span[0]:span[1]]) + "\n"
    out["port"] = int((saved or {}).get("port") or 0)
    out["backup"] = str((saved or {}).get("backup") or "")
    out["foreign"] = foreign_env(text)
    out["canUndo"] = bool(saved) and not error
    out["canApply"] = (not span) and not out["foreign"] and not error
    return out


def plan(port: int) -> dict:
    """预览：要写进哪个文件、写什么、会不会挡到已有的配置。"""
    path, why = rc_path()
    if not path:
        raise ValueError(why)
    num = _port(port)
    text = _load(path)
    lines = text.splitlines()
    if _span(lines):
        raise ValueError("这个文件里已经有本工具的标记块，请先撤销")
    foreign = foreign_env(text)
    if foreign:
        raise ValueError(
            f"{path.name} 第 {'、'.join(str(n) for n in foreign[:4])} 行已经有代理变量；"
            "两块配置会互相覆盖，请先自己处理这几行")
    return {
        "file": str(path),
        "exists": path.is_file(),
        "port": num,
        "block": _block(num),
        "append": True,
        "backup": str(BACKUP_DIR),
    }


def _port(value) -> int:
    try:
        num = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("端口必须是数字，例如 7890") from exc
    if not 0 < num < 65536:
        raise ValueError("端口要在 1–65535 之间")
    return num


def _apply(port, verify: bool = True, prober=None) -> dict:
    """把标记块追加到登录 shell 的 rc 文件末尾。"""
    if not compat.IS_MAC:
        raise ValueError("此功能仅支持 macOS")
    num = _port(port)
    path, why = rc_path()
    if not path:
        raise ValueError(why)
    _guard(path)
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未修改")
    info = plan(num)

    if verify:
        # 写进去之前先确认这个端口真的能出去：写一个死端口只会让终端更糟
        check = (prober or probe_port)(num)
        if not check.get("ok"):
            raise ValueError(check.get("error") or "这个端口不能用，未写入")

    backup = _backup(path)
    text = _load(path)
    if text and not text.endswith("\n"):
        text += "\n"
    # 不额外插空行：多插一个，撤销时就得多判断一次「这个空行是不是我加的」，
    # 而「撤销后与原来一字不差」比好看重要。
    path.write_text(text + _block(num), encoding="utf-8")

    if not _span(_load(path).splitlines()):
        raise RuntimeError(f"写入 {path.name} 没有生效；原文件已备份，未记录")
    _write_state({
        "version": 1,
        "createdAt": time.time(),
        "file": str(path),
        "port": num,
        "backup": backup,
    })
    return {**status(),
            "message": f"已把代理变量写进 {path.name}（端口 {num}）；"
                       "新开的终端会生效，已经开着的终端要重开或手动 source。"}


def _undo() -> dict:
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未撤销")
    if not saved:
        raise ValueError("没有本工具留下的终端代理记录")
    path = Path(saved.get("file") or "")
    if not path.name:
        raise ValueError("记录里的文件路径不合法，未撤销")
    _guard(path)
    text = _load(path)
    stripped = strip_block(text)
    if stripped == text:
        # 块已经被手动删掉了：只清记录，不动文件
        STATE.unlink(missing_ok=True)
        return {**status(), "message": "标记块已经不在了，只清掉了本工具的记录。"}
    _backup(path)
    path.write_text(stripped, encoding="utf-8")
    if _span(_load(path).splitlines()):
        raise RuntimeError(f"从 {path.name} 移除标记块没有生效；原文件已备份，记录保留")
    STATE.unlink(missing_ok=True)
    return {**status(), "message": f"已从 {path.name} 移除本工具写入的代理变量。"}


def apply(port, verify: bool = True, prober=None) -> dict:
    try:
        result = _apply(port, verify=verify, prober=prober)
    except Exception as exc:
        history.log("shellproxy.apply", ok=False, detail=type(exc).__name__)
        raise
    history.log("shellproxy.apply", target="终端代理变量", ok=True)
    return result


def undo() -> dict:
    try:
        result = _undo()
    except Exception as exc:
        history.log("shellproxy.undo", ok=False, detail=type(exc).__name__)
        raise
    history.log("shellproxy.undo", target="终端代理变量", ok=True)
    return result
