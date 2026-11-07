"""不用管理员权限的时区/语言对齐。

`align` 改的是**系统**设置：时区要走 `systemsetup` 授权弹窗，区域格式写
`NSGlobalDomain`。那是对的做法——浏览器、Office、系统时钟一起对齐。但它有
两种人用不了：公司电脑不给管理员密码；或者只是不想为了一个账号把整台机器
（日历、会议提醒、系统时钟）都改掉。

这一层换个位置：把 `TZ` / `LANG` / `LC_ALL` 写进登录 shell 的 rc，只影响从
终端启动的进程。Claude Code 就在这一类里——它是个 Node 进程，读的是环境
变量，不是「系统设置」那个界面。

四条规矩，和 `shellproxy` 一致（踩过的坑是同一批）：

1. **只写一个文件。** 登录 shell 真正会读的那个 rc；fish 语法不同，不代写。
2. **只写一个带标记的块。** 撤销按标记删，块外的内容一个字都不动。
3. **块外已经有别人的 TZ/LANG 就不写。** 两块配置谁在后面谁生效，这种事
   不该由本工具替用户决定——报出行号让他自己处理。
4. **写前备份、写后回读。** 回读确认块真的在里面，没写进去就报错且不留记录。

还要说清代价：`TZ` 写进 rc 之后，**这个终端里所有命令**看到的时区都变了，
`date`、`git log` 的时间戳会跟着走。这正是它生效的方式，不是副作用漏了。
"""
from __future__ import annotations

import json
import os
import re
import shlex
import tempfile
import time
from pathlib import Path

from . import compat, history, netcfg, netprobe, regioncfg, shellproxy

STATE = Path.home() / ".ccclean/shellenv.json"
WRAPPER = Path.home() / ".ccclean/bin/claude-env"
BLOCK0 = "# >>> ccclean locale env >>>"
BLOCK1 = "# <<< ccclean locale env <<<"
MAX_BYTES = 512 * 1024

_KEYS = ("TZ", "LANG", "LC_ALL")
# 块外已有的时区/语言赋值。`LANGUAGE` 也算——它是 gettext 的优先级链，
# 留着中文的话，界面语言照样是中文，和「只改 LANG」是一个坑。
_FOREIGN_RE = re.compile(
    r"^\s*(?:export\s+)?(?:TZ|LANG|LC_ALL|LANGUAGE)\s*=", re.I)
_KEY_RE = re.compile(r'^\s*(?:export\s+)?(TZ|LANG|LC_ALL)\s*=\s*"?([^"\n]*)"?\s*$')

# 国家 → 主要城市时区。只列能确定的：猜错时区比不改更糟，
# 认不出来的国家直接拒绝，让用户自己填。
_TZ_BY_COUNTRY = {
    "US": "America/New_York", "CA": "America/Toronto", "MX": "America/Mexico_City",
    "BR": "America/Sao_Paulo", "AR": "America/Argentina/Buenos_Aires",
    "CL": "America/Santiago", "CO": "America/Bogota", "PE": "America/Lima",
    "GB": "Europe/London", "IE": "Europe/Dublin", "FR": "Europe/Paris",
    "DE": "Europe/Berlin", "NL": "Europe/Amsterdam", "BE": "Europe/Brussels",
    "IT": "Europe/Rome", "ES": "Europe/Madrid", "PT": "Europe/Lisbon",
    "CH": "Europe/Zurich", "AT": "Europe/Vienna", "SE": "Europe/Stockholm",
    "NO": "Europe/Oslo", "DK": "Europe/Copenhagen", "FI": "Europe/Helsinki",
    "PL": "Europe/Warsaw", "CZ": "Europe/Prague", "HU": "Europe/Budapest",
    "RO": "Europe/Bucharest", "GR": "Europe/Athens", "TR": "Europe/Istanbul",
    "RU": "Europe/Moscow", "UA": "Europe/Kyiv", "IL": "Asia/Jerusalem",
    "AE": "Asia/Dubai", "SA": "Asia/Riyadh", "QA": "Asia/Qatar",
    "IN": "Asia/Kolkata", "SG": "Asia/Singapore", "MY": "Asia/Kuala_Lumpur",
    "TH": "Asia/Bangkok", "VN": "Asia/Ho_Chi_Minh", "ID": "Asia/Jakarta",
    "PH": "Asia/Manila", "JP": "Asia/Tokyo", "KR": "Asia/Seoul",
    "AU": "Australia/Sydney", "NZ": "Pacific/Auckland",
    "ZA": "Africa/Johannesburg", "EG": "Africa/Cairo", "NG": "Africa/Lagos",
    "KE": "Africa/Nairobi", "CN": "Asia/Shanghai", "HK": "Asia/Hong_Kong",
    "TW": "Asia/Taipei", "MO": "Asia/Macau",
}


# ---------------------------------------------------------------- 目标值


def tz_for(country: str) -> str:
    return _TZ_BY_COUNTRY.get((country or "").upper(), "")


def lang_for(country: str) -> str:
    """`en_US` 这种区域格式 → `en_US.UTF-8`（LANG 要的是这个形状）。"""
    loc = regioncfg.LOCALES.get((country or "").upper(), "")
    if not loc:
        return ""
    return loc if "." in loc else f"{loc}.UTF-8"


def _egress_country() -> str:
    """此刻的出口国家。探不到就返回空——不拿预期国家冒充实际出口。"""
    try:
        info = netprobe.probe() or {}
    except Exception:
        return ""
    if not info.get("available"):
        return ""
    return (info.get("country") or "").upper()


def target(country: str = "", timezone: str = "", locale: str = "") -> dict:
    """算出要写的三个值。

    国家的顺序：调用方指定 → 用户设定的预期国家 → 实际出口。

    预期排在出口前面，看着和 `align` 相反，但理由很硬：出口是**此刻**的状态，
    预期是用户长期要的样子。代理关掉的那几分钟里出口会掉回本地，这时按出口
    写只会把时区改成 Asia/Shanghai——等于把用户想摆脱的那个状态原样写回去，
    他还会以为工具坏了。预期国家是他自己声明的意图，稳定得多。

    出口留作兜底：没设预期的人（第一次用）至少能按「现在从哪出去」推一个值，
    这时和 `align` 的算法一致。两边都没有就留空，由上层报「推不出」，不猜。

    `source` 把来源一并报出去：两种来源推出来的值可能不一样，界面要说清是
    哪一个，用户才有机会发现「预期设错了」。
    """
    given = (country or "").upper()
    if given:
        code, source = given, "explicit"
    else:
        wanted = netcfg.expected_country()
        code, source = (wanted, "expected") if wanted else (
            _egress_country(), "egress")
    tz = timezone or tz_for(code)
    lang = locale or lang_for(code)
    if lang and "." not in lang:
        lang = f"{lang}.UTF-8"
    if tz and (not isinstance(tz, str) or not compat.IANA_TZ.fullmatch(tz)):
        raise ValueError("时区名格式不合法")
    if lang and (not isinstance(lang, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_@.\-]*", lang)):
        raise ValueError("区域格式不合法")
    return {
        "country": code,
        "source": source,
        "timezone": tz,
        "lang": lang,
        "lcAll": lang,
        "resolved": bool(tz and lang),
    }


# ---------------------------------------------------------------- 读写


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


def _span(lines: list[str]) -> tuple[int, int] | None:
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


def block_values(text: str) -> dict:
    """标记块里实际写着的值。没块就返回空字典。"""
    lines = (text or "").splitlines()
    span = _span(lines)
    if not span:
        return {}
    out: dict[str, str] = {}
    for line in lines[span[0]:span[1]]:
        hit = _KEY_RE.match(line)
        if hit:
            out[hit.group(1)] = hit.group(2)
    return out


def strip_block(text: str) -> str:
    lines = (text or "").splitlines(keepends=True)
    span = _span(lines)
    if not span:
        return text or ""
    return "".join(lines[:span[0]] + lines[span[1]:])


def foreign_lines(text: str) -> list[int]:
    """块外已有的时区/语言赋值行号（1 起）。"""
    lines = (text or "").splitlines()
    span = _span(lines)
    skip = set(range(span[0], span[1])) if span else set()
    return [i + 1 for i, line in enumerate(lines)
            if i not in skip and _FOREIGN_RE.match(line)]


def render(values: dict) -> str:
    return "\n".join([
        BLOCK0,
        "# 由 CC Tower 写入：只影响从终端启动的进程，系统设置不动。",
        "# 删掉这两行注释之间的内容即可还原。",
        f'export TZ="{values["timezone"]}"',
        f'export LANG="{values["lang"]}"',
        f'export LC_ALL="{values["lcAll"]}"',
        BLOCK1,
        "",
    ])


# ---------------------------------------------------------------- 状态


def _read_state() -> tuple[dict, str]:
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, ""
    except (OSError, ValueError) as exc:
        return {}, f"环境变量记录无法读取：{exc}"
    if not isinstance(data, dict) or data.get("version") != 1:
        return {}, "环境变量记录格式不正确"
    return data, ""


def _write_state(data: dict) -> None:
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".shellenv-", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _require_mac() -> None:
    """本模块只做 macOS 的登录 shell。

    `shellproxy.rc_path()` 在别的平台上靠「认不出这个 shell」返回空路径，
    看起来也能挡住，但那是巧合：换个平台上的 zsh，它就认得了，然后会去写
    一个本工具并不打算支持的 rc。闸门写在入口，不靠下游兜。
    """
    if not compat.IS_MAC:
        raise ValueError("此功能仅支持 macOS")


def _guard(path: Path | None) -> None:
    targets = [STATE, STATE.parent, WRAPPER, WRAPPER.parent]
    if path is not None:
        targets += [path, path.parent]
    for item in targets:
        if item.is_symlink():
            raise ValueError(f"{item} 是符号链接，未修改")


def status(country: str = "") -> dict:
    path, why = shellproxy.rc_path()
    if not compat.IS_MAC:
        why = "此功能仅支持 macOS"
    saved, error = _read_state()
    tgt = target(country)
    out = {
        "supported": bool(path) and compat.IS_MAC,
        "shell": Path(os.environ.get("SHELL") or "/bin/zsh").name,
        "file": str(path) if path else "",
        "exists": bool(path and path.is_file()),
        "applied": False,
        "block": {},
        "foreign": [],
        "env": {k: os.environ.get(k, "") for k in _KEYS},
        "system": {
            "timezone": compat.timezone_name(),
            # current() 返回 (AppleLocale 原值, 解析出的地区)，这里要的是原值
            "locale": regioncfg.current()[0],
        },
        "target": tgt,
        "wrapper": {"path": str(WRAPPER), "exists": WRAPPER.is_file()},
        "canApply": False,
        "canUndo": False,
        "reason": error or why,
        "message": "",
    }
    if not compat.IS_MAC or not path:
        return out
    try:
        text = _load(path)
    except ValueError as exc:
        out["reason"] = str(exc)
        return out
    out["block"] = block_values(text)
    out["applied"] = bool(out["block"])
    out["foreign"] = foreign_lines(text)
    out["canUndo"] = bool(saved) and not error
    out["canApply"] = (not out["applied"] and not out["foreign"]
                       and tgt["resolved"] and not error)
    if out["applied"]:
        same = all(out["block"].get(k) == tgt[{"TZ": "timezone", "LANG": "lang",
                                               "LC_ALL": "lcAll"}[k]]
                   for k in _KEYS)
        out["message"] = ("已对齐到 " + tgt["timezone"]) if same else "已写入，但目标值变了"
    elif out["foreign"]:
        out["message"] = "启动文件里已有别的时区/语言设置"
    elif not tgt["resolved"]:
        out["message"] = "推不出目标时区，请手动指定"
    return out


# ---------------------------------------------------------------- 写入 / 撤销


def _backup(path: Path) -> str:
    """复用 shellproxy 的脱敏备份：rc 里可能有 API 密钥，副本不能原样留。"""
    return shellproxy._backup(path)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".shellenv-w-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def apply(country: str = "", timezone: str = "", locale: str = "") -> dict:
    """把目标值写进 rc 的标记块。失败时不留下任何记录。"""
    _require_mac()
    path, why = shellproxy.rc_path()
    if not path:
        raise ValueError(why)
    _guard(path)
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未修改")
    if saved:
        raise ValueError("已有未撤销的环境变量记录；请先撤销，再写")

    tgt = target(country, timezone, locale)
    if not tgt["timezone"]:
        raise ValueError("没有可用的目标时区：请指定出口国家，或直接填时区名")
    if not tgt["lang"]:
        raise ValueError("没有可用的目标语言：请指定出口国家，或直接填区域格式")
    if not compat.IANA_TZ.match(tgt["timezone"]):
        raise ValueError("时区名格式不合法")

    text = _load(path)
    if _span(text.splitlines()):
        raise ValueError("启动文件里已经有本工具的标记块，请先撤销")
    foreign = foreign_lines(text)
    if foreign:
        raise ValueError(
            f"{path.name} 第 {'、'.join(str(n) for n in foreign[:4])} 行已经有"
            "时区/语言设置；两块配置会互相覆盖，请先自己处理这几行")

    created = not path.is_file()
    backup = "" if created else _backup(path)
    body = text
    if body and not body.endswith("\n"):
        body += "\n"
    # 不在块前留空行：留了之后撤销就多出一行空行，文件回不到原样。
    # 视觉上的分隔由块里的注释行负责。
    _write_text(path, body + render(tgt))

    back = _load(path)
    got = block_values(back)
    if got.get("TZ") != tgt["timezone"] or got.get("LANG") != tgt["lang"]:
        # 回读对不上：把文件改回原样，再报错。不能留个「看起来写好了」的状态。
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        else:
            _write_text(path, text)
        raise RuntimeError("写入后回读不一致，已改回原样")

    try:
        _write_state({
            "version": 1,
            "createdAt": time.time(),
            "file": str(path),
            "createdFile": created,
            "backup": backup,
            "before": {},
            "after": {"timezone": tgt["timezone"], "lang": tgt["lang"],
                      "lcAll": tgt["lcAll"]},
        })
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        else:
            _write_text(path, text)
        raise

    history.log("shellenv.apply", target=path.name, ok=True,
                detail=f"TZ={tgt['timezone']} LANG={tgt['lang']}")
    return {
        "ok": True,
        "file": str(path),
        "backup": backup,
        "values": tgt,
        "message": (f"已写入 {path.name}。新开的终端生效；"
                    "当前终端执行 `source " + path.name + "` 或重开一个。"),
    }


def undo() -> dict:
    """按标记删块。文件是我们建的就一并删掉。"""
    _require_mac()
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未撤销")
    if not saved:
        raise ValueError("没有可撤销的环境变量记录")
    path = Path(saved.get("file") or "")
    if not path.is_file():
        STATE.unlink(missing_ok=True)
        return {"ok": True, "message": "启动文件已不存在，记录已清除"}
    _guard(path)
    text = _load(path)
    if not _span(text.splitlines()):
        STATE.unlink(missing_ok=True)
        return {"ok": True, "message": "标记块已不在文件里，记录已清除"}

    stripped = strip_block(text)
    if saved.get("createdFile") and not stripped.strip():
        # 整个文件都是我们写的，撤完就空了——删掉，别留一个空壳
        path.unlink()
    else:
        _write_text(path, stripped)
    STATE.unlink(missing_ok=True)
    history.log("shellenv.undo", target=path.name, ok=True, detail="已移除标记块")
    return {
        "ok": True,
        "file": str(path),
        "message": f"已从 {path.name} 移除时区/语言设置。新开的终端恢复原样。",
    }


# ---------------------------------------------------------------- 进程级注入


def write_wrapper(country: str = "", timezone: str = "", locale: str = "") -> dict:
    """生成一个只在这一次运行里带目标环境的启动器。

    给「rc 也不想改」的人用：`~/.ccclean/bin/claude-env claude`。
    进程退出即失效，磁盘上除了这个脚本没有别的痕迹。
    """
    _require_mac()
    tgt = target(country, timezone, locale)
    if not tgt["resolved"]:
        raise ValueError("推不出目标时区/语言，请手动指定")
    _guard(WRAPPER)
    body = "\n".join([
        "#!/bin/sh",
        "# 由 CC Tower 生成：只在这一次运行里带上目标时区与语言。",
        f"# 用法：{WRAPPER} claude",
        f'TZ={shlex.quote(tgt["timezone"])} LANG={shlex.quote(tgt["lang"])} '
        f'LC_ALL={shlex.quote(tgt["lcAll"])} exec "$@"',
        "",
    ])
    _write_text(WRAPPER, body)
    os.chmod(WRAPPER, 0o755)
    history.log("shellenv.wrapper", target="claude-env", ok=True,
                detail=f"TZ={tgt['timezone']} LANG={tgt['lang']}")
    return {"ok": True, "path": str(WRAPPER), "values": tgt,
            "message": f"已生成 {WRAPPER}。用 `{WRAPPER} claude` 启动即可。"}
