"""区域格式（AppleLocale）：看清楚、改成跟出口一致、改回来。

只动 `NSGlobalDomain` 的 `AppleLocale` 一个键。它决定日期、数字、度量衡的
格式，也就是网页里 `Intl.DateTimeFormat().resolvedOptions().locale` 拿到的
那个值（`zh-CN` / `en-US` 这种）——和出口 IP 摆在一起时，它是设备画像里
最容易被忽略、又最容易对不上的那一条。

**不改系统语言（AppleLanguages）**：那是用户每天看的界面语言，改它是另一回事，
本工具不碰。**不改时区**：时区有独立的一项在管，两个键一起动只会让「是谁改的」
说不清。改 AppleLocale 不需要管理员权限，退出登录或重启应用后生效。

记录写在 `~/.ccclean/region.json`（0600），只存改之前的值，恢复后即删。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from . import compat

STATE = Path.home() / ".ccclean/region.json"
DOMAIN = "NSGlobalDomain"
KEY = "AppleLocale"

_REGION = re.compile(r"^[A-Za-z]{2}$")
# 语言、可选的书写系统、地区。分隔符两种都认：本机真实值就可能是
# `zh-Hant_US` 这种混写，恢复时必须原样写回去，不能因为形状少见就拒绝。
_LOCALE = re.compile(r"^[a-z]{2,3}([_-][A-Z][a-z]{3})?[_-][A-Z]{2}$")

# 出口国家 → 当地常用的区域格式。没列到的国家退化成 en_<CC>：不猜语言，
# 只把「格式看起来像那个国家」这件事做到，界面上会原样显示要写进去的值。
LOCALES = {
    "US": "en_US", "GB": "en_GB", "CA": "en_CA", "AU": "en_AU", "NZ": "en_NZ",
    "IE": "en_IE", "SG": "en_SG", "IN": "en_IN", "MY": "en_MY", "PH": "en_PH",
    "ZA": "en_ZA", "AE": "en_AE", "JP": "ja_JP", "KR": "ko_KR", "CN": "zh_CN",
    "HK": "zh_HK", "TW": "zh_TW", "MO": "zh_MO", "DE": "de_DE", "AT": "de_AT",
    "CH": "de_CH", "FR": "fr_FR", "NL": "nl_NL", "BE": "nl_BE", "IT": "it_IT",
    "ES": "es_ES", "PT": "pt_PT", "BR": "pt_BR", "MX": "es_MX", "AR": "es_AR",
    "SE": "sv_SE", "NO": "nb_NO", "DK": "da_DK", "FI": "fi_FI", "PL": "pl_PL",
    "RU": "ru_RU", "TR": "tr_TR", "IL": "he_IL", "ID": "id_ID", "TH": "th_TH",
    "VN": "vi_VN",
}


def _run(args, timeout=6):
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                             check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    if out.returncode != 0:
        return ""
    return (out.stdout or "").strip()


def parse_region(value: str) -> str:
    """从 AppleLocale 里取出地区。

    `zh_CN` / `en-GB` / `zh-Hans_CN` 都认；`en` 这种只有语言、没有地区的
    返回空串——语言不是地区，不能拿它去跟出口国家比。
    """
    text = (value or "").strip()
    if not text:
        return ""
    text = text.split("@", 1)[0]
    parts = re.split(r"[_\-]", text)
    for part in parts[1:]:
        if _REGION.fullmatch(part):
            return part.upper()
    return ""


def locale_for(region: str) -> str:
    """这个国家该用哪种区域格式。认不出就退回 en_<CC>。"""
    code = (region or "").strip().upper()
    if not _REGION.fullmatch(code):
        return ""
    return LOCALES.get(code, f"en_{code}")


def current() -> tuple[str, str]:
    """(AppleLocale 原值, 解析出的地区)。读不到时两者都为空。"""
    if not compat.IS_MAC:
        return "", ""
    raw = _run(["defaults", "read", "-g", KEY])
    return raw, parse_region(raw)


def _guard():
    if STATE.is_symlink() or STATE.parent.is_symlink():
        raise ValueError("状态路径是符号链接，未修改")


def _read_state():
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError) as exc:
        return None, f"区域格式记录无法读取：{exc}"
    if not isinstance(data, dict) or data.get("version") != 1:
        return None, "区域格式记录格式不正确"
    if not isinstance(data.get("previous"), str):
        return None, "区域格式记录格式不正确"
    return data, ""


def _write_state(data):
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".region-", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _write_locale(value: str) -> bool:
    if not _LOCALE.fullmatch(value or ""):
        return False
    _run(["defaults", "write", "-g", KEY, value])
    return current()[0] == value


def status() -> dict:
    raw, region = current()
    saved, error = _read_state()
    return {
        "supported": compat.IS_MAC,
        "locale": raw,
        "region": region,
        "path": str(STATE),
        "error": error,
        "locales": dict(LOCALES),
        "savedAt": (saved or {}).get("createdAt") or 0,
        "savedLocale": (saved or {}).get("locale") or "",
        "savedRegion": (saved or {}).get("region") or "",
        "previous": (saved or {}).get("previous") or "",
        "canRestore": bool(saved) and not error,
    }


def apply(region: str, locale: str = "") -> dict:
    """把区域格式改成 region 对应的那种。改之前的值记下来，随时能恢复。"""
    if not compat.IS_MAC:
        raise ValueError("此功能仅支持 macOS")
    code = (region or "").strip().upper()
    if not _REGION.fullmatch(code):
        raise ValueError("地区必须是两位字母代码，例如 US、JP、SG")
    target = (locale or locale_for(code)).strip()
    if not _LOCALE.fullmatch(target):
        raise ValueError("区域格式要写成 语言_地区，例如 en_US")
    if parse_region(target) != code:
        raise ValueError(f"区域格式 {target} 和地区 {code} 对不上")
    _guard()
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未修改")
    if saved:
        raise ValueError("已有未恢复的区域格式记录；请先恢复，再改")
    raw, now = current()
    if not raw:
        raise ValueError("读不到当前的 AppleLocale；本机可能禁用了 defaults 写入")
    if raw == target:
        return {**status(), "message": f"区域格式已经是 {target}，没有修改。"}
    if not _write_locale(target):
        raise RuntimeError(f"写入 {KEY} 没有生效；系统可能拦截了 defaults 写入。未记录改动。")
    _write_state({
        "version": 1,
        "createdAt": time.time(),
        "previous": raw,
        "region": code,
        "locale": target,
    })
    return {**status(),
            "message": f"区域格式已从 {raw} 改成 {target}；重启应用或重新登录后生效。"}


def restore() -> dict:
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未恢复")
    if not saved:
        raise ValueError("没有本工具留下的区域格式记录")
    previous = saved.get("previous") or ""
    if not _LOCALE.fullmatch(previous):
        raise ValueError("记录里的原值不合法，未恢复；请在系统设置里手动改回")
    _guard()
    if not _write_locale(previous):
        raise RuntimeError(f"写回 {previous} 没有生效；系统可能拦截了 defaults 写入。记录保留。")
    STATE.unlink(missing_ok=True)
    return {**status(), "message": f"区域格式已恢复为 {previous}；重启应用或重新登录后生效。"}
