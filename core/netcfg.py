"""可选的出口国家预期。

只保存一个两位国家代码；没设置时扫描不做任何国家判断。这里不切换地区、
不改系统网络，也不尝试让出口「看起来像」某个国家。
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

CONFIG = Path.home() / ".ccclean" / "netcfg.json"
_CODE = re.compile(r"^[A-Za-z]{2}$")


def _read():
    try:
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, ""
    except (OSError, ValueError) as exc:
        return {}, f"出口国家预期无法读取：{exc}"
    if not isinstance(data, dict) or data.get("version") != 1:
        return {}, "出口国家预期格式不正确"
    country = data.get("expectedCountry") or ""
    if country and (not isinstance(country, str) or not _CODE.fullmatch(country)):
        return {}, "出口国家预期格式不正确"
    return data, ""


def expected_country() -> str:
    data, _ = _read()
    return (data.get("expectedCountry") or "").upper()


def status() -> dict:
    data, error = _read()
    return {
        "country": (data.get("expectedCountry") or "").upper(),
        "path": str(CONFIG),
        "error": error,
    }


def _guard_paths():
    if CONFIG.is_symlink() or CONFIG.parent.is_symlink():
        raise ValueError("状态路径是符号链接，未保存")


def set_country(value: str) -> dict:
    country = (value or "").strip()
    if country and not _CODE.fullmatch(country):
        raise ValueError("出口国家必须是两位字母代码，例如 US、JP、SG；留空可清除")
    country = country.upper()
    _guard_paths()
    CONFIG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".netcfg-", dir=str(CONFIG.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "expectedCountry": country}, stream,
                      ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, CONFIG)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return status()
