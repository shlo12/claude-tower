"""按出口把三样东西对齐：预期国家、系统时区、区域格式。

三样各自都有独立的模块和记录（`netcfg` / `compat.apply_timezone` /
`regioncfg`），这里只做编排：算出「现状 → 目标」，让用户逐项勾选，然后按
顺序执行，并把**改之前的值**记下来（`~/.ccclean/align.json`，0600）。

两条边界：

- **不自动做**。这是用户显式勾选并确认的动作，扫描只提示，不会替你改。
- **时区要管理员授权**。密码只出现在系统原生授权窗口，本应用不接触；
  这一项在界面上单独标出来，取消授权就只跳过这一项，其余照常。

区域格式的记录归 `regioncfg` 自己管，这里不重复记——两份记录必然有一天
对不上，那时候谁说了算就成了新问题。
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import subprocess
import tempfile
import time
from pathlib import Path

from . import compat, netcfg, netprobe, regioncfg

STATE = Path.home() / ".ccclean/align.json"
ROWS = ("country", "timezone", "locale", "language")
_CODE = re.compile(r"^[A-Za-z]{2}$")


def _languages():
    out = subprocess.run(["defaults", "export", "-g", "-"], capture_output=True, timeout=6)
    if out.returncode:
        raise RuntimeError("读不到系统语言列表，未修改")
    value = plistlib.loads(out.stdout).get("AppleLanguages")
    if value is not None and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
        raise RuntimeError("系统语言列表格式不正确")
    return value


def _set_languages(value):
    args = (["defaults", "delete", "-g", "AppleLanguages"] if value is None else
            ["defaults", "write", "-g", "AppleLanguages", "-array", *value])
    out = subprocess.run(args, capture_output=True, timeout=6)
    if out.returncode or _languages() != value:
        raise RuntimeError("系统语言写入未生效；恢复记录已保留")


def _language_for(country):
    return {"TW": "zh-Hant-TW", "HK": "zh-Hant-HK", "MO": "zh-Hant-MO", "CN": "zh-Hans-CN"}.get(
        country, regioncfg.LOCALES.get(country, "").replace("_", "-"))


# ---------------------------------------------------------------- 记录

def _guard():
    if STATE.is_symlink() or STATE.parent.is_symlink():
        raise ValueError("状态路径是符号链接，未修改")


def _read_state():
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError) as exc:
        return None, f"对齐记录无法读取：{exc}"
    if not isinstance(data, dict) or data.get("version") != 1:
        return None, "对齐记录格式不正确"
    for key in ("country", "timezone"):
        if key in data and (not isinstance(data[key], dict)
                            or not all(isinstance(data[key].get(v), str) for v in ("from", "to"))):
            return None, "对齐记录格式不正确"
    if "language" in data:
        entry = data["language"]
        if (not isinstance(entry, dict) or set(entry) != {"from", "to"}
                or any(v is not None and (not isinstance(v, list) or not all(isinstance(x, str) for x in v))
                       for v in entry.values()) or not entry["to"]):
            return None, "对齐记录格式不正确"
    return data, ""


def _write_state(data):
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".align-", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


# ---------------------------------------------------------------- 现状

def _egress():
    """出口信息。探不到就返回空字典——不拿预期国家冒充实际出口。"""
    try:
        info = netprobe.probe() or {}
    except Exception:
        return {}
    return info if info.get("available") else {}


def status(with_network: bool = True) -> dict:
    egress = _egress() if with_network else {}
    country = (egress.get("country") or "").upper()
    tz_target = egress.get("timezone") or ""

    expected = netcfg.expected_country()
    cur_tz = compat.timezone_name() if compat.IS_MAC else ""
    reg = regioncfg.status()
    cur_locale = reg.get("locale") or ""
    locale_target = regioncfg.locale_for(country) if country else ""

    rows = []
    rows.append({
        "key": "country",
        "label": "预期出口国家",
        "current": expected or "未设置",
        "target": country,
        "needed": bool(country) and expected != country,
        "needsAdmin": False,
        "note": "" if country else "出口没探到，这一项没有目标值",
    })
    tz_note = ""
    if not tz_target:
        tz_note = "出口接口没返回时区，这一项没有目标值"
    elif not cur_tz:
        tz_note = "读不到当前时区"
    rows.append({
        "key": "timezone",
        "label": "系统时区",
        "current": cur_tz or "读不到",
        "target": tz_target,
        "needed": bool(tz_target) and bool(cur_tz) and cur_tz != tz_target,
        "needsAdmin": True,
        "note": tz_note or "需要管理员授权",
    })
    loc_note = ""
    if not locale_target:
        loc_note = "出口没探到，这一项没有目标值"
    elif reg.get("canRestore"):
        loc_note = "上次改过的区域格式还没恢复，先恢复再改"
    elif cur_locale == locale_target:
        loc_note = ""
    elif regioncfg.parse_region(cur_locale) == country:
        # 地区已经对上，只是语言不同：zh-Hant_US 在网页里仍然读作 zh-Hant-US
        loc_note = f"地区已对上，但格式仍是 {cur_locale}"
    rows.append({
        "key": "locale",
        "label": "区域格式",
        "current": cur_locale or "读不到",
        "target": locale_target,
        "needed": bool(locale_target) and cur_locale != locale_target
        and not reg.get("canRestore"),
        "needsAdmin": False,
        "note": loc_note,
    })

    saved, error = _read_state()
    try:
        languages = _languages() if compat.IS_MAC else None
        language_error = ""
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        languages, language_error = None, str(exc)
    language_target = _language_for(country)
    rows.append({"key": "language", "label": "系统首选语言", "current": ", ".join(languages or []) or "系统默认",
                 "target": language_target, "needed": bool(language_target) and not language_error
                 and (not languages or languages[0] != language_target), "needsAdmin": False,
                 "requiresOptIn": True, "note": language_error or "可选建议；多语言地区不唯一。会影响界面语言，重新登录或重启应用后生效；不会自动重启。"})
    return {
        "supported": compat.IS_MAC,
        "egress": {
            "country": country,
            "timezone": tz_target,
            "ip": egress.get("ip_masked") or "",
            "source": egress.get("source") or "",
        },
        "rows": rows,
        "canApply": compat.IS_MAC and any(r["needed"] for r in rows) and not error and not saved,
        "canRestore": (bool(saved) or bool(reg.get("canRestore"))) and not error,
        "savedAt": (saved or {}).get("createdAt") or 0,
        "error": error,
        "path": str(STATE),
    }


# ---------------------------------------------------------------- 执行

def _check_country(value: str) -> str:
    code = (value or "").strip().upper()
    if not _CODE.fullmatch(code):
        raise ValueError("国家代码必须是两位字母，例如 US、JP")
    return code


def _check_tz(value: str) -> str:
    tz = (value or "").strip()
    if not compat.IANA_TZ.match(tz):
        raise ValueError("时区名必须是 Area/City 的形式，例如 America/Los_Angeles")
    return tz


def apply(keys, country: str = "", timezone: str = "", locale: str = "", language: str = "") -> dict:
    """按勾选的项执行。目标值由调用方带回来，不在执行时重新探测。

    预览和执行必须是同一组值——中途重新探一次出口，用户看到的是一个目标，
    写下去的是另一个，这种「差不多」比报错更难查。
    """
    if not compat.IS_MAC:
        raise ValueError("此功能仅支持 macOS")
    if not isinstance(keys, list) or any(k not in ROWS for k in keys):
        raise ValueError("对齐项目不合法")
    picked = [k for k in ROWS if k in set(keys or ())]
    if not picked:
        raise ValueError("没有勾选任何一项")
    _guard()
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未修改")
    if saved:
        raise ValueError("已有未恢复的对齐记录；请先恢复，再改")

    # 所有输入先验证，避免前一项已改、后一项参数无效却没有恢复记录。
    if "country" in picked:
        _check_country(country)
    if "timezone" in picked:
        _check_tz(timezone)
    if "locale" in picked:
        if not regioncfg._LOCALE.fullmatch(locale or ""):
            raise ValueError("区域格式无效")
    if "language" in picked and language not in {_language_for(c) for c in regioncfg.LOCALES}:
        raise ValueError("首选语言无效")

    results = []
    record = {"version": 1, "createdAt": time.time()}
    changed = False

    if "country" in picked:
        target = _check_country(country)
        before = netcfg.expected_country()
        if before == target:
            results.append({"key": "country", "ok": True, "skipped": True,
                            "message": f"预期国家已经是 {target}"})
        else:
            record["country"] = {"from": before, "to": target}
            _write_state(record)
            netcfg.set_country(target)
            changed = True
            results.append({"key": "country", "ok": True, "skipped": False,
                            "message": f"预期国家 {before or '未设置'} → {target}"})

    if "timezone" in picked:
        target = _check_tz(timezone)
        before = compat.timezone_name()
        if before == target:
            results.append({"key": "timezone", "ok": True, "skipped": True,
                            "message": f"系统时区已经是 {target}"})
        else:
            record["timezone"] = {"from": before, "to": target}
            _write_state(record)
            ok, note = compat.apply_timezone(target)
            if ok:
                record["timezone"] = {"from": before, "to": target}
                changed = True
                results.append({"key": "timezone", "ok": True, "skipped": False,
                                "message": f"系统时区 {before} → {target}"})
            else:
                record.pop("timezone", None)
                _write_state(record)
                # 取消授权不该拖垮其余项，但要如实说这一项没做成
                results.append({"key": "timezone", "ok": False, "skipped": False,
                                "message": note or "时区未修改"})

    if "locale" in picked:
        target = (locale or "").strip()
        before = regioncfg.status().get("locale") or ""
        try:
            regioncfg.apply(regioncfg.parse_region(target), target)
            changed = True
            results.append({"key": "locale", "ok": True, "skipped": False,
                            "message": f"区域格式 {before} → {target}"})
        except (ValueError, RuntimeError) as exc:
            results.append({"key": "locale", "ok": False, "skipped": False,
                            "message": str(exc)})

    if "language" in picked:
        before = _languages()
        target = [language, *(v for v in (before or []) if v != language)]
        if before != target:
            record["language"] = {"from": before, "to": target}
            _write_state(record)
            _set_languages(target)
            changed = True
        results.append({"key": "language", "ok": True, "skipped": before == target,
                        "message": "首选语言已设置；重新登录或重启应用后生效"})
    if changed:
        _write_state(record)
    elif not any(k in record for k in ROWS):
        STATE.unlink(missing_ok=True)

    done = [r for r in results if r["ok"] and not r["skipped"]]
    failed = [r for r in results if not r["ok"]]
    if failed and not done:
        raise RuntimeError("；".join(f"{r['key']}：{r['message']}" for r in failed))
    message = "；".join(r["message"] for r in results)
    return {**status(with_network=False), "results": results, "message": message}


def restore() -> dict:
    """把本工具改过的每一项按记录写回去。时区失败就停下并保留记录。"""
    saved, error = _read_state()
    if error:
        raise ValueError(error + "，未恢复")
    reg = regioncfg.status()
    if not saved and not reg.get("canRestore"):
        raise ValueError("没有本工具留下的对齐记录")
    _guard()

    done, failed = [], []
    lang = (saved or {}).get("language")
    if lang:
        if _languages() != lang["to"]:
            raise RuntimeError("系统语言已被手动更改，未覆盖；恢复记录保留")
        _set_languages(lang["from"])
        saved.pop("language")
        _write_state(saved)
        done.append("系统语言已恢复，重新登录或重启应用后生效")
    if reg.get("canRestore"):
        try:
            regioncfg.restore()
            done.append("区域格式已恢复")
        except (ValueError, RuntimeError) as exc:
            failed.append(f"区域格式：{exc}")

    tz = (saved or {}).get("timezone") or {}
    if tz.get("from") and not failed:
        ok, note = compat.apply_timezone(tz["from"])
        if ok:
            done.append(f"系统时区已恢复为 {tz['from']}")
        else:
            failed.append(f"系统时区：{note or '未修改'}")

    country = (saved or {}).get("country") or {}
    if "country" in (saved or {}) and not failed:
        netcfg.set_country(country.get("from") or "")
        done.append("预期国家已恢复")

    if failed:
        raise RuntimeError("；".join(failed) + "；记录保留，可重试")
    STATE.unlink(missing_ok=True)
    return {**status(with_network=False), "message": "；".join(done) or "没有需要恢复的项"}
