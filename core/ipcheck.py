"""对接 ip.net.coffee 的 Claude IP 纯净度检测接口。

除了单次查询，这里还负责记录**出口 IP 的历史**：同一个账号在短时间里从不同国家
出去，是风控眼里最典型的「异地瞬移」信号——单次 IP 再干净也盖不住跳变本身。
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

from . import netprobe

BASE = "https://ip.net.coffee"
PAGE = "https://ip.net.coffee/claude/"
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

STATE_DIR = Path.home() / ".ccclean"
EGRESS_FILE = STATE_DIR / "egress.json"
EGRESS_KEEP = 60
# 同一个 IP 最多一小时记一次，够画出漂移曲线又不至于把文件写爆
HEARTBEAT = 3600
DRIFT_WINDOW = 24 * 3600

_cache: dict = {"at": 0.0, "data": None}
CACHE_TTL = 120


def _get(url: str, timeout: float = 10.0) -> dict | None:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Referer": PAGE,
            "Origin": BASE,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def check(force: bool = False) -> dict:
    """查询当前出口 IP 的纯净度；失败时 available=False。"""
    now = time.time()
    if not force and _cache["data"] and now - _cache["at"] < CACHE_TTL:
        return _cache["data"]

    info = netprobe.probe()
    ip = info.get("ip") if info.get("available") else None
    if not ip:
        data = {"available": False, "reason": "无法获取本机出口 IP", "page": PAGE}
        _cache.update(at=now, data=data)
        return data

    raw = _get(f"{BASE}/api/iprisk/{ip}")
    if not raw:
        data = {
            "available": False,
            "reason": "接口无响应（可能需要代理规则放行 ip.net.coffee）",
            "page": PAGE,
            "ip": ip,
        }
        _cache.update(at=now, data=data)
        return data

    trust = raw.get("trust_score")
    data = {
        "available": True,
        "page": PAGE,
        "ip": raw.get("ip") or ip,
        "ipMasked": netprobe._mask_ip(raw.get("ip") or ip),
        "trustScore": trust if isinstance(trust, (int, float)) else None,
        "residential": bool(raw.get("isResidential")),
        "datacenter": bool(raw.get("is_datacenter")),
        "vpn": bool(raw.get("is_vpn")),
        "proxy": bool(raw.get("is_proxy")),
        "tor": bool(raw.get("is_tor")),
        "crawler": bool(raw.get("is_crawler")),
        "abuser": bool(raw.get("is_abuser")),
        "mobile": bool(raw.get("is_mobile")),
        "companyType": raw.get("company_type") or raw.get("asn_kind") or "",
        "companyName": raw.get("company_name") or raw.get("asOrganization") or "",
        "asn": raw.get("asn"),
        "country": raw.get("countryCode", "").upper() if raw.get("countryCode") else "",
        "region": raw.get("region"),
        "city": raw.get("city"),
        "timezone": raw.get("timezone"),
        "abuserScore": raw.get("abuser_score"),
        "checkedAt": time.strftime("%H:%M:%S"),
    }
    _record(data)
    _cache.update(at=now, data=data)
    return data


# ---------------------------------------------------------------- 出口历史


def _load_rows() -> list[dict]:
    try:
        data = json.loads(EGRESS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = data.get("rows") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict) and r.get("ip")]


def _save_rows(rows: list[dict]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        EGRESS_FILE.write_text(
            json.dumps({"rows": rows[-EGRESS_KEEP:]}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
    except OSError:
        pass


def _record(data: dict) -> None:
    """把这次出口写进历史。IP 没变就一小时记一次，变了立刻记。"""
    ip = data.get("ip") or ""
    if not data.get("available") or not ip:
        return
    rows = _load_rows()
    now = time.time()
    last = rows[-1] if rows else None
    if last and last.get("ip") == ip and now - float(last.get("ts") or 0) < HEARTBEAT:
        return
    rows.append({
        "ts": now,
        "ip": ip,
        "country": (data.get("country") or "").upper(),
        "city": data.get("city") or "",
        "asn": str(data.get("asn") or ""),
        "org": data.get("companyName") or "",
    })
    _save_rows(rows)


def history(limit: int = EGRESS_KEEP) -> list[dict]:
    """给界面看的出口记录：IP 打码，按时间正序。"""
    rows = _load_rows()[-limit:]
    out = []
    for r in rows:
        out.append({
            "ts": r.get("ts") or 0,
            "at": time.strftime("%m-%d %H:%M", time.localtime(r.get("ts") or time.time())),
            "ip": netprobe._mask_ip(r.get("ip") or ""),
            "country": r.get("country") or "",
            "city": r.get("city") or "",
            "asn": r.get("asn") or "",
            "org": r.get("org") or "",
        })
    return out


def drift(window: int = DRIFT_WINDOW) -> dict:
    """判断窗口期内出口有没有跳变。

    「跳变」按国家算主信号，ASN 算次信号：同一国家里换机房也算换出口，
    但比跨国要轻一档。
    """
    rows = _load_rows()
    now = time.time()
    recent = [r for r in rows if now - float(r.get("ts") or 0) <= window]
    base = {
        "enough": len(recent) >= 2,
        "count": len(recent),
        "total": len(rows),
        "windowHours": round(window / 3600),
        "recent": history(len(recent))[-5:] if recent else [],
    }
    if len(recent) < 2:
        return {**base, "countries": [], "switches": 0, "asns": [], "spanHours": 0}

    seq = [(r.get("country") or "").upper() for r in recent if r.get("country")]
    asn_seq = [str(r.get("asn") or "") for r in recent if r.get("asn")]
    countries = sorted(set(seq))
    asns = sorted(set(asn_seq))
    switches = sum(1 for a, b in zip(seq, seq[1:]) if a != b)
    span = (float(recent[-1].get("ts") or 0) - float(recent[0].get("ts") or 0)) / 3600
    return {
        **base,
        "countries": countries,
        "switches": switches,
        "asns": asns,
        "spanHours": round(span, 1),
    }
