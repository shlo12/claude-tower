"""出口 IP 探测。只用公开的免密钥接口。

三家情报源**并行**问一遍，再比对它们给出的答案。

一开始这里是「依次降级」：谁先成功就用谁。那等于把多源当冗余用——第一个
源说你在美国，第二个源说你在加拿大，我们只记下美国那半句，然后把不确定
性藏起来了。而 Anthropic 自己的情报库完全可能给出第三种答案。

比对的是三样：IP、国家、ASN。IP 对不上说明探测期间出口自己变了；国家或
ASN 对不上说明这个地址的归属本身就是模糊的。两种都不是「噪声」，是信号。
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.request
import threading

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

# 机房/云厂商特征词，用于在接口不返回 ASN 类型时做保守推断
HOSTING_HINTS = [
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "vultr",
    "linode", "akamai", "hetzner", "ovh", "contabo", "oracle", "cloudflare",
    "alibaba", "aliyun", "tencent", "huawei", "choopa", "leaseweb", "m247",
    "datacamp", "hosting", "server", "colo", "cdn", "cloud", "fiberstate",
    "cogent", "gcore", "psychz", "quadranet", "sharktech", "colocrossing",
]


def _get(url: str, timeout: float = 5.0) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _guess_hosting(org: str) -> bool | None:
    if not org:
        return None
    low = org.lower()
    return any(h in low for h in HOSTING_HINTS)


# 情报源给的国名是全称（`United States`），其余接口给的是 ISO 码。
# 不归一的话，多源比对会把「同一件事的两种写法」报成不一致——
# 而这种假阳性比漏报更糟：用户会去改一个根本不存在的问题。
_COUNTRY_CODES = {
    "united states": "US", "united states of america": "US", "usa": "US",
    "united kingdom": "GB", "great britain": "GB", "england": "GB",
    "canada": "CA", "australia": "AU", "new zealand": "NZ", "ireland": "IE",
    "singapore": "SG", "india": "IN", "malaysia": "MY", "philippines": "PH",
    "south africa": "ZA", "united arab emirates": "AE", "japan": "JP",
    "south korea": "KR", "korea": "KR", "republic of korea": "KR",
    "china": "CN", "hong kong": "HK", "taiwan": "TW", "macao": "MO",
    "macau": "MO", "germany": "DE", "austria": "AT", "switzerland": "CH",
    "france": "FR", "netherlands": "NL", "belgium": "BE", "italy": "IT",
    "spain": "ES", "portugal": "PT", "brazil": "BR", "mexico": "MX",
    "argentina": "AR", "sweden": "SE", "norway": "NO", "denmark": "DK",
    "finland": "FI", "poland": "PL", "russia": "RU", "turkey": "TR",
    "israel": "IL", "indonesia": "ID", "thailand": "TH", "vietnam": "VN",
    "ukraine": "UA", "czechia": "CZ", "czech republic": "CZ",
    "romania": "RO", "hungary": "HU", "greece": "GR", "chile": "CL",
    "colombia": "CO", "peru": "PE", "egypt": "EG", "nigeria": "NG",
    "kenya": "KE", "saudi arabia": "SA", "qatar": "QA", "kuwait": "KW",
    "pakistan": "PK", "bangladesh": "BD", "sri lanka": "LK", "nepal": "NP",
    "kazakhstan": "KZ", "belarus": "BY", "bulgaria": "BG", "croatia": "HR",
    "serbia": "RS", "slovakia": "SK", "slovenia": "SI", "lithuania": "LT",
    "latvia": "LV", "estonia": "EE", "iceland": "IS", "luxembourg": "LU",
}


def _country_code(raw: str) -> str:
    """国名或 ISO 码统一成两位大写码。认不出来就原样返回（不猜）。"""
    text = (raw or "").strip()
    if not text:
        return ""
    if len(text) == 2 and text.isalpha():
        return text.upper()
    return _COUNTRY_CODES.get(text.lower(), text)


def _from_ipapi_is() -> dict | None:
    """ipapi.is 免费层。

    注意返回形状有两种，必须都认：

    - **嵌套**（带 `?q=` 的完整版）：`location: {country_code, city, state, timezone}`，
      `asn: {asn, org, type}`，`company: {name}`。
    - **扁平**（免费层 `api.ipapi.is/` 的现状）：`country` 直接是**全名**
      （`"United States"`），`asn` 是字符串 `"AS15169 Google LLC"`，
      `company` 是字符串，没有 `is_datacenter` / `asn_type`。

    以前只读嵌套形状，扁平形状下 `country` / `city` / `timezone` 全变成 None，
    而它又是首选源——于是出口检查一直显示「未知」，时区比对也因为 `ip_tz`
    为空而整条跳过。多源比对把这件事顶出来了。
    """
    data = _get("https://api.ipapi.is/", timeout=4.0)
    if not data or not data.get("ip"):
        return None
    loc = data.get("location")
    if not isinstance(loc, dict) or not loc:
        # 扁平形状：字段在顶层
        loc = data
    raw_asn = data.get("asn")
    if isinstance(raw_asn, str):
        asn = {"asn": raw_asn, "org": raw_asn}
    elif isinstance(raw_asn, dict):
        asn = raw_asn
    else:
        asn = {}
    company = data.get("company")
    if isinstance(company, dict):
        company_name = company.get("name") or ""
    elif isinstance(company, str):
        company_name = company
    else:
        company_name = ""
    country_raw = loc.get("country_code") or loc.get("country") or ""
    org = company_name or str(asn.get("org") or "")
    # 扁平形状里 `asn` 是 "AS15169 Google LLC" 整串，运营方名字被拼在 ASN 后面。
    # 直接拿来当 org 会让「运营方」字段变成一句带编号的废话。
    org = re.sub(r"^AS\s*\d+\s*", "", org).strip()
    return {
        "source": "ipapi.is",
        "ip": data.get("ip"),
        "country": _country_code(country_raw),
        "country_name": loc.get("country") or "",
        "city": loc.get("city"),
        "region": loc.get("state") or loc.get("region"),
        "timezone": loc.get("timezone") or data.get("timezone"),
        "org": org,
        "asn": _asn_key(str(asn.get("asn") or "")),
        "asn_type": (asn.get("type") or "").lower() if isinstance(asn.get("type"), str) else "",
        "is_datacenter": bool(data.get("is_datacenter")),
        "is_vpn": bool(data.get("is_vpn")),
        "is_proxy": bool(data.get("is_proxy")),
        "is_tor": bool(data.get("is_tor")),
        "is_abuser": bool(data.get("is_abuser")),
        "hosting_guess": _guess_hosting(org),
    }


def _from_ipwho() -> dict | None:
    data = _get("https://ipwho.is/")
    if not data or not data.get("success", True) or not data.get("ip"):
        return None
    conn = data.get("connection")
    if not isinstance(conn, dict):
        conn = {}
    tz = data.get("timezone")
    if not isinstance(tz, dict):
        tz = {}
    org = conn.get("org") or conn.get("isp") or ""
    return {
        "source": "ipwho.is",
        "ip": data.get("ip"),
        "country": _country_code(data.get("country_code") or data.get("country") or ""),
        "country_name": data.get("country"),
        "city": data.get("city"),
        "region": data.get("region"),
        "timezone": tz.get("id"),
        "org": org,
        "asn": f"AS{conn.get('asn')}" if conn.get("asn") else "",
        "asn_type": "",
        "is_datacenter": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
        "is_abuser": False,
        "hosting_guess": _guess_hosting(org),
    }


def _from_ipinfo() -> dict | None:
    data = _get("https://ipinfo.io/json")
    if not data or not data.get("ip"):
        return None
    org = data.get("org") or ""
    if not isinstance(org, str):
        org = str(org)
    return {
        "source": "ipinfo.io",
        "ip": data.get("ip"),
        "country": _country_code(data.get("country") or ""),
        "country_name": data.get("country"),
        "city": data.get("city"),
        "region": data.get("region"),
        "timezone": data.get("timezone"),
        "org": org,
        "asn": org.split(" ")[0] if org.startswith("AS") else "",
        "asn_type": "",
        "is_datacenter": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
        "is_abuser": False,
        "hosting_guess": _guess_hosting(org),
    }


_SOURCES = (_from_ipapi_is, _from_ipwho, _from_ipinfo)
# 主源顺序：ipapi.is 字段最全（is_vpn / asn_type / is_datacenter），
# 其余两家只用来交叉验证，不用来取结论。
_PREFER = ("ipapi.is", "ipwho.is", "ipinfo.io")
# 一次扫描里 probe() 会被出口检查、IP 纯净度、对齐预览各调一次。
# 不缓存就是九次外部请求，而且三次结果可能来自不同的出口瞬间。
CACHE_TTL = 90
_cache: dict = {"at": 0.0, "rows": None}


def _fetch_all(timeout: float = 6.0) -> list[dict]:
    """并行问一遍全部情报源，只留拿到 IP 的。

    并发而不是串行：三家的单次超时都是 4–5 秒，串行最坏要等十几秒，
    而这一步在扫描路径上，用户是盯着界面等的。
    """
    rows: list[dict] = []
    lock = threading.Lock()
    def worker(fn):
        try:
            info = fn()
        except Exception:
            return
        if info and info.get("ip"):
            with lock:
                rows.append(info)
    threads = [threading.Thread(target=worker, args=(fn,), daemon=True) for fn in _SOURCES]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))
    with lock:
        rows = list(rows)

    return rows


def probe_all(force: bool = False) -> list[dict]:
    """全部情报源的结果。同一进程内 90 秒内复用，避免重复外发。"""
    now = time.time()
    cached = _cache.get("rows")
    if not force and cached is not None and now - _cache.get("at", 0.0) < CACHE_TTL:
        return list(cached)
    try:
        rows = _fetch_all()
    except Exception:
        rows = []
    _cache["at"] = now
    _cache["rows"] = rows
    return list(rows)


def _asn_key(value: str) -> str:
    """把 ASN 归一成 `AS4134`。

    三家写法不一样：ipapi.is 给 `AS4134`，ipwho.is 给 `AS4134`，
    但有的源会把运营方名字拼进去（`AS4134 CHINANET BACKBONE`）。
    不归一就会把同一家网络报成两家，多出一条假的不一致。
    """
    hit = re.search(r"AS\s*(\d+)", (value or "").upper())
    return f"AS{hit.group(1)}" if hit else ""


def consensus(rows: list[dict]) -> dict:
    """比对多家给出的答案。纯函数，不联网，测试直接喂数据。

    `consistent` 只看国家与 ASN——IP 对不上是另一回事（探测期间出口变了），
    单独放在 `drifted` 里，免得「换了节点」被说成「情报源打架」。
    """
    rows = [r for r in (rows or []) if r and r.get("ip")]
    out = {
        "count": len(rows),
        "sources": [r.get("source") or "?" for r in rows],
        "countries": [],
        "asns": [],
        "disagree": [],
        "drifted": False,
        "consistent": True,
    }
    if len(rows) < 2:
        # 只有一家时没有可比的东西。说「一致」是编结论，说「不一致」也是。
        if rows:
            out["countries"] = sorted(
                {(x.get("country") or "").upper() for x in rows} - {""})
            out["asns"] = sorted(
                {_asn_key(x.get("asn")) for x in rows} - {""})
        return out

    ips = {(r.get("ip") or "") for r in rows}
    out["drifted"] = len(ips) > 1
    if out["drifted"]:
        out["disagree"].append({"field": "ip", "values": sorted(ips)})

    countries = sorted({(r.get("country") or "").upper() for r in rows} - {""})
    asns = sorted({_asn_key(r.get("asn")) for r in rows} - {""})
    out["countries"] = countries
    out["asns"] = asns
    if len(countries) > 1:
        out["disagree"].append({"field": "country", "values": countries})
    if len(asns) > 1:
        out["disagree"].append({"field": "asn", "values": asns})
    out["consistent"] = not any(
        d["field"] in ("country", "asn") for d in out["disagree"])
    return out


def _primary(rows: list[dict]) -> dict | None:
    for name in _PREFER:
        for row in rows:
            if row.get("source") == name:
                return row
    return rows[0] if rows else None


def probe() -> dict:
    """返回出口信息；全部失败时 available=False。"""
    rows = probe_all()
    info = _primary(rows)
    if info:
        info = dict(info)
        agreed = consensus(rows)
        info["available"] = True
        info["ip_masked"] = _mask_ip(info.get("ip") or "")
        info["hosting_likely"] = bool(
            info.get("is_datacenter")
            or info.get("asn_type") in ("hosting", "datacenter")
            or info.get("hosting_guess")
        )
        info["sourceCount"] = agreed["count"]
        info["multiSourceConsistent"] = agreed["consistent"]
        info["sources"] = agreed["sources"]
        info["countries"] = agreed["countries"]
        info["disagree"] = agreed["disagree"]
        info["drifted"] = agreed["drifted"]
        return info
    return {
        "available": False,
        "source": None,
        "ip": None,
        "ip_masked": None,
        "country": None,
        "city": None,
        "timezone": None,
        "org": None,
        "asn_type": "",
        "is_datacenter": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
        "is_abuser": False,
        "hosting_guess": None,
        "hosting_likely": False,
        "sourceCount": 0,
        "multiSourceConsistent": True,
        "sources": [],
        "countries": [],
        "disagree": [],
        "drifted": False,
    }


def _mask_ip(ip: str) -> str:
    if not ip:
        return ""
    if ":" in ip:  # IPv6 只留前两段
        return ":".join(ip.split(":")[:2]) + ":****"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.{parts[3]}"
    return ip


def resolve(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, 443)})
    except Exception:
        return []
