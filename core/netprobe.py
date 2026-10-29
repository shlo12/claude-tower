"""出口 IP 探测。只用公开的免密钥接口，按可用性依次降级。"""

from __future__ import annotations

import json
import re
import socket
import urllib.request

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


def _from_ipapi_is() -> dict | None:
    data = _get("https://api.ipapi.is/", timeout=4.0)
    if not data or not data.get("ip"):
        return None
    loc = data.get("location")
    if not isinstance(loc, dict):
        loc = {}
    asn = data.get("asn")
    if isinstance(asn, str):
        asn = {"asn": asn}
    elif not isinstance(asn, dict):
        asn = {}
    company = data.get("company")
    if not isinstance(company, dict):
        company = {}
    return {
        "source": "ipapi.is",
        "ip": data.get("ip"),
        "country": loc.get("country_code") or loc.get("country"),
        "country_name": loc.get("country"),
        "city": loc.get("city"),
        "region": loc.get("state"),
        "timezone": loc.get("timezone"),
        "org": asn.get("org") or company.get("name"),
        "asn": str(asn.get("asn") or ""),
        "asn_type": (asn.get("type") or "").lower() if isinstance(asn.get("type"), str) else "",
        "is_datacenter": bool(data.get("is_datacenter")),
        "is_vpn": bool(data.get("is_vpn")),
        "is_proxy": bool(data.get("is_proxy")),
        "is_tor": bool(data.get("is_tor")),
        "is_abuser": bool(data.get("is_abuser")),
        "hosting_guess": None,
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
        "country": data.get("country_code"),
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
        "country": data.get("country"),
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


def probe() -> dict:
    """返回出口信息；全部失败时 available=False。"""
    for fn in (_from_ipapi_is, _from_ipwho, _from_ipinfo):
        try:
            info = fn()
        except Exception:
            # 外部接口偶尔换字段形状，坏一个就降级到下一个，别让整个接口 500
            info = None
        if info:
            info["available"] = True
            info["ip_masked"] = _mask_ip(info.get("ip") or "")
            info["hosting_likely"] = bool(
                info.get("is_datacenter")
                or info.get("asn_type") in ("hosting", "datacenter")
                or info.get("hosting_guess")
            )
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
