"""真正做递归的解析器是谁。

fake-ip 是本地伪造出来的地址，在任何上游查询之前就生成好了：拿到它只能
证明「查询被内核接管」，证明不了后面由谁解析。要问出这个答案，只能让
解析器自己报出地址——`o-o.myaddr.l.google.com` 的 TXT 记录由 Google 的
权威服务器填写，内容是发起这次递归的那台解析器。

只在有出口时调用：没有出口的时候查一次，等于自己制造一次泄漏。
归属查询只把解析器地址发出去，不发本机地址。
"""
from __future__ import annotations

import ipaddress
import time

from . import compat, ipcheck, netprobe

TARGET = "o-o.myaddr.l.google.com"
CACHE_TTL = 120

_cache: dict = {"at": 0.0, "data": None}


def parse(text: str) -> str:
    """`dig +short TXT` 把答案连着引号打出来，一条记录也可能有多个字符串。

    只认第一个像 IP 的片段，`ns` / `ip` 这类标签直接跳过。
    """
    for raw in (text or "").splitlines():
        for token in raw.replace('"', " ").split():
            try:
                return str(ipaddress.ip_address(token))
            except ValueError:
                continue
    return ""


def _lookup(ip: str) -> dict:
    """归属查询。地址必须是合法的 IP——它会被拼进 URL，不能直接透传。"""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {}
    return ipcheck.lookup(ip) or {}


def probe(force: bool = False) -> dict:
    """查一次解析器出口；失败时 checked=False，不替调用方下结论。"""
    now = time.time()
    if not force and _cache["data"] and now - _cache["at"] < CACHE_TTL:
        return _cache["data"]

    out = {"checked": False, "ip": "", "masked": "", "country": "",
           "org": "", "domestic": False, "at": now}
    text = compat.run(["/usr/bin/dig", "+short", "+time=2", "+tries=1",
                       "TXT", TARGET], timeout=4)
    ip = parse(text)
    if ip:
        geo = _lookup(ip)
        country = (geo.get("country") or "").upper()
        out.update({
            "checked": True,
            "ip": ip,
            "masked": netprobe._mask_ip(ip),
            "country": country,
            "org": geo.get("org") or "",
            "domestic": country == "CN",
        })
    _cache.update(at=now, data=out)
    return out
