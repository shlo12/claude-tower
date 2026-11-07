"""按域名探测 Claude 边缘看到的出口地址。

`netprobe` 只回答「某个第三方 IP 接口看到我是谁」。分流规则是按域名生效的：
claude.ai 可能被送去直连，而 ipinfo 走代理——这时出口检测全绿，Claude 看到
的却是真实地址。这个模块补的就是这一段。

claude.ai / claude.com / api.anthropic.com 都在 Cloudflare 后面，
`/cdn-cgi/trace` 会回 `ip=`（边缘看到的来源地址）、`loc=`（它判定的国家）
和 `colo=`（接入点）。终端里的 Claude Code 连的是 api.anthropic.com，
所以它也要在这条链上。
只取这几个字段，不下载页面、不带 Cookie、不带账号。

三条规矩：

1. **完整地址不交给调用方。** 比对在内存里做完，返回的每一行都先打码；
   日志、页面、导出的战报都只会看到 `1.2.*.4`。
2. **没有基线就只说「看到了什么」。** 比对需要一个参照，拿自己的无知去
   判「一致」或「不一致」都是编结论。
3. **出口不在时不发请求。** 调用方负责这道门：这里的 `probe()` 一旦被调用
   就会真的连 claude.ai，不能拿它做连通性试探。
"""
from __future__ import annotations

import ipaddress
import threading
import time
import urllib.request

from . import netprobe, stun

# 只认这几个写死的目标：它们是 Claude 自己的域名，不接受用户输入。
TARGETS = (
    ("claude.ai", "https://claude.ai/cdn-cgi/trace"),
    ("claude.com", "https://claude.com/cdn-cgi/trace"),
    ("api.anthropic.com", "https://api.anthropic.com/cdn-cgi/trace"),
)
UA = "CCTower domain-egress"
TIMEOUT = 4.0
MAX_BODY = 8192


def _get(url: str, timeout: float = TIMEOUT) -> str | None:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "text/plain"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(MAX_BODY).decode("utf-8", "replace")
    except Exception:
        return None


def parse_trace(text: str) -> dict | None:
    """从 Cloudflare trace 里取 ip / loc / colo。格式不对就返回 None。"""
    if not isinstance(text, str):
        return None
    vals: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("ip", "loc", "colo"):
            vals[key] = value.strip()
    try:
        ip = str(ipaddress.ip_address(vals.get("ip", "")))
    except ValueError:
        return None
    return {"ip": ip, "loc": vals.get("loc", "").upper(),
            "colo": vals.get("colo", "").upper()}


def _family(ip: str) -> str:
    try:
        return "v6" if ipaddress.ip_address(ip).version == 6 else "v4"
    except ValueError:
        return ""


def _matches(ip: str, baseline_ip: str, baseline_mask: str) -> bool | None:
    """True 一致 / False 不一致 / None 地址族不同没法比。"""
    if baseline_ip:
        if _family(ip) != _family(baseline_ip):
            return None
        return ip == baseline_ip
    if baseline_mask:
        return stun.matches_mask(ip, baseline_mask)
    return None


def assess(rows: list[dict], baseline_ip: str = "", baseline_mask: str = "") -> dict:
    """把两条 trace 结果收敛成一个结论。纯函数，不发请求。"""
    ok = [r for r in rows if r.get("ip")]
    display = []
    for r in rows:
        item = {"host": r.get("host") or ""}
        if r.get("ip"):
            item["ipMasked"] = netprobe._mask_ip(r["ip"])
            item["loc"] = r.get("loc") or ""
            item["colo"] = r.get("colo") or ""
        else:
            item["error"] = r.get("error") or "没取到"
        display.append(item)

    out = {
        "checked": bool(ok),
        "state": "unavailable",
        "title": "Claude 边缘出口没取到",
        "detail": f"{len(TARGETS)} 个 Claude 域名的 /cdn-cgi/trace 都没有回可用的地址；"
                  "可能被分流规则拦了，也可能当前网络到 Cloudflare 不通。",
        "rows": display,
        "baselineMasked": netprobe._mask_ip(baseline_ip) if baseline_ip else (baseline_mask or ""),
        "domains": {r["host"]: r.get("ipMasked") for r in display if r.get("ipMasked")},
    }
    if not ok:
        return out

    if not baseline_ip and not baseline_mask:
        out.update(
            state="unbaselined",
            title="Claude 边缘出口已取到，但没有比对基线",
            detail="看到了地址，但这次出口探测没有拿到基线，无法判断它们是不是同一个出口。",
        )
        return out

    verdicts = [_matches(r["ip"], baseline_ip, baseline_mask) for r in ok]
    comparable = [r for r, v in zip(ok, verdicts) if v is not None]
    if not comparable:
        out.update(
            state="family",
            title="Claude 边缘出口的地址族与基线不同",
            detail=f"Claude 看到的是 {_family(ok[0]['ip'])} 地址，基线是"
                   f" {_family(baseline_ip) if baseline_ip else '另一种地址族'}，没法直接比对。",
        )
        return out

    distinct = {r["ip"] for r in comparable}
    mismatched = [r for r, v in zip(ok, verdicts) if v is False]
    names = "、".join(r["host"] for r in ok)
    if len(distinct) > 1:
        out.update(
            state="split",
            title=f"{names} 的出口不同",
            detail="这些域名被分流到了不同的出口。Claude 侧看到的地址取决于请求走哪条规则，"
                   "这种不一致通常说明分流表里只写了其中一个域名。",
        )
    elif mismatched:
        out.update(
            state="mismatch",
            title="Claude 看到的出口与探测出口不一致",
            detail="第三方 IP 接口和 Claude 边缘看到的不是同一个地址，"
                   "说明这两个请求走了不同的路径——按域名分流的规则可能只生效了一半。",
        )
    elif len(ok) < len(rows):
        out.update(
            state="partial",
            title="只取到一个 Claude 域名的出口",
            detail="另一个域名没回可用的地址；已取到的那个虽然和基线一致，"
                   "但不能据此判断两个域名走了同一条路。",
        )
    elif len(comparable) < len(ok):
        out.update(
            state="partial",
            title="部分地址族无法比对",
            detail="至少一个域名给出了与基线不同地址族的地址，这一部分既不按一致算，也不按不一致算。",
        )
    else:
        out.update(
            state="match",
            title="Claude 看到的出口与探测一致",
            detail=f"{names} 的边缘节点看到的地址，都和这次出口探测记录一致。",
        )
    return out


def probe(baseline_ip: str = "", baseline_mask: str = "",
          fetcher=None, timeout: float = TIMEOUT) -> dict:
    """并行取两个域名的 trace，返回已打码的结论。fetcher 只给测试注入。

    用 threading 而不是 concurrent.futures：内置运行时为了瘦身把 concurrent
    整个包删了，import 不到。daemon 线程超时就丢下不管，不阻塞扫描。
    """
    fetch = fetcher or _get
    rows: list[dict] = [dict(host=host) for host, _ in TARGETS]
    lock = threading.Lock()

    def one(index: int, url: str) -> None:
        body = fetch(url)
        if body is None:
            with lock:
                rows[index]["error"] = "请求失败"
            return
        parsed = parse_trace(body)
        with lock:
            if parsed is None:
                rows[index]["error"] = "响应格式不对"
            else:
                rows[index].update(parsed)

    threads = [threading.Thread(target=one, args=(i, url), daemon=True)
               for i, (_, url) in enumerate(TARGETS)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout + 1
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))

    for row in rows:
        if not row.get("ip"):
            row.setdefault("error", "没有结果")
    return assess(rows, baseline_ip=baseline_ip, baseline_mask=baseline_mask)
