"""安全 DNS：浏览器有没有把解析请求加密，以及加密通道还通不通。

这两件事必须分开测，因为它们是两个独立的事实：

1. **配置** —— Chrome / Edge / Brave 的 `Local State` 里写着
   `dns_over_https.mode`（桌面版读的是 profile 根的 `Local State`，不是
   配置档里的 `Preferences`——后者只是设置界面的缓存，内核不读它），
   Firefox 的 `prefs.js` 里写着 `network.trr.mode`。
   读文件就知道开没开，不需要联网。
2. **通路** —— DoH 端点现在连不连得上。开着但连不上比没开更糟：浏览器会
   悄悄回退到明文解析，而用户以为自己已经加密了。所以「建议开安全 DNS」
   这句话必须先验证端点可达，否则是在给一条走不通的建议。

Safari 没有用户可见的开关，跟随系统解析器，单独标成 `system`。

**为什么不把「系统 DNS 是国内解析器」算进这一项**：那是 3-4 关卡
`net.dns` 已经在管的事，两边都报一次，用户会以为有两个问题。
"""
from __future__ import annotations

import json
import os
import random
import re
import struct
import threading
import time
import urllib.request
from pathlib import Path

from . import compat

HOME = Path.home()

# 一次扫描会问三个端点。打开页面、切回页面都可能触发重扫，
# 五分钟内复用同一份结果，别把同一组请求反复送出去。
CACHE_TTL = 300.0
_cache: tuple[float, dict] | None = None
_cache_lock = threading.Lock()

PROBE_NAME = "example.com"

# (显示名, DoH 地址)。按 IP 写是为了绕开「解析 DoH 域名本身」这一步——
# 那一步恰恰会走明文 DNS，测出来的东西就不是我们想问的了。
# 三个端点的证书都带 IP SAN，按 IP 直连能过 TLS 校验（三台都实测过）。
DOH_ENDPOINTS = (
    ("Cloudflare", "https://1.1.1.1/dns-query"),
    ("Google", "https://8.8.8.8/dns-query"),
    ("AliDNS", "https://223.5.5.5/dns-query"),
)

# 浏览器配置文件。Chrome 系一家一个目录，Firefox 走 prefs.js。
CHROMIUM_DIRS = (
    ("Chrome", "Google/Chrome"),
    ("Edge", "Microsoft Edge"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Chromium", "Chromium"),
    ("Arc", "Arc/User Data"),
)
FIREFOX_DIRS = (
    "Firefox",
    "Mozilla/Firefox",
)

FIREFOX_TRR_ON = (2, 3)

# Chrome 的三种模式：off / automatic / secure。只有 automatic 和 secure 会
# 尝试 DoH，区别是前者失败时回落到明文。Firefox 的 race 也是同一个意思。
KNOWN_MODES = ("secure", "automatic", "race", "off")


def _bases() -> list[Path]:
    """Chromium 系与 Firefox 的配置根目录候选。"""
    if compat.IS_MAC:
        return [HOME / "Library" / "Application Support"]
    roots = []
    for env in ("LOCALAPPDATA", "APPDATA"):
        value = os.environ.get(env)
        if value:
            roots.append(Path(value))
    return roots


def _newest(paths: list[Path]) -> Path | None:
    """同一浏览器有多个配置档时，取最近用过的那个。

    用户真正在用的是最近改过的配置档；拿一个两年前的档位去判断
    「你现在有没有开安全 DNS」，测的是别人的电脑。
    """
    best, best_mtime = None, -1.0
    for path in paths:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime > best_mtime:
            best, best_mtime = path, mtime
    return best


def _chromium_mode(state_file: Path) -> tuple[str, str, str]:
    """读 Chrome 系 `Local State` 里的安全 DNS 配置。

    返回 (mode, template, problem)。problem 为空表示读到了；"denied" 表示
    文件在、但读不出来或不是合法 JSON——这时我们**不知道**开关状态，不能
    回落成「没开」。prefs 键不存在则返回 ("", "", "")，由调用方记成 unset。
    """
    if not state_file.is_file():
        return "", "", ""
    try:
        raw = state_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", "", "denied"
    try:
        data = json.loads(raw)
    except ValueError:
        return "", "", "denied"
    if not isinstance(data, dict):
        return "", "", "denied"
    doh = data.get("dns_over_https")
    if not isinstance(doh, dict):
        return "", "", ""
    mode = str(doh.get("mode") or "").strip().lower()
    template = str(doh.get("templates") or "").strip()
    return mode, template, ""


def _firefox_prefs(prefs_file: Path) -> tuple[int, str]:
    """读 Firefox 的 `network.trr.mode`。0 关闭 / 1 竞速 / 2 优先 / 3 只走 TRR / 5 明确关闭。

    读不出来返回 -2；文件能读但没有这个键返回 -1。两者都不能合并成
    「关闭」——前者是我们看不见，后者是我们看见了。
    """
    try:
        text = prefs_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return -2, ""
    mode = -1
    uri = ""
    for match in re.finditer(r'user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;', text):
        key, value = match.group(1), match.group(2)
        if key == "network.trr.mode":
            try:
                mode = int(str(value).strip())
            except ValueError:
                mode = -1
        elif key == "network.trr.uri":
            uri = str(value).strip().strip('"')
    return mode, uri


def _safari_present() -> bool:
    """Safari 没有用户可见的 DoH 开关，跟随系统解析器。单独拆出来是为了能打桩。"""
    return Path("/Applications/Safari.app").exists()


def browsers() -> list[dict]:
    """列出本机能找到的浏览器及其安全 DNS 状态。找不到的不编。

    「找不到」和「读不到」必须分开报。macOS 上 `~/Library/Application Support`
    里别的应用的目录可能受系统保护（实测 Chrome 目录会返回 EPERM），
    这时候我们**不知道**开关是开是关，不能当成「没开」——那是在替用户猜。
    """
    out: list[dict] = []
    roots = _bases()
    for name, sub in CHROMIUM_DIRS:
        states: list[Path] = []
        for root in roots:
            base = root / sub
            if not base.is_dir():
                continue
            # 桌面版 Chrome / Edge / Brave 把安全 DNS 写在 profile 根的
            # Local State；配置档里的 Preferences 不参与解析决策。
            candidate = base / "Local State"
            if candidate.is_file():
                states.append(candidate)
        if not states:
            continue
        newest = _newest(states) or states[0]
        mode, template, problem = _chromium_mode(newest)
        if problem:
            out.append({"browser": name, "mode": "denied",
                        "template": "", "source": str(newest)})
        else:
            out.append({"browser": name, "mode": mode or "unset",
                        "template": template, "source": str(newest)})

    for sub in FIREFOX_DIRS:
        for root in roots:
            base = root / sub / "Profiles"
            if not base.is_dir():
                continue
            try:
                prefs = list(base.glob("*/prefs.js"))
            except OSError:
                out.append({"browser": "Firefox", "mode": "denied",
                            "template": "", "source": str(base)})
                break
            if not prefs:
                continue
            newest = _newest(prefs)
            mode, uri = _firefox_prefs(newest) if newest else (-1, "")
            if mode in FIREFOX_TRR_ON:
                label = "secure"
            elif mode in (1, 4):
                # 竞速 / shadow 都会尝试 DoH，失败则回落明文
                label = "race"
            elif mode in (0, 5):
                label = "off"
            elif mode == -1:
                label = "unset"
            else:
                label = "denied"
            out.append({"browser": "Firefox", "mode": label,
                        "template": uri, "source": str(newest) if newest else ""})
            break

    if _safari_present():
        out.append({"browser": "Safari", "mode": "system",
                    "template": "", "source": "/Applications/Safari.app"})
    return out


def _wire(name: str, qid: int) -> bytes:
    """手搓一个 DNS 查询报文。为一条 A 记录装一个 DNS 库不值得。"""
    labels = [part for part in name.split(".") if part]
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels) + b"\x00"
    # ID, flags(RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", 1, 1)


def _ask(url: str, name: str = PROBE_NAME, timeout: float = 4.0) -> dict:
    """发一次 DoH 查询。只看「有没有拿到带应答的正常回包」。"""
    qid = random.randrange(0, 0x10000)
    body = _wire(name, qid)
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message"},
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(4096)
    except Exception as exc:  # noqa: BLE001 - 网络层什么都可能抛
        return {"ok": False, "ms": int((time.monotonic() - started) * 1000),
                "note": _short(exc)}
    ms = int((time.monotonic() - started) * 1000)
    if len(data) < 12:
        return {"ok": False, "ms": ms, "note": "回应太短"}
    rid, flags, _qd, an = struct.unpack("!HHHH", data[:8])
    if rid != qid:
        return {"ok": False, "ms": ms, "note": "事务 ID 不匹配"}
    rcode = flags & 0x000F
    if rcode:
        return {"ok": False, "ms": ms, "note": f"rcode={rcode}"}
    return {"ok": True, "ms": ms, "note": f"{an} 条应答"}


def _short(exc: Exception) -> str:
    """把异常压成一句人话。urllib 的异常串动辄几百字符，界面里放不下。"""
    text = str(exc) or exc.__class__.__name__
    if "timed out" in text.lower() or "timeout" in text.lower():
        return "超时"
    if "certificate" in text.lower() or "ssl" in text.lower():
        return "证书校验失败"
    if "refused" in text.lower():
        return "连接被拒绝"
    if "network is unreachable" in text.lower() or "no route" in text.lower():
        return "网络不可达"
    return text.split("\n")[0][:60]


def endpoints(use_cache: bool = True) -> list[dict]:
    """并发问三个 DoH 端点。任一成功即说明「加密通道是通的」。"""
    global _cache
    now = time.monotonic()
    if use_cache:
        with _cache_lock:
            if _cache and _cache[0] > now:
                return [dict(x) for x in _cache[1]["endpoints"]]

    results: dict[str, dict] = {}
    lock = threading.Lock()

    def worker(name: str, url: str) -> None:
        r = _ask(url)
        with lock:
            results[name] = {"name": name, "url": url, **r}

    threads = [threading.Thread(target=worker, args=(n, u), daemon=True)
               for n, u in DOH_ENDPOINTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(7.0)

    out = [results[name] for name, _ in DOH_ENDPOINTS if name in results]
    if use_cache:
        with _cache_lock:
            _cache = (now + CACHE_TTL, {"endpoints": [dict(x) for x in out]})
    return out


def reset_cache() -> None:
    """测试用。真实扫描不需要手动清，五分钟自然过期。"""
    global _cache
    with _cache_lock:
        _cache = None


def _verdict(state: str, title: str, detail: str, advice: str = "") -> dict:
    return {"state": state, "title": title, "detail": detail, "advice": advice}


def assess(browser_rows: list[dict], endpoint_rows: list[dict]) -> dict:
    """判定浏览器安全 DNS 的整体状态。

    state: pass / auto / fallback / off / unknown
    `fallback` 是这一项唯一真正危险的状态：开关开着、端点不通。
    浏览器会静默退回明文，用户看不到任何提示。

    `auto` 和 `pass` 必须分开：Chrome 的 `automatic`、Firefox 的竞速都会
    尝试 DoH，但失败时回落到明文。报成「已开启」等于替用户保证了一件
    浏览器没有保证的事。

    「读不到配置」和「没开」绝不能合并——前者是我们看不见，
    后者是我们看见了。把前者报成后者，用户会去改一个本来就对的设置。
    """
    readable = [b for b in browser_rows if b.get("mode") not in ("denied", "system")]
    denied = [b["browser"] for b in browser_rows if b.get("mode") == "denied"]
    if not readable:
        if denied:
            return _verdict(
                "unknown",
                f"读不到 {'、'.join(denied)} 的安全 DNS 设置",
                "配置目录存在，但文件读不出来（macOS 会保护其它应用的 "
                "Application Support 目录）。这一项不按通过算，也不按关闭算——"
                "我们确实不知道。",
                "给本应用「完全磁盘访问权限」后重新检测，就能读到开关状态。",
            )
        return _verdict(
            "unknown",
            "没找到可读的浏览器配置",
            "本机没有 Chrome / Edge / Firefox 的配置目录，读不到安全 DNS 开关。"
            "Safari 没有这个开关，跟随系统解析器，也读不到。",
        )

    strict = [b for b in readable if b.get("mode") == "secure"]
    auto = [b for b in readable if b.get("mode") in ("automatic", "race")]
    off = [b for b in readable if b.get("mode") == "off"]
    unset = [b for b in readable if b.get("mode") not in KNOWN_MODES]
    on = strict + auto
    reachable = [e for e in endpoint_rows if e.get("ok")]
    tested = bool(endpoint_rows)
    blocked = tested and not reachable
    note = f"另有 {'、'.join(denied)} 读不到配置。" if denied else ""

    def names(rows):
        return "、".join(b["browser"] for b in rows)

    if on and blocked:
        return _verdict(
            "fallback",
            f"{names(on)} 开着安全 DNS，但端点一个都连不上",
            "开关是开的，加密通道却不通。这种情况下浏览器会静默回退到明文解析，"
            "而界面上的开关仍然显示「已开启」——比没开更容易让人误判。",
            "先把出口修通再开安全 DNS；或者把浏览器的安全 DNS 换成能连上的那个端点。",
        )
    if strict:
        title = f"{names(strict)} 已开启安全 DNS"
        if auto:
            title += f"，{names(auto)} 是自动模式"
        if not tested:
            # 离线扫描时根本没问端点。这时只能说「开关是开的」，
            # 不能顺手补一句「通道可用」——那句是没测过的话。
            detail = "开关是开的。本次关闭了联网检测，没有验证端点可达性。"
            if auto:
                detail += f"{names(auto)} 没有强制加密，失败时会回落明文。"
            return _verdict("pass", title, detail + note)
        best = min(reachable, key=lambda e: e.get("ms") or 99999)
        detail = (f"加密通道可用，最快的是 {best['name']}（{best.get('ms')} ms）。"
                  "浏览器发出的解析请求不会再以明文经过本地网络。")
        if auto:
            detail += f"{names(auto)} 是自动模式：只有解析器支持时才走加密，失败会回落明文。"
        return _verdict("pass", title, detail + note)
    if auto:
        if tested and reachable:
            best = min(reachable, key=lambda e: e.get("ms") or 99999)
            return _verdict(
                "auto",
                f"{names(auto)} 的安全 DNS 是自动模式",
                "不是强制加密：只有当前解析器支持时浏览器才会走 DoH，"
                f"失败会回落明文。本次端点可达（最快 {best['name']} "
                f"{best.get('ms')} ms），改成强制模式就能用。" + note,
                "想确保解析请求一定加密，把安全 DNS 改成「始终使用」"
                "（Firefox 把 network.trr.mode 设为 3）。",
            )
        return _verdict(
            "auto",
            f"{names(auto)} 的安全 DNS 是自动模式",
            "不是强制加密：只有当前解析器支持时浏览器才会走 DoH，失败会回落明文。"
            "本次没有验证端点可达性。" + note,
            "想确保解析请求一定加密，把安全 DNS 改成「始终使用」"
            "（Firefox 把 network.trr.mode 设为 3）。",
        )
    if off:
        if blocked:
            return _verdict(
                "off",
                "浏览器没开安全 DNS，且 DoH 端点不可达",
                "现在开也连不上：三个端点全部失败。先解决出口，再谈加密。" + note,
            )
        advice = ("想彻底消掉这条路径，可以在浏览器的「隐私与安全」里开启安全 DNS，"
                  "端点选 Cloudflare 或 Google（本机实测可达）。" if tested else
                  "想彻底消掉这条路径，可以在浏览器的「隐私与安全」里开启安全 DNS，"
                  "端点选 Cloudflare 或 Google（本次没测可达性）。")
        return _verdict(
            "off",
            "浏览器没开安全 DNS",
            "解析请求仍然走系统解析器。开了系统代理时这部分多半也在隧道里，"
            "所以不按问题算；只有在代理只管 TCP 的情况下才会以明文出去。" + note,
            advice,
        )
    return _verdict(
        "unknown",
        f"{names(unset) or '浏览器'}的配置里没有安全 DNS 设置",
        "Local State 里没有 dns_over_https 这一项，说明没有改过这个开关，"
        "浏览器会沿用版本默认值。默认值是开是关随版本变化，"
        "这一项不按通过算，也不按关闭算。" + note,
        "在浏览器设置的「隐私与安全」里看一眼实际开关。",
    )
