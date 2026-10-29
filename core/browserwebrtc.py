"""浏览器侧 WebRTC 实测。

`stun.py` 测的是「本机的 UDP 包从哪个地址出去」；浏览器有自己一套 ICE 栈，
它交给网页的候选地址未必和本机 UDP 出口一致——系统代理模式下浏览器发 UDP
根本不经过代理，mDNS 混淆又只在部分内核里默认打开。这一项只能由浏览器
自己回答，所以做成两段式：页面收集候选 → POST 回来 → 这里判定。

四个设计决定：

1. **回传的地址先打码再落盘。** 浏览器报出的公网地址就是用户家的真实出口，
   完整写进报告和导出的战报，等于这次检测自己制造了一次泄漏。和
   shield.json 一个规矩：只存 `1.2.*.4`。

2. **没有基线就只说「测到了什么」，不下结论。** 比对需要一个「应该是什么」
   的参照。塔没记录过出口时，任何比对都是编的。

3. **只有 mDNS 候选算「已隐藏」，不算「没测到」。** Chrome / Safari 把本机
   地址换成了 `xxxx.local`，这是主动混淆，是好事，不能和探测失败混在一起。

4. **判定逻辑和 IO 分开。** `assess()` 是纯函数，`parse_candidate()` 也是。
   真发 ICE 的测试在 CI 上不可靠，而「什么情况算泄漏」恰恰最需要固定下来。

5. **不同地址族的候选不拿来定罪。** 塔记录的出口多半是 IPv4，浏览器却可能
   报出 IPv6 反射地址。拿 IPv4 基线判 IPv6 候选「不一致」，等于编了一个
   泄漏结论；这时只能说「没法比对」。
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import time
from pathlib import Path

from . import netprobe, stun

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
STATE_FILE = STATE_DIR / "webrtc.json"
VERSION = 1

# 浏览器一次 offer 通常给出 5~30 条候选；给足余量但不接受无限长的输入——
# 这个接口收的是页面 POST 上来的数组，不设上限等于让页面决定我们读多少内存。
MAX_CANDIDATES = 200
MAX_LINE = 400
MAX_UA = 160

# 基线超过这个岁数就不拿来定罪。和 shield.py 认出口的窗口保持一致：
# 一天前记录的出口，今天可能已经换了三个节点。
STALE_AFTER = 24 * 3600


def parse_candidate(line: str) -> dict | None:
    """从一条 ICE 候选里取出地址、端口、协议与类型。

    格式见 RFC 5245 §15.1：

        candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type> ...

    按位置取字段而不是按 `typ` 下标取，是因为带前缀和不带前缀两种写法都
    出现过（`RTCIceCandidate.candidate` 带，某些 polyfill 不带）。剥掉前缀
    之后 ip 固定在 4、port 固定在 5、`typ` 固定在 6，比猜位置可靠。
    """
    if not isinstance(line, str):
        return None
    text = line.strip()
    if not text:
        return None
    if text.startswith("candidate:"):
        text = text[len("candidate:"):]
    parts = text.split()
    if len(parts) < 8 or parts[6] != "typ":
        return None
    ip = parts[4]
    if not ip:
        return None
    return {
        "ip": ip,
        "port": parts[5],
        "protocol": parts[2].lower(),
        "typ": parts[7].lower(),
    }


def _uniq(seq):
    seen: set = set()
    out: list = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def summarize(raw) -> dict:
    """把候选行整理成可判定的结构。解析不了的直接丢，不猜。"""
    host: list[str] = []
    srflx: list[str] = []
    relay: list[str] = []
    mdns = 0
    if not isinstance(raw, list):
        return {"host": [], "srflx": [], "relay": [], "mdns": 0, "private": []}
    for line in raw[:MAX_CANDIDATES]:
        cand = parse_candidate(line if isinstance(line, str) else str(line)[:MAX_LINE])
        if not cand:
            continue
        if cand["typ"] == "host":
            # `*.local` 是 mDNS 混淆后的主机名，不是 IP，也不该当地址存
            if cand["ip"].endswith(".local"):
                mdns += 1
            else:
                host.append(cand["ip"])
        elif cand["typ"] == "srflx":
            srflx.append(cand["ip"])
        elif cand["typ"] == "relay":
            relay.append(cand["ip"])
    host = _uniq(host)
    return {
        "host": host,
        "srflx": _uniq(srflx),
        "relay": _uniq(relay),
        "mdns": mdns,
        "private": [ip for ip in host if _is_private(ip)],
    }


def _family(addr: str) -> str:
    return "IPv6" if ":" in addr else "IPv4"


def _verdict(state: str, title: str, detail: str, advice: str = "") -> dict:
    return {"state": state, "title": title, "detail": detail, "advice": advice}


def assess(summary: dict, mask: str = "", age: int | None = None) -> dict:
    """判定浏览器报出来的地址算不算泄漏。

    state 取值：pass / leak / stale / hidden / lan / relay / unknown / empty。
    `stale` 和 `leak` 必须分开：基线过期时不一致是正常的，报成泄漏只会
    教用户忽略这个告警。
    """
    srflx = summary.get("srflx") or []
    if srflx:
        if not mask:
            return _verdict(
                "unknown",
                "浏览器报出了公网地址，但塔还没记录出口",
                "探针拿到了 STUN 反射地址，比对需要一个「出口应该是什么」的参照，"
                "这次扫描没能记录到出口地址，所以不下结论。",
                "等出口探测恢复正常后再实测一次。",
            )
        # 地址族不同的候选没法拿基线作证：先分开，再在同类里比。
        comparable = [ip for ip in srflx if _family(ip) == _family(mask)]
        foreign = [ip for ip in srflx if _family(ip) != _family(mask)]
        if not comparable:
            return _verdict(
                "unknown",
                f"浏览器报出的是 {_family(srflx[0])} 地址，基线是 {_family(mask)}",
                "地址族不同，没法直接比对。塔记录的出口和浏览器报出的反射地址"
                "不在同一族，这一项既不按通过算，也不按泄漏算。",
                "用支持同一地址族的出口重新扫描一次，再实测本项。",
            )
        hit = [ip for ip in comparable if stun.matches_mask(ip, mask)]
        miss = [ip for ip in comparable if not stun.matches_mask(ip, mask)]
        if hit and miss:
            return _verdict(
                "leak",
                "浏览器同时报出了两个公网地址",
                "其中一个和出口一致、另一个不一致。这说明一部分 UDP 进了隧道、"
                "另一部分走了直连——网页里的 WebRTC 会从直连那条把真实地址交给对端。",
                "在代理客户端里开 TUN 全接管，或把 STUN/TURN 的标准端口"
                "（3478 / 5349 / 19302）也指向代理。",
            )
        if hit:
            if foreign:
                return _verdict(
                    "unknown",
                    f"{_family(comparable[0])} 与出口一致，但还有 {_family(foreign[0])} 候选没法比对",
                    f"基线是 {_family(mask)} 地址，浏览器另外报出了 {_family(foreign[0])} "
                    "反射地址。两种族各走各的路，这一半没法拿基线验证，"
                    "所以不按通过算。",
                    "在代理客户端里开 TUN 全接管（含 IPv6），让两种地址族都走同一个出口，"
                    "然后再实测一次。",
                )
            return _verdict(
                "pass",
                "浏览器报出的地址与出口一致",
                "STUN 反射地址和塔记录的出口吻合，WebRTC 这条路上没有额外暴露。",
            )
        if age is not None and age > STALE_AFTER:
            return _verdict(
                "stale",
                "浏览器报出的地址与旧基线不一致",
                "塔记录出口已经过去一天以上，中途换过节点的话本来就会不一样。"
                "先重新扫描一次拿到新基线，再实测一次才能定性。",
                "点一次重新检测，然后重跑本项。",
            )
        return _verdict(
            "leak",
            "浏览器报出的公网地址与出口不一致",
            "STUN 反射地址和刚记录的出口对不上：浏览器的 UDP 没有走代理，"
            "走的是本机直连。这是 WebRTC 泄漏最典型的样子。",
            "在代理客户端里开 TUN 全接管；只开系统代理时浏览器发 UDP 不受影响。",
        )
    if summary.get("mdns"):
        return _verdict(
            "pass",
            "浏览器已隐藏本机地址",
            "候选里只有 mDNS 主机名（`*.local`），没有可读的内网地址，"
            "也没有 STUN 反射地址——说明 UDP 出不去，也就没有泄漏面。",
        )
    if summary.get("private"):
        return _verdict(
            "lan",
            "浏览器报出了内网地址",
            "没有公网地址，但候选里带着本机内网 IP（如 192.168.x.x）。"
            "这只暴露内网拓扑，不暴露公网出口，危害比公网泄漏低一档。",
            "Chrome / Edge 可开启「匿名化本地 IP」；Firefox 关掉 "
            "media.peerconnection.enabled。",
        )
    if summary.get("relay"):
        return _verdict(
            "relay",
            "只拿到 TURN 中继地址",
            "候选里只有 relay，说明 UDP 走的是 TURN 服务器。中继地址是中转方的，"
            "不是你的出口，这一项不构成泄漏。",
        )
    return _verdict(
        "empty",
        "探针没收到任何候选地址",
        "可能浏览器禁用了 WebRTC，也可能页面在收集完成前就被关掉了。"
        "没测到不等于没问题，这一项不按通过算。",
        "重跑一次，并确认浏览器没有装禁用 WebRTC 的扩展。",
    )


def _masked(summary: dict) -> dict:
    """落盘前打码。公网地址打码后仍能比对，但不再是一条可用的泄漏证据。"""
    return {
        "host": [netprobe._mask_ip(ip) for ip in summary.get("host") or []],
        "srflx": [netprobe._mask_ip(ip) for ip in summary.get("srflx") or []],
        "relay": [netprobe._mask_ip(ip) for ip in summary.get("relay") or []],
        "mdns": int(summary.get("mdns") or 0),
        "private": [netprobe._mask_ip(ip) for ip in summary.get("private") or []],
    }


def save(payload: dict, mask: str = "", age: int | None = None) -> dict:
    """收下页面 POST 上来的候选，判定后落盘。返回给页面看的结论。"""
    raw = payload.get("candidates") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        raise ValueError("缺少 candidates 字段")
    if len(raw) > MAX_CANDIDATES:
        raw = raw[:MAX_CANDIDATES]

    summary = summarize(raw)
    verdict = assess(summary, mask, age)
    ua = payload.get("ua") if isinstance(payload, dict) else ""
    record = {
        "version": VERSION,
        "at": int(time.time()),
        "ua": str(ua or "")[:MAX_UA],
        "summary": _masked(summary),
        "assessment": verdict,
    }
    _write(record)
    return verdict


def _write(record: dict) -> bool:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(STATE_DIR, 0o700)
        fd, tmp = tempfile.mkstemp(dir=str(STATE_DIR), prefix=".webrtc-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record, fh, ensure_ascii=False, indent=2, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, STATE_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except (OSError, ValueError):
        return False
    return True


def load() -> dict:
    """读上一次实测结果。读不到、读坏了都返回空字典——不该让扫描起不来。"""
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    at = int(data.get("at") or 0)
    data["age"] = max(0, int(time.time()) - at) if at else None
    return data


def clear() -> None:
    """测试与「清空记录」用。"""
    try:
        STATE_FILE.unlink()
    except OSError:
        pass
