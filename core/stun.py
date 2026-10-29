"""WebRTC / UDP 泄漏探测：手写 RFC 5389 Binding 请求。

不依赖浏览器内核。headless Chrome 的 ICE 子系统在无人值守场景下根本不工作，
而且为了查一个 UDP 出口去起一个浏览器，代价完全不成比例。

判断的是「UDP 有没有和 HTTP 走同一条路」。这个判据有个绕不开的前提：
得知道 HTTP 出口是什么。所以 probe() 接受一个打码后的出口地址
（`5.34.*.136`，塔自己写进 shield.json 的那种），第三段当通配符。

两个设计决定，都是实测出来的：

1. **国内节点不参与判定。** 分流规则把国内域名放直连，一个国内的 STUN
   服务器回你家里的真实地址，那是正确答案，不是泄漏。拿它判会天天误报。

2. **只报「分裂」，不报「不符」。** 境外节点里必须同时有一个对上基线、
   一个对不上，才算泄漏。全部对不上多半是出口换了节点、基线过期。
   见一个报一个，用户两天就学会无视通知了。
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time

MAGIC = 0x2112A442
MAGIC_BYTES = b"\x21\x12\xA4\x42"

# 一次扫描就会打四个节点；打开页面、切回页面都可能触发重扫。
# 60 秒内复用同一份结果，避免把同一组 UDP 包反复送出去。
CACHE_TTL = 60.0
_cache: tuple[str, float, dict] | None = None
_cache_lock = threading.Lock()

# (host, port, 是否境外)。境外节点才参与判定。
#
# 国内三个只用来证明「UDP 本身没断」：它们走分流里的直连规则，裸连时
# 必须能回应，但回应回来的家庭地址不参d判泄漏。境外三个对基线。
SERVERS = (
    ("stun.miwifi.com", 3478, False),
    ("stun.chat.bilibili.com", 3478, False),
    ("stun.qq.com", 3478, False),
    ("stun1.l.google.com", 19302, True),
    ("stun.freeswitch.org", 3478, True),
    ("stun.nextcloud.com", 443, True),
)


def is_fake(ip: str) -> bool:
    """fake-ip 网段。Clash / sing-box / Surge 默认都落在 198.18.0.0/15。"""
    return ip.startswith("198.18.") or ip.startswith("198.19.")


def _v6_prefix(addr: str) -> tuple[str, ...]:
    """取 IPv6 的前两段。`::` 开头的地址拿不出有意义的前缀。"""
    heads = [p for p in addr.split(":")[:2] if p]
    return tuple(p.lower() for p in heads) if len(heads) == 2 else ()


def matches_mask(ip: str, mask: str) -> bool:
    """比对打码地址：`1.2.*.4` 对上 `1.2.3.4`；IPv6 比前两段。

    地址族不同一律返回 False。调用方必须把这种组合当成「没法比对」，
    而不是「不一致」——拿 IPv4 基线去给 IPv6 候选定罪，结论是编出来的。
    """
    if ":" in ip or ":" in mask:
        if ":" not in ip or ":" not in mask:
            return False
        a, b = _v6_prefix(ip), _v6_prefix(mask)
        return bool(a) and a == b
    a, b = ip.split("."), mask.split(".")
    if len(a) != 4 or len(b) != 4:
        return False
    return all(bi == "*" or ai == bi for ai, bi in zip(a, b))


def parse(data: bytes, txn: bytes) -> str | None:
    """解析一条 STUN 响应。拆出来是为了能拿构造好的包做单元测试——
    位运算这块最容易写错，而真发 UDP 的测试在 CI 上不可靠。"""
    if len(data) < 20 or data[0:2] != b"\x01\x01":
        return None
    # 事务 ID 必须对得上：UDP 不保证来源，可能收到别的会话的包
    if data[8:20] != txn:
        return None

    pos = 20
    while pos + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        val = pos + 4
        if val + alen > len(data):
            break
        # 0x0020 = XOR-MAPPED-ADDRESS（RFC 5389），0x0001 = 老版 MAPPED-ADDRESS
        if atype in (0x0020, 0x0001) and alen >= 8 and data[val + 1] == 0x01:
            octets = bytearray(data[val + 4:val + 8])
            if atype == 0x0020:
                for i in range(4):
                    octets[i] ^= MAGIC_BYTES[i]
            return ".".join(str(b) for b in octets)
        # 属性按 4 字节对齐，末尾补零不计入 alen
        pos = val + alen + ((4 - alen % 4) % 4)
    return None


def query(host: str, port: int, timeout: float) -> str | None:
    txn = os.urandom(12)
    req = struct.pack("!HHI", 0x0001, 0, MAGIC) + txn
    try:
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except OSError:
        return None

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, addr)
        data, _ = s.recvfrom(1024)
    except OSError:
        return None
    finally:
        s.close()
    return parse(data, txn)


def _judge_state(foreign: list[str], mask: str) -> tuple[str, str]:
    """返回 (状态, 理由)。状态是 leak / pass / unknown。

    unknown 和 pass 必须分开：没有境外回应、只有一条回应、没有基线，
    这些都不构成「UDP 和 HTTP 走了同一条路」的证据。把它们算成 pass
    会让面板在最该怀疑的时候显示绿色。
    """
    mask = (mask or "").strip()
    if not foreign:
        return "unknown", "没有境外节点回应"
    if not mask:
        return "unknown", "塔还没记录过出口地址，没法比对"
    if ":" in mask:
        return "unknown", "出口是 IPv6，打码后只剩两段，没法比对"
    if len(foreign) < 2:
        return "unknown", "境外节点只有一个回应，不足以判断是否分裂"

    hit = any(matches_mask(ip, mask) for ip in foreign)
    miss = any(not matches_mask(ip, mask) for ip in foreign)
    if hit and miss:
        return "leak", "境外节点给出了两个不同的出口地址"
    if not hit:
        return "unknown", "境外节点的结果和基线全都不一致，多半是出口换了节点"
    return "pass", "境外节点结果与基线一致"


def judge(foreign: list[str], mask: str) -> tuple[bool, str]:
    """判断境外节点的结果算不算泄漏。返回 (是否泄漏, 理由)。

    单独拆出来是为了能不联网就测：真发 UDP 的测试在 CI 上不可靠，
    而「什么情况算泄漏」恰恰是最需要固定下来的部分。
    """
    state, reason = _judge_state(foreign, mask)
    return state == "leak", reason


def reset_cache() -> None:
    """测试用。真实扫描不需要手动清，60 秒后自然过期。"""
    global _cache
    with _cache_lock:
        _cache = None


def probe(egress_mask: str = "", timeout: float = 3.0, use_cache: bool = True) -> dict:
    """并发打几个 STUN 服务器。

    返回 {ips, foreign, ok, leak, state, mask, reason}。
    `ok` 只表示「至少有一个服务器回了」——不代表没泄漏；
    `state` 才是判定结果，unknown 不能被展示成 pass。
    """
    global _cache
    mask = (egress_mask or "").strip()
    now = time.monotonic()
    if use_cache:
        with _cache_lock:
            if _cache and _cache[0] == mask and _cache[1] > now:
                return dict(_cache[2])

    found: dict[str, bool] = {}   # ip -> 是否来自境外节点
    lock = threading.Lock()

    def worker(host: str, port: int, foreign: bool) -> None:
        ip = query(host, port, timeout)
        if not ip:
            return
        with lock:
            # 同一个地址可能同时被国内和境外节点看到；只要有一次来自境外就记境外
            found[ip] = found.get(ip, False) or foreign

    threads = [threading.Thread(target=worker, args=s, daemon=True) for s in SERVERS]
    for t in threads:
        t.start()
    for t in threads:
        # 单个线程最多等 timeout + 2 秒（DNS 解析也要时间）
        t.join(timeout + 2)

    ips = sorted(found)
    foreign = sorted(ip for ip, f in found.items() if f)
    ok = bool(ips)
    if ok:
        state, reason = _judge_state(foreign, mask)
    else:
        state, reason = "unknown", "没有 STUN 服务器回应，UDP 可能被完全阻断"

    result = {"ips": ips, "foreign": foreign, "ok": ok,
              "leak": state == "leak", "state": state,
              "mask": mask, "reason": reason}
    if use_cache:
        with _cache_lock:
            _cache = (mask, now + CACHE_TTL, dict(result))
    return result

