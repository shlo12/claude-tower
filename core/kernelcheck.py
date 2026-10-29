"""向运行中的 Clash 内核核对：规则到底加载了没有。

proxyfix 写完配置、重启客户端，然后回头读生成出来的配置文本。文本里有，
不等于内核加载了——Script.js 可能没启用、代理组名可能被订阅改掉、节点
可能不支持 UDP。这三种失败都不会报错，只是安静地不生效，用户以为修好了。

这里直接问内核：`/configs` 看模式，`/rules` 看规则是否真的按顺序在里面、
指向哪个策略，`/proxies` 看策略组当前节点的类型和 UDP 支持。

控制接口只允许本机回环（unix socket 或 127.0.0.1），不会连到别的机器上。
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit

TIMEOUT = 2.0
MAX_BODY = 2 * 1024 * 1024
CONFIG_NAMES = ("clash-verge.yaml", "verge.yaml", "config.yaml")
BLOCKING_TYPES = ("direct", "reject", "rejectdrop", "block", "pass")


class Unavailable(Exception):
    """没有可用的控制接口，或者接口不可达。

    这不是「规则有问题」——是「没法核对」。调用方必须把两者分开处理，
    否则用户会看到「修复失败」，而其实什么都没坏。
    """


# ---------------------------------------------------------------- 读配置

def _scalar(path: Path, key: str) -> str:
    """从 yaml 里取一个普通标量。控制接口这几个键都是标量，不做完整解析。"""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"^" + re.escape(key) + r":[ \t]*(.*)$", text, re.M)
    if not m:
        return ""
    raw = m.group(1).strip()
    if not raw or raw in ("null", "~", "''", '""'):
        return ""
    if raw[0] in "'\"":
        end = raw.find(raw[0], 1)
        return raw[1:end] if end > 0 else ""
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def _is_verge(d) -> bool:
    """这个候选目录是不是 Clash Verge 的。

    服务模式的 unix socket 只有 Verge 会建。给 FlClash / ClashX 也补这两条
    路径，等于拿别人的内核回答我们的问题——配置里的 secret 还可能是空的，
    最后会得出一个关于「用户根本没在跑的客户端」的结论。
    """
    return "verge" in str(d).lower()


def _unix_sockets(configured: str, verge: bool = False) -> list[str]:
    """配置里的 unix socket 常常是上一次运行的临时路径，重启后就失效了。

    只有 Verge 的目录才补服务实际使用的用户级路径，谁存在用谁。
    """
    out = []
    if configured and os.path.isabs(configured):
        out.append(configured)
    if verge:
        uid = os.getuid() if hasattr(os, "getuid") else 0
        out.append(f"/var/run/clash-verge-service/users/{uid}/verge-mihomo.sock")
        out.append(f"/tmp/clash-verge-service/users/{uid}/verge-mihomo.sock")
    return [p for p in dict.fromkeys(out) if os.path.exists(p)]


def _tcp_endpoint(raw: str):
    """把 `external-controller` 解析成 (scheme, host, port)，只接受回环地址。"""
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    host = parsed.hostname or ""
    if host in ("0.0.0.0",):
        host = "127.0.0.1"
    elif host in ("::", "[::]"):
        host = "::1"
    if host == "localhost":
        host = "127.0.0.1"
    try:
        if not ipaddress.ip_address(host).is_loopback:
            return None
    except ValueError:
        return None
    if (parsed.scheme not in ("http", "https") or not parsed.port
            or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        return None
    return (parsed.scheme, host, parsed.port)


def find_controller(dirs) -> tuple[tuple, str]:
    """在候选目录里找控制接口，返回 ((scheme, target, port), secret)。"""
    for d in dirs:
        if not d:
            continue
        for name in CONFIG_NAMES:
            path = Path(d) / name
            if not path.is_file():
                continue
            secret = _scalar(path, "secret")
            for sock in _unix_sockets(_scalar(path, "external-controller-unix"),
                                      verge=_is_verge(d)):
                return ("unix", sock, None), secret
            endpoint = _tcp_endpoint(_scalar(path, "external-controller"))
            if endpoint:
                return endpoint, secret
    raise Unavailable("没有找到本机 Clash 控制接口")


# ---------------------------------------------------------------- 问内核

def _get(endpoint, secret: str, path: str, timeout: float = TIMEOUT) -> dict:
    scheme, host, port = endpoint
    conn = None
    try:
        if scheme == "unix":
            conn = http.client.HTTPConnection("localhost", timeout=timeout)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(host)
            conn.sock = sock
        else:
            cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = cls(host, port, timeout=timeout)
        headers = {"Accept": "application/json"}
        if secret:
            headers["Authorization"] = "Bearer " + secret
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(MAX_BODY + 1)
        if resp.status != 200:
            raise Unavailable(f"控制接口返回 {resp.status}")
        if len(body) > MAX_BODY:
            raise Unavailable("控制接口响应过大")
        data = json.loads(body.decode("utf-8", "replace"))
        if not isinstance(data, dict):
            raise Unavailable("控制接口返回格式异常")
        return data
    except Unavailable:
        raise
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise Unavailable(f"控制接口不可用（{type(exc).__name__}）") from exc
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def snapshot(dirs) -> dict:
    """一次取回三份状态。任何一步不通都抛 Unavailable。"""
    endpoint, secret = find_controller(dirs)
    return {
        "endpoint": endpoint,
        "configs": _get(endpoint, secret, "/configs"),
        "rules": _get(endpoint, secret, "/rules"),
        "proxies": _get(endpoint, secret, "/proxies"),
    }


# ---------------------------------------------------------------- 判定

def _norm_type(value) -> str:
    """内核返回 CamelCase（DomainSuffix / DstPort），配置里是 DOMAIN-SUFFIX。"""
    return re.sub(r"[^A-Z0-9]", "", str(value).upper())


def _resolve_node(proxies_state, name: str):
    """顺着策略组往下找到真正承载流量的那个节点。"""
    proxies = proxies_state.get("proxies") if isinstance(proxies_state, dict) else None
    if not isinstance(proxies, dict) or not name:
        return "", "", None
    seen = set()
    current = name
    for _ in range(8):
        if current in seen:
            return current, "", None
        seen.add(current)
        item = proxies.get(current)
        if not isinstance(item, dict):
            return current, "", None
        nxt = item.get("now")
        if isinstance(nxt, str) and nxt and nxt != current:
            current = nxt
            continue
        return current, str(item.get("type", "")), item.get("udp")
    return current, "", None


def _disabled(rule: dict) -> bool:
    if rule.get("disabled") is True:
        return True
    extra = rule.get("extra")
    return isinstance(extra, dict) and extra.get("disabled") is True


def _spec(spec, policy: str):
    """specs 每项可以是 (类型, 载荷) 或 (类型, 载荷, 期望策略)。

    第三条是可选的：端口规则可能被故意写成 REJECT，它和域名规则指向的
    代理组不是同一个策略，用一个 policy 套全部会把「按设计拒掉」误报成错。
    """
    kind = spec[0]
    payload = spec[1]
    want = spec[2] if len(spec) > 2 else policy
    return str(kind), str(payload), str(want or "")


def assess(state: dict, specs, policy: str = "", expect: str = "present") -> dict:
    """核对规则是否真的按预期在内核里。

    specs 是 [(类型, 载荷)]，例如 [("DOMAIN-SUFFIX", "claude.ai")]。
    expect="absent" 用于撤销之后：这时要确认这些规则一条都不剩。
    """
    out = {
        "state": "ok", "mode": "", "total": 0, "matched": 0,
        "missing": [], "reason": "", "node": "", "nodeType": "", "udp": None,
        "expect": expect,
    }
    configs = state.get("configs")
    mode = str(configs.get("mode", "")).lower() if isinstance(configs, dict) else ""
    out["mode"] = mode
    rules = state.get("rules")
    rules = rules.get("rules") if isinstance(rules, dict) else None
    if not isinstance(rules, list):
        out["state"] = "unavailable"
        out["reason"] = "内核 /rules 返回格式异常"
        return out
    if mode and mode != "rule":
        # 全局模式下所有流量都走代理，规则不参与匹配——这不是失败
        out["state"] = "global"
        out["total"] = len(rules)
        out["reason"] = f"内核当前是 {mode} 模式，规则不参与匹配"
        return out

    out["total"] = len(rules)
    first_match = None
    index = {}
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        kind = _norm_type(rule.get("type"))
        if kind == "MATCH" and first_match is None:
            first_match = i
        key = (kind, str(rule.get("payload", "")).strip().lower())
        index.setdefault(key, (i, rule))

    if expect == "absent":
        leftover = []
        for spec in specs:
            kind, payload, _ = _spec(spec, policy)
            if (_norm_type(kind), payload.strip().lower()) in index:
                leftover.append(f"{kind},{payload}")
        out["matched"] = len(specs) - len(leftover)
        if leftover:
            out["state"] = "mismatch"
            out["reason"] = f"撤销后内核里还剩 {len(leftover)} 条"
            out["missing"] = leftover[:8]
        return out

    missing, dead, wrong = [], [], []
    for spec in specs:
        kind, payload, want = _spec(spec, policy)
        key = (_norm_type(kind), payload.strip().lower())
        hit = index.get(key)
        if not hit:
            missing.append(f"{kind},{payload}")
            continue
        pos, rule = hit
        if _disabled(rule):
            missing.append(f"{kind},{payload}（被禁用）")
            continue
        if first_match is not None and pos > first_match:
            dead.append(f"{kind},{payload}")
            continue
        if want and str(rule.get("proxy", "")) != want:
            wrong.append(f"{kind},{payload} → {rule.get('proxy') or '空'}")

    out["matched"] = len(specs) - len(missing) - len(dead) - len(wrong)
    if missing or dead or wrong:
        bits = []
        if missing:
            bits.append(f"{len(missing)} 条没加载")
        if dead:
            bits.append(f"{len(dead)} 条排在 MATCH 之后，等于没写")
        if wrong:
            bits.append(f"{len(wrong)} 条指向了别的策略")
        out["state"] = "mismatch"
        out["reason"] = "；".join(bits)
        out["missing"] = (missing + dead + wrong)[:8]
        return out

    node, node_type, udp = _resolve_node(state.get("proxies"), policy)
    out["node"], out["nodeType"], out["udp"] = node, node_type, udp
    if node_type and _norm_type(node_type) in {_norm_type(t) for t in BLOCKING_TYPES}:
        out["state"] = "mismatch"
        out["reason"] = (f"策略组 {policy} 当前指向 {node}（{node_type}），"
                         "规则加载了但流量不会走代理")
    return out


def verify(dirs, specs, policy: str = "", expect: str = "present") -> dict:
    """核对失败不抛异常，一律用 state 表达，调用方好区分「没法核对」和「没生效」。"""
    try:
        state = snapshot(dirs)
    except Unavailable as exc:
        return {"state": "unavailable", "reason": str(exc), "mode": "",
                "total": 0, "matched": 0, "missing": [], "node": "",
                "nodeType": "", "udp": None, "expect": expect}
    return assess(state, specs, policy, expect)


def default_dirs() -> list[Path]:
    """巡检场景下没有「当前客户端」的上下文，挨个试一遍。"""
    base = Path.home()
    return [
        base / "Library/Application Support/com.follow.clash",
        base / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev",
        base / ".config/clash",
        base / ".config/mihomo",
        base / ".config/clash-verge",
        base / ".config/clash-verge-rev",
    ]


def verify_default(specs, policy: str = "", expect: str = "present") -> dict:
    return verify(default_dirs(), specs, policy, expect)


def describe(result: dict) -> str:
    """一句话结论，给界面和日志用。"""
    state = result.get("state")
    absent = result.get("expect") == "absent"
    if state == "ok":
        if absent:
            return f"内核里已确认清除（核对 {result.get('matched', 0)} 条）"
        bits = [f"内核已加载 {result.get('matched', 0)} 条规则"]
        if result.get("node"):
            bits.append(f"出口节点 {result['node']}")
        udp = result.get("udp")
        if udp is True:
            bits.append("节点支持 UDP")
        elif udp is False:
            bits.append("节点不支持 UDP，WebRTC 仍可能泄漏")
        return "，".join(bits)
    if state == "mismatch":
        return "内核里和预期不一致：" + (result.get("reason") or "原因未知")
    if state == "global":
        return result.get("reason") or "内核处于全局模式"
    return result.get("reason") or "没有可用的控制接口，无法核对内核"
