"""代理内核自己的 DNS：系统 DNS 之外的那条解析路径。

TUN 打开后，macOS 的 DNS 设置会被内核劫持：系统把查询发给 208.67.222.222
也好、8.8.8.8 也好，实际解析发生在客户端内核里，用的是它自己的
`dns.nameserver`。只看 `scutil --dns` 会把「系统 DNS 干净」当成结论，
而真正看到域名的可能是配置里那两个国内 DoH。

这里做的事很小：找到正在运行的客户端，读它当前生效的那份配置，把 DNS
名单分成四组——

- **解析域名用**（`nameserver` / `fallback` / `direct-nameserver`）：
  访问的每个域名都会经过这里，命中国内解析器才算泄漏面；
- **国内域名用**（`nameserver-policy` 里 `geosite:cn` 一类的选择器）：
  只把国内域名交给国内解析器，让 `GEOIP,CN` 判得准、直连不走代理；
  代理域名的解析不受影响；
- **启动解析用**（`default-nameserver`）：只用来解析 DoH 服务器自己的域名；
- **节点域名用**（`proxy-server-nameserver`）：只解析代理节点地址。
  用国内解析器是正常且必要的，不参与泄漏判定。

只读文件，不改任何配置。找不到运行中的客户端时不下结论。
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from . import compat

# 国内公共解析器。与关卡里原本的名单保持一致，另加常见的 DoH 域名——
# 只认写死的 IP 会漏掉 `https://doh.pub/dns-query` 这类写法。
CN_DNS_IPS = frozenset({
    "114.114.114.114", "114.114.115.115",
    "223.5.5.5", "223.6.6.6",
    "119.29.29.29", "180.76.76.76",
    "1.2.4.8", "210.2.4.8",
})
CN_DNS_HOSTS = (
    "doh.pub", "dot.pub",            # DNSPod / 腾讯
    "dns.alidns.com", "doh.alidns.com",  # 阿里
    "dns.qq.com",                     # 腾讯
    "doh.360.cn",                     # 360
    "dns.baidu.com",
)

# 客户端目录与管理它的进程名。进程必须真的在跑，否则一份去年留下的
# 配置会一直替用户「背锅」。helper / service 这类常驻进程要排除。
_ROOT_SPECS = (
    ("Library/Application Support/com.follow.clash", "FlClash",
     ("flclash",), ()),
    ("Library/Application Support/Clash Verge", "Clash Verge",
     ("clash-verge", "verge-mihomo"), ()),
    ("Library/Application Support/clash-verge", "Clash Verge",
     ("clash-verge", "verge-mihomo"), ()),
    ("Library/Application Support/mihomo-party", "Mihomo Party",
     ("mihomo-party",), ()),
    ("Library/Application Support/ClashX Pro", "ClashX Pro",
     ("clashx pro",), ()),
    ("Library/Application Support/ClashX", "ClashX",
     ("clashx",), ("clashx pro",)),
    ("Library/Application Support/Stash", "Stash", ("stash",), ()),
    ("Library/Application Support/sing-box", "sing-box", ("sing-box",), ()),
    (".config/mihomo", "mihomo", ("mihomo",), ()),
    (".config/clash", "Clash", ("clash",),
     ("clash-verge", "clashx", "mihomo", "service", "helper")),
)

# 正在生效的合并结果优先；模板和订阅原件通常没有解析后的 dns 段。
_CONFIG_NAMES = (
    "config.yaml", "config.yml",
    "work/config.yaml", "work/config.yml",
    "clash-verge.yaml", "verge.yaml",
    "mihomo.yaml", "mihomo.yml",
    "profile.yaml", "profile.yml",
)

_MAX_BYTES = 2 * 1024 * 1024
_HELPER_HINTS = ("helper", "service", "widgetextension", "launcher")

_DEST_KEYS = ("nameserver", "fallback", "direct-nameserver")
_BOOT_KEYS = ("default-nameserver",)
_NODE_KEYS = ("proxy-server-nameserver",)
_MODE_KEYS = ("enhanced-mode",)
_WANTED_KEYS = _DEST_KEYS + _BOOT_KEYS + _NODE_KEYS + _MODE_KEYS
_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$")

# `#` 后面这些是协议参数，不是代理组名：`#h3` 走 HTTP/3，`#no-resolve` 只查不解析。
_RELAY_PARAMS = ("h3", "h2", "no-resolve", "disable-qtype-65")


def relay_group(raw: str) -> str:
    """这个解析器挂的「查询走代理」后缀，返回组名；没挂就是空串。

    mihomo 的 DoH 地址可以写成 `https://1.1.1.1/dns-query#PROXY`：这条查询
    本身从 PROXY 组出去，解析器看到的是代理侧的地址。不写这个后缀、内核的
    `respect-rules` 又没开（FlClash 生成配置时恒为 false），查询就从本机 IP
    直接发出——解析器记下的是你的真实地址，和 HTTP 走的不是同一条路。

    `system` / `dhcp://` 没法挂后缀，不算「没挂」。
    """
    text = (raw or "").strip().strip("\"'")
    if "#" not in text:
        return ""
    # `#PROXY#h3` 这类混写要把两段都看一遍：参数段跳过，第一段组名才算数。
    for tail in text.split("#")[1:]:
        tail = tail.strip()
        if tail and tail.lower() not in _RELAY_PARAMS:
            return tail
    return ""


def relay_missing(raw: str) -> bool:
    """该挂后缀却没挂。

    只判 DoH（`https://`）：明文 53 与 DoT 能不能挂后缀取决于内核版本，
    没实测过的写法不替用户下结论。跟随系统 DNS 的那几条也无从挂起。
    """
    text = (raw or "").strip().strip("\"'")
    if not text.lower().startswith("https://"):
        return False
    return not relay_group(text)



def _host(raw: str) -> str:
    """把 `https://doh.pub/dns-query` / `tls://223.5.5.5:853` / `8.8.8.8`
    统一成主机名或地址。`system` / `dhcp://en0` 返回 system。"""
    text = (raw or "").strip().strip("\"'")
    if not text:
        return ""
    low = text.lower()
    if low == "system" or low.startswith("dhcp://") or low == "dhcp":
        return "system"
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/#?]+)", text, re.I)
    host = m.group(1) if m else text
    host = host.split("#", 1)[0]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.lower().rstrip(".")


def is_domestic(raw: str, system_dns: list[str] | None = None) -> bool:
    """这个解析器是不是国内的。

    `system` 跟随系统 DNS：系统里是 8.8.8.8 就不算国内，是 223.5.5.5 才算。
    不做 IPv6 归属推断——没有可靠名单时宁可说不知道，也不猜。
    """
    host = _host(raw)
    if not host:
        return False
    if host == "system":
        return any(_is_cn_ip(d) for d in (system_dns or []))
    try:
        ipaddress.ip_address(host)
    except ValueError:
        low = host
        return any(low == h or low.endswith("." + h) for h in CN_DNS_HOSTS)
    return _is_cn_ip(host)


def _is_cn_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return ip.version == 4 and str(ip) in CN_DNS_IPS


def label(raw: str) -> str:
    """面板上显示的名字：去掉协议和路径，`https://doh.pub/dns-query` → doh.pub。"""
    host = _host(raw)
    return host or (raw or "").strip()


# 解析器属于哪一家。nameserver 里挂两家，内核就并行发查询、谁先回用谁，
# 「DNS 出口」于是随查询在两家之间跳。不同厂商的递归出口策略不一样：
# Cloudflare 在入口 PoP 就地解析（入口就是出口侧，所以地理跟着出口走），
# Google 常从自己的骨干网出去，出口在美东时可能报在蒙特利尔。
# 这不是泄漏，是「看起来不稳」——但探针会把它画成两个国家。
_PROVIDERS = (
    ("cloudflare", ("1.1.1.1", "1.0.0.1", "cloudflare", "2606:4700:4700")),
    ("google", ("8.8.8.8", "8.8.4.4", "dns.google", "2001:4860:4860")),
    ("quad9", ("9.9.9.9", "149.112.112.112", "quad9")),
    ("opendns", ("opendns", "208.67.222.222", "208.67.220.220")),
    ("adguard", ("adguard", "94.140.14.14", "94.140.15.15")),
    ("nextdns", ("nextdns",)),
    ("controld", ("controld",)),
    ("mullvad", ("mullvad",)),
    ("alidns", ("alidns", "223.5.5.5", "223.6.6.6")),
    ("dnspod", ("doh.pub", "dot.pub", "119.29.29.29", "1.12.12.12")),
    ("system", ("system",)),
)


def provider(raw: str) -> str:
    """这个解析器属于哪一家。认不出来的记 other，空地址记空串。"""
    host = _host(raw).lower()
    if not host:
        return ""
    for name, keys in _PROVIDERS:
        if any(k in host for k in keys):
            return name
    return "other"


_PROVIDER_NAMES = {
    "cloudflare": "Cloudflare", "google": "Google", "quad9": "Quad9",
    "opendns": "OpenDNS", "adguard": "AdGuard", "nextdns": "NextDNS",
    "controld": "Control D", "mullvad": "Mullvad",
    "alidns": "阿里 DNS", "dnspod": "DNSPod", "system": "系统",
    "other": "未识别",
}


def provider_label(name: str) -> str:
    """面板上显示的服务商名。"""
    return _PROVIDER_NAMES.get(name, name)


def parse_dns(text: str) -> dict:
    """只取 `dns:` 下我们关心的几组名单。

    不引第三方 YAML：配置是客户端生成的，结构固定。块式列表与 flow 列表
    都认；`nameserver-policy` 这类嵌套映射里的列表不能混进 `nameserver`。
    """
    out: dict[str, list[str]] = {}
    in_dns = False
    key = ""
    key_indent = 0
    item_indent = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            if re.match(r"^dns\s*:\s*$", stripped):
                in_dns = True
                key = ""
                continue
            if in_dns:
                break
            continue
        if not in_dns:
            continue
        m = _KEY_RE.match(stripped)
        if m and indent <= 2:
            key = m.group(1)
            key_indent = indent
            item_indent = None
            rest = m.group(2).strip()
            if key in _WANTED_KEYS:
                out.setdefault(key, [])
                if rest.startswith("["):
                    out[key].extend(_flow(rest))
                elif rest:
                    value = _clean(rest)
                    if value and value not in ("null", "~", "''", '""'):
                        out[key].append(value)
                else:
                    item_indent = None
            continue
        if stripped.startswith("- ") and key in _WANTED_KEYS:
            if item_indent is None:
                item_indent = indent
            if indent == item_indent:
                value = _clean(stripped[2:])
                if value:
                    out.setdefault(key, []).append(value)
            continue
        if m and indent > key_indent:
            # 进入嵌套映射（比如 nameserver-policy 的规则名），
            # 后面的列表不属于当前名单。
            if key in _WANTED_KEYS and indent <= (item_indent or key_indent + 2):
                key = ""
    return out


def parse_policy(text: str) -> list[dict]:
    """`nameserver-policy:` 里的「选择器 → 解析器」配对。

    只认块式写法（客户端生成配置的写法）。整段 flow 映射也能兜住，
    但为了不把 `https://` 里的冒号当分隔符，配对时只按 `: ` 切。
    """
    out: list[dict] = []
    in_dns = False
    in_policy = False
    policy_indent = 0
    selector = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_dns = bool(re.match(r"^dns\s*:\s*$", stripped))
            in_policy = False
            selector = ""
            continue
        if not in_dns:
            continue
        if not in_policy:
            m = re.match(r"^nameserver-policy\s*:\s*(.*)$", stripped)
            if m:
                in_policy = True
                policy_indent = indent
                rest = m.group(1).strip()
                if rest.startswith("{"):
                    out.extend(_policy_flow(rest))
            continue
        if indent <= policy_indent:
            in_policy = False
            selector = ""
            continue
        if stripped.startswith("- "):
            value = _clean(stripped[2:])
            if selector and value:
                out.append({"selector": selector, "server": value})
            continue
        if stripped.endswith(":"):
            selector = _clean(stripped[:-1].rstrip(":"))
            continue
        left, sep, right = stripped.partition(": ")
        if sep:
            name = _clean(left.rstrip(":"))
            rest = right.strip()
            values = _flow(rest) if rest.startswith("[") else [_clean(rest)]
            if name:
                selector = name
            for value in values:
                if selector and value:
                    out.append({"selector": selector, "server": value})
    return out


def _policy_flow(text: str) -> list[dict]:
    inner = text.strip()
    if inner.startswith("{"):
        inner = inner[1:]
    if inner.endswith("}"):
        inner = inner[:-1]
    out: list[dict] = []
    for m in re.finditer(r"(\"[^\"]+\"|[^:,{}\[\]\s]+)\s*:\s*(\[[^\]]*\]|[^,{}]+)", inner):
        selector = _clean(m.group(1))
        raw = m.group(2).strip()
        values = _flow(raw) if raw.startswith("[") else [_clean(raw)]
        for value in values:
            if selector and value:
                out.append({"selector": selector, "server": value})
    return out


def _clean(value: str) -> str:
    """去掉行尾注释和引号。`#` 只有前面带空白才算注释——DoH 的
    `...#h3` / `...#PROXY` 是地址的一部分。"""
    text = re.sub(r"\s+#.*$", "", (value or "").strip()).strip()
    return text.strip("\"'")


def _flow(text: str) -> list[str]:
    inner = _clean(text)
    if inner.startswith("["):
        inner = inner[1:]
    if inner.endswith("]"):
        inner = inner[:-1]
    values = []
    for part in inner.split(","):
        value = _clean(part)
        if value:
            values.append(value)
    return values


def _uniq(values) -> list[str]:
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


def inspect_text(text: str, name: str, config: str = "",
                 system_dns: list[str] | None = None) -> dict | None:
    """把一份配置文本变成「解析域名 / 国内域名 / 启动解析 / 节点域名」四组。"""
    dns = parse_dns(text)
    destination = _uniq(v for k in _DEST_KEYS for v in dns.get(k, []))
    bootstrap = _uniq(v for k in _BOOT_KEYS for v in dns.get(k, []))
    node = _uniq(v for k in _NODE_KEYS for v in dns.get(k, []))
    if not destination and not node:
        return None
    sys_dns = system_dns or []
    mode = dns.get("enhanced-mode") or [""]
    # 代理域名与直连域名走的不是同一组名单。泄漏检测站点访问的域名都走
    # 代理，只有 nameserver/fallback 才决定别人的递归看到谁；direct-nameserver
    # 只解析本来就直连的域名，那些流量本身就从本机 IP 发出。
    proxied = _uniq(v for k in ("nameserver", "fallback") for v in dns.get(k, []))
    direct = _uniq(dns.get("direct-nameserver", []))
    policy = parse_policy(text)
    policy_servers = _uniq(entry["server"] for entry in policy)
    providers = _uniq(provider(v) for v in proxied if provider(v))
    # `system` 不算一家：它跟随系统设置，没有自己的递归出口。
    named = [p for p in providers if p != "system"]
    return {
        "name": name,
        "config": config,
        "mode": mode[0] if mode else "",
        "destination": destination,
        "bootstrap": bootstrap,
        "node": node,
        "policy": policy,
        "providers": providers,
        "mixedProviders": len(named) >= 2,
        "domesticDestination": [v for v in destination if is_domestic(v, sys_dns)],
        "domesticProxied": [v for v in proxied if is_domestic(v, sys_dns)],
        "domesticDirect": [v for v in direct if is_domestic(v, sys_dns)],
        "domesticBootstrap": [v for v in bootstrap if is_domestic(v, sys_dns)],
        "domesticNode": [v for v in node if is_domestic(v, sys_dns)],
        "domesticPolicy": [v for v in policy_servers if is_domestic(v, sys_dns)],
        # 国内解析器已经由 domesticProxied 单独报，这里只留「看不出泄漏」的那种：
        # 境外 DoH 没挂代理后缀，查询从本机 IP 发出。
        "unrelayed": [v for v in proxied
                      if not is_domestic(v, sys_dns) and relay_missing(v)],
    }


def _running_commands() -> list[str]:
    if compat.IS_MAC:
        out = compat.run(["ps", "-axo", "comm="], 5)
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    return compat.proxy_processes(
        ("clash", "mihomo", "verge", "flclash", "stash", "sing-box"))


def _active(commands: list[str], keys: tuple, exclude: tuple) -> bool:
    for cmd in commands:
        low = cmd.lower()
        if any(h in low for h in _HELPER_HINTS):
            continue
        if any(x in low for x in exclude):
            continue
        if any(k in low for k in keys):
            return True
    return False


def _pick_config(root: Path) -> Path | None:
    for name in _CONFIG_NAMES:
        path = root / name
        try:
            if path.is_file() and path.stat().st_size <= _MAX_BYTES:
                return path
        except OSError:
            continue
    return None


def _roots(specs) -> list[tuple[Path, str, tuple, tuple]]:
    out = []
    for rel, name, keys, exclude in specs:
        path = Path(rel)
        out.append((path if path.is_absolute() else compat.HOME / rel, name, keys, exclude))
    return out


def collect(system_dns: list[str] | None = None, commands: list[str] | None = None,
            specs=None) -> dict:
    """读一遍正在运行的客户端配置。不给结论，只整理事实。"""
    sys_dns = list(system_dns if system_dns is not None else compat.system_dns())
    cmds = list(commands if commands is not None else _running_commands())
    report = {
        "system": sys_dns,
        "systemDomestic": [d for d in sys_dns if is_domestic(d, sys_dns)],
        "clients": [],
        "domesticDestination": [],
        "domesticProxied": [],
        "domesticDirect": [],
        "domesticBootstrap": [],
        "domesticNode": [],
        "domesticPolicy": [],
        "unrelayed": [],
        "providers": [],
        "mixedProviders": False,
        "note": "",
    }
    if not compat.IS_MAC:
        report["note"] = "代理 DNS 核对只做了 macOS 的配置目录"
        return report
    for root, name, keys, exclude in _roots(_ROOT_SPECS if specs is None else specs):
        if not root.is_dir() or not _active(cmds, keys, exclude):
            continue
        path = _pick_config(root)
        if not path:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        client = inspect_text(text, name, str(path), sys_dns)
        if not client:
            continue
        report["clients"].append(client)
        report["domesticDestination"] = _uniq(
            report["domesticDestination"] + client["domesticDestination"])
        report["domesticProxied"] = _uniq(
            report["domesticProxied"] + client["domesticProxied"])
        report["domesticDirect"] = _uniq(
            report["domesticDirect"] + client["domesticDirect"])
        report["domesticBootstrap"] = _uniq(
            report["domesticBootstrap"] + client["domesticBootstrap"])
        report["domesticNode"] = _uniq(
            report["domesticNode"] + client["domesticNode"])
        report["domesticPolicy"] = _uniq(
            report["domesticPolicy"] + client["domesticPolicy"])
        report["unrelayed"] = _uniq(report["unrelayed"] + client.get("unrelayed", []))
        report["providers"] = _uniq(report["providers"] + client.get("providers", []))
        if client.get("mixedProviders"):
            report["mixedProviders"] = True
    if not report["clients"]:
        report["note"] = "没找到运行中的客户端配置，读不到它的 DNS 名单"
    return report
