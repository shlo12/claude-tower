"""代理内核自己的 DNS：系统 DNS 之外的那条解析路径。

TUN 打开后，macOS 的 DNS 设置会被内核劫持：系统把查询发给 208.67.222.222
也好、8.8.8.8 也好，实际解析发生在客户端内核里，用的是它自己的
`dns.nameserver`。只看 `scutil --dns` 会把「系统 DNS 干净」当成结论，
而真正看到域名的可能是配置里那两个国内 DoH。

这里做的事很小：找到正在运行的客户端，读它当前生效的那份配置，把 DNS
名单分成三组——

- **解析域名用**（`nameserver` / `fallback` / `direct-nameserver`）：
  访问的每个域名都会经过这里，命中国内解析器才算泄漏面；
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
    """把一份配置文本变成「解析域名 / 启动解析 / 节点域名」三组。"""
    dns = parse_dns(text)
    destination = _uniq(v for k in _DEST_KEYS for v in dns.get(k, []))
    bootstrap = _uniq(v for k in _BOOT_KEYS for v in dns.get(k, []))
    node = _uniq(v for k in _NODE_KEYS for v in dns.get(k, []))
    if not destination and not node:
        return None
    sys_dns = system_dns or []
    mode = dns.get("enhanced-mode") or [""]
    return {
        "name": name,
        "config": config,
        "mode": mode[0] if mode else "",
        "destination": destination,
        "bootstrap": bootstrap,
        "node": node,
        "domesticDestination": [v for v in destination if is_domestic(v, sys_dns)],
        "domesticBootstrap": [v for v in bootstrap if is_domestic(v, sys_dns)],
        "domesticNode": [v for v in node if is_domestic(v, sys_dns)],
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
        "domesticBootstrap": [],
        "domesticNode": [],
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
        report["domesticBootstrap"] = _uniq(
            report["domesticBootstrap"] + client["domesticBootstrap"])
        report["domesticNode"] = _uniq(
            report["domesticNode"] + client["domesticNode"])
    if not report["clients"]:
        report["note"] = "没找到运行中的客户端配置，读不到它的 DNS 名单"
    return report
