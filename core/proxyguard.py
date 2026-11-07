"""代理客户端的失败回落与 v6 开关。

关卡要回答两件配置事实：

- **失败时退到哪。** fallback / url-test / load-balance 组里只要列了
  DIRECT，节点全挂或测速选中它时，请求就从本机真实地址发出——分流规则
  看起来全绿，出口却是国内。select 组里的 DIRECT 只是「可以手动选」，
  不参与自动回落；它的第一个成员仅代表配置默认顺序，不能据此推断当前实际选择。
- **客户端自己有没有开 IPv6。** 系统层关了、客户端还开着，解析与走 v6
  的请求仍可能绕过只接管 v4 的链路。

只读**正在运行**的客户端配置：没在跑的客户端留下旧配置不能替用户背锅。
只做 Clash / mihomo 系（FlClash、Clash Verge、Mihomo Party、ClashX、Stash）——
sing-box 的 outbound 结构与这里不同，不猜。
"""
from __future__ import annotations

import re

from . import compat, proxydns

# 当前生效的合并结果优先；根目录的 config 往往只是模板或旧副本。
_CONFIG_NAMES = (
    "work/config.yaml", "work/config.yml",
    "config.yaml", "config.yml",
    "clash-verge.yaml", "clash-verge.yml",
    "verge.yaml", "verge.yml",
    "mihomo.yaml", "mihomo.yml",
    "profile.yaml", "profile.yml",
)

_MAX_BYTES = 2 * 1024 * 1024

# 只有这几种组会在「失败/测速/分配」时自动挑成员。select 不算。
_AUTO_TYPES = ("fallback", "url-test", "load-balance", "least-ping")
_TERMINALS = ("DIRECT", "REJECT", "REJECT-DROP", "PASS", "BLOCK", "COMPATIBLE")
_ECO_MATCH = ("claude", "anthropic")
_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$")


def _pick(root) -> object | None:
    for name in _CONFIG_NAMES:
        path = root / name
        try:
            if path.is_file() and path.stat().st_size <= _MAX_BYTES:
                return path
        except OSError:
            continue
    return None


def _split_top(text: str) -> list[str]:
    """按顶层逗号切分；引号、方括号、圆括号里的逗号不切。"""
    out: list[str] = []
    buf: list[str] = []
    quote = ""
    depth = 0
    for ch in text or "":
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "[{(":
            depth += 1
            buf.append(ch)
        elif ch in "]})":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf).strip())
    return [x for x in out if x]


def _scalar(value: str):
    text = (value or "").strip()
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        text = text[1:-1]
    low = text.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    return text


def _flow_list(value: str) -> list[str]:
    text = (value or "").strip()
    if text.startswith("["):
        text = text[1:]
    if text.endswith("]"):
        text = text[:-1]
    return [_scalar(p) for p in _split_top(text) if _scalar(p) is not None]


def _flow_map(value: str) -> dict:
    text = (value or "").strip()
    if text.startswith("{"):
        text = text[1:]
    if text.endswith("}"):
        text = text[:-1]
    out: dict = {}
    for part in _split_top(text):
        key, sep, val = part.partition(":")
        if not sep:
            continue
        out[key.strip().strip("\"'")] = val.strip()
    return out


def _parse_tun(text: str) -> dict:
    """`tun:` 下的 enable / strict-route / auto-route。块式与 flow 都认。"""
    out: dict = {}
    in_tun = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            m = _KEY_RE.match(line.strip())
            in_tun = bool(m and m.group(1) == "tun")
            if in_tun and m and m.group(2).strip().startswith("{"):
                for key, value in _flow_map(m.group(2)).items():
                    if key in ("enable", "strict-route", "auto-route"):
                        out[key] = _scalar(value)
            continue
        if not in_tun:
            continue
        m = _KEY_RE.match(line.strip())
        if m and m.group(1) in ("enable", "strict-route", "auto-route"):
            out[m.group(1)] = _scalar(m.group(2))
    return out


def _parse_top_bool(text: str, name: str):
    """顶层标量，比如 mihomo 的 `ipv6: false`。嵌套的同名键不算。"""
    for raw in text.splitlines():
        if not raw.strip() or raw[:1] in (" ", "\t", "#"):
            continue
        m = _KEY_RE.match(raw.strip())
        if m and m.group(1) == name:
            return _scalar(m.group(2))
    return None


def _parse_groups(text: str) -> list[dict]:
    groups: list[dict] = []
    in_sec = False
    cur: dict | None = None
    key = ""
    key_indent = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and not stripped.startswith("- "):
            m = _KEY_RE.match(stripped)
            in_sec = bool(m and m.group(1) == "proxy-groups")
            if in_sec and m:
                rest = m.group(2).strip()
                if rest.startswith("["):
                    for part in _flow_list(rest):
                        if isinstance(part, str) and part.startswith("{"):
                            g = _group_from_flow(_flow_map(part))
                            if g:
                                groups.append(g)
            cur = None
            key = ""
            continue
        if not in_sec:
            continue
        # 成员列表行必须先判：它也以 "- " 开头，但不是新的组。
        if (key == "proxies" and stripped.startswith("- ") and indent >= key_indent
                and not stripped[2:].strip().startswith("{")
                and ":" not in stripped[2:].split(",")[0]):
            if cur is not None:
                value = _scalar(stripped[2:])
                if value is not None:
                    cur["members"].append(str(value))
            continue
        if stripped.startswith("- "):
            rest = stripped[2:].strip()
            if rest.startswith("{"):
                g = _group_from_flow(_flow_map(rest))
                cur = g
                if g:
                    groups.append(g)
            else:
                cur = {"name": "", "type": "", "members": []}
                m = _KEY_RE.match(rest)
                if m and m.group(1) == "name":
                    cur["name"] = str(_scalar(m.group(2)) or "")
                groups.append(cur)
            key = ""
            continue
        if cur is None:
            continue
        m = _KEY_RE.match(stripped)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if name == "name" and not cur["name"]:
            cur["name"] = str(_scalar(value) or "")
        elif name == "type":
            cur["type"] = str(_scalar(value) or "").lower()
        elif name == "proxies":
            key, key_indent = "proxies", indent
            if value.startswith("["):
                cur["members"].extend(_flow_list(value))
                key = ""
            elif value:
                cur["members"].append(str(_scalar(value)))
        else:
            key = ""
    return [g for g in groups if g.get("name")]


def _group_from_flow(fields: dict) -> dict | None:
    name = _scalar(fields.get("name") or "")
    if not name:
        return None
    members = _flow_list(fields.get("proxies") or "")
    return {"name": str(name), "type": str(_scalar(fields.get("type") or "") or "").lower(),
            "members": [str(m) for m in members if m is not None]}


def _parse_rules(text: str) -> dict:
    """`rules:` 的落点：Claude 规则的目标、最终 MATCH、所有规则目标。"""
    eco: list[dict] = []
    targets: list[str] = []
    final = ""
    in_sec = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and not stripped.startswith("- "):
            m = _KEY_RE.match(stripped)
            in_sec = bool(m and m.group(1) == "rules")
            if in_sec and m:
                rest = m.group(2).strip()
                if rest.startswith("["):
                    for item in _flow_list(rest):
                        final = _take_rule(str(item), eco, targets) or final
            continue
        if not in_sec or not stripped.startswith("- "):
            continue
        item = stripped[2:].strip()
        if len(item) >= 2 and item[0] in "\"'" and item[-1] == item[0]:
            item = item[1:-1]
        final = _take_rule(item, eco, targets) or final
    return {"eco": eco, "targets": targets, "final": final}


def _take_rule(item: str, eco: list, targets: list) -> str:
    """记一条规则；`MATCH` 的落点作为返回值。"""
    fields = _split_top(item)
    if len(fields) < 2:
        return ""
    rtype = fields[0].upper()
    raw = fields[1] if rtype == "MATCH" and len(fields) > 1 else fields[-1]
    target = str(_scalar(raw) or "")
    if not target:
        return ""
    if target not in targets:
        targets.append(target)
    if rtype == "MATCH":
        return target
    low = item.lower()
    if any(k in low for k in _ECO_MATCH):
        raw_payload = fields[1] if len(fields) > 2 else rtype
        entry = {"payload": str(_scalar(raw_payload) or rtype), "target": target}
        if entry not in eco:
            eco.append(entry)
    return ""


def _walk(start: str, groups: dict) -> dict:
    """按默认选择往下走：select 与回落组都先看第一个成员。

    返回的 `direct` 只在规则直接指向 DIRECT 时为真。组内第一个成员
    仅用于收集配置风险，不代表当前选择。url-test 谁最快不确定，不在这里下结论；但组成员里有
    DIRECT 会记进 `failopen`，那才是要报的风险。
    """
    hops: list[dict] = []
    failopen: list[dict] = []
    name = start or ""
    seen: set[str] = set()
    while name:
        up = name.upper()
        if up in _TERMINALS:
            return {"terminal": up, "hops": hops, "failopen": failopen,
                    "direct": up == "DIRECT" and not hops}
        if name in seen:
            break
        seen.add(name)
        group = groups.get(name)
        if not group:
            return {"terminal": name, "hops": hops, "failopen": failopen, "direct": False}
        gtype = group.get("type") or ""
        members = group.get("members") or []
        if gtype in _AUTO_TYPES:
            for index, member in enumerate(members):
                if member.upper() == "DIRECT":
                    failopen.append({"name": name, "type": gtype, "index": index,
                                     "reachable": True})
        hops.append({"name": name, "type": gtype})
        if not members:
            break
        # 仅沿配置默认路径收集潜在风险，不把组内 DIRECT 当作实际选择。
        name = members[0]

    return {"terminal": name, "hops": hops, "failopen": failopen, "direct": False}


def _reachable(targets: list[str], groups: dict) -> set[str]:
    seen: set[str] = set()
    stack = list(targets)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        group = groups.get(name)
        if group:
            stack.extend(group.get("members") or [])
    return seen


def inspect_text(text: str, name: str, config: str = "") -> dict:
    """把一份配置变成「回落 / 默认路径 / v6」三组事实。纯函数。"""
    groups = _parse_groups(text)
    gmap = {g["name"]: g for g in groups}
    rules = _parse_rules(text)
    reach = _reachable(rules["targets"], gmap)

    routes: list[dict] = []
    direct_hits: list[dict] = []
    drift: list[dict] = []
    failopen: dict[str, dict] = {}
    seeds: list[tuple[str, dict]] = []
    if rules["final"]:
        seeds.append(("最终规则", {"payload": "MATCH", "target": rules["final"]}))
    for entry in rules["eco"]:
        seeds.append(("Claude 规则", entry))
    for kind, entry in seeds:
        walked = _walk(entry["target"], gmap)
        routes.append({"kind": kind, "payload": entry["payload"],
                       "target": entry["target"], **walked})
        if walked["direct"]:
            direct_hits.append({"kind": kind, "payload": entry["payload"],
                                "target": entry["target"]})
        for risk in walked["failopen"]:
            failopen[risk["name"]] = risk
        # 这条路上有没有「自己会换节点」的组。select 组换节点是用户按下去的，
        # 自动组换节点是它自己决定的——后者会让同一个账号的出口在一天里跳好几次。
        # Claude 只认出口 IP，跳一次就是一次新的关联信号，而分流规则这时全绿。
        #
        # 同一个组被多条域名规则指着时只记一条：证据要说的是「这条路会漂」，
        # 不是「有四条规则都会漂」。
        for hop in walked["hops"]:
            if hop["type"] not in _AUTO_TYPES:
                continue
            if not any(x["kind"] == kind and x["group"] == hop["name"] for x in drift):
                drift.append({"kind": kind, "payload": entry["payload"],
                              "group": hop["name"], "type": hop["type"]})
            break
    for group in groups:
        gtype = group.get("type") or ""
        if gtype not in _AUTO_TYPES:
            continue
        for index, member in enumerate(group.get("members") or []):
            if member.upper() == "DIRECT":
                failopen.setdefault(group["name"], {
                    "name": group["name"], "type": gtype, "index": index,
                    "reachable": group["name"] in reach,
                })
                break

    return {
        "checked": bool(groups or rules["targets"]),
        "note": "" if (groups or rules["targets"]) else "配置里没读到 proxy-groups / rules",
        "client": name,
        "config": (config or "").replace(str(compat.HOME), "~"),
        "ipv6": _parse_top_bool(text, "ipv6"),
        "tun": _parse_tun(text),
        "routes": routes,
        "final": rules["final"],
        "eco": rules["eco"],
        "defaultDirect": direct_hits,
        "failopen": list(failopen.values()),
        "drift": drift,
    }


def inspect(commands: list[str] | None = None, specs=None) -> dict:
    """读一遍正在运行的客户端配置；没找到时 checked=False，不替用户下结论。"""
    out = {
        "checked": False, "client": "", "config": "", "ipv6": None, "tun": {},
        "routes": [], "final": "", "eco": [], "defaultDirect": [], "failopen": [],
        "drift": [],
        "note": "",
    }
    if not compat.IS_MAC:
        out["note"] = "回落策略只读 macOS 上的 Clash 系配置"
        return out
    cmds = list(commands if commands is not None else proxydns._running_commands())
    for root, name, keys, exclude in proxydns._roots(
            proxydns._ROOT_SPECS if specs is None else specs):
        if not root.is_dir() or not proxydns._active(cmds, keys, exclude):
            continue
        path = _pick(root)
        if not path:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        return inspect_text(text, name, str(path))
    out["note"] = "没找到运行中的 Clash 系客户端配置"
    return out
