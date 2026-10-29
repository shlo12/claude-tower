"""把 Claude 生态域名与 STUN 端口置顶到正在使用的代理客户端。

支持三种能安全改写的客户端：

- FlClash：附加规则存在 database.sqlite 的 rules 表里（profile_id 为空），
  生成配置时排在订阅 rules 之前，订阅更新不会冲掉。
- Clash Verge：改写 profiles/Script.js 里的全局扩展脚本，把规则 prepend 到
  生成配置的 rules 前面；订阅更新不会覆盖。
- ClashX：直接改写当前生效的 config.yaml，在 rules: 顶部插入标记块。
  订阅更新会重写这个文件，规则随之消失，需要重新执行。

Shadowrocket / Surge / sing-box / Mihomo Party 的配置格式或管理方式不适合
由本工具直接改，只做识别并给出手动步骤，不碰它们的文件。

写入前必须退出客户端（避免它把内存里的旧规则写回去），写完后重启。
FlClash 只在 rules 表里插入自己的行，撤销时只删自己记下的 id；后两种只删除
自己写入的标记块，不整份覆盖，也不备份整份配置（里面有节点凭据）。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from . import compat, kernelcheck, shield as shield_state

HOME = Path.home()
STATE = HOME / ".ccclean/proxyfix.json"
LOCK = threading.Lock()

FLCLASH_DIR = HOME / "Library/Application Support/com.follow.clash"
FLCLASH_CONFIG = FLCLASH_DIR / "config.yaml"
FLCLASH_DB = FLCLASH_DIR / "database.sqlite"
FLCLASH_APP_CANDIDATES = (
    Path("/Applications/FlClash.app"),
    HOME / "Applications/FlClash.app",
)
FLCLASH_PROC = "/FlClash.app/Contents/MacOS/FlClash"

VERGE_DIR_CANDIDATES = (
    HOME / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev",
    HOME / "Library/Application Support/clash-verge",
    HOME / "Library/Application Support/Clash Verge",
)
VERGE_APP_CANDIDATES = (
    Path("/Applications/Clash Verge.app"),
    HOME / "Applications/Clash Verge.app",
)
VERGE_PROC = "/Clash Verge.app/Contents/MacOS/"
VERGE_BUNDLES = ("io.github.clash-verge-rev.clash-verge-rev", "com.clashverge.app")
VERGE_SCRIPT = "profiles/Script.js"
VERGE_CONFIGS = (
    "work/config.yaml", "work/config.yml", "clash-verge.yaml", "clash-verge.yml",
    "config.yaml", "config.yml",
)

CLASHX_DIR = HOME / ".config/clash"
CLASHX_CONFIGS = (CLASHX_DIR / "config.yaml", CLASHX_DIR / "config.yml")
CLASHX_APP_CANDIDATES = (
    Path("/Applications/ClashX.app"),
    HOME / "Applications/ClashX.app",
)
CLASHX_PROC = "/ClashX.app/Contents/MacOS/"
CLASHX_BUNDLES = ("com.west2online.ClashX",)

# 只识别、不改写。配置由客户端自己管理，或格式和 Clash/Mihomo 不兼容。
MANUAL_CLIENTS = (
    {
        "id": "shadowrocket", "name": "Shadowrocket",
        "apps": (Path("/Applications/Shadowrocket.app"),),
        "proc": "/Shadowrocket.app/Contents/MacOS/",
        "guidance": (
            "Shadowrocket 的规则在应用内编辑：配置 → 编辑纯文本。",
            "把 DOMAIN-SUFFIX 规则放在规则列表最上面，代理列选你的节点/策略组。",
            "至少加入 claude.ai / anthropic.com / claudeusercontent.com；"
            "STUN 端口 3478/5349/19302 需要在 UDP 规则里选代理。",
        ),
    },
    {
        "id": "surge", "name": "Surge",
        "apps": (Path("/Applications/Surge.app"),),
        "proc": "/Surge.app/Contents/MacOS/",
        "guidance": (
            "Surge → 配置 → 编辑当前配置文件，在 [Rule] 段最上面加入。",
            "格式：DOMAIN-SUFFIX,claude.ai,<策略组>（anthropic.com 等同样）。",
            "UDP 端口规则：DEST-PORT,3478,<策略组>，3478/5349/19302 各一条。",
        ),
    },
    {
        "id": "sing-box", "name": "sing-box",
        "apps": (Path("/Applications/sing-box.app"),),
        "proc": "/sing-box.app/Contents/MacOS/",
        "guidance": (
            "sing-box 配置是 JSON，本工具不改写。",
            "在 route.rules 最前面加入 domain_suffix 规则（claude.ai、anthropic.com 等），"
            "outbound 指向代理出站。",
            "UDP 端口同样用 port 规则（3478/5349/19302）指向代理出站。",
        ),
    },
    {
        "id": "mihomo-party", "name": "Mihomo Party",
        "apps": (Path("/Applications/Mihomo Party.app"),),
        "proc": "/Mihomo Party.app/Contents/MacOS/",
        "guidance": (
            "Mihomo Party 的配置由订阅生成，直接改 config.yaml 会被下一次订阅覆盖。",
            "在客户端的「覆写 / Override」里加入 prepend-rules，把 Claude 域名与 "
            "STUN 端口指向代理组。",
            "手动改当前配置只能临时生效，下次订阅更新后需要重做。",
        ),
    },
)

POLICY_PREFS = ("Ai+", "AI", "Claude", "全球代理", "手动选择", "节点选择",
                "漏网之鱼", "Proxy", "GLOBAL")

# 置顶规则覆盖的目标，按用途分五组。statsig 四个域是客户端功能开关/
# 实验平台的落点——漏掉它们，指纹和开关流量会绕开代理单独直连。
DOMAIN_GROUPS = (
    ("service",   ("claude.ai", "claude.com", "anthropic.com",
                   "claudeusercontent.com")),
    ("challenge", ("challenges.cloudflare.com",)),
    ("telemetry", ("datadoghq.com", "segment.io", "featuregates.org",
                   "featureassets.org", "prodregistryv2.org", "statsigapi.net")),
    ("billing",   ("stripe.com", "stripe.network", "stripecdn.com")),
    ("support",   ("intercom.io", "intercomcdn.com", "intercomassets.com")),
)
DOMAINS = tuple(d for _, group in DOMAIN_GROUPS for d in group)
PORTS = ("3478", "5349", "19302")
# 端口有两种写法：跟着域名一起走代理组，或者直接拒掉。对不用 WebRTC 通话的人，
# REJECT 比 proxy 更彻底——UDP 根本出不去，不存在「代理组不支持 UDP 就漏」。
PORT_MODES = ("proxy", "reject")
REJECT = "REJECT"

MARK0 = "  # >>> ccclean pinned rules >>>"
MARK1 = "  # <<< ccclean pinned rules <<<"
VERGE_MARK0 = "// >>> ccclean pinned rules >>>"
VERGE_MARK1 = "// <<< ccclean pinned rules <<<"

IMPACT = ("会退出并重新打开客户端，代理会中断几秒；期间已经建立的连接会断开。"
          "改动只写本工具自己的规则块，订阅更新不会覆盖（ClashX 例外）。")
LIMITS = ("只写 Claude 生态域名与 STUN/TURN 端口（3478/5349/19302），"
          "不改节点、不改代理组、不改订阅；如果客户端里更靠前的同名直连规则挡住，"
          "或代理组本身不支持 UDP，WebRTC 仍可能泄漏。端口选「直接拒绝」时这三个"
          "端口的 UDP 完全出不去，浏览器 WebRTC 通话会不可用。ClashX 的规则在订阅更新后可能丢失。")



# ---------------------------------------------------------------- 小工具

def _run(args, timeout=8):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return r


def _proc_alive(pattern=FLCLASH_PROC):
    r = _run(["pgrep", "-f", pattern], 5)
    return bool(r and r.returncode == 0 and r.stdout.strip())


def _wait_gone(pattern, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _proc_alive(pattern):
            return True
        time.sleep(0.25)
    return not _proc_alive(pattern)


def _app_path():
    for p in FLCLASH_APP_CANDIDATES:
        if p.is_dir():
            return p
    return None


def _quit():
    """先礼后兵。SIGKILL 不用：它可能留下没写完的数据库。"""
    if not _proc_alive():
        return True
    _run(["/usr/bin/osascript", "-e", 'tell application "FlClash" to quit'], 10)
    if _wait_gone(FLCLASH_PROC, 8):
        return True
    _run(["pkill", "-TERM", "-f", FLCLASH_PROC], 5)
    return _wait_gone(FLCLASH_PROC, 5)


def _launch():
    app = _app_path()
    args = ["/usr/bin/open", "-a", str(app)] if app else \
        ["/usr/bin/open", "-b", "com.follow.clash"]
    _run(args, 10)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _proc_alive():
            return True
        time.sleep(0.4)
    return _proc_alive()


def _display(path):
    try:
        return str(path).replace(str(HOME), "~")
    except Exception:
        return str(path)


def _mtime(path):
    try:
        return path.stat().st_mtime
    except OSError:
        return 0


def _first_app(candidates):
    for p in candidates:
        if p.is_dir():
            return p
    return None


def _quit_named(app_name, pattern):
    """先礼后兵。SIGKILL 不用：客户端可能还有没写完的配置。"""
    if not _proc_alive(pattern):
        return True
    _run(["/usr/bin/osascript", "-e", f'tell application "{app_name}" to quit'], 10)
    if _wait_gone(pattern, 8):
        return True
    _run(["pkill", "-TERM", "-f", pattern], 5)
    return _wait_gone(pattern, 5)


def _launch_named(candidates, bundles, pattern):
    app = _first_app(candidates)
    if app:
        _run(["/usr/bin/open", "-a", str(app)], 10)
    else:
        opened = False
        for bundle in bundles:
            r = _run(["/usr/bin/open", "-b", bundle], 10)
            if r and r.returncode == 0:
                opened = True
                break
        if not opened:
            return False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _proc_alive(pattern):
            return True
        time.sleep(0.4)
    return _proc_alive(pattern)


# ---------------------------------------------------------------- 客户端发现

def _verge_root():
    for d in VERGE_DIR_CANDIDATES:
        if (d / VERGE_SCRIPT).is_file() or (d / "profiles").is_dir():
            return d
    return None


def _verge_script(root=None):
    root = root or _verge_root()
    if not root:
        return None
    p = root / VERGE_SCRIPT
    return p if p.is_file() else None


def _verge_config(root=None):
    root = root or _verge_root()
    if not root:
        return None
    for name in VERGE_CONFIGS:
        p = root / name
        if p.is_file():
            return p
    return None


def _clashx_config():
    for p in CLASHX_CONFIGS:
        if p.is_file():
            return p
    return None


def _config_mode(text):
    m = re.search(r"^mode:\s*[\"']?([\w-]+)", text, re.M)
    return (m.group(1) if m else "").lower()


def _manual_present(client):
    return any(p.is_dir() for p in client["apps"])


def _detect():
    """按「正在运行优先、其次最近改过的配置」排候选。

    同时装了两三个客户端时，不能只按目录存在与否选——用户真正在用的
    那个才会接管流量。运行状态是最强信号，其次是配置文件的新鲜度。
    """
    items = []
    if FLCLASH_CONFIG.is_file() and FLCLASH_DB.is_file():
        items.append({
            "kind": "flclash", "name": "FlClash",
            "running": _proc_alive(FLCLASH_PROC),
            "mtime": max(_mtime(FLCLASH_CONFIG), _mtime(FLCLASH_DB)),
        })
    root = _verge_root()
    if root:
        script = _verge_script(root)
        items.append({
            "kind": "clash-verge", "name": "Clash Verge",
            "running": _proc_alive(VERGE_PROC),
            "mtime": _mtime(script or root / "profiles"),
        })
    cfg = _clashx_config()
    if cfg:
        items.append({
            "kind": "clashx", "name": "ClashX",
            "running": _proc_alive(CLASHX_PROC), "mtime": _mtime(cfg),
        })
    for client in MANUAL_CLIENTS:
        if _manual_present(client):
            items.append({
                "kind": client["id"], "name": client["name"],
                "running": _proc_alive(client["proc"]), "mtime": 0,
                "manual": client,
            })
    items.sort(key=lambda x: (1 if x["running"] else 0, x["mtime"]), reverse=True)
    return items


def _client_name(kind):
    for item in ({"kind": "flclash", "name": "FlClash"},
                 {"kind": "clash-verge", "name": "Clash Verge"},
                 {"kind": "clashx", "name": "ClashX"}):
        if item["kind"] == kind:
            return item["name"]
    for client in MANUAL_CLIENTS:
        if client["id"] == kind:
            return client["name"]
    return kind or "未知客户端"


# ---------------------------------------------------------------- Verge / ClashX 文本块

def _verge_strip(text):
    out, inside = [], False
    for line in text.splitlines(keepends=True):
        if line.strip() == VERGE_MARK0:
            inside = True
            continue
        if line.strip() == VERGE_MARK1:
            inside = False
            continue
        if not inside:
            out.append(line)
    return "".join(out)


def _verge_block_text(text):
    out, inside = [], False
    for line in text.splitlines(keepends=True):
        if line.strip() == VERGE_MARK0:
            inside = True
        if inside:
            out.append(line)
        if line.strip() == VERGE_MARK1:
            inside = False
    return "".join(out)


def _verge_block(indent, rules):
    lines = [indent + VERGE_MARK0, indent + "config.rules = ["]
    for rule in rules:
        lines.append(indent + "  " + json.dumps(rule, ensure_ascii=False) + ",")
    lines += [indent + "].concat(config.rules || []);", indent + VERGE_MARK1]
    return "\n".join(lines) + "\n"


def _verge_inject(text, rules):
    """在 main(config) 的 return config 之前插入规则块。

    只认 `return config` 单独占一行的写法；认不出就明确失败，不猜。
    """
    text = _verge_strip(text)
    m = re.search(r"function\s+main\s*\(\s*config[^)]*\)\s*\{", text)
    if not m:
        return ""
    end = text.find("return config", m.end())
    if end < 0:
        return ""
    line_start = text.rfind("\n", 0, end) + 1
    indent = text[line_start:end]
    if indent.strip():
        return ""
    block = _verge_block(indent, rules)
    return text[:line_start] + block + indent + text[end:]


def _verge_rules(text):
    rules = []
    for line in _verge_block_text(text).splitlines():
        s = line.strip()
        if s.startswith('"') and s.endswith(","):
            s = s[:-1]
        if s.startswith('"') and s.endswith('"'):
            try:
                value = json.loads(s)
            except ValueError:
                continue
            if isinstance(value, str):
                rules.append(value)
    return rules


def _config_coverage(text, mode="proxy"):
    """ClashX 当前配置里，在第一条 MATCH 之前已经指向代理的规则。

    我们的块会插在 rules: 最前面，所以更靠后的 DIRECT/REJECT 挡不住它；
    真正需要补的是「在 MATCH 之后」或「根本没有」的条目。
    """
    first = {}
    for line in _rules_section(text):
        fields = _rule_fields(line)
        if len(fields) < 3:
            continue
        rtype, payload, policy = fields[0].upper(), fields[1], fields[2]
        if rtype == "MATCH":
            break
        first.setdefault((rtype, payload.lower()), policy)
    specs = [(a, p.lower()) for a, p in _spec_pairs()]
    # 这里没有「域名该指向哪个组」的上下文，policy 传空：域名规则只要不是
    # 直连/拒绝就算覆盖，端口规则按所选策略判定。
    port = _port_target("", mode)
    covered = [key for key in specs
               if key in first and not _conflict(key[0], first[key], "", port)]
    missing = [key for key in specs if key not in covered]
    return covered, missing



# ---------------------------------------------------------------- 配置解析

def _rules_section(text):
    out = []
    inside = False
    for line in text.splitlines():
        if re.match(r"^rules:\s*$", line):
            inside = True
            continue
        if inside:
            if line and not line.startswith((" ", "\t", "-")):
                break
            out.append(line)
    return out


def _rule_fields(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    if line.startswith("-"):
        line = line[1:].strip()
    if len(line) >= 2 and line[0] in "\"'" and line[-1] == line[0]:
        line = line[1:-1]
    parts = [p.strip().strip("\"'") for p in line.split(",")]
    return parts if len(parts) >= 3 else []


def _blocked(policy):
    return policy.upper() in ("DIRECT", "REJECT", "REJECT-DROP", "PASS",
                              "BLOCK", "COMPATIBLE")


def _groups(text):
    """proxy-groups 里可被规则指向的组名。flow / block 两种写法都认。"""
    names = []
    inside = False
    for line in text.splitlines():
        if re.match(r"^proxy-groups:\s*$", line):
            inside = True
            continue
        if inside:
            if line and not line.startswith((" ", "\t", "-")):
                break
            m = re.match(r"\s*-\s*\{?\s*name:\s*([^,}]+)", line)
            if m:
                names.append(m.group(1).strip().strip("\"'"))
    return names


def _policy(text):
    """优先沿用现有 Claude 规则指向的组，再按常用名兜底。"""
    groups = _groups(text)
    if not groups:
        return "", groups, "读不到 proxy-groups，未修改"
    lowered = {g.lower(): g for g in groups}
    candidates = []
    for line in _rules_section(text):
        fields = _rule_fields(line)
        if len(fields) < 3:
            continue
        rtype, payload, policy = fields[0].upper(), fields[1], fields[2]
        if not any(k in payload.lower() for k in ("claude", "anthropic")):
            continue
        if policy in groups or policy.lower() in lowered:
            candidates.append((0 if rtype == "RULE-SET" else 1,
                               lowered.get(policy.lower(), policy)))
    if candidates:
        candidates.sort(key=lambda item: item[0])
        target = candidates[0][1]
        if not _blocked(target):
            return target, groups, ""
    for name in POLICY_PREFS:
        for group in groups:
            if group.lower() == name.lower() and not _blocked(group):
                return group, groups, ""
    for group in groups:
        if not _blocked(group):
            return group, groups, ""
    return "", groups, "找不到可用的代理组，未修改"


def _config_rules(text):
    out = set()
    for line in _rules_section(text):
        fields = _rule_fields(line)
        if len(fields) >= 3:
            out.add((fields[0].upper(), fields[1].lower()))
    return out


def _strip_marker(text):
    out, inside = [], False
    for line in text.splitlines(keepends=True):
        if line.strip() == MARK0.strip():
            inside = True
            continue
        if line.strip() == MARK1.strip():
            inside = False
            continue
        if not inside:
            out.append(line)
    return "".join(out)


def _inject_rules(text, rules):
    """在 rules: 下面插入标记块；没有 rules: 键就返回空串。"""
    text = _strip_marker(text)
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if re.match(r"^rules:\s*$", line):
            block = [MARK0 + "\n"]
            block += [f'  - "{rule}"\n' for rule in rules]
            block.append(MARK1 + "\n")
            lines[i + 1:i + 1] = block
            return "".join(lines)
    return ""


def _write_text(path, text):
    fd, name = tempfile.mkstemp(prefix=".proxyfix-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        try:
            os.chmod(name, path.stat().st_mode & 0o777)
        except OSError:
            os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


# ---------------------------------------------------------------- 数据库

def _db_columns(con):
    return {row[1] for row in con.execute("pragma table_info(rules)")}


def _global_rules(con):
    rows = con.execute(
        'select id, rule_action, content, rule_target, "order" '
        'from rules where profile_id is null order by "order"'
    ).fetchall()
    return rows


def _domain_pairs():
    return [("DOMAIN-SUFFIX", d) for d in DOMAINS]


def _port_pairs():
    return [("DST-PORT", p) for p in PORTS]


def _spec_pairs():
    """要写的全部条目。顺序只影响预览显示，不影响判定。"""
    return _domain_pairs() + _port_pairs()


def _port_mode(value) -> str:
    """端口策略。认不出的值一律退回 proxy，不猜。"""
    text = str(value or "").strip().lower()
    return text if text in PORT_MODES else "proxy"


def _port_target(policy: str, mode: str) -> str:
    """这三个端口该指向谁：代理组，或者直接拒掉。"""
    return REJECT if _port_mode(mode) == "reject" else policy


def _wanted(action, policy: str, port_target: str) -> str:
    return port_target if str(action).upper() == "DST-PORT" else policy


def _rules_for(pairs, policy: str, mode: str = "proxy"):
    """按域名/端口分别取策略，拼成规则文本。"""
    port = _port_target(policy, mode)
    return [_rule_text(a, p, _wanted(a, policy, port)) for a, p in pairs]


def _conflict(action, target: str, policy: str, port_target: str) -> bool:
    """已存在的这条规则是不是挡路。

    端口选「直接拒绝」时，本来就是 REJECT 的那条不算冲突——那正是我们要的。
    其余任何直连/拒绝都和我们的目标相反。
    """
    if not _blocked(target):
        return False
    return not (str(target).upper() == REJECT
                and str(_wanted(action, policy, port_target)).upper() == REJECT)


def _rule_text(action, payload, policy):
    return f"{action.replace('_', '-')},{payload},{policy}"


def _policy_label(policy: str, port_target: str) -> str:
    """写进提示里的策略说法。端口走的是别的策略时要讲出来。"""
    if port_target and policy and port_target != policy:
        return f"{policy}（STUN 端口 {port_target}）"
    return policy or port_target


def _snowflake(ms, seq):
    return ((ms - 1704067200000) << 22) | (1 << 12) | seq


def _order_keys(n, below):
    """取 n 个都排在 below 之前的 fractional-indexing 键。

    FlClash 用 fractional_indexing 生成 order；它的键允许的字符集是
    0-9A-Za-z，且不能以 0 结尾。这里只用「数字/大写字母 + z」两字符键，
    必要时在前面补 0，保证互不相等且升序。
    """
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    keys = []
    for i in range(n):
        keys.append(alphabet[i % len(alphabet)] + "z")
    if not below:
        return keys
    for _ in range(8):
        if all(k < below for k in keys):
            return keys
        keys = ["0" + k for k in keys]
    # 合法 fractional key 不会以 0 结尾；真遇到「已经最小」的键就明确失败，
    # 不能在这里空转。
    raise ValueError("现有附加规则的排序键太小，无法再往前插入；未修改")


def _state_guard():
    if STATE.is_symlink() or STATE.parent.is_symlink():
        raise ValueError("状态路径是符号链接，未修改")


def _read_state():
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError) as exc:
        return None, f"分流修复记录无法读取：{exc}"
    if not isinstance(data, dict) or data.get("version") != 1:
        return None, "分流修复记录格式不正确"
    client = data.get("client") or "flclash"
    if not isinstance(data.get("rules"), list):
        return None, "分流修复记录格式不正确"
    if client == "flclash":
        if (not isinstance(data.get("ids"), list)
                or not all(isinstance(i, int) for i in data["ids"])):
            return None, "分流修复记录格式不正确"
        data["client"] = "flclash"
    elif client in ("clash-verge", "clashx"):
        if not isinstance(data.get("config"), str) or not isinstance(data.get("block"), str):
            return None, "分流修复记录格式不正确"
    else:
        return None, "分流修复记录里的客户端未知"
    return data, ""


def _state(strict=False):
    data, error = _read_state()
    if error and strict:
        raise ValueError(error + "，未修改")
    return data, error


def _write_state(data):
    parent = STATE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".proxyfix-state-", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


# ---------------------------------------------------------------- 状态

def _target_flclash(port_mode="proxy"):
    if not FLCLASH_CONFIG.is_file() or not FLCLASH_DB.is_file():
        return None, "没找到 FlClash 的配置文件"
    try:
        text = FLCLASH_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"读不到 FlClash 配置：{exc}"
    policy, groups, error = _policy(text)
    if error:
        return None, error
    mode = _port_mode(port_mode)
    return {
        "kind": "flclash",
        "name": "FlClash",
        "manual": False,
        "text": text,
        "config": FLCLASH_CONFIG,
        "policy": policy,
        "groups": groups,
        "portMode": mode,
        "portPolicy": _port_target(policy, mode),
        "running": _proc_alive(FLCLASH_PROC),
        "rules": _rules_for(_spec_pairs(), policy, mode),
    }, ""


def _target_verge(port_mode="proxy"):
    root = _verge_root()
    if not root:
        return None, "没找到 Clash Verge 的配置目录"
    script = _verge_script(root)
    if not script:
        return None, ("Clash Verge 没有 profiles/Script.js；请先在客户端的"
                      "「全局扩展脚本」里创建并启用它")
    cfg = _verge_config(root)
    if not cfg:
        return None, "读不到 Clash Verge 的生成配置；请先启动客户端并应用一次订阅"
    try:
        script_text = script.read_text(encoding="utf-8", errors="replace")
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"读不到 Clash Verge 配置：{exc}"
    policy, groups, error = _policy(text)
    if error:
        return None, "Clash Verge：" + error
    mode = _port_mode(port_mode)
    return {
        "kind": "clash-verge",
        "name": "Clash Verge",
        "manual": False,
        "script": script,
        "scriptText": script_text,
        "config": cfg,
        "text": text,
        "mode": _config_mode(text),
        "policy": policy,
        "groups": groups,
        "portMode": mode,
        "portPolicy": _port_target(policy, mode),
        "running": _proc_alive(VERGE_PROC),
        "rules": _rules_for(_spec_pairs(), policy, mode),
    }, ""


def _target_clashx(port_mode="proxy"):
    cfg = _clashx_config()
    if not cfg:
        return None, "没找到 ClashX 的 config.yaml"
    if cfg.is_symlink():
        return None, "ClashX 的 config.yaml 是符号链接，未修改"
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"读不到 ClashX 配置：{exc}"
    policy, groups, error = _policy(text)
    if error:
        return None, "ClashX：" + error
    mode = _port_mode(port_mode)
    return {
        "kind": "clashx",
        "name": "ClashX",
        "manual": False,
        "config": cfg,
        "text": text,
        "mode": _config_mode(text),
        "policy": policy,
        "groups": groups,
        "portMode": mode,
        "portPolicy": _port_target(policy, mode),
        "running": _proc_alive(CLASHX_PROC),
        "rules": _rules_for(_spec_pairs(), policy, mode),
    }, ""


def _target(port_mode="proxy"):
    if not compat.IS_MAC:
        return None, "此功能仅支持 macOS"
    picked = _detect()
    if not picked:
        return None, "没找到可修复的代理客户端（支持 FlClash / Clash Verge / ClashX）"
    item = picked[0]
    if item.get("manual"):
        client = item["manual"]
        return {
            "kind": client["id"],
            "name": client["name"],
            "manual": True,
            "guidance": list(client["guidance"]),
            "running": item["running"],
            "rules": [],
        }, ""
    if item["kind"] == "flclash":
        return _target_flclash(port_mode)
    if item["kind"] == "clash-verge":
        return _target_verge(port_mode)
    if item["kind"] == "clashx":
        return _target_clashx(port_mode)
    return None, f"客户端 {item['name']} 暂不支持自动改写"



def _coverage(text, policy, port_mode="proxy"):
    """返回 (已覆盖, 被直连规则挡住, 缺的规则)。只看全局附加规则。"""
    try:
        con = sqlite3.connect(f"file:{FLCLASH_DB}?mode=ro", uri=True, timeout=5)
        try:
            cols = _db_columns(con)
            need = {"id", "rule_action", "content", "rule_target", "order"}
            if not need <= cols:
                return [], [], [], "FlClash 数据库结构不认识，未修改"
            rows = _global_rules(con)
        finally:
            con.close()
    except (sqlite3.Error, OSError) as exc:
        return [], [], [], f"读不到 FlClash 附加规则：{exc}"
    existing = {}
    for row in rows:
        action = (row[1] or "").replace("_", "-").upper()
        payload = (row[2] or "").lower()
        existing[(action, payload)] = row[3] or ""
    specs = [(a, p.lower()) for a, p in _spec_pairs()]
    port = _port_target(policy, port_mode)
    blocked = [_rule_text(a, p, existing[(a, p)])
               for a, p in specs
               if (a, p) in existing
               and _conflict(a, existing[(a, p)], policy, port)]
    covered = [key for key in specs if key in existing]
    missing = [key for key in specs if key not in existing]
    return covered, blocked, missing, ""


def _coverage_verge(text, mode="proxy"):
    present = set()
    for rule in _verge_rules(text):
        parts = [p.strip() for p in rule.split(",")]
        if len(parts) >= 2:
            present.add((parts[0].upper(), parts[1].lower()))
    specs = [(a, p.lower()) for a, p in _spec_pairs()]
    covered = [key for key in specs if key in present]
    missing = [key for key in specs if key not in present]
    return covered, [], missing, ""


def _coverage_clashx(text, mode="proxy"):
    covered, missing = _config_coverage(text, mode)
    return covered, [], missing, ""


def _marker_block_text(text):
    out, inside = [], False
    for line in text.splitlines(keepends=True):
        if line.strip() == MARK0.strip():
            inside = True
        if inside:
            out.append(line)
        if line.strip() == MARK1.strip():
            inside = False
    return "".join(out)


def _status_saved(saved, state_error):
    return {
        "stateError": state_error,
        "savedAt": (saved or {}).get("createdAt") or 0,
        "savedCount": len((saved or {}).get("ids") or [])
        if (saved or {}).get("client", "flclash") == "flclash"
        else len((saved or {}).get("rules") or []),
        "savedRules": (saved or {}).get("rules") or [],
        "canUndo": bool(saved),
    }


def _status_unavailable(saved, state_error, error, target=None):
    client = target["name"] if target else ""
    client_id = target["kind"] if target else ""
    manual = bool(target and target.get("manual"))
    out = {
        "supported": compat.IS_MAC,
        "available": False,
        "client": client,
        "clientId": client_id,
        "manual": manual,
        "reason": error,
        "guidance": list(target.get("guidance") or []) if target else [],
        "running": bool(target.get("running")) if target else False,
        "applied": False,
        "canApply": False,
        "impact": IMPACT,
        "limits": LIMITS,
    }
    out.update(_status_saved(saved, state_error))
    return out


def _status_flclash(target, saved, state_error):
    policy = target["policy"]
    mode = target.get("portMode", "proxy")
    port = target.get("portPolicy") or _port_target(policy, mode)
    covered, blocked, missing, db_error = _coverage(target["text"], policy, mode)
    active_ids = []
    if saved and saved.get("client", "flclash") == "flclash":
        try:
            con = sqlite3.connect(f"file:{FLCLASH_DB}?mode=ro", uri=True, timeout=5)
            try:
                ids = {row[0] for row in con.execute(
                    "select id from rules where profile_id is null")}
            finally:
                con.close()
            active_ids = [i for i in saved["ids"] if i in ids]
        except sqlite3.Error:
            active_ids = list(saved["ids"])
    reason = db_error
    can_apply = (bool(compat.IS_MAC) and not db_error and not blocked
                 and not state_error and not saved and bool(missing))
    if blocked:
        reason = "附加规则里已有 Claude/STUN 端口的直连或拒绝规则：" + "；".join(blocked[:3])
    elif state_error:
        reason = state_error
    elif saved:
        reason = "本工具已经写入过规则；如需重新写入，请先撤销"
    elif not missing:
        reason = "规则已经齐全"
    out = {
        "supported": compat.IS_MAC,
        "available": True,
        "client": "FlClash",
        "clientId": "flclash",
        "manual": False,
        "running": target["running"],
        "appPath": _display(_app_path() or ""),
        "configPath": _display(FLCLASH_CONFIG),
        "policy": policy,
        "groups": target["groups"],
        "portMode": mode,
        "portPolicy": port,
        "rules": target["rules"],
        "covered": _rules_for(covered, policy, mode),
        "missing": _rules_for(missing, policy, mode),
        "blocked": blocked,
        "reason": reason,
        "applied": bool(saved and active_ids),
        "canApply": can_apply and target["running"],
        "restart": "会退出并重新打开 FlClash，代理中断几秒。",
        "impact": IMPACT,
        "limits": LIMITS,
    }
    out.update(_status_saved(saved, state_error))
    return out


def _status_verge(target, saved, state_error):
    policy = target["policy"]
    mode = target.get("portMode", "proxy")
    port = target.get("portPolicy") or _port_target(policy, mode)
    covered, blocked, missing, error = _coverage_verge(target["scriptText"], mode)
    current_block = _verge_block_text(target["scriptText"])
    saved_block = (saved or {}).get("block") or ""
    applied = bool(saved and saved.get("client") == "clash-verge"
                   and current_block and current_block == saved_block)
    can_apply = (bool(compat.IS_MAC) and not error and not state_error
                 and not saved and not current_block and bool(missing)
                 and target["mode"] != "global")
    reason = error
    if target["mode"] == "global":
        reason = "全局模式（全部流量走代理），不需要再写规则"
    elif state_error:
        reason = state_error
    elif saved and saved.get("client") == "clash-verge":
        reason = "本工具已经写入过规则；如需重新写入，请先撤销"
    elif saved:
        reason = f"本工具已经对 {_client_name(saved.get('client'))} 写入过规则；请先撤销"
    elif current_block:
        reason = "Script.js 里已有本工具的标记块，但没有撤销记录；请先手动处理"
    elif not missing:
        reason = "规则已经齐全"
    out = {
        "supported": compat.IS_MAC,
        "available": True,
        "client": "Clash Verge",
        "clientId": "clash-verge",
        "manual": False,
        "running": target["running"],
        "appPath": _display(_first_app(VERGE_APP_CANDIDATES) or ""),
        "configPath": _display(target["config"]),
        "scriptPath": _display(target["script"]),
        "policy": policy,
        "groups": target["groups"],
        "mode": target["mode"],
        "portMode": mode,
        "portPolicy": port,
        "rules": target["rules"],
        "covered": _rules_for(covered, policy, mode),
        "missing": _rules_for(missing, policy, mode),
        "blocked": blocked,
        "reason": reason,
        "applied": applied,
        "canApply": can_apply and target["running"],
        "restart": "会退出并重新打开 Clash Verge，代理中断几秒。",
        "impact": IMPACT,
        "limits": LIMITS,
    }
    out.update(_status_saved(saved, state_error))
    return out


def _status_clashx(target, saved, state_error):
    policy = target["policy"]
    mode = target.get("portMode", "proxy")
    port = target.get("portPolicy") or _port_target(policy, mode)
    covered, blocked, missing, error = _coverage_clashx(target["text"], mode)
    current_block = _marker_block_text(target["text"])
    saved_block = (saved or {}).get("block") or ""
    applied = bool(saved and saved.get("client") == "clashx"
                   and current_block and current_block == saved_block)
    can_apply = (bool(compat.IS_MAC) and not error and not state_error
                 and not saved and not current_block and bool(missing)
                 and target["mode"] != "global")
    reason = error
    if target["mode"] == "global":
        reason = "全局模式（全部流量走代理），不需要再写规则"
    elif state_error:
        reason = state_error
    elif saved and saved.get("client") == "clashx":
        reason = "本工具已经写入过规则；如需重新写入，请先撤销"
    elif saved:
        reason = f"本工具已经对 {_client_name(saved.get('client'))} 写入过规则；请先撤销"
    elif current_block:
        reason = "config.yaml 里已有本工具的标记块，但没有撤销记录；请先手动处理"
    elif not missing:
        reason = "规则已经齐全"
    out = {
        "supported": compat.IS_MAC,
        "available": True,
        "client": "ClashX",
        "clientId": "clashx",
        "manual": False,
        "running": target["running"],
        "appPath": _display(_first_app(CLASHX_APP_CANDIDATES) or ""),
        "configPath": _display(target["config"]),
        "policy": policy,
        "groups": target["groups"],
        "mode": target["mode"],
        "portMode": mode,
        "portPolicy": port,
        "rules": target["rules"],
        "covered": _rules_for(covered, policy, mode),
        "missing": _rules_for(missing, policy, mode),
        "blocked": blocked,
        "reason": reason,
        "applied": applied,
        "canApply": can_apply and target["running"],
        "restart": "会退出并重新打开 ClashX，代理中断几秒。",
        "impact": IMPACT,
        "limits": LIMITS,
    }
    out.update(_status_saved(saved, state_error))
    return out


def status(port_mode=""):
    """port_mode 只是「打算怎么写」，写下去的那一次以记录里的为准。

    已经写过一次时，覆盖统计必须按记录里的策略算——否则界面会拿用户刚选的
    另一种策略去评价已经存在的规则，结论对不上。
    """
    saved, state_error = _state()
    mode = _port_mode((saved or {}).get("portMode") or port_mode)
    target, error = _target(mode)
    if not target:
        return _status_unavailable(saved, state_error, error)
    if target.get("manual"):
        return _status_unavailable(saved, state_error, target.get(
            "name", "") + " 的配置由客户端自己管理，本工具只提供手动步骤。", target)
    if target["kind"] == "flclash":
        return _status_flclash(target, saved, state_error)
    if target["kind"] == "clash-verge":
        return _status_verge(target, saved, state_error)
    if target["kind"] == "clashx":
        return _status_clashx(target, saved, state_error)
    return _status_unavailable(saved, state_error, "暂不支持自动改写这个客户端", target)



# ---------------------------------------------------------------- 应用 / 撤销

def _apply_flclash(port_mode="proxy"):
    saved, _ = _state(strict=True)
    if saved:
        raise ValueError("已有未撤销的分流修复，请先撤销")
    target, error = _target_flclash(port_mode)
    if not target:
        raise ValueError(error)
    if not target["running"]:
        raise ValueError("FlClash 没有运行；请先启动它，再执行修复")
    policy = target["policy"]
    mode = target["portMode"]
    port = target["portPolicy"]
    rules = target["rules"]
    covered, blocked, missing, db_error = _coverage(target["text"], policy, mode)
    if db_error:
        raise ValueError(db_error)
    if blocked:
        raise ValueError("附加规则里已有直连/拒绝规则：" + "；".join(blocked[:3])
                         + "。请先在 FlClash 里删掉它们")
    if not missing:
        shield_state.record_rule_guard(
            "flclash", "FlClash 运行配置", FLCLASH_CONFIG, rules)
        return {**_status_flclash(target, _state()[0], ""),
                "message": "规则已经齐全，没有修改。"}

    try:
        con = sqlite3.connect(f"file:{FLCLASH_DB}?mode=ro", uri=True, timeout=5)
        try:
            before = [dict(zip(("id", "rule_action", "content", "rule_target", "order"), row))
                      for row in _global_rules(con)]
            min_order = min((row[4] for row in _global_rules(con)
                             if row[4]), default="")
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise ValueError(f"读不到 FlClash 附加规则：{exc}") from exc

    if not _quit():
        raise RuntimeError("FlClash 没有退出；请手动退出后再修复。配置未修改。")

    inserted, marker_written = [], False
    try:
        missing_specs = [(a, p) for a, p in _spec_pairs()
                         if (a, p.lower()) in set(missing)]
        keys = _order_keys(len(missing_specs), min_order)
        now = int(time.time() * 1000)
        con = sqlite3.connect(FLCLASH_DB, timeout=10)
        try:
            with con:
                existing_ids = {row[0] for row in con.execute("select id from rules")}
                for i, (action, payload) in enumerate(missing_specs):
                    rid = _snowflake(now, i)
                    while rid in existing_ids:
                        now += 1
                        rid = _snowflake(now, i)
                    existing_ids.add(rid)
                    con.execute(
                        'insert into rules (id, profile_id, rule_action, content, '
                        'rule_target, rule_provider, sub_rule, no_resolve, src, "order") '
                        "values (?, null, ?, ?, ?, null, null, 0, 0, ?)",
                        (rid, action.replace("-", "_"), payload,
                         _wanted(action, policy, port), keys[i]),
                    )
                    inserted.append(rid)
        finally:
            con.close()

        new_text = _inject_rules(target["text"], rules)
        if not new_text:
            raise ValueError("配置里没有 rules: 段，未写入运行配置")
        _write_text(FLCLASH_CONFIG, new_text)
        marker_written = True

        _write_state({
            "version": 1,
            "createdAt": time.time(),
            "client": "flclash",
            "config": str(FLCLASH_CONFIG),
            "db": str(FLCLASH_DB),
            "policy": policy,
            "portMode": mode,
            "ids": inserted,
            "rules": rules,
            "before": before,
        })
        # 记给哨兵：它每轮只看这几个键，规则从运行时配置里消失就挂横幅。
        # 修复动作仍然只在塔里做，哨兵没有改写配置的权限。
        shield_state.record_rule_guard(
            "flclash", "FlClash 运行配置", FLCLASH_CONFIG, rules)
    except Exception:
        # 数据库已改但状态没记下来最危险：先按本次插入的 id 回滚。
        if inserted:
            try:
                con = sqlite3.connect(FLCLASH_DB, timeout=10)
                try:
                    with con:
                        con.execute(
                            f"delete from rules where id in ({','.join('?' * len(inserted))})",
                            inserted,
                        )
                finally:
                    con.close()
            except sqlite3.Error:
                pass
        if marker_written:
            try:
                _write_text(FLCLASH_CONFIG, _strip_marker(new_text)
                            if "new_text" in locals() else target["text"])
            except OSError:
                pass
        try:
            _launch()
        except Exception:
            pass
        raise

    started = _launch()
    verified = _wait_verified(rules) if started else False
    kernel = _kernel_check("flclash", policy, rules)
    result = _status_flclash(target, _state()[0], "")
    result["kernel"] = kernel
    note = _kernel_note(kernel)
    if kernel["state"] == "mismatch":
        result["message"] = ("规则已写入，但" + note +
                             "。FlClash 可能没重新生成配置，可撤销后重试。")
    elif not started:
        result["message"] = "规则已写入，但 FlClash 没有重新启动；请手动打开它后重新扫描。"
    elif not verified:
        result["message"] = ("规则已写入，但没在重新生成的配置里看到它们；"
                             "FlClash 可能没有重新加载。可撤销后重试。")
    else:
        result["message"] = (f"已把 {len(rules)} 条 Claude/STUN 规则置顶到 "
                             f"{_policy_label(policy, port)}，"
                             f"并重启 FlClash；{note}")
    result["verified"] = verified and kernel["state"] != "mismatch"
    return result


def _wait_rules(rules, present, timeout=15):
    expected = set()
    for rule in rules:
        parts = rule.split(",")
        if len(parts) >= 2:
            expected.add((parts[0].upper(), parts[1].lower()))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = FLCLASH_CONFIG.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        seen = _config_rules(text)
        if present and expected <= seen:
            return True
        if not present and not (expected & seen):
            return True
        time.sleep(0.4)
    return False


def _wait_verified(rules, timeout=15):
    return _wait_rules(rules, True, timeout)


def _wait_cleared(rules, timeout=15):
    return _wait_rules(rules, False, timeout)


def _undo_flclash():
    saved, _ = _state(strict=True)
    if not saved:
        raise ValueError("没有本工具留下的分流修复记录")
    try:
        con = sqlite3.connect(f"file:{FLCLASH_DB}?mode=ro", uri=True, timeout=5)
        try:
            cols = _db_columns(con)
            if not {"id", "rule_action", "content", "rule_target"} <= cols:
                raise ValueError("FlClash 数据库结构不认识，未撤销")
            rows = {row[0]: (row[1], row[2], row[3]) for row in con.execute(
                "select id, rule_action, content, rule_target from rules "
                "where profile_id is null")}
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise ValueError(f"读不到 FlClash 附加规则：{exc}") from exc

    doomed = [i for i in saved["ids"] if i in rows]
    # 端口那三条可能指向 REJECT 而不是代理组，逐条按记录里的策略核对，
    # 不能拿一个 policy 去套全部。
    base_policy = saved.get("policy") or ""
    for rid in doomed:
        action, payload, target = rows[rid]
        kind = action.replace("_", "-").upper()
        base = base_policy or target
        expected = _wanted(kind, base, _port_target(base, saved.get("portMode")))
        if payload not in DOMAINS and payload not in PORTS:
            raise ValueError("附加规则已被手动修改，未撤销；请在 FlClash 里检查")
        if kind not in ("DOMAIN-SUFFIX", "DST-PORT"):
            raise ValueError("附加规则已被手动修改，未撤销；请在 FlClash 里检查")
        if target != expected:
            raise ValueError("附加规则已被手动修改，未撤销；请在 FlClash 里检查")

    was_running = _proc_alive()
    quit_done = False
    if doomed:
        if not _quit():
            raise RuntimeError("FlClash 没有退出；请手动退出后再撤销。配置未修改。")
        quit_done = True

    if doomed:
        con = sqlite3.connect(FLCLASH_DB, timeout=10)
        try:
            with con:
                con.execute(
                    f"delete from rules where id in ({','.join('?' * len(doomed))})",
                    doomed,
                )
        finally:
            con.close()

    # 运行配置里可能还留着我们插入的标记块（客户端没重新生成过）。
    try:
        text = FLCLASH_CONFIG.read_text(encoding="utf-8", errors="replace")
        cleaned = _strip_marker(text)
        if cleaned != text:
            _write_text(FLCLASH_CONFIG, cleaned)
    except OSError:
        pass

    STATE.unlink(missing_ok=True)
    shield_state.clear_rule_guard()
    started = _launch() if (quit_done and was_running) else True
    cleared = _wait_cleared(saved.get("rules") or []) if quit_done and was_running else False
    target_now, _ = _target_flclash()
    result = (_status_flclash(target_now, _state()[0], "") if target_now
              else status())
    kernel = _kernel_check("flclash", "", saved.get("rules") or [], expect="absent")
    result["kernel"] = kernel
    if kernel["state"] == "mismatch":
        result["message"] = ("附加规则已删除，但" + _kernel_note(kernel) +
                             "；请再重启一次 FlClash。")
    elif not started:
        result["message"] = "附加规则已删除，但 FlClash 没有重新启动；请手动打开。"
    elif quit_done and was_running and not cleared:
        result["message"] = ("附加规则已删除，但运行配置里仍能看到它们；"
                             "请再重启一次 FlClash。")
    else:
        result["message"] = f"已删除本工具写入的 {len(doomed)} 条附加规则。"
    result["verified"] = (((not quit_done) or (started and cleared))
                          and kernel["state"] != "mismatch")
    return result


# ---------------------------------------------------------------- Verge / ClashX

def _quit_verge():
    return _quit_named("Clash Verge", VERGE_PROC)


def _launch_verge():
    return _launch_named(VERGE_APP_CANDIDATES, VERGE_BUNDLES, VERGE_PROC)


def _quit_clashx():
    return _quit_named("ClashX", CLASHX_PROC)


def _launch_clashx():
    return _launch_named(CLASHX_APP_CANDIDATES, CLASHX_BUNDLES, CLASHX_PROC)


def _rule_pairs(rules):
    pairs = set()
    for rule in rules:
        parts = rule.split(",")
        if len(parts) >= 2:
            pairs.add((parts[0].upper(), parts[1].lower()))
    return pairs


def _wait_verge(rules, present, timeout=15):
    expected = _rule_pairs(rules)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cfg = _verge_config()
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace") if cfg else ""
        except OSError:
            text = ""
        seen = _config_rules(text)
        if present and expected <= seen:
            return True
        if not present and not (expected & seen):
            return True
        time.sleep(0.4)
    return False


def _wait_clashx(rules, present, timeout=15):
    expected = _rule_pairs(rules)
    cfg = _clashx_config()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace") if cfg else ""
        except OSError:
            text = ""
        seen = _config_rules(text)
        if present and expected <= seen:
            return True
        if not present and not (expected & seen):
            return True
        time.sleep(0.4)
    return False


def _kernel_specs(rules):
    """[(类型, 载荷, 期望策略)]。

    带上每条自己的策略：端口可能被写成 REJECT，拿一个 policy 去套全部规则
    会把「按设计拒掉」误判成「指向了别的策略」。
    """
    specs = []
    for rule in rules or []:
        parts = [p.strip() for p in str(rule).split(",")]
        if len(parts) >= 2:
            specs.append((parts[0], parts[1],
                          parts[2] if len(parts) >= 3 else ""))
    return specs


def _kernel_dirs(kind):
    """控制接口的配置在哪个目录。找不到就返回空，判定为「没法核对」。"""
    if kind == "flclash":
        return [FLCLASH_DIR]
    if kind == "clash-verge":
        root = _verge_root()
        return [root] if root else []
    if kind == "clashx":
        cfg = _clashx_config()
        return [cfg.parent] if cfg else []
    return []


def _kernel_check(kind, policy, rules, expect="present"):
    """问一次内核。

    这是「写完配置」之外唯一能证明它真的生效的办法：文件里有，不等于
    内核加载了。查不到控制接口时返回 unavailable，不是失败。
    """
    specs = _kernel_specs(rules)
    if not specs:
        return {"state": "unavailable", "reason": "没有可核对的规则",
                "matched": 0, "missing": [], "node": "", "nodeType": "",
                "udp": None, "expect": expect}
    try:
        return kernelcheck.verify(_kernel_dirs(kind), specs, policy, expect)
    except Exception as exc:            # 核对本身不许把修复流程搞崩
        return {"state": "unavailable", "reason": f"核对失败（{type(exc).__name__}）",
                "matched": 0, "missing": [], "node": "", "nodeType": "",
                "udp": None, "expect": expect}


def _kernel_note(kernel):
    """把核对结果拼成一句话，接在原有提示后面。"""
    state = kernel.get("state")
    if state == "unavailable":
        return "本机没有可用的 Clash 控制接口，无法核对内核是否真的加载；请手动确认客户端里规则已生效。"
    if state == "global":
        return "内核处于全局模式，规则不参与匹配。"
    return kernelcheck.describe(kernel)


def _apply_verge(port_mode="proxy"):
    saved, _ = _state(strict=True)
    if saved:
        raise ValueError("已有未撤销的分流修复，请先撤销")
    target, error = _target_verge(port_mode)
    if not target:
        raise ValueError(error)
    if target["mode"] == "global":
        raise ValueError("Clash Verge 当前是全局模式，全部流量已经走代理，不需要写入规则")
    if not target["running"]:
        raise ValueError("Clash Verge 没有运行；请先启动它，再执行修复")
    if _verge_block_text(target["scriptText"]):
        raise ValueError("Script.js 里已有本工具的标记块，但没有撤销记录；请先手动处理")
    _, _, missing, err = _coverage_verge(target["scriptText"], target["portMode"])
    if err:
        raise ValueError(err)
    rules = target["rules"]
    if not missing:
        shield_state.record_rule_guard(
            "clash-verge", "Clash Verge Script.js", target["script"], rules)
        return {**_status_verge(target, None, ""), "message": "规则已经齐全，没有修改。"}

    new_text = _verge_inject(target["scriptText"], rules)
    if not new_text:
        raise ValueError("Script.js 的 main(config) 结构不认识"
                         "（找不到单独一行的 return config），未修改")
    if _verge_strip(new_text) != _verge_strip(target["scriptText"]):
        raise ValueError("注入后无法无损还原 Script.js，未修改")
    block = _verge_block_text(new_text)
    script = target["script"]
    if script.is_symlink():
        raise ValueError("Script.js 是符号链接，未修改")

    if not _quit_verge():
        raise RuntimeError("Clash Verge 没有退出；请手动退出后再修复。配置未修改。")

    written, state_written = False, False
    try:
        _write_text(script, new_text)
        written = True
        _write_state({
            "version": 1,
            "createdAt": time.time(),
            "client": "clash-verge",
            "config": str(script),
            "script": str(script),
            "policy": target["policy"],
            "portMode": target["portMode"],
            "rules": rules,
            "block": block,
        })
        state_written = True
        shield_state.record_rule_guard(
            "clash-verge", "Clash Verge Script.js", script, rules)
    except Exception:
        if written and not state_written:
            try:
                _write_text(script, target["scriptText"])
            except OSError:
                pass
        try:
            _launch_verge()
        except Exception:
            pass
        raise

    started = _launch_verge()
    verified = _wait_verge(rules, True) if started else False
    # 配置文本里有了，还要问内核是不是真的加载了：Script.js 没启用、代理组
    # 被订阅改掉、节点不支持 UDP，这三种都不会报错，只是安静地不生效。
    kernel = _kernel_check("clash-verge", target["policy"], rules)
    now_target, _ = _target_verge()
    result = (_status_verge(now_target, _state()[0], "") if now_target
              else status())
    result["kernel"] = kernel
    note = _kernel_note(kernel)
    if kernel["state"] == "mismatch":
        result["message"] = ("规则已写入 Script.js，但" + note +
                             "。请确认全局扩展脚本已启用、代理组存在，且节点支持 UDP。")
    elif not started:
        result["message"] = "规则已写入 Script.js，但 Clash Verge 没有重新启动；请手动打开。"
    elif not verified:
        result["message"] = ("规则已写入 Script.js，但没在重新生成的配置里看到它们；"
                             "Clash Verge 可能还没重新应用订阅，可稍后重新扫描或撤销后重试。")
    else:
        result["message"] = (f"已把 {len(rules)} 条 Claude/STUN 规则置顶到 "
                             f"{_policy_label(target['policy'], target['portPolicy'])}，"
                             f"并重启 Clash Verge；{note}")
    try:
        block_ok = _verge_block_text(script.read_text(
            encoding="utf-8", errors="replace")) == block
    except OSError:
        block_ok = False
    result["verified"] = (verified or block_ok) and kernel["state"] != "mismatch"
    return result


def _undo_verge(saved):
    script = Path(saved.get("config") or "")
    if not script.is_file():
        raise ValueError("Clash Verge 的 Script.js 不在了，未撤销")
    if script.is_symlink():
        raise ValueError("Script.js 是符号链接，未撤销")
    try:
        text = script.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"读不到 Script.js：{exc}") from exc
    if _verge_block_text(text) != saved.get("block"):
        raise ValueError("Script.js 里的标记块已被手动修改，未撤销；请在客户端里检查")
    cleaned = _verge_strip(text)

    was_running = _proc_alive(VERGE_PROC)
    quit_done = False
    if was_running:
        if not _quit_verge():
            raise RuntimeError("Clash Verge 没有退出；请手动退出后再撤销。配置未修改。")
        quit_done = True
    _write_text(script, cleaned)
    STATE.unlink(missing_ok=True)
    shield_state.clear_rule_guard()
    started = _launch_verge() if (quit_done and was_running) else True
    try:
        cleared = not _verge_block_text(script.read_text(encoding="utf-8",
                                                         errors="replace"))
    except OSError:
        cleared = False
    now_target, _ = _target_verge()
    result = (_status_verge(now_target, _state()[0], "") if now_target
              else status())
    kernel = _kernel_check("clash-verge", "", saved.get("rules") or [], expect="absent")
    result["kernel"] = kernel
    if kernel["state"] == "mismatch":
        result["message"] = ("标记块已删除，但" + _kernel_note(kernel) +
                             "；请再重启一次 Clash Verge。")
    elif not started:
        result["message"] = "Script.js 已清理，但 Clash Verge 没有重新启动；请手动打开。"
    elif not cleared:
        result["message"] = "标记块已删除，但 Script.js 里仍能看到它；请检查文件权限。"
    else:
        result["message"] = f"已删除本工具写入的 {len(saved.get('rules') or [])} 条置顶规则。"
    result["verified"] = (((not quit_done) or (started and cleared))
                          and kernel["state"] != "mismatch")
    return result


def _apply_clashx(port_mode="proxy"):
    saved, _ = _state(strict=True)
    if saved:
        raise ValueError("已有未撤销的分流修复，请先撤销")
    target, error = _target_clashx(port_mode)
    if not target:
        raise ValueError(error)
    if target["mode"] == "global":
        raise ValueError("ClashX 当前是全局模式，全部流量已经走代理，不需要写入规则")
    if not target["running"]:
        raise ValueError("ClashX 没有运行；请先启动它，再执行修复")
    if _marker_block_text(target["text"]):
        raise ValueError("config.yaml 里已有本工具的标记块，但没有撤销记录；请先手动处理")
    _, _, missing, err = _coverage_clashx(target["text"], target["portMode"])
    if err:
        raise ValueError(err)
    rules = target["rules"]
    if not missing:
        shield_state.record_rule_guard(
            "clashx", "ClashX config.yaml", target["config"], rules)
        return {**_status_clashx(target, None, ""), "message": "规则已经齐全，没有修改。"}

    new_text = _inject_rules(target["text"], rules)
    if not new_text:
        raise ValueError("config.yaml 里没有可插入的 rules: 段（行内数组不支持），未修改")
    if _strip_marker(new_text) != _strip_marker(target["text"]):
        raise ValueError("注入后无法无损还原 config.yaml，未修改")
    block = _marker_block_text(new_text)
    cfg = target["config"]

    if not _quit_clashx():
        raise RuntimeError("ClashX 没有退出；请手动退出后再修复。配置未修改。")

    written, state_written = False, False
    try:
        _write_text(cfg, new_text)
        written = True
        _write_state({
            "version": 1,
            "createdAt": time.time(),
            "client": "clashx",
            "config": str(cfg),
            "policy": target["policy"],
            "portMode": target["portMode"],
            "rules": rules,
            "block": block,
        })
        state_written = True
        shield_state.record_rule_guard(
            "clashx", "ClashX config.yaml", cfg, rules)
    except Exception:
        if written and not state_written:
            try:
                _write_text(cfg, target["text"])
            except OSError:
                pass
        try:
            _launch_clashx()
        except Exception:
            pass
        raise

    started = _launch_clashx()
    verified = _wait_clashx(rules, True) if started else False
    kernel = _kernel_check("clashx", target["policy"], rules)
    now_target, _ = _target_clashx()
    result = (_status_clashx(now_target, _state()[0], "") if now_target
              else status())
    result["kernel"] = kernel
    note = _kernel_note(kernel)
    if kernel["state"] == "mismatch":
        result["message"] = ("规则已写入 config.yaml，但" + note +
                             "。ClashX 可能用订阅重写了配置。")
    elif not started:
        result["message"] = "规则已写入 config.yaml，但 ClashX 没有重新启动；请手动打开。"
    elif not verified:
        result["message"] = ("规则已写入 config.yaml，但重启后没看到它们；"
                             "ClashX 可能用订阅重写了配置，可撤销后重试或改用 Clash Verge。")
    else:
        result["message"] = (f"已把 {len(rules)} 条 Claude/STUN 规则置顶到 "
                             f"{_policy_label(target['policy'], target['portPolicy'])}，"
                             f"并重启 ClashX；{note}")
    try:
        block_ok = _marker_block_text(cfg.read_text(
            encoding="utf-8", errors="replace")) == block
    except OSError:
        block_ok = False
    result["verified"] = (verified or block_ok) and kernel["state"] != "mismatch"
    return result


def _undo_clashx(saved):
    cfg = Path(saved.get("config") or "")
    if not cfg.is_file():
        raise ValueError("ClashX 的 config.yaml 不在了，未撤销")
    if cfg.is_symlink():
        raise ValueError("config.yaml 是符号链接，未撤销")
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"读不到 ClashX 配置：{exc}") from exc
    if _marker_block_text(text) != saved.get("block"):
        raise ValueError("config.yaml 里的标记块已被手动修改，未撤销；请检查配置")

    was_running = _proc_alive(CLASHX_PROC)
    quit_done = False
    if was_running:
        if not _quit_clashx():
            raise RuntimeError("ClashX 没有退出；请手动退出后再撤销。配置未修改。")
        quit_done = True
    _write_text(cfg, _strip_marker(text))
    STATE.unlink(missing_ok=True)
    shield_state.clear_rule_guard()
    started = _launch_clashx() if (quit_done and was_running) else True
    try:
        cleared = not _marker_block_text(cfg.read_text(encoding="utf-8",
                                                       errors="replace"))
    except OSError:
        cleared = False
    now_target, _ = _target_clashx()
    result = (_status_clashx(now_target, _state()[0], "") if now_target
              else status())
    kernel = _kernel_check("clashx", "", saved.get("rules") or [], expect="absent")
    result["kernel"] = kernel
    if kernel["state"] == "mismatch":
        result["message"] = ("标记块已删除，但" + _kernel_note(kernel) +
                             "；请再重启一次 ClashX。")
    elif not started:
        result["message"] = "config.yaml 已清理，但 ClashX 没有重新启动；请手动打开。"
    elif not cleared:
        result["message"] = "标记块已删除，但 config.yaml 里仍能看到它；请检查文件权限。"
    else:
        result["message"] = f"已删除本工具写入的 {len(saved.get('rules') or [])} 条置顶规则。"
    result["verified"] = (((not quit_done) or (started and cleared))
                          and kernel["state"] != "mismatch")
    return result


def _apply(port_mode="proxy"):
    target, error = _target(port_mode)
    if not target:
        raise ValueError(error)
    if target.get("manual"):
        raise ValueError(target["name"] + " 不支持自动改写；请按面板里的手动步骤添加规则")
    if target["kind"] == "flclash":
        return _apply_flclash(port_mode)
    if target["kind"] == "clash-verge":
        return _apply_verge(port_mode)
    if target["kind"] == "clashx":
        return _apply_clashx(port_mode)
    raise ValueError("暂不支持自动改写这个客户端")


def _undo():
    saved, _ = _state(strict=True)
    if not saved:
        raise ValueError("没有本工具留下的分流修复记录")
    kind = saved.get("client") or "flclash"
    if kind == "flclash":
        return _undo_flclash()
    if kind == "clash-verge":
        return _undo_verge(saved)
    if kind == "clashx":
        return _undo_clashx(saved)
    raise ValueError("分流修复记录里的客户端未知，未撤销")


def apply(action, port_mode="proxy"):
    if not compat.IS_MAC:
        raise ValueError("此功能仅支持 macOS")
    mode = str(port_mode or "proxy").strip().lower()
    if mode not in PORT_MODES:
        raise ValueError("端口策略只能是 proxy（跟着代理组）或 reject（直接拒绝）")
    with LOCK:
        try:
            _state_guard()
            if action == "apply":
                return _apply(mode)
            if action == "undo":
                return _undo()
        except sqlite3.Error as exc:
            raise RuntimeError(f"FlClash 数据库操作失败：{exc}") from exc
        raise ValueError("未知操作")
