"""深层检测：环境标记特征、会话画像、网络链路深挖、权限配置。

这一层对应 claude-env-inspector 里我们之前没有的盲区：
二进制特征签名、渲染标记、MITM 根证书、会话节奏画像、DNSBL、
PAC/Clash 分流规则、IPv6 泄露面、launchd 全局环境变量、高危权限配置。
全部为只读检测；能安全清理的项会带 fix，其余只给证据与建议。

按编号分节，跟 tower.py 里的关卡号一一对应（搜「---- N-M」可跳转）：

    1-5  launchd 全局环境变量
    2-4  多版本残留
    2-6  环境标记特征扫描
    2-7  会话画像（节奏 + 自动化痕迹）
    2-8  浏览器集成
    2-x  遥测文件残留（可清理）
    3-6  分流法阵（PAC + Clash/Mihomo + 隧道 + 代理进程）
    3-7  暗哨名录（DNSBL）
    3-8  截听之证（MITM 根证书）
    3-9  IPv6 暗门
    4-6  权限裂隙（高危配置 + 隐私开关）

各节之间没有共享状态，唯一的耦合是底部的 _item / _ev 两个构造函数。
之所以还没拆成多个文件：这些检查彼此独立但都很短，拆开之后每个文件
只剩两三个函数，反而更难按「第几关」去找。真要拆，按上面编号分组最自然。
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import (compat, kernelcheck, proxydns, proxyguard, resolveregress, shellenv,
               stun, telemetry, terminalegress, vmnetwork)

HOME = Path.home()
CLAUDE_DIR = HOME / ".claude"
CLAUDE_JSON = HOME / ".claude.json"


# ---------------------------------------------------------------- 基础工具（与 scanner 同款，局部复刻避免环引用）


def _run(cmd: list[str], timeout: float = 6.0) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return (out.stdout or "").strip()
    except Exception:
        return ""


def _item(id, category, title, severity, detail, evidence=None, advice="", fix=None):
    return {
        "id": id,
        "category": category,
        "title": title,
        "severity": severity,
        "detail": detail,
        "evidence": evidence or [],
        "advice": advice,
        "fix": fix,
        "tags": [],
    }


def _ev(label: str, value: str, mono: bool = False) -> dict:
    return {"label": label, "value": value, "mono": mono}


def _path_size(path: Path) -> tuple[int, int]:
    total, count = 0, 0
    if not path.exists():
        return 0, 0
    if path.is_file():
        try:
            return path.stat().st_size, 1
        except OSError:
            return 0, 1
    for root, _d, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
                count += 1
            except OSError:
                continue
    return total, count


def _human(n: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u in ("B", "KB") else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} GB"


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 8:
        return val[:2] + "****"
    return val[:4] + "****" + val[-4:]


# ---------------------------------------------------------------- 2-6 环境标记特征扫描

# 客户端二进制里被公开分析出的"环境标记"实现特征（字节级字符串）
_BINARY_SIGS: list[tuple[str, list[bytes], bool]] = [
    ("assume-first-party-base-url", [b"_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL"], False),
    ("cn-timezone-table", [b"Asia/Shanghai", b"Asia/Urumqi"], True),
    ("invisible-apostrophe-table", [b"\\u2019", b"\\u02BC", b"\\u02B9"], False),
    ("date-inject-template", [b"Today${", b"s date is ${"], True),
    ("date-dash-rewrite", [b'replaceAll("-","/")'], False),
    ("b64-xor-obfuscation", [b"Buffer.from(", b'"base64"', b"String.fromCharCode"], True),
    ("lab-keyword-table", [b"labKw", b"cnTZ", b"host:null"], True),
]

# 渲染标记：写入会话内容里的隐形字符日期（非 ASCII 撇号 = 标记特征）
_RENDERED_RE = re.compile(r"Today[’ʼʹ]s date is", re.U)


def _client_binaries() -> list[Path]:
    """定位本机的 claude 客户端二进制/JS 入口。"""
    found: set[str] = set()
    for line in compat.which_claude():
        if line.strip():
            found.add(line.strip())
    candidates = [CLAUDE_DIR / "local" / "claude"]
    if compat.IS_WIN:
        ra = Path(os.environ.get("APPDATA", str(HOME)))
        candidates += [
            ra / "npm" / "claude.cmd",
            ra / "npm" / "node_modules" / "@anthropic-ai" / "claude-code" / "cli.js",
            ra / "npm" / "claude.exe",
        ]
    else:
        candidates += [
            Path("/usr/local/bin/claude"),
            Path("/opt/homebrew/bin/claude"),
            Path("/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"),
            Path("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"),
            HOME / ".npm-global" / "lib" / "node_modules" / "@anthropic-ai" / "claude-code" / "cli.js",
        ]
    versions = CLAUDE_DIR / "local" / "versions"
    if versions.is_dir():
        candidates.extend(versions.iterdir())
    for c in candidates:
        if c.is_file():
            found.add(str(c))
    # which 出来的是 shim 的话跟到真实文件
    out = []
    for p in sorted(found):
        path = Path(p)
        try:
            real = path.resolve()
        except OSError:
            real = path
        if real.is_file():
            out.append(real)
    return out[:6]


def _scan_marker_sigs(path: Path, limit: int = 90 * 1024 * 1024) -> list[str]:
    try:
        if path.stat().st_size > limit:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    hits = []
    for sig_id, pats, require_all in _BINARY_SIGS:
        matched = [p in data for p in pats]
        if (all(matched) if require_all else any(matched)):
            hits.append(sig_id)
    return hits


def _scan_rendered_markers() -> list[str]:
    """在最近的项目 jsonl 里找渲染出来的标记文本。"""
    proj = CLAUDE_DIR / "projects"
    if not proj.is_dir():
        return []
    files = sorted(proj.glob("*/*.jsonl"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    hits = []
    budget = 40 * 1024 * 1024
    for f in files[:80]:
        if budget <= 0:
            break
        try:
            data = f.read_bytes()[:budget]
            budget -= len(data)
        except OSError:
            continue
        if _RENDERED_RE.search(data.decode("utf-8", "replace")):
            hits.append(str(f).replace(str(HOME), "~"))
    return hits[:5]


def check_marker_signature() -> dict:
    bins = _client_binaries()
    sig_hits: dict[str, list[str]] = {}
    for b in bins:
        hits = _scan_marker_sigs(b)
        if hits:
            sig_hits[str(b).replace(str(HOME), "~")] = hits
    rendered = _scan_rendered_markers()

    ev: list[dict] = []
    for path, sigs in sig_hits.items():
        ev.append(_ev("特征命中", f"{path} → {', '.join(sigs[:4])}", mono=True))
    for r in rendered:
        ev.append(_ev("渲染标记", r, mono=True))

    if rendered:
        return _item(
            "fp.markers", "marker",
            f"检测到已渲染的环境标记（{len(rendered)} 处会话记录）",
            "high",
            "客户端把不可见字符写进了会话内容——这类标记就是用来给环境打指纹的，"
            "历史会话里已经有它的痕迹。",
            ev,
            "标记注入由客户端完成，不能靠删文件根治；换一条干净的安装与出口，并清理旧会话记录。",
        )
    if sig_hits:
        return _item(
            "fp.markers", "marker",
            "客户端携带环境标记机制（未渲染）",
            "info",
            "本地客户端二进制里包含标记实现代码——这是官方客户端自带的判定机制，"
            "说明它有能力上报环境特征；当前会话里还没发现渲染出来的标记文本。",
            ev or [_ev("说明", "官方客户端都带这套机制，属于常态")],
            "机制本身没法删；要它不上报，靠的是别让客户端读到触发条件（中转地址、CN 时区等）。",
        )
    if not bins:
        return _item(
            "fp.markers", "marker",
            "未找到 claude 客户端，无法扫描标记特征",
            "pass",
            "没有客户端就没有标记载体。",
        )
    return _item(
        "fp.markers", "marker",
        "客户端未检出标记特征",
        "pass",
        "二进制与最近会话记录里都没见到已知的标记实现。",
        ev,
    )


# ---------------------------------------------------------------- 2-7 会话画像（节奏 + 自动化痕迹）


def _iter_jsonl_ts() -> list[float]:
    proj = CLAUDE_DIR / "projects"
    if not proj.is_dir():
        return []
    files = sorted(
        (p for p in proj.glob("*/*.jsonl") if p.is_file()),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )[:60]
    ts: list[float] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if '"timestamp"' not in line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            raw = obj.get("timestamp")
            if not isinstance(raw, str):
                continue
            try:
                ts.append(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
            except Exception:
                continue
        if len(ts) > 40000:
            break
    return ts


def check_rhythm() -> dict:
    ts = _iter_jsonl_ts()
    signals = []
    ev: list[dict] = []

    cron = _run(["crontab", "-l"], 4)
    cron_hits = [ln for ln in cron.splitlines() if "claude" in ln.lower() and not ln.lstrip().startswith("#")]
    hist_hits = 0
    for hist in (HOME / ".zsh_history", HOME / ".bash_history"):
        try:
            for ln in hist.read_text(encoding="utf-8", errors="replace").splitlines()[-3000:]:
                low = ln.lower()
                if "claude" in low and re.search(r"(for .+ do|xargs|while read|\|\s*while|yes \|)", low):
                    hist_hits += 1
        except OSError:
            continue
    if cron_hits:
        signals.append(f"crontab 里有 {len(cron_hits)} 条 claude 定时任务")
        ev.append(_ev("crontab", cron_hits[0][:90], mono=True))
    if hist_hits:
        signals.append(f"shell 历史里有 {hist_hits} 条批量调用模式")

    if not ts and not signals:
        return _item(
            "fp.rhythm", "fingerprint",
            "没有可分析的会话节奏",
            "pass",
            "本地没有会话记录，也找不到自动化调用痕迹。",
        )

    detail_bits = []
    if ts:
        ts.sort()
        span_days = max(1.0, (ts[-1] - ts[0]) / 86400)
        per_day = len(ts) / span_days
        # 每分钟最大并发（滑动窗口近似）
        buckets: dict[int, int] = {}
        night = 0
        for t in ts:
            buckets[int(t // 60)] = buckets.get(int(t // 60), 0) + 1
            if datetime.fromtimestamp(t).hour < 7:
                night += 1
        max_per_min = max(buckets.values())
        night_ratio = night / len(ts)
        ev.append(_ev("事件", f"{len(ts)} 条 / {span_days:.0f} 天（日均 {per_day:.0f}）"))
        ev.append(_ev("峰值", f"单分钟最高 {max_per_min} 次 · 凌晨占比 {night_ratio * 100:.0f}%", mono=True))
        detail_bits.append(
            f"{len(ts)} 条事件 / {span_days:.0f} 天，日均 {per_day:.0f} 次，"
            f"单分钟峰值 {max_per_min} 次，凌晨时段占 {night_ratio * 100:.0f}%。"
        )
        if max_per_min > 40:
            signals.append(f"单分钟爆发 {max_per_min} 次")
        if per_day > 300:
            signals.append(f"日均 {per_day:.0f} 次")
        if night_ratio > 0.3 and len(ts) > 200:
            signals.append(f"{night_ratio * 100:.0f}% 请求发生在凌晨")

    detail = (
        "会话时间戳构成使用画像：间隔、爆发、昼夜分布都会被拿来判断是人在敲还是脚本在跑。"
        + " ".join(detail_bits)
    )
    if signals:
        return _item(
            "fp.rhythm", "fingerprint",
            "会话节奏命中自动化画像",
            "medium",
            detail + "注：Claude Code 自身的多 agent 并发也会造成短爆发，需结合 crontab/历史命令综合判断。",
            ev,
            "这不是清理能解决的画像——把它当体检指标看：降低并发、拉长间隔、避开整点定时模式。",
        )
    return _item(
        "fp.rhythm", "fingerprint",
        "会话节奏在人工范围内",
        "pass",
        detail or "事件量不足以构成画像。",
        ev,
    )


# ---------------------------------------------------------------- 2-8 浏览器集成

_BROWSER_ROOTS = [(n, p) for n, ps in compat.browser_dirs().items() for p in ps]

_NATIVE_MSG = [
    "com.anthropic.claude_browser_extension.json",
    "com.anthropic.claude_code_browser_extension.json",
]


def _browser_profiles(root: Path) -> list[Path]:
    """列出浏览器配置目录。

    Chrome 系是 Default / Profile 1 / Profile 2；Firefox 是 `<随机>.default-release`，
    所以不能只按 Chrome 的命名规则过滤——否则 Firefox 一个都扫不到。
    """
    if not root.is_dir():
        return []
    out = [root]
    try:
        for p in root.iterdir():
            if not p.is_dir():
                continue
            if (
                p.name.startswith("Profile")
                or p.name in ("Default", "Guest Profile", "System Profile")
                or (p / "prefs.js").is_file()
            ):
                out.append(p)
    except OSError:
        pass
    return out


def _firefox_privacy(prof: Path) -> dict:
    """读 Firefox prefs.js 里的 WebRTC / 安全 DNS 开关。读不到会抛 OSError。"""
    f = prof / "prefs.js"
    if not f.is_file():
        return {}
    text = f.read_text(encoding="utf-8", errors="replace")
    out: dict = {}
    for key in ("media.peerconnection.enabled", "network.trr.mode", "network.trr.uri"):
        m = re.search(rf'user_pref\("{re.escape(key)}",\s*([^)]+)\);', text)
        if m:
            out[key] = m.group(1).strip().strip('"')
    return out


def _chromium_privacy(root: Path) -> dict:
    """读 Chromium 系 Local State 里的安全 DNS 配置。读不到会抛 OSError。"""
    f = root / "Local State"
    if not f.is_file():
        return {}
    try:
        data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return {}
    d = data.get("dns_over_https") or {}
    return {"doh_mode": d.get("mode") or "", "doh_templates": d.get("templates") or ""}


def check_browser() -> dict:
    ev: list[dict] = []
    ext_hits, native_hits, site_hits = [], [], []
    webrtc_on: list[str] = []
    doh_off: list[str] = []
    blocked: list[str] = []
    for name, root in _BROWSER_ROOTS:
        if not root.is_dir():
            continue
        # 隐私开关：浏览器有自己一套网络栈，系统代理管不到它
        if name == "Firefox":
            for prof in _browser_profiles(root):
                try:
                    p = _firefox_privacy(prof)
                except OSError:
                    if f"{name}/{prof.name}" not in blocked:
                        blocked.append(f"{name}/{prof.name}")
                    continue
                if not p:
                    continue
                if p.get("media.peerconnection.enabled", "true") != "false":
                    webrtc_on.append(f"{name}/{prof.name}")
                if p.get("network.trr.mode", "0") in ("0", "5"):
                    doh_off.append(f"{name}/{prof.name}")
        else:
            try:
                p = _chromium_privacy(root)
            except OSError:
                blocked.append(name)
                p = {}
            if p and (p.get("doh_mode") or "off") in ("off", "secure_off"):
                doh_off.append(name)
        for prof in _browser_profiles(root):
            # 原生消息宿主 manifest
            nm = prof / "NativeMessagingHosts"
            if nm.is_dir():
                try:
                    for f in nm.iterdir():
                        if "claude" in f.name.lower() or "anthropic" in f.name.lower():
                            native_hits.append(f"{name}: {f.name}")
                except OSError:
                    if name not in blocked:
                        blocked.append(name)
            # Local Storage 里的 claude.ai 站点数据
            ls = prof / "Local Storage" / "leveldb"
            if ls.is_dir():
                try:
                    if any("claude.ai" in f.name or "anthropic" in f.name for f in ls.iterdir()):
                        site_hits.append(f"{name}/{prof.name}")
                except OSError:
                    if name not in blocked:
                        blocked.append(name)
            # 扩展目录里直接带 claude/anthropic 名字的
            ext = prof / "Extensions"
            if ext.is_dir():
                try:
                    for f in ext.iterdir():
                        if "claude" in f.name.lower() or "anthropic" in f.name.lower():
                            ext_hits.append(f"{name}/{prof.name}: {f.name[:20]}")
                except OSError:
                    if name not in blocked:
                        blocked.append(name)
    for h in native_hits[:3]:
        ev.append(_ev("原生消息宿主", h, mono=True))
    for h in ext_hits[:3]:
        ev.append(_ev("扩展目录", h, mono=True))
    for h in site_hits[:4]:
        ev.append(_ev("站点数据", h, mono=True))
    if webrtc_on:
        ev.append(_ev("WebRTC 未关闭", ", ".join(sorted(set(webrtc_on))[:3]), mono=True))
    if doh_off:
        ev.append(_ev("未启用安全 DNS", ", ".join(sorted(set(doh_off))[:3]), mono=True))
    if blocked:
        ev.append(_ev("读不到配置", ", ".join(sorted(set(blocked))[:3]), mono=True))

    total = len(native_hits) + len(ext_hits) + len(site_hits)
    leaks = len(webrtc_on) + len(doh_off)
    # WebRTC 会绕开代理直接暴露本机地址；DNS 不走加密解析时，查询会落回系统解析器
    if webrtc_on and doh_off:
        sev = "medium"
    elif leaks:
        sev = "low"
    elif total:
        sev = "medium" if (native_hits or ext_hits) else "info"
    else:
        sev = ""

    if sev:
        bits = []
        if total:
            bits.append(f"浏览器集成 {total} 处")
        if webrtc_on:
            bits.append("WebRTC 未关闭")
        if doh_off:
            bits.append("未启用安全 DNS")
        return _item(
            "res.browser", "residue",
            " · ".join(bits) if bits else "浏览器回声",
            sev,
            "浏览器里有自己一套网络栈：WebRTC 可以绕开系统代理直接协商连接并暴露本机地址，"
            "安全 DNS 没开时查询会落回系统解析器——出口在海外、解析却在本地，是很常见的错配。"
            "扩展与原生消息宿主还会复用同一账号，把网页指纹叠加到会话上。",
            ev,
            "WebRTC：Firefox 在 about:config 里把 media.peerconnection.enabled 设为 false；"
            "安全 DNS：Chrome 设置 → 隐私与安全 → 安全，或 Firefox 开启 DNS over HTTPS。",
        )
    if blocked:
        return _item(
            "res.browser", "residue",
            f"浏览器配置读不到（{len(set(blocked))} 个）",
            "info",
            ("macOS 的 TCC 保护挡住了 Chrome / Edge 的配置目录，这项检测没跑完。" if compat.IS_MAC else
             "浏览器配置目录读不到，这项检测没跑完。")
            + "注意：这不等于「浏览器里是干净的」，只是没读到。",
            ev,
            ("在「系统设置 → 隐私与安全性 → 完全磁盘访问权限」里给 CC Tower 授权后重新闯关。"
             if compat.IS_MAC else "确认目录权限后重新闯关。"),
        )
    return _item("res.browser", "residue", "浏览器里未发现 Claude 集成", "pass",
                 "没有扩展、没有原生消息宿主、没有站点数据；WebRTC 已关闭、安全 DNS 已启用。")


# ---------------------------------------------------------------- 4-6 权限裂隙（高危配置 + 隐私开关）

_TELEMETRY_KILL_VARS = [
    "DISABLE_TELEMETRY",
    "DISABLE_ERROR_REPORTING",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "DISABLE_FEEDBACK_COMMAND",
    "DO_NOT_TRACK",
]


def check_permissions() -> dict:
    files = [CLAUDE_DIR / "settings.json", CLAUDE_DIR / "settings.local.json", CLAUDE_JSON]
    risky: list[str] = []
    ev: list[dict] = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        blob = f.read_text(encoding="utf-8", errors="replace")
        perms = data.get("permissions") or {}
        if perms.get("defaultMode") == "bypassPermissions" or '"bypassPermissions"' in blob:
            risky.append(f"{f.name}: bypassPermissions")
        allow = perms.get("allow") or []
        wild = [a for a in allow if isinstance(a, str) and re.search(r"(Bash|\*)\s*\(.*\*\)|^\*$|^Bash$", a)]
        if wild:
            risky.append(f"{f.name}: 通配放行 {len(wild)} 条")
            ev.append(_ev("通配规则", wild[0][:80], mono=True))
    if risky:
        # 只挑写有 bypass/通配的那个文件做手术
        bad_files = sorted({r.split(":", 1)[0] for r in risky})
        target = CLAUDE_DIR / bad_files[0] if bad_files else CLAUDE_DIR / "settings.json"
        if bad_files and bad_files[0] == ".claude.json":
            target = CLAUDE_JSON
        return _item(
            "cfg.permissions", "behavior",
            f"高危权限配置 {len(risky)} 处",
            "medium",
            "bypassPermissions / 通配 allow 会让客户端不再向你确认就执行命令；"
            "这台机器上别人或脚本改过的配置，可能在你不知道的情况下处于放行状态。",
            [_ev("位置", r, mono=True) for r in risky[:4]] + ev,
            "一键收紧会把 bypassPermissions 改回默认、删掉通配放行；精细规则保留。",
            {"kind": "json_patch", "file": str(target),
             "title": f"收紧 {target.name} 的权限配置",
             "set": {"permissions.defaultMode": "default"},
             "filter": {"permissions.allow": r"(Bash|\*)\s*\(.*\*\)|^\*$|^Bash$"},
             "risk": "bypassPermissions 会被改成 default（逐条确认），通配放行条目被移除；你自己的精细 allow 规则保留。",
             "manual": f"手动：编辑 {str(target).replace(str(HOME), '~')}，把 defaultMode 改回 default 并删掉通配放行"},
        )
    return _item(
        "cfg.permissions", "behavior",
        "未发现高危权限配置",
        "pass",
        "没有 bypassPermissions 或通配放行；隐私通道由独立检测项展示。",
        [],
        "要关遥测可在 settings.json 的 env 里加 DISABLE_TELEMETRY=1 等开关。",
    )


# ---------------------------------------------------------------- 1-5 launchd 全局环境变量

_LAUNCHD_VARS = [
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL",
    "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
]


def check_launchd_env() -> dict:
    layer = "launchd 全局环境" if compat.IS_MAC else "持久化环境变量（注册表）"
    # *_proxy 变量由 check_proxy_env 专项覆盖，这里不重复计
    hits = [(h["name"], h["value"], h.get("scope", "")) for h in compat.persistent_env()
            if (h["name"] in _LAUNCHD_VARS or h["name"].startswith("ANTHROPIC"))
            and not h["name"].lower().endswith("_proxy")]
    if not hits:
        return _item("sys.launchd_env", "locale", f"{layer}无敏感变量", "pass",
                     "持久层环境域里没有 ANTHROPIC_* 或代理变量。")
    sev = "medium" if any(n.startswith("ANTHROPIC") for n, _, _ in hits) else "low"
    return _item(
        "sys.launchd_env", "locale",
        f"{layer}有 {len(hits)} 个敏感变量",
        sev,
        ("launchctl setenv 写入的变量会注入到登录会话的所有 GUI 进程" if compat.IS_MAC else
         "setx/注册表写入的变量会注入所有新启进程"),
        [_ev(n, _mask(v), mono=True) for n, v, _ in hits[:6]],
        "一键清理会逐个删除这些变量（不影响正在运行的进程）。",
        {"kind": "envvar",
         "vars": [{"name": n, "scope": s or ("launchd" if compat.IS_MAC else "用户")} for n, _, s in hits],
         "risk": "变量删除后新启进程读不到它；如果某工具还在依赖它会启动失败——先确认这些变量是谁写的。",
         "manual": ("手动：launchctl unsetenv <名> 逐个取消" if compat.IS_MAC else
                   "手动：系统属性 → 环境变量里删除")},
    )


# ---------------------------------------------------------------- 环境变量代理遗留（rc 文件 + launchd）

_PROXY_ENV_FILES = [".zshrc", ".bashrc", ".bash_profile", ".zprofile", ".profile", ".zshenv"]
_PROXY_ENV_RE = re.compile(r"^\s*(?:export\s+)?(https?_proxy|all_proxy|no_proxy)\s*=", re.I)
_PROXY_LAUNCHD_VARS = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def check_proxy_env() -> list:
    """启动脚本与持久层里的 *_proxy 变量：会静默劫持命令行流量，不走系统代理层。"""
    items: list[dict] = []
    for path in compat.rc_files():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        hits = [
            (i, m.group(1), ln.strip()[:70])
            for i, ln in enumerate(lines, 1)
            if not ln.lstrip().startswith("#") and (m := _PROXY_ENV_RE.match(ln))
        ]
        if not hits:
            continue
        items.append(_item(
            f"net.proxy_env.{path.name.replace('.', '_')}",
            "network",
            f"{path.name} 里留有 {len(hits)} 条代理环境变量",
            "medium",
            "启动脚本里的 http_proxy/https_proxy 会劫持终端里所有命令行程序的流量——"
            "它不走系统代理层，旧教程留下的失效地址会让 claude 直连一个已经死掉的代理，或者绕到你不知道的出口。",
            [_ev(var, raw, mono=True) for _, var, raw in hits[:5]],
            "确认这些变量还在不在用；清理会把对应行注释掉并备份。",
            {"kind": "shellrc", "file": str(path), "lines": [h[0] for h in hits]},
        ))
    ld = [h for h in compat.persistent_env() if h["name"].lower().endswith("_proxy")]
    if ld:
        layer = "launchd 全局环境" if compat.IS_MAC else "持久化环境变量"
        items.append(_item(
            "net.proxy_env.launchd",
            "network",
            f"{layer}里有 {len(ld)} 个代理变量",
            "medium",
            ("launchctl setenv 写进全局环境的代理变量会注入所有 GUI 进程" if compat.IS_MAC else
             "setx/注册表写入的代理变量会注入所有新启进程"),
            [_ev(h["name"], h["value"][:70], mono=True) for h in ld[:6]],
            "一键清理会逐个删除这些代理变量。",
            {"kind": "envvar",
             "vars": [{"name": h["name"], "scope": h.get("scope") or ("launchd" if compat.IS_MAC else "用户")} for h in ld],
             "risk": "代理变量删了之后新启进程直连——先确认这不是你正在用的代理。",
             "manual": ("手动：launchctl unsetenv <变量名>" if compat.IS_MAC else
                       "手动：系统属性 → 环境变量里删除")},
        ))
    if not items:
        items.append(_item("net.proxy_env", "network", "没有代理环境变量遗留", "pass",
                           "启动脚本与持久层环境都没有 *_proxy 变量。"))
    return items


# ---------------------------------------------------------------- 3-6 分流法阵（PAC + Clash/Mihomo + 隧道 + 代理进程）

_CLASH_ROOTS = compat.clash_roots()

_PROXY_PROC_KEYS = ("clash", "mihomo", "surge", "v2ray", "xray", "sing-box",
                    "shadowsock", "shadowrocket", "trojan", "stash", "quantumult",
                    "surfboard", "v2box", "clashx", "singbox", "loon", "outline",
                    "wireguard", "openvpn")

_TUN_ENABLED_RE = re.compile(r"^tun:\s*$[\s\S]{0,400}?enable:\s*true", re.M)
_TUN_ENABLED_FLOW_RE = re.compile(r"tun:.*?enable:.*?true", re.S)

# 代理节点的 server 字段。机场给的节点绝大多数写的是域名，
# 只认字面量 IP 会漏掉真实节点，于是「TUN 回环」这一项永远不报。
#
# 两种写法都要认：块式 `  - name: x` + `    server: host`，以及订阅里更常见的
# flow 式 `- {name: x, server: host, port: 443}`。前面的 (?<![A-Za-z0-9_-])
# 是为了避开 `nameserver:` / `default-nameserver:` —— 它们以 server: 结尾，
# 一旦误认就会把 DNS 服务器当成代理节点。
_SERVER_LINE = re.compile(r"(?<![A-Za-z0-9_-])server\s*:\s*[\"']?([^\s\"'#,}\]]+)")

# 解析结果里这些地址不能当作代理节点：fake-ip 是编造的，其余是回环/链路本地。
_UNUSABLE_SERVER_NETS = (
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def _server_hosts(text: str) -> tuple[set[str], set[str]]:
    """从配置里抠出代理服务器地址，分成「已是 IP」和「待解析的域名」两拨。"""
    ips: set[str] = set()
    names: set[str] = set()
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue  # 注释掉的老节点不算
        for raw in _SERVER_LINE.findall(line):
            host = raw.strip().strip("\"'")
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError:
                # 只认像主机名的，别把端口、占位符、变量名当成域名
                if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", host) and "." in host:
                    names.add(host)
            else:
                ips.add(host)
    return ips, names


def _usable_server_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in _UNUSABLE_SERVER_NETS)


def _resolve_all(names: set[str], budget: float = 3.0,
                 cap: int = 80) -> tuple[dict[str, list[str]], list[str]]:
    """并发解析域名，整体限时。

    用 threading 而不是 concurrent.futures：内置运行时为了瘦身把 concurrent
    整个包删了，import 不到。daemon 线程超时就丢下不管，不阻塞扫描。
    订阅里动辄上百个节点，cap 只是防手滑，实际去重后通常只有十几个域名。
    """
    if not names:
        return {}, []
    targets = sorted(names)[:cap]
    results: dict[str, list[str]] = {}
    lock = threading.Lock()

    def work(name: str) -> None:
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = sorted({i[4][0] for i in infos})
        except OSError:
            ips = []
        with lock:
            results[name] = ips

    threads = [threading.Thread(target=work, args=(n,), daemon=True) for n in targets]
    for t in threads:
        t.start()
    deadline = time.monotonic() + budget
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    with lock:
        snapshot = dict(results)
    return snapshot, sorted(n for n in targets if n not in snapshot)


# 匹配用的关键词不能是完整域名（claude.ai / anthropic.com / claudeusercontent.com
# / claude.com）：规则集里还常见 `DOMAIN-KEYWORD,anthropic` 和
# `GEOSITE,anthropic,PROXY` 这两种写法，一个 "anthropic.com" 都套不上。
_ECO_MATCH = ("anthropic", "claude")

# 这些策略等于「不走隧道」。DIRECT 是明文放行，REJECT 是直接掐断，
# 两种都算事故——区别只在于用户看到的是「裸奔」还是「连不上」。
_BLOCK_POLICY = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "BLOCK", "COMPATIBLE"}

# 只认这几种规则类型。代理节点定义（`- {name: ..., password: ...}`）也含
# claude 字样，但那是节点，不是分流规则；不设白名单会把密码当策略读出来。
_RULE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE",
    "GEOIP", "IP-ASN", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "DST-PORT",
    "SRC-PORT", "PROCESS-NAME", "PROCESS-PATH", "RULE-SET", "MATCH",
    "AND", "OR", "NOT", "SUB-RULE", "NETWORK",
}

# 只看「当前生效」的配置。订阅目录里动辄几十个 profile，把没启用的
# 订阅也扫进来，会把「某份订阅曾经写过 DIRECT」算成现在的事故。
_CONFIG_NAMES = (
    # 正在生效的合并结果优先；根目录的 config 往往是模板或旧副本
    "work/config.yaml", "work/config.yml",
    "config.yaml", "config.yml",
    "clash-verge.yaml", "clash-verge.yml",
    "mihomo.yaml", "mihomo.yml",
    "Merge.yaml", "Merge.yml",
    "override.yaml", "override.yml",
    "profile.yaml", "profile.yml",
    "profiles/Merge.yaml", "profiles/Merge.yml",
)


def _config_files(root: Path, limit: int = 4) -> list[Path]:
    """挑当前可能生效的配置文件，不遍历整个订阅目录。"""
    out: list[Path] = []
    for name in _CONFIG_NAMES:
        p = root / name
        try:
            if p.is_file() and p.stat().st_size < 2 * 1024 * 1024:
                out.append(p)
        except OSError:
            continue
    # 根目录的 config 和 work/config 可能互为副本，内容去重
    unique: list[Path] = []
    seen: set[str] = set()
    for p in out:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique[:limit]


def _strip_rule_comment(line: str) -> str:
    """去掉行尾注释，但不碰引号里的 #。"""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return line[:i]
    return line


def _rule_fields(line: str) -> list[str]:
    """把一行规则切成字段；不是规则行就返回空。"""
    line = line.strip()
    if not line or line.startswith(("#", ";", "//")):
        return []
    line = _strip_rule_comment(line).strip()
    if line.startswith("-"):
        line = line[1:].strip()
    if not line or line.startswith("{"):
        return []
    if line.startswith("[") and line.endswith("]"):
        line = line[1:-1].strip()
    if len(line) >= 2 and line[0] in "\"'" and line[-1] == line[0]:
        line = line[1:-1].strip()
    try:
        fields = next(csv.reader([line], skipinitialspace=True))
    except (csv.Error, StopIteration):
        return []
    return [f.strip().strip("\"'") for f in fields]


def _policy_is_blocked(policy: str) -> bool:
    up = policy.upper()
    return up in _BLOCK_POLICY or any(k in policy for k in ("直连", "拒绝", "拦截", "阻断"))


def classify_rule_entries(text: str) -> list[dict]:
    """把配置里的生态域名规则解析成结构化条目。

    每条记下 type / payload / policy / section / kind。section 用来区分
    `prepend-rules` 和普通 `rules`：前者在 Clash Verge 里优先于订阅规则，
    同一条 DIRECT 写在普通 rules 里可以被置顶规则覆盖。
    """
    entries: list[dict] = []
    section = ""
    for raw in text.splitlines():
        key = re.match(r"^([A-Za-z0-9_-]+):\s*$", raw.strip())
        if key:
            name = key.group(1).lower()
            section = "prepend" if name == "prepend-rules" else (
                "rules" if name == "rules" else "")
            continue
        fields = _rule_fields(raw)
        if len(fields) < 3:
            continue
        rtype = fields[0].upper()
        if rtype not in _RULE_TYPES:
            continue
        payload, policy = fields[1], fields[2]
        if not payload or not policy:
            continue
        if not any(k in payload.lower() for k in _ECO_MATCH):
            continue
        entries.append({
            "type": rtype,
            "payload": payload,
            "policy": policy,
            "section": section,
            "kind": "blocked" if _policy_is_blocked(policy) else "pinned",
        })
    return entries


def classify_rules(text: str) -> tuple[list[str], list[str]]:
    """把一份 Clash 风格配置里的生态域名规则分成 (置顶, 直连/拒绝)。

    拆成纯函数是为了能拿写死的配置片段做测试——真正跑起来的时候，
    这段逻辑要读用户机器上的 yaml，而结果取决于那人当天装了什么。
    """
    pinned: list[str] = []
    blocked: list[str] = []
    for e in classify_rule_entries(text):
        label = f"{e['payload']} → {e['policy']}"
        target = blocked if e["kind"] == "blocked" else pinned
        if label not in target:
            target.append(label)
    return pinned, blocked


def _scan_rule_configs() -> tuple[list[str], list[dict]]:
    scanned: list[str] = []
    entries: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    for root in (*_CLASH_ROOTS, *((Path('/usr/local/etc/mihomo'),) if vmnetwork.enabled() else ())):
        if not root.exists():
            continue
        for y in _config_files(root):
            try:
                text = y.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned.append(str(y).replace(str(HOME), "~"))
            for e in classify_rule_entries(text):
                key = (e["type"], e["payload"], e["policy"], e["section"])
                if key in seen:
                    continue
                seen.add(key)
                e["file"] = str(y).replace(str(HOME), "~")
                entries.append(e)
    return scanned, entries


def _behavior_label(state: str) -> str:
    return {
        "fake": "fake-ip（DNS 已接管）",
        "real": "真实地址（未接管）",
        "mixed": "真假混合",
        "unresolved": "解析失败",
        "unchecked": "未检测",
    }.get(state, state)


def _dns_behavior(online: bool) -> dict[str, str]:
    """三个生态域名解析到哪：fake-ip / 真实地址 / 解析失败。

    只看「像不像被隧道接管」，不展示解析出来的真实 IP。解析失败不降级——
    网络抖一下不等于规则有问题。
    """
    domains = ("claude.ai", "api.anthropic.com", "claudeusercontent.com")
    if not online:
        return {d: "unchecked" for d in domains}
    resolved, unresolved = _resolve_all(set(domains), budget=4.0)
    out: dict[str, str] = {}
    for d in domains:
        ips = resolved.get(d) or []
        if d in unresolved or not ips:
            out[d] = "unresolved"
        elif all(stun.is_fake(ip) for ip in ips):
            out[d] = "fake"
        elif any(stun.is_fake(ip) for ip in ips):
            out[d] = "mixed"
        else:
            out[d] = "real"
    return out


def _fake_route_iface() -> str:
    """fake-ip 段实际从哪张网卡出去。默认路由是 en0 时，分流 TUN 仍然可能
    只接管 198.18/15；不看这条路由就会把「DNS 被接管 + 流量走 TUN」误判成
    「只有 DNS 被接管」。"""
    if not compat.IS_MAC:
        return ""
    m = re.search(r"interface:\s*(\S+)",
                  compat.run(["route", "-n", "get", "198.18.0.1"], 3))
    return m.group(1) if m else ""


# 「加置顶规则」和「别留 Claude 专属规则」是同一件事的两面。这两句建议必须
# 一起给，否则用户会看到塔一边让他加规则、一边让他把规则摘掉，只会觉得在耍他。
_PIN_COST = ("代价是分流配置里会多出一条 Claude 专属条目，这本身也是一条画像信号。"
             "「不漏流量」和「少一条痕迹」没法同时满足，按你更在意哪一头选。")


def pinned_verdict(entries: list[dict], scanned: list[str], tun_on: bool,
                   proxy_on: bool, behavior: dict[str, str],
                   fake_route_on: bool = False) -> tuple[str, str, str, str]:
    """(severity, title, detail, advice)。拆成纯函数，判定矩阵才能单测。"""
    prepend_blocked = [e for e in entries
                       if e["section"] == "prepend" and e["kind"] == "blocked"]
    prepend_pinned = [e for e in entries
                      if e["section"] == "prepend" and e["kind"] == "pinned"]
    blocked = [e for e in entries if e["kind"] == "blocked"]
    pinned = [e for e in entries if e["kind"] == "pinned"]
    fake_seen = any(v in ("fake", "mixed") for v in behavior.values())
    routed = tun_on or proxy_on or fake_route_on

    if prepend_blocked:
        return (
            "critical",
            "prepend-rules 把 Claude 域名指向了直连或拒绝",
            "置顶规则优先级最高，这几乎等于明确要求这些请求绕开隧道。"
            "它不是可能被订阅误伤，而是已经写死了。",
            "把 prepend-rules 里的 DIRECT / REJECT 改成代理组，或删掉这几条。",
        )
    if blocked and not prepend_pinned:
        return (
            "critical",
            "分流规则把 Claude 域名指向了直连或拒绝",
            "规则里有针对生态域名的 DIRECT / REJECT。这比「没写规则」危险得多——"
            "没写规则只是可能被误判，写了 DIRECT 是明确让这些请求绕开隧道。",
            "把这几条改成指向代理组，或者直接在 prepend-rules 顶部加一条"
            "`DOMAIN-SUFFIX,anthropic.com,<代理组名>` 盖住它。"
            "用 FlClash / Clash Verge / ClashX 的话，先删掉冲突规则，"
            "再到「隐私设置 → WebRTC / 置顶分流修复」预览后一键写入；其它客户端面板会给手动步骤。",
        )
    if prepend_pinned or pinned:
        extra = ("普通 rules 里也有 DIRECT / REJECT，但 prepend-rules 的置顶规则"
                 "优先，当前按置顶走。" if blocked else "")
        return (
            "pass",
            f"生态域名已置顶走代理（{len(prepend_pinned or pinned)} 条）",
            "Claude 相关域名被显式锁定在代理上，不会被订阅规则集误伤。"
            + extra,
            "",
        )
    if routed:
        if tun_on:
            how = "默认路由走隧道"
        elif fake_route_on:
            how = "fake-ip 路由走隧道"
        else:
            how = "系统代理已启用"
        return (
            "pass",
            f"流量已被代理接管（{how}）",
            "没找到生态域名的专属规则，但整条链路已经进代理，请求不会裸奔。",
            "",
        )
    if not scanned:
        return (
            "info",
            "没找到代理配置文件",
            "本机没有 Clash / Mihomo 一类可读的配置，没法判断生态域名是怎么分流的。"
            "如果你用的是别的客户端，这条可以忽略。",
            "",
        )
    if fake_seen:
        return (
            "info",
            "DNS 已被接管，但没找到置顶规则",
            "生态域名解析到了 fake-ip，说明 DNS 被代理客户端接管；"
            "但仅凭这一点无法确认 TCP/UDP 也走了同一条路。",
            "在客户端的全局扩展配置（prepend-rules）顶部加："
            "`DOMAIN-SUFFIX,anthropic.com,<代理组>` 和 `DOMAIN-SUFFIX,claude.ai,<代理组>`。"
            "用 FlClash / Clash Verge / ClashX 的话，可在「隐私设置 → WebRTC / 置顶分流修复」预览后一键写入；"
            "Shadowrocket / Surge / sing-box / Mihomo Party 面板里会给手动步骤。"
            + _PIN_COST,
        )
    return (
        "medium",
        "生态域名没有置顶规则",
        "配置里没找到针对 claude.ai / anthropic.com 的规则，"
        "也没有看到 TUN 或系统代理接管。订阅规则集一旦更新出一条 REJECT 或 DIRECT，"
        "请求会安静地失败或者绕开隧道，而且不会有任何提示。",
        "在客户端的全局扩展配置（prepend-rules）顶部加："
        "`DOMAIN-SUFFIX,anthropic.com,<代理组>` 和 `DOMAIN-SUFFIX,claude.ai,<代理组>`。"
        "用 FlClash / Clash Verge / ClashX 的话，可在「隐私设置 → WebRTC / 置顶分流修复」预览后一键写入；"
        "Shadowrocket / Surge / sing-box / Mihomo Party 面板里会给手动步骤。"
        + _PIN_COST,
    )


def check_pinned(online: bool = True) -> dict:
    """生态域名有没有被「置顶」锁定走代理。

    第三方规则集（尤其是带广告拦截的）经常把 anthropic / claude 相关域名
    误判成 REJECT 或 DIRECT。它不会报错，只会让请求安静地死在半路，
    或者绕开隧道裸奔。置顶规则的作用就是把这些域名钉在代理上，
    优先级高于任何订阅规则。

    除了读配置，还做一次行为探测：三个生态域名解析到 fake-ip，说明 DNS
    被代理客户端接管。两者不能互相替代——配置说 DIRECT 时 fake-ip 也可能是
    DNS 劫持的结果，最终仍按配置判事故。
    """
    scanned, entries = _scan_rule_configs()
    proxy = compat.system_proxy() or {}
    proxy_on = bool(proxy.get("enabled") or proxy.get("pac"))
    iface = compat.default_route_iface()
    # 不能用 tunnel_interfaces() 判「TUN 在接管」：macOS 上永远躺着十几个
    # 系统自带的空 utun（本机实测 14 个），默认路由却还是 en0。
    # 只有默认路由指向 utun，才说明流量真的进了隧道。
    tun_on = bool(iface) and iface.startswith("utun")
    behavior = _dns_behavior(online)
    fake_seen = any(v in ("fake", "mixed") for v in behavior.values())
    fake_route = _fake_route_iface() if fake_seen else ""
    fake_route_on = fake_route.startswith("utun")

    sev, title, detail, advice = pinned_verdict(
        entries, scanned, tun_on, proxy_on, behavior, fake_route_on)

    ev: list[dict] = []
    if scanned:
        ev.append(_ev("配置", scanned[0], mono=True))
    pinned = [e for e in entries if e["kind"] == "pinned"]
    blocked = [e for e in entries if e["kind"] == "blocked"]
    if pinned:
        ev.append(_ev("置顶规则", "；".join(
            f"{e['payload']} → {e['policy']}" for e in pinned[:3]), mono=True))
    if blocked:
        ev.append(_ev("直连/拒绝", "；".join(
            f"{e['payload']} → {e['policy']}" for e in blocked[:3]), mono=True))
    if iface:
        ev.append(_ev("默认路由", iface, mono=True))
    if proxy_on:
        ev.append(_ev("系统代理", proxy.get("server") or proxy.get("pac") or "已启用", mono=True))
    if behavior:
        ev.append(_ev("行为探测", "；".join(
            f"{d} → {_behavior_label(s)}" for d, s in behavior.items()), mono=True))
    if fake_route:
        ev.append(_ev("fake-ip 路由", fake_route, mono=True))

    # 配置文本里有，不等于内核加载了。Script.js 没启用、代理组被订阅改名、
    # 客户端没重新加载，三种情况都不会报错——规则只是「写在那里」，流量
    # 并不受它管。有控制接口就问一句，没有就跳过（不降级、不冒充通过）。
    if pinned and sev in ("pass", "info"):
        doms = [e["payload"] for e in pinned if "." in str(e.get("payload") or "")][:6]
        if doms:
            kern = kernelcheck.verify_default(
                [("DOMAIN-SUFFIX", d) for d in doms], str(pinned[0].get("policy") or ""))
            if kern.get("state") == "ok":
                extra = f" · 节点 {kern['node']}" if kern.get("node") else ""
                ev.append(_ev("内核规则", f"已加载 {kern['matched']} 条{extra}", mono=True))
            elif kern.get("state") == "mismatch":
                sev = "medium"
                title = "配置里有置顶规则，但内核没加载"
                detail = ("配置文件里写着这些域名走代理，内核的规则表里却没有。"
                          "常见原因是全局扩展脚本没启用、代理组被订阅改名，"
                          "或者客户端根本没重新加载。这种状态下规则只是「写在那里」，"
                          "流量并不受它管。")
                advice = ("重启客户端后重新扫描；仍不生效就检查全局扩展脚本是否启用、"
                          "代理组是否存在。")
                ev.append(_ev("内核规则", kern.get("reason") or "未加载", mono=True))

    return _item("net.pinned", "network", title, sev, detail, ev, advice)


def _tun_enabled_in_configs() -> bool:
    """当前生效的代理配置里有没有启用 TUN。只读，不探测网络。"""
    for root in (*_CLASH_ROOTS, *((Path('/usr/local/etc/mihomo'),) if vmnetwork.enabled() else ())):
        if not root.exists():
            continue
        try:
            yamls = _config_files(root, limit=4)
        except OSError:
            continue
        for y in yamls[:3]:
            try:
                text = y.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _TUN_ENABLED_RE.search(text) or _TUN_ENABLED_FLOW_RE.search(text):
                return True
    return False


def _transport_state() -> dict:
    """当前流量路径的三类证据：本地代理进程、系统代理、TUN/VPN。"""
    proxy = compat.system_proxy() or {}
    system_proxy_on = bool(proxy.get("enabled") or proxy.get("pac"))
    iface = compat.default_route_iface()
    tun_on = bool(iface) and iface.startswith("utun")
    fake_route = _fake_route_iface()
    fake_route_on = fake_route.startswith("utun")
    return {
        "system_proxy_on": system_proxy_on,
        "system_proxy": proxy,
        "default_iface": iface,
        "tun_on": tun_on,
        "fake_route": fake_route,
        "fake_route_on": fake_route_on,
        "tunneled": tun_on or fake_route_on or system_proxy_on,
        "processes": compat.proxy_processes(_PROXY_PROC_KEYS),
        "vpns": compat.proxy_vpn_connections(),
        "tun_configured": _tun_enabled_in_configs(),
    }


def check_proxy_path(state: dict | None = None) -> dict:
    """有没有一条能解释 Claude 出口的代理链路。

    只看「本机有没有代理」不够：有人用系统代理、有人用 TUN、macOS 上的
    Shadowrocket 还可能是 Network Extension，三种都不会同时出现。这里把
    本地监听进程、系统代理、TUN/VPN 连接合并成一条独立判据。
    """
    st = _transport_state() if state is None else state
    how: list[str] = []
    ev: list[dict] = []
    if st["processes"]:
        how.append("本地代理进程")
        ev.append(_ev("代理进程", ", ".join(st["processes"][:5]), mono=True))
    if st["vpns"]:
        how.append("VPN 客户端")
        ev.append(_ev("VPN 客户端", ", ".join(st["vpns"][:5]), mono=True))
    if st["system_proxy_on"]:
        how.append("系统代理")
        proxy = st["system_proxy"] or {}
        ev.append(_ev("系统代理", proxy.get("server") or proxy.get("pac") or "已启用",
                      mono=True))
    if st["tun_on"] or st["fake_route_on"]:
        how.append("TUN")
        ev.append(_ev("默认路由", st["default_iface"] or "-", mono=True))
        if st["fake_route"]:
            ev.append(_ev("fake-ip 路由", st["fake_route"], mono=True))
    if how:
        return _item(
            "net.proxy_path", "network",
            "代理链路已建立（" + " + ".join(how) + "）",
            "pass",
            "检测到至少一条能承载 Claude 出口的代理链路。"
            "具体走哪一条取决于客户端的分流设置，这一项只回答「有没有」。",
            ev,
        )
    return _item(
        "net.proxy_path", "network",
        "未检测到代理链路",
        "high",
        "没有本地代理进程、没有系统代理、没有 TUN/VPN 连接。"
        "如果 Claude 现在联网，它走的就是本机真实出口——出口 IP、DNS 与后续请求都直接暴露。",
        ev or [_ev("系统代理", "未启用"), _ev("本地监听", "无代理进程"),
               _ev("TUN/VPN", "无连接")],
        "确认这台机器是否应该走代理：需要就启动客户端并重新扫描；"
        "如果本来就直连，这一项说明的是真实出口，不是误报。",
    )


def check_tun(state: dict | None = None) -> dict:
    """TUN 是否按预期接管。

    不是所有人都该用 TUN：系统代理用户本来就不需要它。只有配置里明确
    启用了 TUN、默认路由却没进隧道时才算偏高；其余情况只记录，不扣分。
    """
    st = _transport_state() if state is None else state
    if st["tun_on"] or st["fake_route_on"]:
        ev = [_ev("默认路由", st["default_iface"] or "-", mono=True)]
        if st["fake_route"]:
            ev.append(_ev("fake-ip 路由", st["fake_route"], mono=True))
        return _item("net.tun", "network", "TUN 已接管默认流量", "pass",
                     "默认路由已经落在隧道上，TUN 模式按配置生效。", ev)
    ev = [
        _ev("默认路由", st["default_iface"] or "-", mono=True),
        _ev("配置中的 TUN", "已启用" if st["tun_configured"] else "未启用"),
        _ev("系统代理", "已启用" if st["system_proxy_on"] else "未启用"),
    ]
    if st["tun_configured"] and st["system_proxy_on"]:
        return _item(
            "net.tun", "network",
            "配置了 TUN，但当前由系统代理承载",
            "info",
            "代理配置里启用了 TUN，默认路由却没有进隧道；系统代理同时开着，"
            "流量仍可能经本地代理转发。这一项只说明 TUN 没接管，不判泄漏。",
            ev,
            "不打算用 TUN 就把配置里的 tun.enable 关掉，避免两套路径互相干扰；"
            "要用 TUN 则重启客户端确认它真的接管默认路由。",
        )
    if st["tun_configured"]:
        return _item(
            "net.tun", "network",
            "配置了 TUN，但默认路由没有进隧道",
            "high",
            "代理配置里明确启用了 TUN，默认路由却仍在 " + (st["default_iface"] or "非隧道接口") +
            "。客户端可能没启动、没拿到权限，或 TUN 启动失败——此时请求不一定按你以为的路径出去。",
            ev,
            "打开代理客户端确认 TUN 模式已生效并重新扫描；"
            "如果不打算用 TUN，把配置里的 tun.enable 关掉，改用系统代理。",
        )
    return _item(
        "net.tun", "network",
        "未启用 TUN（当前不要求 TUN）",
        "info",
        "没有 TUN 接管，也没有在配置里启用 TUN。系统代理或本地代理进程"
        "同样可以承载出口；这一项不因为「没开 TUN」扣分。",
        ev,
    )


def check_dns_route(behavior: dict | None = None, state: dict | None = None) -> dict:
    """DNS 有没有跟着流量一起进隧道。

    不用「必须返回 fake-ip」当硬判据：系统代理本来就不接管 DNS，
    公共 DoH 也可能返回真实地址。只有「解析到真实地址、而且整条链路
    没有 TUN/系统代理」时才算偏高；链路已接管时只提示。
    """
    st = _transport_state() if state is None else state
    states = behavior or {}
    values = list(states.values())
    ev = [_ev("解析结果", "；".join(f"{d} → {_behavior_label(v)}"
                                   for d, v in states.items()), mono=True)]
    if st["tun_on"] or st["fake_route_on"]:
        ev.append(_ev("链路", "TUN", mono=True))
    elif st["system_proxy_on"]:
        ev.append(_ev("链路", "系统代理", mono=True))
    else:
        ev.append(_ev("链路", "未检测到 TUN / 系统代理", mono=True))

    if not values or all(v == "unchecked" for v in values):
        return _item("net.dns_route", "network", "DNS 路径未检测", "info",
                     "本轮关闭了联网检测，没有解析生态域名。", ev)
    fake = [v for v in values if v == "fake"]
    real = [v for v in values if v == "real"]
    mixed = [v for v in values if v == "mixed"]
    if fake and not real and not mixed:
        return _item("net.dns_route", "network", "DNS 已被代理接管", "pass",
                     "生态域名解析到 fake-ip 段，说明 DNS 查询已经被代理客户端接管。", ev)
    if real and not fake and not mixed:
        if st["tunneled"]:
            how = "TUN" if (st["tun_on"] or st["fake_route_on"]) else "系统代理"
            return _item(
                "net.dns_route", "network",
                "DNS 返回真实地址，但流量链路已接管",
                "info",
                f"链路当前由{how}承载。系统代理本来就不接管 DNS，返回真实地址是正常的；"
                "TUN 模式下则说明 DNS 可能没有完整走进隧道。此项只提示，不判高危。",
                ev,
                "如果用的是 TUN，确认客户端的 DNS 分流也指向代理；"
                "系统代理用户可忽略这一条。",
            )
        return _item(
            "net.dns_route", "network",
            "DNS 解析到真实地址，且没有代理链路",
            "high",
            "三个生态域名都解析到真实地址，同时没有检测到 TUN 或系统代理。"
            "DNS 查询和后续连接都可能从本机真实出口发出，出口伪装在这条路径上不起作用。",
            ev,
            "启动代理并确认 DNS 被客户端接管；或把系统 DNS 指到与出口一致的解析器。"
            "不要只看解析结果像不像 fake-ip。",
        )
    if mixed:
        return _item("net.dns_route", "network", "DNS 解析结果真假混合", "info",
                     "部分生态域名返回 fake-ip、部分返回真实地址，无法确认 DNS 是否被完整接管。",
                     ev,
                     "在代理客户端里统一 DNS 模式，再重新扫描确认。")
    return _item("net.dns_route", "network", "DNS 解析失败，无法判断路径", "info",
                 "生态域名没有解析出地址，可能是网络抖动或规则拦截；这一项不下结论。",
                 ev, "网络恢复后重新扫描。")


def _resolver_name(r: dict) -> str:
    return r.get("org") or "国内解析器"


def _resolver_label(r: dict) -> str:
    bits = [r.get("org") or "", r.get("masked") or ""]
    country = (r.get("country") or "").upper()
    if country:
        bits.append(country)
    return " · ".join(b for b in bits if b) or "未知"


def check_proxy_dns(state: dict | None = None, report: dict | None = None,
                    resolver: dict | None = None,
                    egress: dict | None = None) -> dict:
    """代理内核自己的 DNS 名单，加上实测的解析器出口。

    TUN 接管后 macOS 的 DNS 设置会被绕过：系统把查询发给谁不重要，真正
    解析域名的是客户端内核的 nameserver。只看 `scutil` 会把「系统 DNS
    干净」当成结论。这里读运行中客户端当前生效的配置，并把四组名单分开：

    - 解析域名用（nameserver / fallback / direct-nameserver）：访问的每个
      域名都经过这里，命中国内解析器才算泄漏面；
    - 国内域名用（nameserver-policy，比如 geosite:cn）：只把国内域名交给
      国内解析器，让 GEOIP,CN 拿到国内地址、命中直连；代理域名不受影响；
    - 启动解析用（default-nameserver）：只用来解析 DoH 服务器自己的域名；
    - 节点域名用（proxy-server-nameserver）：只解析代理节点地址，国内解析
      是正常且必要的，不参与判定。

    名单只说明配置写了什么。上游把明文 53 截走、或 fallback 悄悄接手时，
    名单可以是干净的而解析仍发生在国内——所以再加一次实测（`resolveregress`），
    由解析器自己报出地址。没有出口时不测，那等于自己制造一次泄漏。

    有了本次 HTTP 出口国家（`egress`），还要比一次：解析器在哪个国家、出口
    在哪个国家。两者不同不是「国内解析」，但外部的 DNS 泄漏探针会把这一项
    标红，所以按低风险记录，而不是替用户判成一致。
    """
    st = _transport_state() if state is None else state
    rep = proxydns.collect() if report is None else report
    if resolver is None:
        resolver = resolveregress.probe() if st.get("tunneled") else {}
    # 完整地址只留在内存里做判定；这一层产出的数据可能落盘，只带打码后的。
    r = {k: v for k, v in (resolver or {}).items() if k != "ip"}
    measured = r if r.get("checked") else None
    leaked = bool(measured and (measured.get("country") or "").upper() == "CN")
    egress_country = ((egress or {}).get("country") or "").upper()
    resolver_country = ((measured or {}).get("country") or "").upper()
    mismatch = bool(measured and resolver_country and egress_country
                    and resolver_country != egress_country)
    data = {
        "system": rep["system"],
        "systemDomestic": rep["systemDomestic"],
        "clients": rep["clients"],
        "domesticDestination": rep["domesticDestination"],
        "domesticNode": rep["domesticNode"],
        "domesticProxied": rep.get("domesticProxied"),
        "domesticDirect": rep.get("domesticDirect"),
        "domesticPolicy": rep.get("domesticPolicy") or [],
        "unrelayed": rep.get("unrelayed") or [],
        "providers": rep.get("providers") or [],
        "mixedProviders": bool(rep.get("mixedProviders")),
        "note": rep["note"],
        "resolver": r,
        "resolverCountry": resolver_country,
        "egressCountry": egress_country,
        "countryMismatch": mismatch,
    }
    ev = [_ev("系统 DNS", ", ".join(rep["system"]) or "未知", mono=True)]
    if measured:
        ev.append(_ev("解析出口", _resolver_label(measured), mono=True))
    if not rep["clients"]:
        detail = (rep["note"] + "。系统 DNS 不等于内核 DNS：TUN 接管时，真正解析域名的是"
                  "客户端自己的名单；这一项只说明读不到，不代表没有国内解析器。")
        title = "没读到代理内核的 DNS 配置"
        severity = "info"
        if leaked:
            detail += f"不过实测递归出口是 {_resolver_label(measured)}，查询确实落在国内解析器上。"
            title = f"解析器出口在国内（{_resolver_name(measured)}）"
            severity = "medium" if st.get("tunneled") else "info"
        elif mismatch:
            detail += (f"实测递归出口在 {resolver_country}，本次出口在 {egress_country}；"
                       "两者不同会让外部探针的 DNS 国家一项变红，但递归本身不在国内。")
        item = _item("net.proxy_dns", "network", title, severity, detail, ev)
        item["dns"] = data
        return item

    client = rep["clients"][0]
    ev.insert(0, _ev("客户端", client["name"]
                     + (" · " + client["mode"] if client["mode"] else ""), mono=True))
    if client["destination"]:
        ev.append(_ev("解析域名用", ", ".join(client["destination"]), mono=True))
    policy_pairs = [(e["selector"], e["server"]) for e in (client.get("policy") or [])]
    if policy_pairs:
        ev.append(_ev("国内域名解析用",
                      ", ".join(f"{sel} = {proxydns.label(srv)}" for sel, srv in policy_pairs),
                      mono=True))
    if client["node"]:
        ev.append(_ev("节点域名用", ", ".join(client["node"]), mono=True))
    if client["bootstrap"]:
        ev.append(_ev("启动解析用", ", ".join(client["bootstrap"]), mono=True))

    domestic = rep["domesticDestination"]
    # 代理域名（nameserver/fallback）与直连域名（direct-nameserver）分开算：
    # 只有前者决定别人递归时看到谁。没有拆分字段的报告按代理域名处理，宁可多报。
    proxied = rep.get("domesticProxied")
    if proxied is None:
        proxied, direct = domestic, []
    else:
        direct = [v for v in domestic if v not in proxied]
    policy = rep.get("domesticPolicy") or []
    policy_selectors: list[str] = []
    for entry in client.get("policy") or []:
        if (proxydns.is_domestic(entry["server"], rep["system"])
                and entry["selector"] not in policy_selectors):
            policy_selectors.append(entry["selector"])
    if proxied or leaked:
        parts = []
        if proxied:
            names = "、".join(proxydns.label(v) for v in proxied[:4])
            parts.append(f"访问的域名会交给客户端的 nameserver 解析，里面有国内解析器（{names}）。")
            if st.get("tunneled"):
                parts.append("TUN/系统代理在位时，macOS 的 DNS 设置会被绕过，真正看到域名的是这一组。")
            else:
                parts.append("客户端当前没有接管流量，这一项目前只记录配置，等接管后才会生效。")
            if rep["domesticNode"]:
                parts.append("「节点域名用」那一组只解析代理节点地址，不算泄漏，可以保留。")
            title = f"代理内核 DNS 混用国内解析器（{names}）"
        else:
            title = f"解析器出口在国内（{_resolver_name(measured)}）"
        if leaked:
            who = _resolver_label(measured)
            if proxied:
                parts.append(f"实测递归出口也是 {who}，和名单一致。")
            else:
                parts.append(f"名单里没有国内解析器，但实测递归出口是 {who}：配置干净不等于"
                             "解析发生在境外，明文 53 可能被截获，或上游被转给了国内递归。")
                if direct:
                    parts.append("「直连域名用」那组里也有国内解析器（"
                                 + "、".join(proxydns.label(v) for v in direct[:4])
                                 + "），它只解析直连域名。")
            if mismatch:
                parts.append(f"本次 HTTP 出口在 {egress_country}，解析器在 {resolver_country}，"
                             "外部探针会同时标出这两个国家。")
            advice = ("把客户端 DNS 改成境外 DoH（如 https://1.1.1.1/dns-query），"
                      "并确认内核真的按这份名单解析；改完重新扫描，看到「解析出口」"
                      "换成境外才算修好——名单和实测都要换。"
                      "两个容易漏的点：① 境外 DoH 后面加 `#<代理组>`，否则查询从本机 IP"
                      "直接发出；② 国内域名用 `nameserver-policy` 时按白名单写"
                      "（只对 `geosite:cn` 指国内），别用 `geolocation-!cn` 这类取反的"
                      "名单——名单外的域名会掉回默认解析器，泄漏探针的随机域名正是名单外的。")
        else:
            advice = ("在客户端的 DNS 设置里删掉 nameserver 里的国内解析器，只留境外 DoH/IP；"
                      "节点域名解析可以继续用国内。")
        item = _item(
            "net.proxy_dns", "network", title,
            "medium" if (st.get("tunneled") or leaked) else "info",
            "".join(parts), ev, advice)
    elif direct or policy:
        parts = []
        if policy:
            servers = "、".join(proxydns.label(v) for v in policy[:4])
            selectors = "、".join(policy_selectors[:4]) or "国内域名"
            parts.append(f"「国内域名用」把 {selectors} 的解析交给国内解析器（{servers}）："
                         "这样 GEOIP,CN 能拿到国内地址、命中直连规则；代理域名的解析"
                         "仍然只走境外名单，不受影响。")
        if direct:
            names = "、".join(proxydns.label(v) for v in direct[:4])
            parts.append(f"「直连域名用」里的 {names} 只解析本来就直连的域名。直连流量本身"
                         "从本机 IP 发出，解析落回国内不会额外暴露访问目标。")
        if measured:
            parts.append(f"实测递归出口是 {_resolver_label(measured)}，代理域名的解析与名单一致。")
        if mismatch:
            parts.append(f"不过它的归属是 {resolver_country}，本次出口在 {egress_country}："
                         "外部探针的「DNS 国家」会因此变红，递归本身不在国内。")
        advice = ("这两组只服务国内/直连域名。要让直连查询也不落在国内，可以换成境外 DoH；"
                  "代理域名的解析不受影响。")
        if policy:
            names = "、".join(proxydns.label(v) for v in policy[:4])
            title = f"国内域名用国内解析器（{names}）"
        else:
            names = "、".join(proxydns.label(v) for v in direct[:4])
            title = f"直连域名用国内解析器（{names}）"
        item = _item("net.proxy_dns", "network", title, "info",
                     "".join(parts), ev, advice)
    else:
        detail = "nameserver 里没有国内解析器。节点域名即使走国内解析，也只暴露代理节点地址。"
        if measured:
            detail += f"实测递归出口是 {_resolver_label(measured)}。"
        unrelayed = rep.get("unrelayed") or []
        providers = [p for p in (rep.get("providers") or []) if p != "system"]
        if unrelayed:
            names = "、".join(proxydns.label(v) for v in unrelayed[:4])
            detail += (f"不过 {names} 没挂「查询走代理」的后缀（`#<代理组>`）：内核会把这条查询"
                       "从本机 IP 直接发出去，解析器记下的是真实地址，和 HTTP 走的不是同一条路。"
                       "DNS 泄漏探针看不到这一层——它只问解析器在哪，不问查询从哪个 IP 发出。")
            if mismatch:
                detail += (f"另外解析器归属 {resolver_country}、本次出口在 {egress_country}，"
                           "探针会把「DNS 国家」一项标红。")
            item = _item(
                "net.proxy_dns", "network", f"DNS 查询没走代理（{names}）", "low",
                detail, ev + [_ev("查询出口", "本机 IP（未挂代理后缀）", mono=True)],
                "在 DoH 地址后面加 `#<代理组>`，例如 `https://1.1.1.1/dns-query#PROXY`，"
                "组名必须是配置里真实存在的代理组；加了之后这条查询从该组出去，解析器看到的是"
                "代理侧地址。内核的 `respect-rules` 通常被客户端强制关掉，指望它按分流规则走不可靠。"
                "改完重新扫描，看「解析出口」是否换成代理侧地址。",
            )
        elif len(providers) >= 2:
            names = "、".join(proxydns.provider_label(p) for p in providers[:4])
            tail = ""
            if mismatch:
                tail = (f"本次实测解析出口在 {resolver_country}、HTTP 出口在 "
                        f"{egress_country}，就是这条的表现。")
            item = _item(
                "net.proxy_dns", "network",
                f"DNS 出口会在多个服务商之间跳（{names}）", "low",
                detail + f"这一组同时挂着 {names}。内核是并行发查询、谁先回用谁，"
                         f"所以同一个域名这次由这家解析、下次换另一家，而配置一个字都没动。"
                         f"不同厂商的递归出口不在同一片网络里：Cloudflare 在入口 PoP 就地"
                         f"解析，地理跟着出口走；Google 常从自己的骨干网出去，出口在美东时"
                         f"它可能报在蒙特利尔。结果就是泄漏探针上的「DNS 出口」在城市甚至"
                         f"国家之间来回变。{tail}",
                ev + [_ev("解析器服务商", names, mono=True)],
                "只留一家。同一家的多个地址可以都留着（比如 1.1.1.1 + 1.0.0.1），"
                "它们走同一片网络，出口不会跨区。优先留 Cloudflare：它在入口 PoP 解析，"
                "DNS 归属会跟着出口走；Google 的递归出口由它自己的骨干网决定，"
                "对不上你的出口。改完重新扫描，看「解析出口」是否固定在一处。",
            )
        elif mismatch:
            item = _item(
                "net.proxy_dns", "network",
                f"解析器国家与出口不一致（{resolver_country} / {egress_country}）", "low",
                detail + f"递归出口在 {resolver_country}，HTTP 出口在 {egress_country}。"
                         "递归本身不在国内，但外部探针会把「DNS 国家」一项标红；"
                         "1.1.1.1 这类 anycast 解析器常被归到美国。",
                ev + [_ev("出口国家", f"HTTP {egress_country} · DNS {resolver_country}",
                          mono=True)],
                "把 nameserver 换成与出口同区、同国的境外 DoH；或者接受探针上的这一项红叉——"
                "它不是国内解析器，也不改变递归发生的位置。",
            )
        else:
            item = _item(
                "net.proxy_dns", "network", "代理内核 DNS 只用境外解析器", "pass",
                detail, ev)
    item["dns"] = data
    return item


def check_proxy_fallback(guard: dict | None = None) -> dict:
    """节点全挂时会不会退到直连。

    `select` 组的 DIRECT 只是「可以手动选」，不在这里定罪；真正的失败面是
    fallback / url-test / load-balance 组：它们会在节点失败或测速时自己挑
    成员，DIRECT 一旦在名单里，请求就可能从本机真实地址出去。默认成员
    （第一个）就是 DIRECT 的组，还要再算一条「规则指向它时默认直连」。
    """
    g = proxyguard.inspect() if guard is None else guard
    if not g.get("checked"):
        return _item(
            "net.proxy_fallback", "network",
            "没读到代理客户端的回落策略", "info",
            (g.get("note") or "没找到正在运行的 Clash 系客户端配置")
            + "。读不到不等于回落安全：自动组里列了 DIRECT 时，节点失败就会退到直连。",
            [], "启动代理客户端后重新扫描。",
        )

    tun = g.get("tun") or {}
    tun_on = tun.get("enable") is True
    strict = tun.get("strict-route")
    ev = []
    if g.get("final"):
        ev.append(_ev("最终规则", f"MATCH → {g['final']}", mono=True))
    eco = g.get("eco") or []
    ev.append(_ev("Claude 规则",
                  "、".join(f"{e['payload']} → {e['target']}" for e in eco[:3])
                  if eco else "无（按最终规则走）", mono=True))
    open_groups = g.get("failopen") or []
    if open_groups:
        ev.append(_ev("含 DIRECT 的自动组",
                      "、".join(f"{x['name']}（{x['type']}，第 {x['index'] + 1} 位）"
                               for x in open_groups[:4]), mono=True))
    if tun_on:
        ev.append(_ev("严格路由", {True: "已开启", False: "未开启"}.get(strict, "未配置"),
                      mono=True))

    strict_tip = ""
    if tun_on and strict is not True:
        strict_tip = ("TUN 已启用，但 tun.strict-route 没有打开：部分 UDP 与旁路流量可能"
                      "不走隧道。它不是判泄漏的依据（WebRTC / IPv6 的实测才是），只是一条可补的口子。")

    hits = g.get("defaultDirect") or []
    if hits:
        first = hits[0]
        if first.get("payload") == "MATCH":
            title = f"最终规则直接放行（MATCH → {first['target']}）"
            detail = ("没有命中任何 Claude 规则时，请求按最终规则直接放行，从本机真实地址出去。"
                      "Claude 的域名如果不在前面被显式指向代理，就会落到这里。")
        else:
            title = f"Claude 规则指向直连（{first.get('payload')}）"
            detail = ("这条规则把 Claude 的域名交给了直连（或默认成员是 DIRECT 的组）。"
                      "出口检测看到的海外地址与 Claude 实际看到的不是同一条路。")
        advice = ("把 Claude 规则的目标改成代理组，或把组里默认的 DIRECT 换成 REJECT；"
                  "改完重新扫描，确认「出口」与终端探测一致。")
        if strict_tip:
            advice += " " + strict_tip
        return _item("net.proxy_fallback", "network", title, "high",
                     detail, ev, advice)

    reachable = [x for x in open_groups if x.get("reachable")]
    if reachable:
        names = "、".join(x["name"] for x in reachable[:3])
        detail = ("fallback / url-test / load-balance 会在节点失败或测速时自己挑成员。"
                  "组里列了 DIRECT，节点全挂时请求就从本机真实地址出去——分流规则这时"
                  "看起来仍然全部命中。它至少能被规则或上层选择组选中，属于真实的回落面。")
        advice = ("把这个组里的 DIRECT 换成 REJECT（拒绝）或 REJECT-DROP；"
                  "要保留直连能力就单开一个 select 组，不要放在自动组里。")
        if strict_tip:
            advice += " " + strict_tip
        return _item("net.proxy_fallback", "network",
                     f"自动回落组里有 DIRECT（{names}）", "medium",
                     detail, ev, advice)

    if open_groups:
        names = "、".join(x["name"] for x in open_groups[:3])
        return _item(
            "net.proxy_fallback", "network",
            f"回落组里有 DIRECT，但没有规则指向它（{names}）", "low",
            "这些组列了 DIRECT，但当前没有任何规则或上层组能走到它们；"
            "风险只在于以后改了规则或手动选中。",
            ev, "清理掉自动组里的 DIRECT 更省心；不清也暂时不会被走到。"
                + ((" " + strict_tip) if strict_tip else ""),
        )

    detail = "fallback / url-test / load-balance 组里没有 DIRECT；节点失败时不会退到直连。"
    if strict_tip:
        detail += " " + strict_tip
    return _item("net.proxy_fallback", "network", "代理回落不会退到直连", "pass",
                 detail, ev, strict_tip)


def check_proxy_drift(guard: dict | None = None) -> dict:
    """Claude 走的那条路上，有没有会自己换节点的组。

    和 `check_proxy_fallback` 问的不是一件事：那一条问「节点全挂时会不会退到
    直连」，这一条问「平时会不会自己换出口」。fallback / url-test /
    load-balance 会按测速或失败自己挑成员，用户什么都没做，出口 IP 已经换了。

    Claude 只认出口 IP：同一份订阅里的节点落在不同 AS、不同城市，切一次就是
    一次新的关联信号。而分流规则这时候全部命中、回落也没有 DIRECT，检测全绿。
    今天实际踩到的就是这个：出口 IP 一直是同一个，但组是自动测速的，随时会变。

    不判 `select`：select 组换节点要用户自己按，属于「已经在固定出口」的做法。
    """
    g = proxyguard.inspect() if guard is None else guard
    if not g.get("checked"):
        return _item(
            "net.proxy_drift", "network",
            "没读到代理客户端的代理组", "info",
            (g.get("note") or "没找到正在运行的 Clash 系客户端配置")
            + "。读不到不等于出口固定：自动测速组会自己换节点。",
            [], "启动代理客户端后重新扫描。",
        )

    eco = g.get("eco") or []
    drift = g.get("drift") or []
    ev = []
    if g.get("final"):
        ev.append(_ev("最终规则", f"MATCH → {g['final']}", mono=True))
    ev.append(_ev("Claude 规则",
                  "、".join(f"{e['payload']} → {e['target']}" for e in eco[:3])
                  if eco else "无（按最终规则走）", mono=True))
    if drift:
        ev.append(_ev("会自己换节点的组",
                      "、".join(f"{x['group']}（{x['type']}）" for x in drift[:4]),
                      mono=True))

    if not drift:
        return _item(
            "net.proxy_drift", "network", "Claude 的出口不会被自动切走", "pass",
            "Claude 域名经过的组都是 select 或直接是节点，换节点要用户自己按。"
            "同一个账号长期落在同一个出口上，这是最省事的做法。",
            ev, "",
        )

    # 有 Claude 专用规则、但那条规则落到了自动组上：出口会漂，且和「最终规则」
    # 用同一批节点，看起来像在分流，其实没分开。
    if eco:
        first = next((x for x in drift if x["kind"] == "Claude 规则"), None)
        if first:
            detail = (f"Claude 域名指向的 {first['group']} 是 {first['type']} 组，"
                      "它会按测速结果自己挑成员。测速每轮都可能换人，同一个账号的"
                      "出口 IP 就会跟着换——规则全部命中、回落也没有 DIRECT，"
                      "所有检测都是绿的，只有 Claude 那边看到你在跳。")
            advice = ("给 Claude 单独建一个 select 组（成员放一个固定节点），"
                      "把 Claude 的四条域名规则指向它。select 不会自己动，"
                      "换节点变成你的显式动作。代价是节点挂了要自己切，"
                      "所以组里再放一个备用节点，别放 DIRECT。")
            return _item("net.proxy_drift", "network",
                         f"Claude 走的是自动测速组（{first['group']}）", "medium",
                         detail, ev, advice)

    names = "、".join(x["group"] for x in drift[:3])
    detail = (f"没有 Claude 专用规则，Claude 跟最终规则一起走 {names}（自动测速组）。"
              "整个代理都在漂，Claude 只是其中一个。对只用 Claude 的机器，"
              "这仍然意味着出口不固定。")
    advice = ("要固定的话，把 Claude 的四条域名规则指到一个 select 组，"
              "只放你打算长期用的那个节点；其余流量继续用自动组。")
    return _item("net.proxy_drift", "network",
                 f"出口由自动测速组决定（{names}）", "low",
                 detail, ev, advice)


def _terminal_probe(net_info: dict | None) -> dict:
    """跑一次登录 shell，拿出口和它继承到的环境。

    出口没确认就不跑：没有基线时发请求等于自己制造一次泄漏。

    返回 `{"ran": bool, "result": {...}}`，让调用方能区分「没跑」和「跑了
    但失败」——这两件事的处置完全不同。
    """
    info = net_info or {}
    if not info.get("available") or not info.get("ip"):
        return {"ran": False}
    return {"ran": True,
            "result": terminalegress.probe(info.get("ip") or "",
                                           info.get("ip_masked") or "")}


def check_terminal_egress(net_info: dict | None = None,
                          probe_result: dict | None = None) -> dict:
    """终端里实际发请求的出口，和本次探测是不是同一个。

    Claude Code 在终端里跑，继承的是登录 shell 的代理变量。curl 不读 macOS
    的系统代理：浏览器走代理、终端直连，是「网页全绿、CLI 裸奔」最常见的原因。
    只在出口确认后发请求——没有出口时跑一次，等于自己制造一次泄漏。
    """
    info = net_info or {}
    probe = probe_result if probe_result is not None else _terminal_probe(info)
    if not probe.get("ran"):
        return _item(
            "net.terminal_egress", "network", "终端出口未检测", "info",
            "出口地址还没确认，没有在登录 shell 里发请求。", [],
            "出口确认后再扫一次。",
        )
    r = probe.get("result") or {}
    ev = [_ev("登录 shell", r.get("shell") or "zsh", mono=True)]
    if r.get("ipMasked"):
        where = " · ".join(x for x in (r.get("loc"), r.get("colo")) if x)
        ev.append(_ev("终端看到的出口", r["ipMasked"] + (f" · {where}" if where else ""),
                      mono=True))
    ev.append(_ev("shell 代理变量", "已设置" if r.get("proxyEnv") else "未设置"))
    ev.append(_ev("比对基线", info.get("ip_masked") or "这次没有基线", mono=True))

    if not r.get("checked"):
        return _item(
            "net.terminal_egress", "network", "终端出口没取到", "info",
            "在登录 shell 里跑 curl 没拿到出口地址：" + (r.get("error") or "没有输出") +
            "。可能 shell 启动文件卡住、curl 被拦，或当前网络到 API 边缘不通。",
            ev, "在该终端里手动执行 curl https://api.anthropic.com/cdn-cgi/trace 看看报什么错。",
        )
    if r.get("match") is False:
        return _item(
            "net.terminal_egress", "network",
            "终端里的出口与检测出口不同", "high",
            f"终端（{r.get('shell') or 'zsh'}）里的 curl 从 {r.get('ipMasked')} 出去，"
            f"和本次探测的 {info.get('ip_masked') or '基线'} 不是同一个地址。"
            "curl 不读 macOS 的系统代理；TUN 没接管时，浏览器走代理、CLI 走直连是最常见的组合。"
            "从终端启动的 Claude Code 会继承这条直连路径。",
            ev,
            "在 shell 配置里 export HTTPS_PROXY / HTTP_PROXY 指向客户端端口，或打开 TUN；"
            "「隐私设置 → 终端代理变量」可以直接写进去（写入前会先测通这个端口，"
            "并备份原文件，可随时撤销）。"
            "改完在同一个终端里重跑 curl 确认出口一致，再从该终端启动 Claude Code。",
        )
    if r.get("match") is None:
        return _item(
            "net.terminal_egress", "network", "取到终端出口，但没有可比对的基线", "info",
            f"终端从 {r.get('ipMasked')} 出去，但和基线地址族不同或基线缺失，"
            "没法直接判断是不是同一个出口。", ev,
            "TUN 打开并只保留一种地址族后再扫一次。",
        )
    return _item(
        "net.terminal_egress", "network", "终端出口与检测一致", "pass",
        "登录 shell 里的 curl 与本次出口探测走同一个地址；从该终端启动的 CLI 不会另开一条路。",
        ev,
    )


def _lang_key(value: str) -> str:
    """`en_US.UTF-8` / `en_US.utf8` / `en_US` 是同一个语言。"""
    text = (value or "").strip().split(".")[0]
    return text.replace("-", "_").lower()


def _lang_class(value: str) -> str:
    """把 locale 分成三类：中性 / 中文 / 其它。

    `C` 和 `POSIX` 是「没有区域」，不是「某个国家的区域」。把它们当成
    「与目标不符」会天天误报——容器、CI、部分终端默认就是这个值，
    它不泄露任何中文特征，也不该被推着去改。
    """
    key = _lang_key(value)
    if not key or key in ("c", "posix"):
        return "neutral"
    return "zh" if key.startswith("zh") else "other"


def check_shell_env(net_info: dict | None = None,
                    probe_result: dict | None = None) -> dict:
    """登录 shell 里 Claude 会继承到的时区与语言。

    塔自己的进程环境和终端是两回事：从 Finder 启动的塔读不到终端里的环境
    变量。所以「系统时区对不对」和「终端里的 Claude 看到什么时区」是两个
    问题——后者只有真起一个登录 shell 才问得到。这趟 shell 为了测出口本来
    就要跑，环境变量顺手就拿到了，不额外花时间。

    这一项同时是「免管理员对齐」（`shellenv`）唯一的验收方式：它写进 rc 的
    东西到底生没生效，别的地方都看不出来——塔读的是自己的进程 env，
    哨兵读的是 `/etc/localtime`，两边都绕开了终端。

    只在出口确认后跑（和终端出口共用一次探测），所以这里也不自己发请求。
    """
    info = net_info or {}
    probe = probe_result if probe_result is not None else _terminal_probe(info)
    if not probe.get("ran"):
        return _item(
            "locale.shell_env", "locale", "终端环境未检测", "info",
            "出口地址还没确认，没有起登录 shell。", [],
            "出口确认后再扫一次。",
        )
    r = probe.get("result") or {}
    env = r.get("env") or {}
    if not env:
        why = r.get("error") or ""
        return _item(
            "locale.shell_env", "locale", "终端环境没读到", "info",
            "没能从登录 shell 里拿到 TZ / LANG。"
            + (f"（{why}）" if why else
               "可能启动文件里有提前 return，或者 shell 在打印环境之前就退出了。"),
            [_ev("登录 shell", r.get("shell") or "zsh", mono=True)],
            "在该终端里执行 env | grep -E '^(TZ|LANG|LC_ALL)=' 看看有没有值。",
        )

    tgt = shellenv.target()
    shell_tz = str(env.get("TZ") or "").strip()
    sys_tz = compat.timezone_name() or ""
    lc_all = str(env.get("LC_ALL") or "").strip()
    lang = str(env.get("LANG") or "").strip()
    # POSIX：LC_ALL 压过 LANG。只看 LANG 会在「LC_ALL=zh_CN」时判错。
    effective_lang = lc_all or lang
    chain = str(env.get("LANGUAGE") or "").strip()

    ev = [
        _ev("登录 shell", r.get("shell") or "zsh", mono=True),
        _ev("TZ", shell_tz or f"（未设置，跟随系统 {sys_tz or '未知'}）", mono=True),
        _ev("LANG / LC_ALL", f"{lang or '-'} / {lc_all or '-'}", mono=True),
        _ev("目标", (f"{tgt['timezone']} · {tgt['lang']}" if tgt["resolved"]
                     else "推不出目标值"), mono=True),
    ]
    if chain:
        ev.append(_ev("LANGUAGE", chain, mono=True))

    if not tgt["resolved"]:
        return _item(
            "locale.shell_env", "locale", "终端环境没有目标值", "info",
            "推不出这台机器该用哪个时区/语言（既没设预期出口国家，也探不到出口）。"
            "这一项不比较——没有目标就没有对错。",
            ev,
            "在「网络」里设定预期出口国家，或手动指定时区后再扫一次。",
        )

    tgt_lang_key = _lang_key(tgt["lang"])
    # 只判 shell **自己导出**的值。TZ 没设就是跟随系统，那种不一致是
    # `net.tz_mismatch` / `locale.tz_env` 的地盘——同一件事在这里再报一次，
    # 等于一个毛病扣两遍分，用户会觉得「怎么改都掉血」。
    tz_bad = bool(shell_tz and tgt["timezone"] and shell_tz != tgt["timezone"])
    lang_class = _lang_class(effective_lang)
    # 中性（C / POSIX / 未设置）不泄露任何地域特征，不算问题。
    lang_bad = lang_class == "zh" and not tgt_lang_key.startswith("zh")
    # 其它语言和目标不一致算轻微：不像中文那样是强信号，但环境确实不统一。
    lang_off = (lang_class == "other" and bool(tgt_lang_key)
                and _lang_key(effective_lang) != tgt_lang_key)
    # LANGUAGE 是 gettext 的优先级链，压过 LANG。只改 LANG 不动它，
    # 界面语言照样是中文——这是「明明改了却没生效」最常见的原因。
    chain_bad = bool(chain) and "zh" in chain.lower() and not tgt_lang_key.startswith("zh")

    if not (tz_bad or lang_bad or lang_off or chain_bad):
        return _item(
            "locale.shell_env", "locale",
            "终端环境与出口一致", "pass",
            "登录 shell 没有额外导出与目标冲突的时区/语言；"
            "从该终端启动的 Claude Code 继承的就是这一份环境。",
            ev,
        )

    parts = []
    if tz_bad:
        parts.append(f"TZ 导出成了 {shell_tz}（应为 {tgt['timezone']}）")
    if lang_bad:
        parts.append(f"语言是 {effective_lang}（应为 {tgt['lang']}）")
    if lang_off:
        parts.append(f"语言是 {effective_lang}，和目标 {tgt['lang']} 不一致")
    if chain_bad:
        parts.append(f"LANGUAGE 链里还有中文（{chain}），它会压过 LANG")
    return _item(
        "locale.shell_env", "locale",
        "终端环境与出口对不上", "medium" if (tz_bad or lang_bad or chain_bad) else "low",
        "登录 shell 里" + "；".join(parts) + "。"
        "Claude Code 是 Node 进程，读的就是这些环境变量——系统设置改得再对，"
        "从终端起来的 CLI 拿到的仍是这一份。"
        "「系统时区」和「终端时区」是两件事，很多人只改了前者。",
        ev,
        "用「隐私设置 → 终端时区/语言」写入标记块（免管理员，可随时撤销），"
        "或者手动在启动文件里 export TZ / LANG / LC_ALL；改完开一个新终端，"
        "在那里执行 env | grep -E '^(TZ|LANG|LC_ALL)=' 确认。",
    )


def check_vm_network():
    vm = vmnetwork.read()
    if not vm['managed']:
        return []
    ok = vm['checked'] and vm['protected'] and vm['pfVerified']
    return _item('net.vm_network', 'network',
                 '固定代理与断网保护已核验' if ok else '虚拟机网络保护未通过',
                 'pass' if ok else 'high', vm['message'])


def check_transport(online: bool = True, state: dict | None = None) -> list[dict]:
    st = _transport_state() if state is None else state
    behavior = _dns_behavior(online)
    return [check_proxy_path(st), check_tun(st), check_dns_route(behavior, st)]


def check_routing() -> dict:
    ev: list[dict] = []
    flags = []

    pac_url = (compat.system_proxy() or {}).get("pac") or ""
    if pac_url:
        url = pac_url
        content = ""
        if url.startswith("file://"):
            try:
                content = Path(urllib.request.url2pathname(url[7:])).read_text(encoding="utf-8", errors="replace")[:200000]
            except Exception:
                pass
        elif url.startswith("http"):
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    content = r.read(200000).decode("utf-8", "replace")
            except Exception:
                pass
        if content:
            rules_hit = [ln.strip() for ln in content.splitlines()
                         if re.search(r"claude|anthropic", ln, re.I) and "PROXY" in ln.upper()][:4]
            if rules_hit:
                flags.append(f"PAC 脚本含 {len(rules_hit)} 条 Claude 分流规则")
                ev.append(_ev("PAC", rules_hit[0][:80], mono=True))
            else:
                ev.append(_ev("PAC", "已启用，无 Claude 专属规则"))

    tun_on = False
    claude_rules = 0
    proxy_ips: set[str] = set()
    server_names: set[str] = set()
    tun_excludes: set[str] = set()
    for root in (*_CLASH_ROOTS, *((Path('/usr/local/etc/mihomo'),) if vmnetwork.enabled() else ())):
        if not root.exists():
            continue
        try:
            yamls = _config_files(root, limit=6)
        except OSError:
            continue
        for y in yamls[:3]:
            try:
                text = y.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _TUN_ENABLED_RE.search(text) or _TUN_ENABLED_FLOW_RE.search(text):
                tun_on = True
            claude_rules += len(re.findall(r"claude|anthropic", text, re.I))
            # 代理节点的服务器地址；放行表 = route-exclude-address 段 + IP-CIDR...,DIRECT 规则
            found_ips, found_names = _server_hosts(text)
            proxy_ips.update(found_ips)
            server_names.update(found_names)
            for m in re.finditer(r"route-exclude-address\s*:\s*(?:\[([^\]]*)\]|((?:\n\s*-\s*[^\n]+)+))", text):
                chunk = (m.group(1) or "") + (m.group(2) or "")
                tun_excludes.update(re.findall(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", chunk))
            tun_excludes.update(
                re.findall(r"IP-CIDR6?,(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}),DIRECT", text)
            )
        ev.append(_ev("配置", str(root).replace(str(HOME), "~"), mono=True))

    # 域名形式的节点要解析成 IP 才能和排除表比对。只在 TUN 开着时才值得花这点时间。
    resolved: dict[str, list[str]] = {}
    unresolved: list[str] = []
    fake_names: list[str] = []
    if tun_on and server_names:
        resolved, unresolved = _resolve_all(server_names)
        for name, ips in resolved.items():
            usable = [i for i in ips if _usable_server_ip(i)]
            if usable:
                proxy_ips.update(usable)
            elif ips:
                # 解析出来是 fake-ip 或回环：这地址不是真节点，比对没有意义
                fake_names.append(name)
        if resolved:
            sample = next((f"{n} → {', '.join(i for i in ips if _usable_server_ip(i))}"
                           for n, ips in resolved.items() if any(_usable_server_ip(i) for i in ips)), "")
            if sample:
                ev.append(_ev("节点域名", sample, mono=True))

    utun = compat.tunnel_interfaces()
    proc_names = compat.proxy_processes(_PROXY_PROC_KEYS)
    vpn_names = compat.proxy_vpn_connections()

    if tun_on:
        flags.append("TUN 接管已启用")
    if claude_rules:
        flags.append(f"代理配置里有 {claude_rules} 处 Claude/Anthropic 关键词")
    if utun:
        ev.append(_ev("隧道接口", f"TUN × {utun}", mono=True))
    if proc_names:
        ev.append(_ev("代理进程", ", ".join(proc_names[:5]), mono=True))
    if vpn_names:
        ev.append(_ev("VPN 客户端", ", ".join(vpn_names[:5]), mono=True))
    iface = compat.default_route_iface()
    if iface:
        ev.append(_ev("默认路由", iface, mono=True))

    items = []
    if claude_rules or tun_on:
        # 标题必须说清是哪一种：配置里一处 Claude 规则都没有、只是 TUN 全开时，
        # 还写「有针对 Claude 的规则」是事实错误，用户会去翻一个不存在的规则。
        if claude_rules:
            title = "分流链路上有针对 Claude 的规则"
            detail = (
                "PAC 或 Clash/Mihomo 配置里出现 Claude 专属分流，意味着这台机器对 Claude 流量做了显式路由——"
                "这本身就是一条「这个人很在意 Claude 出口」的画像信号。"
                "但这类规则往往正是为了防订阅误伤才加的：留着它流量不漏，删掉它画像干净，"
                "两头不能同时要。"
                + ("当前 TUN 同时全开，所有流量都过代理。" if tun_on else "")
            )
            advice = (
                "先确认这些规则是你自己写的，而不是订阅规则集塞进来的。"
                "如果是你主动加的置顶规则，留着比删掉安全——"
                "这一条只是把代价标出来，不是让你把规则摘掉。"
            )
        else:
            title = "TUN 全接管，所有流量都过代理"
            detail = ("代理配置启用了 TUN，默认路由进了隧道：不只是 Claude，整台机器的流量都走代理。"
                      "这本身不算事故，只是流量特征比「只代理个别域名」更集中。")
            advice = ("整机走代理确实省事；如果不需要，改成规则模式只代理要用的域名，"
                      "画像信号会窄一些。")
        items.append(_item("net.routing", "network", title, "medium", detail, ev, advice))
    elif proc_names or vpn_names or (iface and iface.startswith("utun")):
        # 不能数 utun 个数：macOS 上十几个空闲 utun 是常态，
        # 默认路由还在 en0 时它们不代表任何代理链路。
        label = ", ".join(proc_names[:2] or vpn_names[:2]) or "TUN"
        items.append(_item(
            "net.routing", "network",
            f"代理链路运转中（{label}）",
            "info",
            "本机有代理进程/VPN/隧道在跑，但没有针对 Claude 的专属分流规则。",
            ev,
            "知道出口被接管就行；节点跳变频繁比代理本身更伤画像。",
        ))
    else:
        items.append(_item("net.routing", "network", "分流链路干净", "pass",
                           "没有 PAC Claude 规则、没有 TUN 接管、没有异常代理进程。", ev))

    # TUN 路由死锁：代理服务器自身 IP 没进排除表 → 流量回环卡死（经典踩坑）
    if tun_on:
        excludes = []
        for c in sorted(tun_excludes):
            try:
                excludes.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                continue
        looped = []
        for ip in sorted(proxy_ips):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not any(addr in net for net in excludes):
                looped.append(ip)

        if looped:
            items.append(_item(
                "net.tun_loop", "network",
                f"{len(looped)} 个代理服务器 IP 没在 TUN 排除表",
                "medium",
                "TUN 虚拟网卡接管了代理节点自身的 IP——流量被送回隧道形成回环，访问 Claude 会超时卡死。"
                "这是 TUN 模式最经典的坑：规则要在 route-exclude-address 里加 <代理IP>/32，"
                "或加一条 IP-CIDR,<代理IP>/32,DIRECT 置顶。",
                [_ev("回环 IP", ip, mono=True) for ip in looped[:6]]
                + [_ev("排除表", f"{len(excludes)} 条", mono=True)],
                "打开代理配置文件，把这几个 IP 加进 tun.route-exclude-address。",
                {"kind": "manual"},
            ))
        elif not proxy_ips:
            # 找不到节点地址就闭嘴，会让人误以为「查过了，没问题」
            why = []
            if unresolved:
                why.append(f"{len(unresolved)} 个域名解析不出来（{unresolved[0]}…）")
            if fake_names:
                why.append(f"{len(fake_names)} 个域名被解析成 fake-ip 段")
            items.append(_item(
                "net.tun_loop", "network",
                "TUN 回环无法实测（找不到节点真实 IP）",
                "info",
                "配置里没有可直接比对的代理节点地址："
                + ("；".join(why) if why else "没读到 server 字段")
                + "。这一项在你的环境里测不出来，不代表没有回环。",
                [_ev("TUN", "已启用", mono=True)]
                + ([_ev("未解析", ", ".join(unresolved[:4]), mono=True)] if unresolved else []),
                "在代理配置里确认节点的 server 是域名还是 IP；域名的话关掉 fake-ip 后重跑才能比对。",
            ))
    return items


# ---------------------------------------------------------------- 3-7 暗哨名录（DNSBL）

_DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.dronebl.org",
    "all.s5h.net",
    "dnsbl-1.uceprotect.net",
]

# DNSBL 的应答约定：命中时返回 127.0.0.0/8 里的地址（第几段表示列入原因），
# 未命中返回 NXDOMAIN。**不在这个段里的应答都不是名单给的**——最常见的是
# 运营商或公共 DNS 把 NXDOMAIN 劫持到自己的落地页，返回一个公网地址。
# 老代码只看「解析出东西就算命中」，于是每个名单都被判成命中，6/6 全红。
_DNSBL_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")

# Clash / Surge / Mihomo 的 fake-ip 段。开着 fake-ip 时，任何域名查询都会
# 被客户端就地编造成这个段里的地址，根本发不到 DNSBL 服务器上去。
# 在这种环境下查黑名单没有意义：拿到的既不是「命中」也不是「干净」。
_FAKE_IP = ipaddress.ip_network("198.18.0.0/15")


def _dnsbl_lookup(zone: str, rev: str) -> tuple[str, str]:
    """查一个名单。返回 (结论, 应答地址)。

    结论取值：hit（命中）/ clean（明确否认）/ fake（被编造）/ hijack（被劫持）
    / noanswer（超时等，什么都没拿到）。把这五种分开是有必要的——
    老代码把「没报错」一律当成命中，又把「报错」一律当成干净，
    两个方向都错。
    """
    try:
        addr = socket.gethostbyname(f"{rev}.{zone}")
    except socket.gaierror as exc:
        # EAI_NONAME = NXDOMAIN，名单明确说「没见过这个地址」，这才是常态
        return ("clean" if exc.errno == socket.EAI_NONAME else "noanswer"), ""
    except OSError:
        return "noanswer", ""
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return "hijack", addr
    if parsed in _FAKE_IP:
        return "fake", addr
    if parsed in _DNSBL_LOOPBACK:
        return "hit", addr
    return "hijack", addr


def check_dnsbl(ip: str | None) -> dict:
    if not ip:
        return _item("net.dnsbl", "network", "无出口 IP，跳过黑名单查询", "info",
                     "网络探测没拿到出口地址。")
    rev = ".".join(reversed(ip.split(".")))
    hits: list[tuple[str, str]] = []
    fake: list[str] = []
    hijack: list[tuple[str, str]] = []
    clean = 0
    noanswer = 0
    socket.setdefaulttimeout(2.5)
    try:
        for z in _DNSBL_ZONES:
            verdict, addr = _dnsbl_lookup(z, rev)
            if verdict == "hit":
                hits.append((z, addr))
            elif verdict == "fake":
                fake.append(z)
            elif verdict == "hijack":
                hijack.append((z, addr))
            elif verdict == "clean":
                clean += 1
            else:
                noanswer += 1
    finally:
        socket.setdefaulttimeout(None)

    # 全都被编造：这一项在当前环境下根本测不了，说清楚比给个假结论强
    if len(fake) == len(_DNSBL_ZONES):
        return _item(
            "net.dnsbl", "network",
            "DNSBL 无法实测（DNS 被 fake-ip 接管）",
            "info",
            "代理客户端把 DNS 查询就地编造成 198.18.x.x，查询到不了名单服务器。"
            "这一项在你的环境里测不出来——不是命中，也不代表干净。",
            [_ev("出口", ip, mono=True), _ev("编造段", "198.18.0.0/15", mono=True)],
            "把代理改成 redir-host 模式，或直连后重跑一次，这一项才有结论。",
        )

    # 有名单被 DNS 劫持：结论只能覆盖真查到的那些
    note = ""
    if hijack:
        note = (f"（{len(hijack)} 个名单的应答被 DNS 劫持成公网地址，"
                f"按无效处理：{hijack[0][1]}）")

    if hits:
        return _item(
            "net.dnsbl", "network",
            f"出口 IP 命中 {len(hits)} 个滥用黑名单",
            "high",
            "公开滥用黑名单记的是「这个地址干过 spam、批量注册这类事」——"
            "和你共用出口的其他人留下的案底，会直接算到你的会话上。" + note,
            [_ev("名单", f"{z} → {a}", mono=True) for z, a in hits] + [_ev("出口", ip, mono=True)],
            "换出口，然后重跑一遍确认黑名单清零。",
        )

    detail = (f"查询了 {len(_DNSBL_ZONES)} 个公开滥用名单：{clean} 个明确否认，"
              f"{noanswer} 个无应答。") + note
    if fake:
        detail += f" 另有 {len(fake)} 个因 fake-ip 无法查询。"
    return _item("net.dnsbl", "network", "出口 IP 未命中公开黑名单", "pass", detail,
                 [_ev("出口", ip, mono=True)])


# ---------------------------------------------------------------- 3-8 截听之证（MITM 根证书）

_MITM_NAMES = [
    "charles", "mitmproxy", "proxyman", "fiddler", "zscaler", "netskope",
    "blue coat", "bluecoat", "palo alto", "globalprotect", "fortinet",
    "avast", "kaspersky", "eset", "bitdefender", "nordvpn mitm",
]

def check_mitm() -> dict:
    hits = compat.mitm_cert_names(_MITM_NAMES)
    store = "钥匙串" if compat.IS_MAC else "证书存储"
    tool = "打开钥匙串访问" if compat.IS_MAC else "运行 certmgr.msc"
    if hits:
        return _item(
            "net.mitm", "network",
            f"{store}里有 {len(hits)} 个 TLS 拦截型根证书",
            "high",
            "这些根证书属于抓包/拦截型代理——装了它就意味着 HTTPS 流量可能被中途解开再重加密，"
            "你的请求内容（包括发给 Claude 的）对拦截方是明文的。",
            [_ev("证书", h, mono=True) for h in hits[:6]],
            f"{tool}找到对应根证书，确认是自己装的；不认识的直接删并把信任改回默认。",
        )
    return _item("net.mitm", "network", "未发现 TLS 拦截型根证书", "pass",
                 f"{store}里没有抓包类代理的根证书。")


# ---------------------------------------------------------------- 3-9 IPv6 暗门


def check_ipv6(guard: dict | None = None) -> dict:
    """IPv6 泄露面。判据只覆盖 Wi-Fi，因为一键关闭也只改 Wi-Fi。

    以太网 / VPN 上的全局 v6 本工具不会动，不能报成「去点一下就能修」的
    中等风险；那种情况只给信息，让用户自己处理对应接口。

    客户端自己的 `ipv6` 开关只作证据：系统已经没有 v6 出口时，它是关是开
    都不构成泄漏面；系统有 v6 出口时，客户端还开着才说明这条链路更容易被
    实际走到。
    """
    vm = vmnetwork.read()
    if vm['managed'] and vm['checked'] and vm['protected'] and vm['pfVerified']:
        return _item('net.ipv6', 'network', '虚拟机物理 IPv6 出站已由 pf 阻断', 'pass',
                     '当前 pf 仅允许批准端点的 IPv4 TCP 与 DHCP；其它出站默认拒绝，不依赖 Wi-Fi 开关。')
    v6 = compat.ipv6_exposure()
    global6 = v6.get("sample") or []
    has_route6 = bool(v6.get("has_default_v6_route"))
    if guard is None:
        guard = proxyguard.inspect()
    client_v6 = guard.get("ipv6") if guard.get("checked") else None
    client_ev = _ev("客户端 v6", {True: "已开启（ipv6: true）",
                                  False: "已关闭（ipv6: false）"}.get(client_v6, "未读到"))
    if not (has_route6 and global6):
        detail = "没有全局 v6 地址或没有 v6 默认路由——代理链路不会被 v6 绕过。"
        if client_v6 is True:
            detail += " 客户端配置允许 v6（ipv6: true），但系统当前没有 v6 全局出口，不构成泄漏面。"
        return _item("net.ipv6", "network", "无可用 IPv6 全局出口", "pass",
                     detail, [client_ev])

    iface = v6.get("default_v6_iface") or ""
    wifi = compat.wifi_device() if compat.IS_MAC else ""
    wifi_v6 = (v6.get("interfaces") or {}).get(wifi, []) if wifi else []
    ev = [
        _ev("v6 地址", _mask(global6[0]), mono=True),
        _ev("v6 默认出口", iface or "-", mono=True),
        client_ev,
    ]
    if wifi:
        ev.append(_ev("Wi-Fi 网卡", wifi, mono=True))
    client_note = ""
    if client_v6 is True:
        client_note = " 客户端也开着 v6（ipv6: true），走 v6 的请求不会被只接管 v4 的代理拦住。"
    elif client_v6 is False:
        client_note = " 客户端已关闭 v6（ipv6: false），这一层只剩系统网络栈。"

    if compat.IS_MAC and wifi and (iface == wifi or (not iface and wifi_v6)):
        return _item(
            "net.ipv6", "network",
            "Wi-Fi 的 IPv6 全局直出存在泄露面",
            "medium",
            "默认 v6 出口落在 Wi-Fi 上，机器同时有全局 IPv6 地址。"
            "多数代理只接管 v4——客户端若优先走 v6，请求会绕过代理从真实 ISP 出去。"
            + client_note,
            ev,
            "「隐私设置 → IPv6 出口（Wi-Fi）」可关闭 Wi-Fi 的 IPv6（需管理员授权）并随时恢复；"
            "关闭后断开重连 Wi-Fi 再检测。以太网、VPN 等其它服务本工具不改。",
        )

    if compat.IS_MAC:
        target = iface or "非 Wi-Fi 接口"
        return _item(
            "net.ipv6", "network",
            f"{target} 上存在 IPv6 全局出口",
            "info",
            f"检测到全局 v6 地址和 v6 默认路由，但默认出口是 {target}，不是 Wi-Fi"
            f"（{wifi or '未识别'}）。本工具的一键关闭只改 Wi-Fi，不会处理这条链路。"
            + client_note,
            ev,
            f"手动处理：系统设置 → 网络 → {target} → 详细信息 → TCP/IP → 配置 IPv6 → 关闭；"
            "或确认代理规则已经覆盖 v6。",
        )

    return _item(
        "net.ipv6", "network",
        "IPv6 全局直出存在泄露面",
        "medium",
        "这台机器有全局 IPv6 地址和 v6 默认路由。多数代理只接管 v4——"
        "客户端若优先走 v6，请求就绕过代理从真实 ISP 直接出去。"
        + client_note,
        ev,
        "在系统网络设置里关闭该接口的 IPv6，或确认代理规则覆盖 v6。",
    )


# ---------------------------------------------------------------- 2-x 遥测文件残留（fixable）


def check_telemetry_files() -> list[dict]:
    roots = [
        ("telemetry", CLAUDE_DIR / "telemetry"),
        ("statsig", CLAUDE_DIR / "statsig"),
        ("logs", CLAUDE_DIR / "logs"),
        ("usage_jsonl", CLAUDE_DIR / "usage.jsonl"),
        ("usage_fix", CLAUDE_DIR / "usage.with-fix.jsonl"),
        ("usage_data", CLAUDE_DIR / "usage-data"),
        ("cache", (HOME / "Library" / "Caches" / "claude-cli-nodejs") if compat.IS_MAC
                  else Path(os.environ.get("LOCALAPPDATA", str(HOME))) / "claude-cli-nodejs" / "Cache"),
    ]
    items = []
    for key, r in roots:
        if not r.exists():
            continue
        size, count = _path_size(r)
        items.append(_item(
            f"res.telemetry.{key}", "residue",
            f"遥测文件残留 {r.name}（{count} 个文件 · {_human(size)}）",
            "low",
            "遥测/用量文件记着事件上报、用量统计与设备标识快照。",
            [_ev("路径", str(r).replace(str(HOME), "~"), mono=True)],
            "直接删除，不备份、不进废纸篓；旧日志和用量数据无法还原。",
            {"kind": "trash", "path": str(r), "size": size, "count": count},
        ))
    if not items:
        items.append(_item("res.telemetry", "residue", "未发现遥测文件残留", "pass",
                           "~/.claude 下没有 telemetry/statsig 缓存。"))
    return items


# ---------------------------------------------------------------- 2-4 多版本残留


def check_versions() -> list[dict]:
    bins = [p for p in compat.which_claude() if p.strip()]
    versions_dir = CLAUDE_DIR / "local" / "versions"
    extra = []
    if versions_dir.is_dir():
        try:
            extra = [str(p) for p in versions_dir.iterdir() if p.is_file()]
        except OSError:
            pass
    ver = _run(["claude", "--version"], 5)
    stale = ""
    if ver:
        try:
            with urllib.request.urlopen(
                "https://registry.npmjs.org/@anthropic-ai%2fclaude-code/latest", timeout=4
            ) as r:
                latest = (json.loads(r.read().decode()) or {}).get("version", "")
            cur = re.search(r"(\d+\.\d+\.\d+)", ver)
            if latest and cur and latest != cur.group(1):
                stale = latest
        except Exception:
            pass
    uniq = sorted(set(bins) | set(extra))
    items = []
    if len(uniq) > 1:
        items.append(_item(
            "res.versions", "residue",
            f"存在 {len(uniq)} 个 claude 安装位置",
            "low",
            "多份安装各自写配置，清理时容易漏掉某一份的旧数据。",
            [_ev("位置", p.replace(str(HOME), "~"), mono=True) for p in uniq[:5]],
            "保留 PATH 里生效的那份，其余按需卸载。",
        ))
    if stale:
        items.append(_item(
            "res.stale", "residue",
            f"客户端版本偏旧（本地 {ver[:30]} · 最新 {stale}）",
            "low",
            "旧版本的标记与上报行为和当前版不同——画像对照表一般按最新版校准。",
            [_ev("本地", ver[:60], mono=True), _ev("最新", stale, mono=True)],
            "npm/brew 升级到最新版后再跑一遍。",
        ))
    return items


# ---------------------------------------------------------------- 汇总入口


def check_deep(net_info: dict | None = None) -> list[dict]:
    """深层检测集合。net_info 传 check_network 的结果（供 DNSBL 用）。"""
    out: list[dict] = []
    fns = [
        check_marker_signature,
        check_rhythm,
        check_browser,
        check_permissions,
        telemetry.inspect,
        check_launchd_env,
        check_proxy_env,
        check_pinned,
        check_routing,
        check_transport,
        check_proxy_dns,
        check_vm_network,
        check_proxy_fallback,
        check_proxy_drift,
        check_terminal_egress,
        check_shell_env,
        check_mitm,
        check_ipv6,
        check_telemetry_files,
        check_versions,
    ]
    guard: dict | None = None
    # 登录 shell 一次扫描只起一次：出口和环境变量是同一趟读出来的，
    # 两个检查项共用。起两次既慢又可能读到两个不同瞬间的状态。
    term: dict | None = None
    for fn in fns:
        try:
            if fn in (check_pinned, check_transport):
                # 只有本轮联网探测成功时才做 DNS 行为探测；关掉联网检测
                # 还去解析域名，等于绕过用户的开关。
                r = fn(bool((net_info or {}).get("available")))
            elif fn is check_proxy_dns:
                r = fn(egress=net_info)
            elif fn in (check_terminal_egress, check_shell_env):
                if term is None:
                    term = _terminal_probe(net_info)
                r = fn(net_info, term)
            elif fn in (check_proxy_fallback, check_proxy_drift, check_ipv6):
                # 回落、漂移与 v6 读的是同一份客户端配置，一次扫描只读一遍。
                if guard is None:
                    guard = proxyguard.inspect()
                r = fn(guard)
            else:
                r = fn()
            out.extend(r if isinstance(r, list) else [r])
        except Exception as exc:
            out.append(_item(f"err.deep_{fn.__name__}", "fingerprint",
                             f"深层检测 {fn.__name__} 异常", "info", str(exc)[:160]))
    try:
        out.append(check_dnsbl((net_info or {}).get("ip")))
    except Exception as exc:
        out.append(_item("err.deep_dnsbl", "network", "DNSBL 查询异常", "info", str(exc)[:160]))
    return out


# ---------------------------------------------------------------- 工具：遥测域名 hosts 封缄 + 开关清单


def telemetry_block_text() -> str:
    lines = [
        "# Claude 遥测主机规则：手动审阅后追加到 /etc/hosts，需要 sudo",
        "# 当前官方 CLI 网络文档：" + telemetry.NETWORK_DOCS,
        *["0.0.0.0 " + host for host in telemetry.DATADOG_HOSTS],
        "# 历史版本目标，是否适用需观察当前客户端：",
        *["0.0.0.0 " + host for host in telemetry.LEGACY_HOSTS],
        "# hosts 不支持通配符；拦截 sentry.io 不会拦截其子域名。",
        "# 请按观察到的具体 Sentry 主机补充规则，优先使用官方关闭开关。",
        "# api.anthropic.com 同时承载正常请求与遥测，不能整域封锁。",
        "# 不覆盖所有版本、Desktop 自身流量或绕过本机 DNS 的连接。",
        "# 关闭非必要上报不等于关闭服务端安全检测。",
        "# 以下是可选开关，不应不加区分全部启用：",
    ]
    lines += [f"#   export {k}=1" for k in _TELEMETRY_KILL_VARS]
    lines += ["# 总开关还会停用自动更新；DISABLE_TELEMETRY 可能影响 Remote Control 等功能。",
              "# 恢复：删除对应 hosts 行并 sudo killall -HUP mDNSResponder；配置变更另行撤销。"]
    return "\n".join(lines)
