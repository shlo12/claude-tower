"""扫描引擎：把 macOS 上与 Claude 相关的本地状态收敛成一份带严重度的清单。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import (browserwebrtc, compat, doh, netcfg, netprobe, regioncfg,
               retention, rules, shield, stun)

HOME = Path.home()
CLAUDE_DIR = HOME / ".claude"
CLAUDE_JSON = HOME / ".claude.json"

SHELL_RC = [
    HOME / ".zshrc",
    HOME / ".zprofile",
    HOME / ".zshenv",
    HOME / ".bash_profile",
    HOME / ".bashrc",
    HOME / ".profile",
    HOME / ".config" / "fish" / "config.fish",
]
if compat.IS_WIN:
    SHELL_RC = compat.rc_files()

FINGERPRINT_KEYS = [
    "userID",
    "machineID",
    "anonymousId",
    "firstStartTime",
    "claudeCodeFirstTokenDate",
    "oauthAccount",
    "clientData",
    # 账号/实验分组缓存：按稳定用户标识下发的分组结果与资格缓存，跨账号复用时是强关联信号
    "s1mAccessCache",
    "groveConfigCache",
    "passesEligibilityCache",
    "additionalModelCostsCache",
    "additionalModelOptionsCache",
    "autoCompactWindowsCache",
    "cachedChromeExtensionInstalled",
    "cachedDynamicConfigs",
    "cachedExperimentData",
    "cachedExperimentFeatures",
    "cachedExtraUsageDisabledReason",
    "cachedGrowthBookFeatures",
    "cachedGrowthBookFeaturesAt",
    "cachedStatsigGates",
    "clientDataCache",
    "clientDataCacheSlots",
    "feedbackSurveyState",
    "metricsStatusCache",
    "modelAccessCache",
    "orgModelDefaultCache",
]

# 账号邮箱：国内服务商注册的账号在风控里几乎是自曝，Gmail / iCloud / Outlook 是公认最稳的一档
CN_MAIL_DOMAINS = (
    "qq.com", "foxmail.com", "163.com", "126.com", "yeah.net", "sina.com", "sina.cn",
    "sohu.com", "aliyun.com", "aliyun.cn", "139.com", "189.cn", "21cn.com", "263.net",
    "tom.com", "wo.cn", "china.com", "vip.qq.com",
)
SAFE_MAIL_DOMAINS = (
    "gmail.com", "googlemail.com", "icloud.com", "me.com", "mac.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "proton.me", "protonmail.com", "pm.me",
)

KEYCHAIN_SERVICES = [
    "Claude Code-credentials",
    "Claude Code",
    "claude-code",
    "claude-code-credentials",
]


# ---------------------------------------------------------------- 基础工具


def _run(cmd: list[str], timeout: float = 6.0) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return (out.stdout or "").strip()
    except Exception:
        return ""


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.0f} {unit}" if unit in ("B", "KB") else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} GB"


def path_stats(path: Path) -> tuple[bool, int, int]:
    """返回 (是否存在, 总字节, 文件数)。"""
    if not path.exists():
        return False, 0, 0
    if path.is_file():
        try:
            return True, path.stat().st_size, 1
        except OSError:
            return True, 0, 1
    total = 0
    count = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
                count += 1
            except OSError:
                continue
    return True, total, count


def _item(
    id: str,
    category: str,
    title: str,
    severity: str,
    detail: str,
    evidence: list[dict] | None = None,
    advice: str = "",
    fix: dict | None = None,
    tags: list[str] | None = None,
    probe: str = "",
) -> dict:
    item = {
        "id": id,
        "category": category,
        "title": title,
        "severity": severity,
        "detail": detail,
        "evidence": evidence or [],
        "advice": advice,
        "fix": fix,
        "tags": tags or [],
    }
    # 需要「在浏览器里跑一段」才能测的项目（目前只有浏览器侧 WebRTC）。
    # 只给需要的项挂这个键：所有项都带一个空字段，前端就得逐项判断空串。
    if probe:
        item["probe"] = probe
    return item


def _ev(label: str, value: str, mono: bool = False) -> dict:
    return {"label": label, "value": value, "mono": mono}


def _short(path) -> str:
    """把家目录替换成 ~，避免界面里出现一长串绝对路径。"""
    text = str(path)
    home = str(HOME)
    return "~" + text[len(home):] if text.startswith(home) else text


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------- 指纹


def check_fingerprint() -> list[dict]:
    items: list[dict] = []

    data = _read_json(CLAUDE_JSON) if CLAUDE_JSON.exists() else None
    if data is None:
        items.append(
            _item(
                "fp.claude_json",
                "fingerprint",
                "未发现 ~/.claude.json",
                "pass",
                "全局状态文件不存在，没有跨账号复用的用户级标识。",
            )
        )
    else:
        present = [k for k in FINGERPRINT_KEYS if data.get(k) not in (None, "", {}, [])]
        if present:
            preview = []
            for key in present[:5]:
                val = data.get(key)
                if isinstance(val, (dict, list)):
                    val = f"<{type(val).__name__} · {len(val)} 项>"
                preview.append(_ev(key, str(val)[:64], mono=True))
            items.append(
                _item(
                    "fp.identity_fields",
                    "fingerprint",
                    f"~/.claude.json 中留存 {len(present)} 个身份标识字段",
                    "high",
                    "userID / anonymousId 是跨会话稳定的设备级标识，换账号登录时不会自动变化，"
                    "是最容易被用来把多个账号串到同一台机器上的字段。",
                    preview,
                    "清理会把 machineID / userID 重置为全新随机值（比删除更彻底——删除后客户端可能按硬件特征算回原值），"
                    "其余标识字段清空，模型、权限等偏好保留。",
                    {
                        "kind": "rotate_ids",
                        "file": "~/.claude.json",
                        "rotate": [k for k in ("machineID", "userID") if k in present],
                        "keys": [k for k in present if k not in ("machineID", "userID")],
                    },
                    ["cross-account"],
                )
            )
        else:
            items.append(
                _item(
                    "fp.identity_fields",
                    "fingerprint",
                    "身份标识字段已清空",
                    "pass",
                    "~/.claude.json 存在但关键标识字段为空。",
                )
            )

        projects = data.get("projects") or {}
        if isinstance(projects, dict) and projects:
            items.append(
                _item(
                    "fp.projects_meta",
                    "fingerprint",
                    f"~/.claude.json 记录了 {len(projects)} 个项目路径",
                    "low",
                    "项目路径会暴露你的目录结构、用户名与工作内容，且长期累积。",
                    [_ev("示例", next(iter(projects))[:80], mono=True)],
                    "如果这台机器要换主人或换账号，建议一并清理。",
                    {"kind": "json_keys", "file": "~/.claude.json", "keys": ["projects"]},
                )
            )

    # 各类本地数据目录
    dir_specs = [
        ("telemetry", "遥测事件", "high", "按会话上报的事件流，含设备与会话标识。"),
        ("statsig", "实验分组缓存", "high", "功能开关的分组结果按稳定用户标识下发并缓存，是强关联信号。"),
        ("stats-cache.json", "统计缓存", "low", "本地用量统计，含时间戳。"),
        ("history.jsonl", "对话历史", "high", "每条提示词、时间、所在项目都会落盘，是最完整的本地行为画像。"),
        ("shell-snapshots", "Shell 快照", "medium", "会话启动时的 shell 环境快照，可能包含代理与密钥变量。"),
        ("session-env", "会话环境变量", "medium", "会话级注入的环境变量。"),
        ("projects", "项目会话记录", "medium", "每个项目目录下的完整对话 jsonl。"),
        ("file-history", "文件修改历史", "low", "支持 undo 的文件快照。"),
        ("paste-cache", "粘贴缓存", "low", "粘贴内容缓存。"),
        ("debug", "调试日志", "low", "最近一次运行的调试输出。"),
        ("sessions", "会话状态", "low", "运行时会话状态。"),
        ("todos", "任务列表", "low", "会话内的待办数据。"),
        ("plans", "计划文档", "low", "Plan Mode 生成的计划。"),
    ]
    for name, label, sev, desc in dir_specs:
        path = CLAUDE_DIR / name
        exists, size, count = path_stats(path)
        if not exists or (count == 0 and path.is_dir()):
            continue
        items.append(
            _item(
                f"fp.{name.replace('.', '_')}",
                "fingerprint",
                f"{label}：{count} 个文件 · {human_size(size)}",
                sev,
                desc,
                [_ev("路径", _short(path), mono=True), _ev("占用", human_size(size))],
                ("清理时直接删除，不备份、不进废纸篓，无法还原。" if retention.path_category(path, HOME)
                 else "清理时整体移入废纸篓，不会直接销毁。"),
                {"kind": "trash", "path": str(path), "size": size, "count": count},
            )
        )

    items.append(_check_fonts())
    items.append(_check_gpu())
    items.append(_check_vm())
    items.append(_email_domain_item())
    return items


# 随中文办公软件一起装进来的字体。系统自带的 PingFang / Hiragino 不算——
# 每台 Mac 都有，不构成区分度。
_REGION_FONTS = ("simsun", "simhei", "simkai", "simfang", "msyh", "msjh",
                 "dengxian", "wqy", "fzshu", "fzkai", "fzhei", "fangsong")
_VIRTUAL_GPU = ("virtual", "vmware", "parallels", "virtualbox", "swiftshader",
                "llvmpipe", "qemu", "cirrus")


def _font_hits(limit: int = 8) -> list[str]:
    """扫用户与全局字体目录，挑出地区特征字体。

    只认文件名关键词，不解析字体元数据——这里要的是「这台机器像不像
    中文办公环境」，不是精确识别字体家族。
    """
    hits: list[str] = []
    seen = 0
    for base in (Path("/Library/Fonts"), HOME / "Library/Fonts"):
        if not base.is_dir():
            continue
        try:
            for path in base.rglob("*"):
                seen += 1
                if seen > 4000:
                    return hits
                if path.suffix.lower() not in (".ttf", ".ttc", ".otf"):
                    continue
                name = path.name.lower()
                if any(key in name for key in _REGION_FONTS) and path.name not in hits:
                    hits.append(path.name)
                    if len(hits) >= limit:
                        return hits
        except OSError:
            continue
    return hits


def _check_fonts() -> dict:
    if not compat.IS_MAC:
        return _item("fp.fonts", "fingerprint", "字体地区特征：仅 macOS 检查", "info",
                     "这一项读的是 macOS 的字体目录，其它系统跳过。")
    hits = _font_hits()
    if hits:
        return _item(
            "fp.fonts", "fingerprint",
            f"装了 {len(hits)} 个地区特征字体",
            "medium",
            "SimSun / 微软雅黑 / 文泉驿 / 方正这类字体通常随中文办公软件装进来，"
            "美区环境里很少见。字体列表是浏览器和部分应用能读到的稳定特征，"
            "装得越多，这台机器的地区画像越明显。",
            [_ev("字体", "、".join(hits), mono=True)],
            "在「字体册」里停用不用的字体就够了，不必删除；只是停用也仍然算已安装，"
            "要彻底消除特征需要卸载。",
        )
    return _item("fp.fonts", "fingerprint", "未发现地区特征字体", "pass",
                 "字体目录里只有系统自带字体，不构成地区特征。")


def _check_gpu() -> dict:
    if not compat.IS_MAC:
        return _item("fp.gpu", "fingerprint", "显卡与显示：仅 macOS 检查", "info",
                     "这一项读的是 macOS 的显卡信息，其它系统跳过。")
    out = _run(["system_profiler", "SPDisplaysDataType"], 12)
    chip, res = "", ""
    for line in out.splitlines():
        s = line.strip()
        if not chip and s.startswith("Chipset Model:"):
            chip = s.split(":", 1)[1].strip()
        elif not res and s.startswith("Resolution:"):
            res = s.split(":", 1)[1].strip()
    if not chip:
        return _item("fp.gpu", "fingerprint", "读不到显卡信息", "info",
                     "system_profiler 没有返回显卡型号，这一项跳过。")
    ev = [_ev("显卡", chip, mono=True)]
    if res:
        ev.append(_ev("分辨率", res, mono=True))
    if any(key in chip.lower() for key in _VIRTUAL_GPU):
        return _item(
            "fp.gpu", "fingerprint", f"检测到虚拟显卡（{chip}）", "medium",
            "虚拟显卡的型号字符串是很强的指纹：正常笔记本不会报 SwiftShader / VMware "
            "这类名字。客户端把渲染信息带出去时，这条比 CPU 型号更少见。",
            ev,
            "偶尔在虚拟机里跑一次问题不大；长期主力使用建议换物理机。",
        )
    return _item("fp.gpu", "fingerprint", f"显卡：{chip}", "pass",
                 "显卡型号属于常规硬件信息，物理机上不构成额外风险。", ev)


def _check_vm() -> dict:
    if not compat.IS_MAC:
        return _item("fp.vm", "fingerprint", "虚拟机检测：仅 macOS 检查", "info",
                     "这一项读的是 macOS 的 hypervisor 标记，其它系统跳过。")
    flag = _run(["sysctl", "-n", "kern.hv_vmm_present"], 4)
    model = _run(["sysctl", "-n", "hw.model"], 4)
    ev = [_ev("kern.hv_vmm_present", flag or "?", mono=True)]
    if model:
        ev.append(_ev("机型", model, mono=True))
    if flag == "1":
        return _item(
            "fp.vm", "fingerprint", "运行在虚拟机里", "medium",
            "kern.hv_vmm_present=1 表示当前系统跑在 hypervisor 之上。虚拟机的硬件标识、"
            "网卡 OUI 和显卡字符串都与常见零售机型不同，是一层看得见的区分度。",
            ev,
            "如果这是有意为之（隔离环境），可以接受；否则建议在物理机上使用。",
        )
    return _item("fp.vm", "fingerprint", "运行在物理机上", "pass",
                 "没有检测到 hypervisor 标记。", ev)


# ---------------------------------------------------------------- Claude Code CLI
def _cli_real_path(path: str) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return path


def _cli_method(real: str) -> str:
    low = real.lower().replace("\\", "/")
    if ".claude/local" in low or ".local/share/claude" in low:
        return "native（官方安装脚本）"
    if "/homebrew/" in low or "/cellar/" in low or "linuxbrew" in low:
        return "Homebrew"
    if "node_modules" in low or ".npm-global" in low or "/.bun/" in low:
        return "npm / bun"
    return ""


def _cli_version(path: str) -> str:
    """只取版本号。CLI 是 node 应用，冷启动慢，给足 5 秒。"""
    out = _run([path, "--version"], 5)
    return out.splitlines()[0].strip()[:80] if out else ""


def _desktop_bundled_cli() -> list[str]:
    """桌面版自带的 CLI 副本。它和 PATH 里那份经常不是同一个版本。"""
    roots = []
    if compat.IS_WIN:
        lad = Path(os.environ.get("LOCALAPPDATA", str(HOME)))
        roots = [lad / "AnthropicClaude" / "claude-code",
                 lad / "Claude" / "claude-code"]
    else:
        roots = [HOME / "Library" / "Application Support" / "Claude" / "claude-code",
                 HOME / "Library" / "Application Support" / "Claude-3p" / "claude-code"]
    found: list[str] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            found += [p.name for p in sorted(root.iterdir()) if p.is_dir()]
        except OSError:
            continue
    return found


_NPM_ROOTS = (
    Path("/opt/homebrew/lib/node_modules"),
    Path("/usr/local/lib/node_modules"),
    HOME / ".npm-global" / "lib" / "node_modules",
    HOME / ".bun" / "install" / "global" / "node_modules",
)
_BREW_CELLARS = (Path("/opt/homebrew/Cellar/claude-code"),
                 Path("/usr/local/Cellar/claude-code"))


def _cli_copies() -> dict[str, str]:
    """按路径找安装，不调用 npm / brew。

    `npm ls -g` 启动一次要好几秒（实测这台机器上 10 秒），而这里要的只是
    「有没有装过」——扫目录足够，而且不会因为 npm 版本差异给出不同格式。
    """
    found: dict[str, str] = {}
    for root in _NPM_ROOTS:
        pkg = root / "@anthropic-ai" / "claude-code"
        if pkg.is_dir():
            found.setdefault("npm", str(pkg))
    try:
        for pkg in HOME.glob(".nvm/versions/node/*/lib/node_modules/@anthropic-ai/claude-code"):
            if pkg.is_dir():
                found.setdefault("npm", str(pkg))
                break
    except OSError:
        pass
    for cellar in _BREW_CELLARS:
        if cellar.is_dir():
            found.setdefault("brew", str(cellar))
    return found


def check_cli() -> list[dict]:
    """Claude Code CLI 装了几份、分别是什么版本。

    桌面版内置的 CLI 和自己用 npm / Homebrew 装的那份经常版本不一致，或者
    PATH 指向了旧版。多份共存本身不是错误，但「用的不是你以为的那一份」
    会让人照着文档排查半天。
    """
    path = shutil.which("claude") or ""
    real = _cli_real_path(path) if path else ""
    method = _cli_method(real) if real else ""
    version = _cli_version(path) if path else ""
    bundled = _desktop_bundled_cli()
    copies = _cli_copies()

    ev: list[dict] = []
    if path:
        ev.append(_ev("PATH", path, mono=True))
    if real and real != path:
        ev.append(_ev("真实路径", real, mono=True))
    if version:
        ev.append(_ev("版本", version, mono=True))
    if method:
        ev.append(_ev("安装方式", method))
    if bundled:
        ev.append(_ev("桌面版内置", bundled[-1], mono=True))
    for kind, where in copies.items():
        ev.append(_ev("npm 全局包" if kind == "npm" else "Homebrew 包",
                      _short(where), mono=True))

    # 数一数到底有几份独立的安装。PATH 里那份如果就是 npm/brew 的软链，
    # 那它是同一份，不能算两次——不然每个正常用户都会被判成「多份共存」。
    kinds: set[str] = set(copies)
    if method == "Homebrew":
        kinds.add("brew")
    elif method == "npm / bun":
        kinds.add("npm")
    elif method.startswith("native"):
        kinds.add("native")

    if len(kinds) >= 2:
        return [_item(
            "cli.claude_code", "residue",
            f"Claude Code CLI 有 {len(kinds)} 种安装方式共存",
            "medium",
            "同一台机器上用不同方式各装了一份 CLI，版本不一定一致：PATH 里先命中的"
            "那一份才生效。照着文档升级、却发现行为没变，通常就是这里。",
            ev,
            "留下你实际在用的那一份，其余卸掉："
            "`npm uninstall -g @anthropic-ai/claude-code` 或 `brew uninstall claude-code`。",
        )]
    if path:
        extra = "；另外桌面版也内置了一份" if bundled else ""
        return [_item(
            "cli.claude_code", "residue",
            f"Claude Code CLI：{version or '版本未取到'}",
            "pass",
            f"PATH 里只有一份 CLI，安装方式明确{extra}。",
            ev,
        )]
    if bundled:
        return [_item(
            "cli.claude_code", "residue",
            "只有桌面版内置的 CLI",
            "info",
            "PATH 里没有 claude 命令，只有桌面版自带的那一份。"
            "在终端里直接敲 claude 会用不了，需要另装或把它加进 PATH。",
            ev,
        )]
    return [_item(
        "cli.claude_code", "residue",
        "没有安装 Claude Code CLI",
        "info",
        "PATH 里没有 claude 命令，也没有发现桌面版内置的副本。",
    )]


def _account_emails() -> set[str]:
    """本地配置里出现过的账号邮箱。"""
    emails: set[str] = set()
    for f in (CLAUDE_JSON, CLAUDE_DIR / "credentials.json", CLAUDE_DIR / ".credentials.json"):
        try:
            blob = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        emails.update(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", blob))
    return emails


def _email_domain_item() -> dict:
    """账号注册邮箱的域名分档：国内服务商几乎等于自曝，Gmail/iCloud/Outlook 最稳。"""
    emails = sorted(_account_emails())
    if not emails:
        return _item(
            "fp.email_domain",
            "fingerprint",
            "本地没有账号邮箱记录",
            "pass",
            "没有登录凭据，读不到注册邮箱，本项不参与判定。",
        )
    domains = sorted({e.rsplit("@", 1)[-1].lower() for e in emails if "@" in e})
    ev = [_ev("账号邮箱", e, mono=True) for e in emails[:3]]
    ev.append(_ev("域名", ", ".join(domains[:4]), mono=True))

    cn = next((d for d in domains if d in CN_MAIL_DOMAINS), "")
    if cn:
        return _item(
            "fp.email_domain",
            "fingerprint",
            f"账号邮箱用的是国内服务商（{cn}）",
            "high",
            "国内邮箱注册的账号在风控里几乎没有缓冲区：邮箱域本身就会暴露注册地，"
            "而且这类邮箱的注册与登录行为更容易被归到同一批人。这是「一开始就不该踩」的一项。",
            ev,
            "换一个 Gmail / iCloud / Outlook 邮箱重新注册，不要在同一台机器上直接切。",
        )
    if all(d in SAFE_MAIL_DOMAINS for d in domains):
        return _item(
            "fp.email_domain",
            "fingerprint",
            f"账号邮箱域名正常（{domains[0]}）",
            "pass",
            "Gmail / iCloud / Outlook 这一档邮箱是最稳的注册选择。",
            ev,
        )
    return _item(
        "fp.email_domain",
        "fingerprint",
        f"账号邮箱域名不在常见分档内（{domains[0]}）",
        "info",
        "既不是国内服务商，也不在 Gmail / iCloud / Outlook 这一档里。"
        "自定义域名或其他服务商需要你自己判断它的注册地与信誉。",
        ev,
        "追求稳妥的话，换成 Gmail / iCloud / Outlook 邮箱。",
    )


# ---------------------------------------------------------------- 凭据


def check_credential() -> list[dict]:
    items: list[dict] = []

    for svc in KEYCHAIN_SERVICES:
        found = (
            subprocess.run(
                ["security", "find-generic-password", "-s", svc],
                capture_output=True,
                timeout=6,
                check=False,
            ).returncode
            == 0
        )
        if found:
            items.append(
                _item(
                    f"cred.keychain.{re.sub(r'[^a-z0-9]+', '_', svc.lower())}",
                    "credential",
                    f"Keychain 中存在「{svc}」",
                    "high",
                    "OAuth 令牌保存在系统钥匙串里，删除它等于让这台机器彻底退出登录，"
                    "换账号前必须处理，否则新旧账号会共用同一份凭据槽位。",
                    [_ev("服务名", svc, mono=True)],
                    "删除后需要重新执行 claude login。",
                    {"kind": "keychain", "service": svc},
                )
            )

    # 旧版本把凭据写在配置目录里
    for legacy in (CLAUDE_DIR / ".credentials.json", CLAUDE_DIR / "credentials.json"):
        if not legacy.exists():
            continue
        size = legacy.stat().st_size
        items.append(
            _item(
                "cred.legacy_file" + (".plain" if not legacy.name.startswith(".") else ""),
                "credential",
                "配置目录中存在明文凭据文件",
                "critical",
                "旧版客户端会把 OAuth 凭据直接写在 ~/.claude/.credentials.json，任何能读该目录的程序都能拿到。",
                [_ev("路径", _short(legacy), mono=True), _ev("大小", human_size(size))],
                "直接删除该文件，不备份、不进废纸篓；需要重新登录。",
                {"kind": "trash", "path": str(legacy), "size": size, "count": 1},
            )
        )

    # settings.json / settings.local.json 里的密钥
    for fname in ("settings.json", "settings.local.json"):
        path = CLAUDE_DIR / fname
        data = _read_json(path) if path.exists() else None
        env = (data or {}).get("env") or {}
        secret_keys = [
            k
            for k in env
            if k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")
        ]
        if secret_keys:
            items.append(
                _item(
                    f"cred.settings.{fname.replace('.', '_')}",
                    "credential",
                    f"{fname} 的 env 中写入了 {len(secret_keys)} 个敏感变量",
                    "critical",
                    "配置文件里的密钥是明文，且 settings.json 会被同步/备份/提交到仓库，泄露面比环境变量大得多。",
                    [_ev(k, "已配置（密钥值不显示）" if retention.secret_name(k) else str(env.get(k))) for k in secret_keys],
                    "把密钥移到 shell 环境或独立的隔离启动器里，配置文件只保留非敏感项。",
                    {
                        "kind": "json_keys",
                        "file": str(path),
                        "keys": [f"env.{k}" for k in secret_keys],
                    },
                )
            )

    # shell 启动文件里的密钥
    for rc in SHELL_RC:
        try:
            text = rc.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        lines = text.splitlines()
        hits = [start for start, _ in retention.shell_secret_spans(text)
                if re.search(r"\bANTHROPIC_(?:API_KEY|AUTH_TOKEN)\b", lines[start - 1])]
        if not hits:
            continue
        items.append(
            _item(
                "cred.shell_keys." + _slug(_short(rc)),
                "credential",
                f"{len(hits)} 处 shell 配置直接导出了 API 密钥",
                "high",
                "密钥以明文形式常驻在 ~/.zshrc 一类文件里，任何进程都能读到，也容易随 dotfiles 仓库外泄。",
                [_ev("位置", f"{_short(rc)}:{line}（值不显示）", mono=True) for line in hits[:4]],
                "清理会真正移除密钥赋值行，不保留配置副本；之后按需从密码管理器注入。",
                {
                    "kind": "shellrc",
                    "file": str(rc),
                    "lines": hits,
                },
            )
        )

    if not any(i["category"] == "credential" for i in items):
        items.append(
            _item(
                "cred.none",
                "credential",
                "未发现本地凭据残留",
                "pass",
                "钥匙串、配置目录与 shell 启动文件中都没有 Claude 相关凭据。",
            )
        )
    return items


def _mask_secret(text: str) -> str:
    text = text.strip()
    m = re.search(r"(sk-[A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]+", text)
    if m:
        return text.replace(m.group(0), m.group(1) + "••••••")
    if len(text) > 48:
        return text[:48] + "…"
    return text


def _scan_shell_rc(needles: list[str]) -> list[dict]:
    hits: list[dict] = []
    for rc in SHELL_RC:
        if not rc.exists():
            continue
        try:
            lines = rc.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if any(n in stripped for n in needles):
                hits.append({"file": str(rc).replace(str(HOME), "~"), "line": idx, "text": stripped})
    return hits


# ---------------------------------------------------------------- 隐蔽标记面


def _collect_base_urls() -> list[dict]:
    found: list[dict] = []

    env_val = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    if env_val:
        found.append({"source": "当前进程环境变量", "value": env_val})

    for fname in ("settings.json", "settings.local.json"):
        path = CLAUDE_DIR / fname
        data = _read_json(path) if path.exists() else None
        val = ((data or {}).get("env") or {}).get("ANTHROPIC_BASE_URL")
        if val:
            found.append({"source": f"~/.claude/{fname}", "value": str(val)})

    for hit in _scan_shell_rc(["ANTHROPIC_BASE_URL"]):
        m = re.search(r"ANTHROPIC_BASE_URL\s*=\s*[\"']?([^\"'\s]+)", hit["text"])
        if m:
            found.append(
                {
                    "source": f"{hit['file']}:{hit['line']}",
                    "value": m.group(1),
                    "file": hit["file"],
                    "line": hit["line"],
                }
            )

    # 去重
    seen = set()
    uniq = []
    for f in found:
        if f["value"] in seen:
            continue
        seen.add(f["value"])
        uniq.append(f)
    return uniq


def _match_domain_rules(url: str) -> list[tuple[str, str]]:
    low = url.lower()
    matched: list[tuple[str, str]] = []
    for group, needles in rules.DOMAIN_RULES:
        for needle in needles:
            if needle in low:
                matched.append((group, needle))
                break
    return matched


def check_marker() -> list[dict]:
    items: list[dict] = []
    urls = _collect_base_urls()

    if not urls:
        items.append(
            _item(
                "marker.base_url",
                "marker",
                "未设置 ANTHROPIC_BASE_URL",
                "pass",
                "请求直连官方 api.anthropic.com，客户端内置的中转地址比对逻辑不会被触发。",
            )
        )
    for u in urls:
        host = _host_of(u["value"])
        is_official = host in rules.OFFICIAL_HOSTS
        matched = _match_domain_rules(u["value"])
        if is_official:
            items.append(
                _item(
                    f"marker.base_url.{_slug(host)}",
                    "marker",
                    f"中转地址指向官方端点（{u['source']}）",
                    "pass",
                    f"{host} 属于官方域名，不构成额外标记。",
                    [_ev("来源", u["source"]), _ev("地址", u["value"], mono=True)],
                )
            )
            continue
        severity = "critical" if matched else "high"
        detail = (
            "公开分析显示，客户端会提取该地址的域名与内置名单比对，并用不可见字符把结果编码进系统提示词。"
            if matched
            else "使用非官方端点时，客户端会激活环境标记逻辑，把时区与中转域名信息带回服务端。"
        )
        evidence = [_ev("来源", u["source"]), _ev("地址", u["value"], mono=True)]
        if matched:
            evidence += [_ev(f"命中：{g}", k, mono=True) for g, k in matched]
        fix = None
        advice = (
            "中转地址本身不违法，但它是风控里权重最高的一项。"
            "如果只是自己用，优先直连官方；必须走中转时，至少让它落在与账号地区一致的干净出口上。"
        )
        if u.get("file"):
            fix = {"kind": "shellrc", "file": u["file"], "lines": [u["line"]]}
            advice += "这一条写在 shell 启动文件里，清理时会把对应行注释掉，不会删除你的其他配置。"
        elif u["source"].startswith("~/.claude/"):
            fname = u["source"].rsplit("/", 1)[-1]
            fix = {
                "kind": "json_patch",
                "file": f"~/.claude/{fname}",
                "delete": [["env", "ANTHROPIC_BASE_URL"]],
                "title": f"删除 {fname} 里的 ANTHROPIC_BASE_URL",
                "risk": "删的是 env 段里这一个键，其他环境变量保留；客户端会回到官方端点直连。",
                "manual": f"手动：编辑 ~/.claude/{fname}，删掉 env 里的 ANTHROPIC_BASE_URL 一行",
            }
            advice += "这一条写在 settings 的 env 段里，清理只删这一个键。"
        items.append(
            _item(
                f"marker.base_url.{_slug(host or u['source'])}",
                "marker",
                f"检测到非官方中转地址（{host or '未知主机'}）",
                severity,
                detail,
                evidence,
                advice,
                fix,
                ["relay"],
            )
        )

    # /etc/hosts 劫持
    hosts_hits = _hosts_overrides()
    if hosts_hits:
        items.append(
            _item(
                "marker.hosts",
                "marker",
                "/etc/hosts 中存在 Anthropic 域名重定向",
                "high",
                "把官方域名指向本地或第三方地址，会改变证书链与请求路径，属于典型的高风险改机行为。",
                [_ev("条目", h, mono=True) for h in hosts_hits[:5]],
                "如需代理请用系统代理或 TUN，不要改 hosts。恢复需要 sudo，命令已附在建议里。",
                None
            )
        )

    # hooks
    settings = _read_json(CLAUDE_DIR / "settings.json") if (CLAUDE_DIR / "settings.json").exists() else None
    hooks = (settings or {}).get("hooks") or {}
    hook_count = sum(len(v) if isinstance(v, list) else 1 for v in hooks.values())
    if hook_count:
        items.append(
            _item(
                "marker.hooks",
                "marker",
                f"settings.json 配置了 {hook_count} 个 hook",
                "info",
                "hook 会在会话中执行本地命令并继承当前环境变量，调试时容易把代理、密钥一起带进子进程。",
                [_ev("事件", ", ".join(hooks.keys()))],
                "确认这些 hook 都是你自己写的；不认识的建议关掉。",
                {"kind": "json_keys", "file": str(CLAUDE_DIR / "settings.json"), "keys": ["hooks"],
                 "risk": "hooks 段整段删除后，所有 hook 事件（含你自己写的）都不再触发；恢复从备份还原。",
                 "manual": "手动：编辑 ~/.claude/settings.json 删掉 \"hooks\" 一段"},
            )
        )

    return items


def _host_of(url: str) -> str:
    m = re.match(r"^(?:https?://)?([^/:]+)", url.strip(), re.I)
    return (m.group(1) if m else url).lower()


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (text or "x").lower()).strip("_")[:40]


def _hosts_overrides() -> list[str]:
    path = compat.hosts_path()
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    hits = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "anthropic" in s.lower() or "claude.ai" in s.lower():
            hits.append(s)
    return hits


# ---------------------------------------------------------------- 系统一致性


def check_locale(net_info: dict | None = None) -> list[dict]:
    items: list[dict] = []
    tz = _system_timezone()
    offset = time.strftime("%z")

    if tz in rules.CN_TRIGGER_TZ:
        items.append(
            _item(
                "locale.tz",
                "locale",
                f"系统时区为 {tz}",
                "critical",
                "这是被公开验证过的第一条判定路径：只要时区是 Asia/Shanghai 或 Asia/Urumqi，"
                "即使网络在海外，客户端仍会把你标记为中国用户。这也是为什么很多人换了 IP 依然被封。",
                [_ev("时区", tz, mono=True), _ev("UTC 偏移", offset, mono=True)],
                "在「系统设置 → 通用 → 日期与时间」里改成与你出口 IP 一致的城市。"
                "注意：只改时区不会影响你看到的时间格式偏好，但会影响日历/提醒的默认时区。",
                {"kind": "manual", "command": compat.set_timezone_command(tz)},
                ["hard-signal"],
            )
        )
    elif tz in rules.GREATER_CHINA_TZ:
        items.append(
            _item(
                "locale.tz",
                "locale",
                f"系统时区为 {tz}（UTC+8 时区带）",
                "medium",
                "不在直接触发名单内。"
                "需要说明的是：Asia/Taipei / Asia/Hong_Kong 属于 Anthropic 官方支持地区，"
                "单独使用时并不构成风险；真正的扣分点是「时区与出口地理不一致」这层叠加信号。",
                [_ev("时区", tz, mono=True)],
                "官方支持地区，此项为可选优化——保持原样也能正常使用。"
                "只有当你希望「时区 / 语言 / 出口」三者完全自洽时，才建议改成出口所在城市；"
                "不要为了表面一致去改动真实资料。",
            )
        )
    else:
        items.append(
            _item(
                "locale.tz",
                "locale",
                f"系统时区为 {tz}",
                "pass",
                "不在已知的高风险时区名单内。",
                [_ev("时区", tz, mono=True), _ev("UTC 偏移", offset, mono=True)],
            )
        )

    tz_env = os.environ.get("TZ", "").strip()
    if tz_env and tz_env != tz:
        # TZ 写在启动文件里的可以直接注释掉；只在当前进程里的只能手动 unset
        tz_rc_hits = [h for h in _scan_shell_rc(["TZ"])
                      if re.search(r"(?:^|\s|export\s+)TZ\s*=", h["text"])]
        fix = None
        advice = "统一成同一个值，或干脆 unset TZ 让系统设置生效。"
        if tz_rc_hits:
            fix = {"kind": "shellrc", "file": tz_rc_hits[0]["file"],
                   "lines": [h["line"] for h in tz_rc_hits],
                   "risk": "export TZ 行被注释后新终端按系统时区走；当前终端要手动 unset TZ 或重开。",
                   "manual": f"手动：编辑 {tz_rc_hits[0]['file']} 注释 export TZ 行，当前终端 unset TZ"}
            advice += "它写在启动文件里——清理会注释该行并备份。"
        items.append(
            _item(
                "locale.tz_env",
                "locale",
                f"环境变量 TZ={tz_env} 与系统时区不一致",
                "medium",
                "两个时区来源打架时，不同组件读到的值可能不同，反而更容易被判定为环境异常。",
                [_ev("TZ", tz_env, mono=True), _ev("系统", tz, mono=True)],
                advice,
                fix or {"kind": "manual", "command": "unset TZ"},
            )
        )

    lang = os.environ.get("LANG", "")
    lc_all = os.environ.get("LC_ALL", "")
    sys_langs = _system_languages()
    sys_locale = _system_locale()
    kbd, sources = _keyboard_layout()

    zh_env = [v for v in (lang, lc_all) if v.lower().startswith("zh")]
    zh_sys = [v for v in sys_langs if v.lower().startswith("zh")]
    cn_kbd = _cn_input(kbd, *sources)

    ev_lang: list[dict] = []
    if sys_langs:
        ev_lang.append(_ev("系统语言", " / ".join(sys_langs[:3]), mono=True))
    if sys_locale:
        ev_lang.append(_ev("区域", sys_locale, mono=True))
    ev_lang.append(_ev("LANG", f"{lang or '-'} · {lc_all or '-'}", mono=True))
    if kbd:
        ev_lang.append(_ev("键盘布局", kbd.replace("com.apple.keylayout.", ""), mono=True))
    if cn_kbd and cn_kbd != kbd:
        ev_lang.append(_ev("输入源", cn_kbd.replace("com.apple.", ""), mono=True))

    if zh_env or zh_sys:
        lead = zh_sys[0] if zh_sys else zh_env[0]
        src = "系统语言" if zh_sys else "终端环境变量"
        items.append(
            _item(
                "locale.lang",
                "locale",
                f"语言环境为 {lead}（{src}）",
                "medium",
                "语言本身不会被单独判罚，但它和时区、IP 地理是同一组信号；三者指向同一个区域时会互相加权。"
                "系统语言会影响所有 App 的界面语言，也会随请求进入 Accept-Language。",
                ev_lang,
                "如果你确实需要中文界面，可以保留；追求一致性时，"
                "把「系统设置 → 通用 → 语言与地区」的首选语言改成英文即可。",
            )
        )
    elif cn_kbd:
        items.append(
            _item(
                "locale.lang",
                "locale",
                f"输入法/键盘布局含中文（{cn_kbd.replace('com.apple.', '')}）",
                "low",
                "系统语言是英文，但输入源里装着中文输入法。它不影响接口判定，"
                "只是设备画像里又多了一条地域线索——换了 IP 却忘了这一层的人很多。",
                ev_lang,
                "不需要中文输入法的话，在「键盘 → 输入法」里删掉；需要就保留，这项权重很低。",
            )
        )
    else:
        items.append(
            _item(
                "locale.lang",
                "locale",
                "语言环境与出口区域无明显冲突",
                "pass",
                f"系统语言 {sys_langs[0] if sys_langs else '-'} · 键盘 {kbd.replace('com.apple.keylayout.', '') or '-'}",
                ev_lang,
            )
        )

    items.append(_check_client_lang(sys_langs))
    items.append(_check_region_format(net_info or {}, sys_locale))
    return items


def _check_region_format(net_info: dict, raw_locale: str = "") -> dict:
    """区域格式（AppleLocale）和出口国家对不对得上。

    网页能直接读到这个值：`Intl.DateTimeFormat().resolvedOptions().locale`
    在 macOS 上就是 AppleLocale。它和 `timeZone`、`navigator.languages` 是
    同一组信号，单看每一条都不致命，三条指向同一个地方就很有说服力。
    """
    raw = raw_locale or _system_locale()
    region = regioncfg.parse_region(raw)
    country = (net_info.get("country") or "").upper()
    expected = netcfg.expected_country()
    target = country or expected

    ev = [_ev("AppleLocale", raw or "读不到", mono=True)]
    if region:
        ev.append(_ev("区域格式", region, mono=True))
    if country:
        ev.append(_ev("出口国家", country, mono=True))
    elif expected:
        ev.append(_ev("预期国家", expected, mono=True))
    tz = _system_timezone()
    if tz:
        ev.append(_ev("时区", tz, mono=True))

    if not region:
        return _item(
            "locale.region", "locale",
            "区域格式读不到（AppleLocale 缺失）",
            "info",
            "系统里没有独立的 AppleLocale 时，浏览器会用语言推一个默认值，"
            "本项无法判断它和出口是否一致。",
            ev,
            "需要时可在「系统设置 → 通用 → 语言与地区 → 地区」里确认一次。",
        )
    if not target:
        return _item(
            "locale.region", "locale",
            f"区域格式为 {region}，没有可比的出口国家",
            "info",
            "出口国家没探测到，也没设置预期国家，本项只报告现状，不做判断。",
            ev,
            "网络恢复后重新扫描，或在上面的「出口国家预期」里填一个国家代码。",
        )
    if region == target:
        return _item(
            "locale.region", "locale",
            f"区域格式与出口一致（{region}）",
            "pass",
            "日期、数字与度量衡格式跟出口国家一致，这一条不再额外扣分。",
            ev,
        )
    return _item(
        "locale.region", "locale",
        f"区域格式为 {region}，出口在 {target}",
        "medium",
        "这个值网页读得到：`Intl.DateTimeFormat().resolvedOptions().locale` 会给出 "
        f"{region} 对应的格式，和出口 IP 摆在一起就是一处对不上的地方。"
        "它不影响接口判定，只是设备画像里多一条地域线索——换了 IP 却忘了这一层的人很多。",
        ev,
        "在「隐私设置 → 区域格式」里改成出口国家对应的格式，不需要管理员权限，"
        "重启浏览器后生效；本工具不会自动改，需要你自己确认。",
    )


def _defaults_read(domain: str, key: str = "") -> tuple[str, bool]:
    """读一个 defaults 域/键。返回 (输出, 域或键是否存在)。

    `defaults read` 在域不存在和键不存在时都返回非零，但两者的含义完全不同：
    前者是「客户端没装/没启动过」，后者是「客户端跟随系统，没有独立设置」。
    所以先读整个域，再读具体键。
    """
    cmd = ["defaults", "read", domain] + ([key] if key else [])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=4, check=False)
    except Exception:
        return "", False
    if out.returncode != 0:
        return "", False
    return (out.stdout or "").strip(), True


def _client_language_state() -> tuple[list[str], bool]:
    """Claude 客户端自己的界面语言，以及这个 defaults 域在不在。

    和系统语言是两回事：客户端有独立的 AppleLanguages 域，可以在系统是英文的
    时候单独显示中文。只读系统设置会漏掉这一层——换了 IP、改了系统语言，
    客户端却还在说中文，这种情况并不少见。
    """
    if compat.IS_WIN:
        # Windows 版把界面语言存在 config.json 里，格式随版本变，先不猜
        return [], False
    blob, domain_exists = _defaults_read("com.anthropic.claudefordesktop")
    if not domain_exists:
        return [], False
    raw, key_exists = _defaults_read("com.anthropic.claudefordesktop", "AppleLanguages")
    if not key_exists:
        # 域在、键不在：客户端没有独立覆盖，跟随系统
        return [], True
    return re.findall(r'"([^"]+)"', raw), True


def _check_client_lang(sys_langs: list[str]) -> dict:
    langs, domain_exists = _client_language_state()
    if not domain_exists:
        return _item(
            "locale.client_lang", "locale",
            "读不到客户端自己的语言设置",
            "info",
            "本机没有 Claude 桌面客户端，或者它还没写过自己的语言偏好"
            "（com.anthropic.claudefordesktop 域不存在）。这一项只查客户端"
            "独立的语言覆盖，系统语言由上一项负责。",
            [_ev("系统语言", " / ".join(sys_langs[:3]) or "-", mono=True)],
            "安装并至少启动一次 Claude 客户端后再看这一项。",
        )
    if not langs:
        return _item(
            "locale.client_lang", "locale",
            "客户端未单独设置界面语言",
            "pass",
            "Claude 客户端没有自己的语言覆盖，跟随系统设置。",
            [_ev("系统语言", " / ".join(sys_langs[:3]) or "-", mono=True)],
        )

    ev = [
        _ev("客户端语言", " / ".join(langs[:3]), mono=True),
        _ev("系统语言", " / ".join(sys_langs[:3]) or "-", mono=True),
    ]
    zh = [v for v in langs if v.lower().startswith("zh")]
    if not zh:
        return _item(
            "locale.client_lang", "locale",
            f"客户端界面语言为 {langs[0]}",
            "pass",
            "客户端有独立的语言设置，且不是中文。",
            ev,
        )
    # 系统已经是中文时，客户端跟着中文不算新增线索，不重复扣分
    if any(v.lower().startswith("zh") for v in sys_langs):
        return _item(
            "locale.client_lang", "locale",
            f"客户端界面语言为 {zh[0]}",
            "low",
            "客户端单独设成了中文。系统语言也是中文，所以没有新增线索，只是把同一件事又说了一遍。",
            ev,
            "改了系统语言之后，记得在客户端设置里也改一次——它不会自动跟随。",
        )
    return _item(
        "locale.client_lang", "locale",
        f"系统是英文，但客户端界面语言为 {zh[0]}",
        "medium",
        "两边不一致：系统设置已经改成英文，Claude 客户端自己却还留着中文偏好。"
        "客户端有独立的 AppleLanguages 域，不会跟随系统。界面语言会随请求进入 Accept-Language，"
        "只改系统设置的人经常漏掉这一层。",
        ev,
        "在 Claude 客户端里把界面语言改成英文（设置 → 通用 → 语言），"
        "或者退出客户端后删掉 com.anthropic.claudefordesktop 的 AppleLanguages 键。",
        tags=["hard-signal"],
    )


def _system_timezone() -> str:
    return compat.timezone_name() or "unknown"


def _system_languages() -> list[str]:
    if compat.IS_WIN:
        lang = compat.os_language()
        return [lang] if lang else []
    out = _run(["defaults", "read", "NSGlobalDomain", "AppleLanguages"], 4)
    return re.findall(r'"([^"]+)"', out)


def _system_locale() -> str:
    if compat.IS_WIN:
        return compat.os_language()
    return _run(["defaults", "read", "NSGlobalDomain", "AppleLocale"], 4)


def _keyboard_layout() -> tuple[str, list[str]]:
    """返回 (当前键盘布局 ID, 已启用的输入源列表)。

    macOS 把键盘布局放在 com.apple.HIToolbox 域；
    Windows 退化为读 HKCU\\Keyboard Layout\\Preload 的区域 ID 列表。
    """
    if compat.IS_WIN:
        try:
            import winreg
            ids = []
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Keyboard Layout\Preload") as k:
                i = 1
                while True:
                    try:
                        v, _ = winreg.QueryValueEx(k, str(i))
                    except OSError:
                        break
                    ids.append(str(v).lstrip("0") or "0")
                    i += 1
            names = {
                "804": "chinese-pinyin.zh-cn", "404": "chinese.zh-tw",
                "409": "us.english", "411": "japanese", "412": "korean",
                "407": "german", "40c": "french", "4090": "uk.english",
            }
            sources = [names.get(x, f"locale-{x}") for x in ids]
            return (sources[0] if sources else "", sources)
        except Exception:
            return "", []
    cur = _run(
        ["defaults", "read", "com.apple.HIToolbox", "AppleCurrentKeyboardLayoutInputSourceID"], 4
    ).strip()
    blob = _run(["defaults", "read", "com.apple.HIToolbox", "AppleEnabledInputSources"], 6)
    sources = sorted(set(re.findall(r"com\.apple\.(?:keylayout|inputmethod)\.[A-Za-z0-9_.]+", blob)))
    return cur, sources


_CN_INPUT_HINTS = (
    "scim", "pinyin", "shuangpin", "zhuyin", "cangjie", "wubi", "stroke",
    "keylayout.cn", "keylayout.chinese", "keylayout.hans", "keylayout.hant",
)


def _cn_input(*values: str) -> str:
    """挑出第一个中文输入源；没有则返回空串。"""
    for v in values:
        low = (v or "").lower()
        if any(h in low for h in _CN_INPUT_HINTS):
            return v
    return ""


# ---------------------------------------------------------------- 网络出口


def _country_expectation(country: str, expected: str, ip_masked: str = "") -> dict | None:
    """设置预期国家后才判断；没设置时完全不出这一项。"""
    expected = (expected or "").upper()
    if not expected:
        return None
    actual = (country or "").upper()
    ev = [_ev("预期国家", expected, mono=True)]
    if ip_masked:
        ev.append(_ev("出口 IP", ip_masked, mono=True))
    if not actual:
        return _item(
            "net.country", "network",
            "出口国家未探测到，无法与预期比对",
            "info",
            f"已设置预期国家 {expected}，但本轮出口探测没有拿到国家代码。",
            ev,
            "网络恢复后重新扫描。",
        )
    ev.append(_ev("实际国家", actual, mono=True))
    if actual == expected:
        return _item(
            "net.country", "network",
            f"出口国家符合预期（{actual}）",
            "pass",
            "当前出口国家与设置里的预期一致。",
            ev,
        )
    return _item(
        "net.country", "network",
        f"出口国家与预期不一致（{actual} ≠ {expected}）",
        "high",
        f"设置里的预期国家是 {expected}，本轮出口却在 {actual}。"
        "出口国家跳变本身就是一个信号，尤其是登录、验证或付款期间。",
        ev,
        "确认你实际身处支持地区，再切回固定出口；本工具不会自动改地区，也不会替你选择国家。",
    )


def check_network(with_network: bool = True) -> tuple[list[dict], dict]:
    items: list[dict] = []
    # 这两项要在「出口探测失败」的早退之前挂上去：
    # 浏览器侧 WebRTC 读的是上一次实测的结果，本来就不需要联网；
    # 安全 DNS 的配置部分也不需要，只有端点可达性要。
    items.append(_check_webrtc_browser())
    items.append(_check_doh(with_network))
    info = netprobe.probe() if with_network else {"available": False}

    if not info.get("available"):
        items.append(
            _item(
                "net.egress",
                "network",
                "出口 IP 未能探测",
                "info",
                "网络探测接口不可达（可能被代理规则拦截），本项跳过，其余检测不受影响。",
                [],
                "可以在网络可用时重新扫描，或手动到 ipinfo.io 核对出口。",
            )
        )
        # 出口没确认时不主动访问 claude.ai / api.anthropic.com：
        # 那等于为了证明链路正常，先把域名明文送出去一次。
        reason = ("本次关闭了联网检测。" if not with_network
                  else "出口地址还没确认，不知道这几次请求会从哪条路出去。")
        items.append(
            _item(
                "net.reachable", "network",
                "生态可达性未检测", "info",
                reason + "检测没有发出任何 http 请求。",
                [],
                "出口确认后再扫一次。",
            )
        )
        return items, info

    country = (info.get("country") or "").upper()
    asn_type = info.get("asn_type") or ""
    risky_type = (
        asn_type in ("hosting", "datacenter")
        or info.get("is_datacenter")
        or info.get("hosting_likely")
    )
    type_label = asn_type or ("机房（按 ASN 名称推断）" if info.get("hosting_likely") else "未知")

    sev = "pass"
    title = f"出口位于 {country or '未知'} · {info.get('city') or ''}".strip(" ·")
    detail = "出口地理位置与 ASN 类型是风控判断「是否像真实住宅用户」的主要依据。"
    if risky_type:
        sev = "high"
        title = f"出口为机房/托管类型（{country}）"
        detail = "数据中心 ASN 是 Claude Code 高频请求最容易被判为非人为操作的信号，"
    if info.get("is_vpn") or info.get("is_proxy") or info.get("is_tor"):
        sev = "high" if sev == "pass" else sev
        title = f"出口被标记为 VPN/代理（{country}）"
        detail = "该 IP 已被公开数据库标记为 VPN/代理出口，属于显性风险信号。"
    if info.get("is_abuser"):
        sev = "critical"
        title = f"出口 IP 有滥用记录（{country}）"
        detail = "该地址段历史上被用于滥用行为，接手的账号容易被连坐。"

    items.append(
        _item(
            "net.egress",
            "network",
            title,
            sev,
            detail,
            [
                _ev("出口 IP", info.get("ip_masked") or "-", mono=True),
                _ev("归属", f"{info.get('country') or '-'} / {info.get('city') or '-'}"),
                _ev("ASN", f"{info.get('asn') or '-'} {info.get('org') or ''}".strip(), mono=True),
                _ev("类型", type_label),
                _ev("数据源", info.get("source") or "-"),
            ],
            "住宅/ISP 类型的固定出口最稳。机房 IP 跑长上下文任务时，建议降低并发并拉长间隔。",
        )
    )

    country_item = _country_expectation(
        country, netcfg.expected_country(), info.get("ip_masked") or "")
    if country_item:
        items.append(country_item)

    ip_tz = info.get("timezone") or ""
    sys_tz = _system_timezone()
    if ip_tz and sys_tz and ip_tz != sys_tz:
        items.append(
            _item(
                "net.tz_mismatch",
                "network",
                "系统时区与出口 IP 时区不一致",
                "medium",
                f"出口在 {ip_tz}，本机却设为 {sys_tz}。地理、时区、语言三者不自洽是最常见的叠加信号。",
                [_ev("出口时区", ip_tz, mono=True), _ev("系统时区", sys_tz, mono=True)],
                "把系统时区改成出口所在城市，一次性消掉这项差异。",
            )
        )

    # 代理配置
    proxy = _proxy_config()
    if proxy:
        items.append(
            _item(
                "net.proxy",
                "network",
                "系统代理已启用",
                "info",
                f"检测到 {len(proxy)} 项代理设置，流量经本地代理转发。",
                [_ev(k, v, mono=True) for k, v in proxy.items()],
                "确保代理的出口稳定、不频繁切换节点；频繁跳变比代理本身更危险。",
            )
        )

    # DNS
    dns = _dns_servers()
    if dns:
        items.append(
            _item(
                "net.dns",
                "network",
                f"DNS：{', '.join(dns[:3])}",
                "info",
                "DNS 解析结果会影响服务端看到的地理线索，但与账号关联度低于 IP。",
                [_ev("nameserver", d, mono=True) for d in dns[:4]],
            )
        )

    items.append(_check_reachable())
    items.append(_check_webrtc(info.get("ip_masked") or ""))
    return items, info


def _check_reachable() -> dict:
    """生态可达性：claude.ai 和 api.anthropic.com 到底连不连得上。

    只看传输层，不看账号状态：拿到任何 HTTP 状态码都算「通」——
    api.anthropic.com 不带凭据必然回 401，那恰恰证明链路是好的。
    真正要抓的是连 DNS 都解析不出来、TCP 都握不上手的情况：
    这时候出口看着正常，实际所有请求都死在半路。
    """
    targets = (
        ("claude.ai", "https://claude.ai/"),
        ("api.anthropic.com", "https://api.anthropic.com/v1/models"),
    )
    ev: list[dict] = []
    dead: list[str] = []
    for name, url in targets:
        t0 = time.time()
        status = None
        note = ""
        try:
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "ClaudeTower"})
            with urllib.request.urlopen(req, timeout=6) as r:
                status = r.status
        except urllib.error.HTTPError as exc:
            # 4xx/5xx 也是「通了」——服务端回了话
            status = exc.code
        except Exception as exc:
            note = type(exc).__name__
        ms = int((time.time() - t0) * 1000)
        if status is None:
            dead.append(name)
            ev.append(_ev(name, f"不可达（{note or '超时'}）· {ms}ms", mono=True))
        else:
            ev.append(_ev(name, f"HTTP {status} · {ms}ms", mono=True))

    if not dead:
        return _item(
            "net.reachable", "network",
            "生态域名可达",
            "pass",
            "claude.ai 与 api.anthropic.com 都能在传输层连上。"
            "这里只看「连不连得上」，不看账号能不能用——不带凭据的请求回 401 是正常的。",
            ev,
        )
    if len(dead) == len(targets):
        return _item(
            "net.reachable", "network",
            "生态域名全部不可达",
            "critical",
            "claude.ai 和 api.anthropic.com 都连不上。出口看着正常、实际请求全死在半路——"
            "常见原因是 DNS 被污染、代理规则把 anthropic 域名送进了黑洞，或者节点本身挂了。",
            ev,
            "先确认代理客户端里节点是通的；如果节点正常，检查分流规则有没有把 "
            "anthropic.com / claude.ai 误判成 REJECT。",
            tags=["hard-signal"],
        )
    return _item(
        "net.reachable", "network",
        f"生态域名部分不可达（{'、'.join(dead)}）",
        "high",
        "有一个目标连不上。单项失败通常指向 DNS 或某条分流规则，而不是整个出口坏了。",
        ev,
        "先单独用浏览器打开失败的那个域名；能打开说明是本机规则问题，打不开说明是节点问题。",
        tags=["hard-signal"],
    )


def _check_webrtc(egress_mask: str) -> dict:
    """UDP 有没有和 HTTP 走同一条路。

    判据和哨兵那边一致：只看境外节点，且只在「分裂」时报警。
    国内节点回真实地址是分流规则的正确结果，拿它判会天天误报。

    证据里的地址一律打码：STUN 拿到的国内地址就是用户家的真实出口，
    完整写进页面和导出的报告，等于这次检测自己制造了一次泄漏。
    """
    r = stun.probe(egress_mask)
    ev = [
        _ev("STUN 结果", "、".join(netprobe._mask_ip(ip) for ip in r["ips"]) or "无", mono=True),
        _ev("境外节点", "、".join(netprobe._mask_ip(ip) for ip in r["foreign"]) or "无", mono=True),
        _ev("比对基线", r["mask"] or "（塔还没记录）", mono=True),
    ]
    if r["leak"]:
        return _item(
            "net.webrtc", "network",
            "UDP 出口分裂，WebRTC 可能泄漏真实地址",
            "high",
            "境外 STUN 节点给出了两个不同的出口地址：一部分 UDP 进了隧道，一部分走了直连。"
            "网页里的 WebRTC 会从直连那条把真实 IP 报给对端。",
            ev,
            "在代理客户端里把 STUN/TURN 的标准端口（3478 / 5349 / 19302）也指向代理，"
            "或者直接开 TUN 全接管。用 FlClash / Clash Verge / ClashX 的话，"
            "可在「隐私设置 → WebRTC / 置顶分流修复」里预览后一键写入；其它客户端面板会给手动步骤。",
            tags=["hard-signal"],
        )
    if not r["ok"]:
        return _item(
            "net.webrtc", "network",
            "UDP 探测没有回应",
            "info",
            f"四个 STUN 服务器都没回。{r['reason']}。",
            ev,
            "如果代理把 UDP 全部拦掉，这其实是好事（UDP 出不去就没法泄漏）；"
            "只有在你确实需要 UDP 时才需要处理。",
        )
    if r["state"] != "pass":
        return _item(
            "net.webrtc", "network",
            "UDP 出口未能判定",
            "info",
            f"STUN 有回应，但证据不足以说明 UDP 和 HTTP 走了同一条路：{r['reason']}。"
            "这一项不按通过算——没看到分裂，不等于确认一致。",
            ev,
            "保持代理配置稳定后再扫一次；如果刚换过节点，基线和 UDP 结果短暂不一致是正常的。",
        )
    return _item(
        "net.webrtc", "network",
        "UDP 出口与 HTTP 一致",
        "pass",
        f"STUN 拿到的地址与出口基线吻合。{r['reason']}。",
        ev,
    )


_WEBRTC_SEV = {
    "pass": "pass",
    "hidden": "pass",
    "relay": "info",
    "lan": "medium",
    "leak": "high",
    "stale": "info",
    "unknown": "info",
    "empty": "info",
}


def _check_webrtc_browser() -> dict:
    """浏览器自己报出来的候选地址。

    这一段读的是上一次实测的结果，不联网——探针必须由浏览器跑，
    Python 这边只能等。所以「还没测」是一个正常状态，不是失败。
    """
    rec = browserwebrtc.load()
    if not rec:
        return _item(
            "net.webrtc_browser", "network",
            "浏览器侧 WebRTC 还没实测",
            "info",
            "上面那条 STUN 测的是本机 UDP 出口。浏览器有自己一套 ICE 栈："
            "系统代理模式下它发 UDP 不经过代理，mDNS 混淆也只在部分内核里默认打开，"
            "所以它交给网页的地址未必和出口一致。这一项只能由浏览器自己回答。",
            [],
            "点「在本机浏览器里实测」，页面会收集 ICE 候选并回传结果，再扫一次就能看到判定。",
            probe="webrtc",
        )

    verdict = rec.get("assessment") or {}
    state = str(verdict.get("state") or "unknown")
    severity = _WEBRTC_SEV.get(state, "info")
    summary = rec.get("summary") or {}
    age = rec.get("age")
    at = int(rec.get("at") or 0)
    when = time.strftime("%m-%d %H:%M", time.localtime(at)) if at else "未知"

    ev = [
        _ev("实测时间", when, mono=True),
        _ev("公网地址", "、".join(summary.get("srflx") or []) or "无", mono=True),
        _ev("内网地址", "、".join(summary.get("private") or []) or "无", mono=True),
        _ev("mDNS 主机名", f"{summary.get('mdns', 0)} 条", mono=True),
        _ev("中继地址", "、".join(summary.get("relay") or []) or "无", mono=True),
    ]
    if rec.get("ua"):
        ev.append(_ev("浏览器", str(rec["ua"])[:80], mono=True))

    title = str(verdict.get("title") or "浏览器侧 WebRTC 实测结果")
    # 超过一天的结果只作参考：出口可能已经换了节点，拿旧结论当现状会误导
    if age is not None and age > browserwebrtc.STALE_AFTER and severity != "pass":
        severity = "info"
        title = f"{title}（{age // 3600} 小时前的实测）"

    return _item(
        "net.webrtc_browser", "network", title, severity,
        str(verdict.get("detail") or ""),
        ev,
        str(verdict.get("advice") or ""),
        probe="webrtc",
    )


def _check_doh(with_network: bool = True) -> dict:
    """浏览器安全 DNS：开关状态 + 加密通道通不通。

    两件事分开测。只看开关会漏掉最危险的那种情况——开着但端点不通，
    浏览器静默回退到明文，用户以为自己已经加密了。
    """
    rows = doh.browsers()
    eps = doh.endpoints() if with_network else []
    verdict = doh.assess(rows, eps)
    severity = {"pass": "pass", "fallback": "medium"}.get(
        str(verdict.get("state")), "info")

    mode_label = {"secure": "已开启", "automatic": "自动（可回退）",
                  "race": "竞速（可回退）", "off": "关闭",
                  "system": "跟随系统", "denied": "读不到", "unset": "未设置"}
    ev = [_ev(f"{b['browser']}", mode_label.get(b.get("mode"), str(b.get("mode"))))
          for b in rows[:5]]
    for e in eps[:3]:
        ev.append(_ev(e["name"], f"{e.get('ms')} ms · {e.get('note')}" if e.get("ok")
                      else f"不可达 · {e.get('note')}", mono=True))
    if not with_network:
        ev.append(_ev("端点", "本次关闭了联网检测，未测", mono=True))

    return _item(
        "net.doh", "network",
        str(verdict.get("title") or "浏览器安全 DNS 状态未知"),
        severity,
        str(verdict.get("detail") or ""),
        ev,
        str(verdict.get("advice") or ""),
    )


def _proxy_config() -> dict:
    p = compat.system_proxy()
    result: dict[str, str] = {}
    if p.get("enabled") and p.get("server"):
        result["代理"] = p["server"]
    if p.get("pac"):
        result["PAC"] = p["pac"]
    return result


def _dns_servers() -> list[str]:
    return compat.system_dns()


# ---------------------------------------------------------------- 客户端残留


def check_residue() -> list[dict]:
    items: list[dict] = []

    if compat.IS_WIN:
        lad = Path(os.environ.get("LOCALAPPDATA", str(HOME)))
        rad = Path(os.environ.get("APPDATA", str(HOME)))
        desktop_paths = [
            lad / "AnthropicClaude",
            rad / "Claude",
            lad / "Programs" / "claude-desktop",
            lad / "claude",
        ]
        pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        pfx = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        desktop_paths += [pf / "Claude", pfx / "Claude"]
    else:
        desktop_paths = [
            Path("/Applications/Claude.app"),
            HOME / "Applications" / "Claude.app",
            HOME / "Library" / "Application Support" / "Claude",
            HOME / "Library" / "Application Support" / "Claude-3p",
            HOME / "Library" / "Caches" / "com.anthropic.claudefordesktop",
            HOME / "Library" / "HTTPStorages" / "com.anthropic.claudefordesktop",
            HOME / "Library" / "Preferences" / "com.anthropic.claudefordesktop.plist",
            HOME / "Library" / "Saved Application State" / "com.anthropic.claudefordesktop.savedState",
            HOME / "Library" / "WebKit" / "com.anthropic.claudefordesktop",
            HOME / "Library" / "Logs" / "Claude",
        ]
        desktop_globs = [
            HOME / "Library" / "Preferences" / "ByHost" / "com.anthropic.claudefordesktop*.plist",
            HOME / "Library" / "Logs" / "DiagnosticReports" / "Claude*",
            HOME / "Library" / "Application Support" / "CrashReporter" / "Claude*",
        ]
        for pattern in desktop_globs:
            try:
                desktop_paths += list(pattern.parent.glob(pattern.name))
            except OSError:
                continue
    existing = [p for p in desktop_paths if p.exists()]
    if existing:
        total = sum(path_stats(p)[1] for p in existing)
        # 家目录内的能一键进废纸篓；/Applications、Program Files 需要管理员权限，只提示
        in_home = [p for p in existing
                   if str(p).startswith(str(HOME))]
        out_home = [p for p in existing if p not in in_home]
        fix = ({"kind": "trash", "paths": [str(p) for p in in_home],
                "risk": "桌面端的登录态与本地数据会一并进废纸篓；下次打开需要重新登录。",
                "manual": "手动：退出 Claude 后把对应目录拖到回收站"}
               if in_home else None)
        advice = "彻底退出应用后再清理，否则进程会把文件写回来。"
        if out_home:
            advice += f"另有 {len(out_home)} 处在应用目录（{out_home[0]}），需要管理员权限手动卸载。"
        items.append(
            _item(
                "res.desktop",
                "residue",
                f"Claude 桌面端残留 {len(existing)} 处（{human_size(total)}）",
                "medium",
                "桌面端持有独立的登录 Cookie 与 WebKit 存储，和命令行是两套凭据；"
                "只清 CLI 不清它，等于换个入口继续用同一身份。",
                [_ev("路径", str(p).replace(str(HOME), "~"), mono=True) for p in existing[:6]],
                advice,
                fix,
            )
        )
    else:
        items.append(
            _item("res.desktop", "residue", "未发现 Claude 桌面端", "pass", "没有独立的应用级登录态。")
        )

    # IDE 插件
    ext_dirs = [
        HOME / ".vscode" / "extensions",
        HOME / ".cursor" / "extensions",
        HOME / ".vscode-insiders" / "extensions",
        HOME / ".windsurf" / "extensions",
    ]
    ext_hits: list[str] = []
    for base in ext_dirs:
        if not base.exists():
            continue
        try:
            for child in base.iterdir():
                if "anthropic" in child.name.lower() or "claude" in child.name.lower():
                    ext_hits.append(str(child).replace(str(HOME), "~"))
        except OSError:
            continue
    if ext_hits:
        # 只收目录级残留（能整体进废纸篓的）
        ext_paths = [
            str(child) for base in ext_dirs if base.exists()
            for child in base.iterdir()
            if "anthropic" in child.name.lower() or "claude" in child.name.lower()
        ]
        items.append(
            _item(
                "res.ide_ext",
                "residue",
                f"IDE 插件残留 {len(ext_hits)} 个",
                "low",
                "插件会复用同一个账号令牌，并在编辑器内维持长连接。",
                [_ev("插件", h, mono=True) for h in ext_hits[:4]],
                "卸载插件后，扩展目录里的旧版本目录可以一并清理。",
                {"kind": "trash", "paths": ext_paths,
                 "risk": "插件目录删除后，编辑器里的 Claude 集成会消失；需要时从扩展商店重装。",
                 "manual": "手动：编辑器的扩展面板里卸载对应插件，或直接删这些目录"},
            )
        )

    # 全局安装
    if compat.IS_WIN:
        ra = Path(os.environ.get("APPDATA", str(HOME)))
        npm_dirs = [
            ra / "npm" / "node_modules" / "@anthropic-ai" / "claude-code",
            HOME / ".claude" / "local",
        ]
    else:
        npm_dirs = [
            Path("/usr/local/lib/node_modules/@anthropic-ai/claude-code"),
            Path("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code"),
            HOME / ".npm-global" / "lib" / "node_modules" / "@anthropic-ai" / "claude-code",
            HOME / ".local" / "share" / "claude",
            HOME / ".claude" / "local",
        ]
    installed = [p for p in npm_dirs if p.exists()]
    cli = _run(["bash", "-lc", "command -v claude"]) if not compat.IS_WIN else "; ".join(compat.which_claude())
    items.append(
        _item(
            "res.install",
            "residue",
            "Claude Code 已安装" if installed or cli else "未检测到 Claude Code 安装",
            "info",
            "安装位置本身不影响风控，但多份安装会各自写配置，清理时容易漏。",
            ([_ev("CLI", cli, mono=True)] if cli else [])
            + [_ev("目录", str(p).replace(str(HOME), "~"), mono=True) for p in installed[:3]],
        )
    )

    # 自启动项
    startup_hits = [it for it in compat.startup_items()
                    if "claude" in it["name"].lower() or "anthropic" in it["name"].lower()
                    or "claude" in it["path"].lower() or "anthropic" in it["path"].lower()]
    if startup_hits:
        items.append(
            _item(
                "res.launchagents",
                "residue",
                f"{len(startup_hits)} 个自启动项",
                "low",
                "自启动项会让后台进程在清理后重新写回配置。",
                [_ev("启动项", it["name"], mono=True) for it in startup_hits[:4]],
                "清理时先卸载再移入废纸篓；文件本身可还原。",
                {"kind": "startup", "items": startup_hits,
                 "risk": "移除后开机不再自启；plist/快捷方式进废纸篓可还原，注册表项删除不可直接还原（需重新写入）。",
                 "manual": "手动：launchctl bootout + 删 plist" if compat.IS_MAC
                          else "手动：任务管理器 → 启动应用 里禁用对应项"},
            )
        )

    # 其他客户端
    others = []
    if compat.IS_WIN:
        lad = Path(os.environ.get("LOCALAPPDATA", str(HOME)))
        pf_dirs = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
                   Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
                   lad / "Programs"]
        for name in ("Cursor", "Codex", "ChatGPT", "Warp"):
            if any((d / name).exists() or (d / f"{name}.exe").exists() for d in pf_dirs):
                others.append(name)
    else:
        for name in ("Cursor", "Codex", "ChatGPT", "Warp"):
            if Path(f"/Applications/{name}.app").exists():
                others.append(name)
    if others:
        items.append(
            _item(
                "res.other_clients",
                "residue",
                f"同时安装了 {len(others)} 个其他 AI 客户端",
                "info",
                f"检测到：{', '.join(others)}。它们与 Claude 无直接关联，但会共享同一出口与设备指纹。",
                [_ev("应用", ", ".join(others))],
                "不需要卸载，知道它们在同一条出口上就行。",
            )
        )

    # 之前的环境检查器遗留
    legacy_inspector = HOME / ".claude-env-inspector"
    if legacy_inspector.exists():
        _e, size, count = path_stats(legacy_inspector)
        items.append(
            _item(
                "res.inspector",
                "residue",
                f"发现旧版环境检查器数据（{count} 个文件 · {human_size(size)}）",
                "info",
                "该目录保存了历史扫描快照，快照里可能记录了当时的出口 IP 与设备信息。",
                [_ev("路径", str(legacy_inspector).replace(str(HOME), "~"), mono=True)],
                "如果不再使用旧工具，可以把快照一并清掉。",
                {"kind": "trash", "path": str(legacy_inspector), "size": size, "count": count},
            )
        )

    return items


# ---------------------------------------------------------------- 设备标识


def check_device() -> list[dict]:
    uuid = ""
    serial = ""
    model = ""
    if compat.IS_WIN:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                uuid, _ = winreg.QueryValueEx(k, "MachineGuid")
        except Exception:
            pass
        out = _run(["cmd", "/c", "wmic csproduct get uuid,identifyingnumber 2>nul"], 6)
        m = re.search(r"([0-9A-F-]{36})", out)
        if m and not uuid:
            uuid = m.group(1)
        model = _run(["cmd", "/c", "wmic computersystem get model 2>nul"], 6).splitlines()
        model = model[-1].strip() if model else ""
    else:
        out = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
        if m:
            uuid = m.group(1)
        m2 = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', out)
        if m2:
            serial = m2.group(1)
        model = _run(["sysctl", "-n", "hw.model"])
    name = compat.computer_name()

    return [
        _item(
            "dev.identity",
            "device",
            "硬件级标识（不可通过清理改变）",
            "info",
            "这些值由硬件决定，任何清理都无法修改。它们说明一件事："
            "同一台机器上反复注册账号，服务端仍有办法把它们归到一起。",
            [
                _ev("平台 UUID", _mask_uuid(uuid), mono=True),
                _ev("序列号", (serial[:4] + "••••" + serial[-2:]) if len(serial) > 6 else "-", mono=True),
                _ev("主机名", name or "-"),
                _ev("机型", model or "-"),
            ],
            "真要做彻底隔离，只有换设备、换虚拟机或换容器，改文件是不够的。",
        )
    ]


def _mask_uuid(value: str) -> str:
    if not value:
        return "-"
    return value[:8] + "-••••-••••-••••-" + value[-4:]


# ---------------------------------------------------------------- 哨兵


def check_shield() -> list[dict]:
    """哨兵在不在。

    塔只管「这一刻」的状态，所以这项不评价哨兵做得好不好，
    只回答一个问题：出口断了的时候，有没有人在替你看着。
    """
    st = shield.status()
    app = st.get("app") or {}
    base = st.get("baseline") or {}
    running = bool(app.get("running"))
    installed = bool(app.get("installed"))
    launch = app.get("launchAgent") or "none"
    launch_label = {
        "loaded": "已加载",
        "installed": "已安装但未加载",
        "none": "未设置",
    }.get(launch, "未设置")
    if installed:
        install_label = "已安装"
    elif running:
        # 开发时经常直接从仓库里跑 .app；在线比安装位置重要
        install_label = "仓库内运行（未装进应用程序目录）"
    else:
        install_label = "未安装"
    ev = [
        _ev("安装", install_label),
        _ev("运行", "运行中" if running else "未运行"),
        _ev("开机自启", launch_label),
        _ev("基线时区", base.get("tz") or "-", mono=True),
        _ev("基线出口", base.get("ip") or "（未记录）", mono=True),
    ]
    age = base.get("ipAge")
    if age is not None:
        ev.append(_ev("出口记录于", f"{age // 3600} 小时前" if age >= 3600
                      else f"{max(1, age // 60)} 分钟前", mono=True))

    if not running and not installed:
        return [
            _item(
                "res.shield", "resource",
                "哨兵未安装",
                "medium",
                "塔是一次性的：进来、检测、清理、走人。你关掉这个页面之后，"
                "出口断掉没有任何人会提醒你。哨兵是随塔一起安装的菜单栏程序，"
                "装好塔就一直在。",
                ev,
                "重新装一遍 Claude Tower.app（哨兵在它的 Resources 里），"
                "然后打开塔或直接打开包内的 Claude Shield.app。",
            )
        ]
    if not running:
        return [
            _item(
                "res.shield", "resource",
                "哨兵已安装但没在运行",
                "medium",
                "装是装了，现在没跑。可能是被退出了，也可能开机自启没开。"
                "这段时间里出口断了不会有人告诉你。",
                ev,
                "打开 Claude Tower 会自动把它带起来；长期值守建议在哨兵面板里"
                "打开「开机自启」。",
            )
        ]

    level = int(app.get("level") or 1)
    ev.append(_ev("强度", "断了就停" if level == 2 else "只观察"))
    if not app.get("enabled", True):
        return [
            _item(
                "res.shield", "resource",
                "哨兵在运行，但已被停用",
                "low",
                "进程在，巡检开关是关的。相当于坐在岗亭里不往外看。",
                ev,
                "在哨兵面板里勾上「继续值守」。",
            )
        ]
    return [
        _item(
            "res.shield", "resource",
            f"哨兵运行中（{'断了就停' if level == 2 else '只观察'}）",
            "pass",
            "出口断了会收到通知；第二档还会直接终止 Claude。",
            ev,
        )
    ]


# ---------------------------------------------------------------- 汇总


def scan(with_network: bool = True) -> dict:
    started = time.time()
    items: list[dict] = []
    # 出口先探：地区格式要拿实际出口国家来比对，只能跟「预期国家」比等于
    # 只在用户填过的时候才有效。其余模块不依赖网络结果，顺序不影响结论。
    net_items, net_info = check_network(with_network)
    for fn in (check_fingerprint, check_credential, check_marker,
               check_residue, check_device, check_cli, check_shield):
        try:
            items.extend(fn())
        except Exception as exc:  # 单个模块失败不影响整体
            items.append(
                _item(
                    f"err.{fn.__name__}",
                    "fingerprint",
                    f"检测模块 {fn.__name__} 执行异常",
                    "info",
                    str(exc)[:200],
                )
            )
    try:
        items.extend(check_locale(net_info))
    except Exception as exc:
        items.append(
            _item("err.check_locale", "locale", "语言与地区检测执行异常",
                  "info", str(exc)[:200])
        )
    items.extend(net_items)

    # 深层检测：标记特征、会话画像、网络链路、权限配置等
    try:
        from . import deep
        items.extend(deep.check_deep(net_info))
    except Exception as exc:
        items.append(
            _item("err.deep", "fingerprint", "深层检测模块执行异常", "info", str(exc)[:200])
        )

    # 排序：严重度优先
    order = {s: i for i, s in enumerate(rules.SEVERITY_ORDER)}
    items.sort(key=lambda x: (order.get(x["severity"], 9), x["category"]))

    counts = {s: 0 for s in rules.SEVERITY_ORDER}
    for it in items:
        counts[it["severity"]] = counts.get(it["severity"], 0) + 1

    penalty = sum(rules.WEIGHTS.get(it["severity"], 0) for it in items)
    score = max(0, min(100, 100 - penalty))
    title, text = rules.verdict_for(score)

    priorities = [it for it in items if it["severity"] in ("critical", "high")][:3]

    return {
        "scannedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "durationMs": int((time.time() - started) * 1000),
        "score": score,
        "grade": rules.grade_for(score),
        "verdict": title,
        "verdictText": text,
        "counts": counts,
        "items": items,
        "priorities": [{"id": p["id"], "title": p["title"], "severity": p["severity"]} for p in priorities],
        "network": {
            "available": net_info.get("available", False),
            "ip": net_info.get("ip_masked"),
            "country": net_info.get("country"),
            "city": net_info.get("city"),
            "org": net_info.get("org"),
            "asn_type": net_info.get("asn_type"),
            "source": net_info.get("source"),
            "datacenter": bool(net_info.get("is_datacenter")),
            "hosting": bool(net_info.get("hosting_likely")),
            "timezone": net_info.get("timezone"),
        },
        "system": {
            "timezone": _system_timezone(),
            "locale": os.environ.get("LANG", "-"),
            "hostname": compat.computer_name() or "-",
        },
        "categories": rules.CATEGORY_META,
    }
