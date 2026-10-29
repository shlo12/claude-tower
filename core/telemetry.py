"""Claude Code 隐私设置与遥测目标识别；配置检测不等同于网络验证。"""

import json
import os
from pathlib import Path

DOCS = "https://code.claude.com/docs/en/env-vars"
NETWORK_DOCS = "https://code.claude.com/docs/en/network-config"
DATADOG_HOSTS = ("http-intake.logs.us5.datadoghq.com", "browser-intake-us5-datadoghq.com")
LEGACY_HOSTS = ("statsig.anthropic.com", "o-sg-statsig.anthropic.com",
                "events.statsig.com", "featuregates.org", "o374024.ingest.sentry.io")
CHANNELS = (
    ("metrics", "使用遥测", "DISABLE_TELEMETRY"),
    ("errors", "Sentry / Datadog 错误报告", "DISABLE_ERROR_REPORTING"),
    ("feedback", "反馈与会话提交", "DISABLE_FEEDBACK_COMMAND"),
    ("minimal", "最小提示词模式", "CLAUDE_CODE_SIMPLE"),
)


def target_label(host):
    host = host.lower().rstrip(".")
    if host in DATADOG_HOSTS:
        return "Datadog 遥测" if host == DATADOG_HOSTS[0] else "Datadog 错误报告"
    if host == "sentry.io" or host.endswith(".sentry.io"):
        return "Sentry 错误报告（版本相关）"
    if host in LEGACY_HOSTS:
        return "Statsig / 特性开关（版本相关）"
    if host == "api.anthropic.com":
        return "Claude API / 混合用途，无法按主机区分遥测"
    return "未分类"


def _enabled(value, presence=False):
    # 当前官方语义：这些关闭开关的任意非空值均生效，包括 0/false。
    if presence:
        return bool(str(value)) if value is not None else False
    return str(value).lower() in ("1", "true", "yes", "on")


def inspect(config_dir=None, environ=None):
    env = os.environ if environ is None else environ
    root = Path(config_dir or env.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude").expanduser()
    path = root / "settings.json"
    settings_env, error = {}, ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
            raise ValueError("配置根节点和 env 必须为对象")
        settings_env = data.get("env", {})
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        error = str(exc)

    def value(key):
        if key in env:
            return env[key], "本工具进程环境（Claude 进程是否继承待核实）"
        return settings_env.get(key), str(path)

    def on(key, presence=False):
        return _enabled(value(key)[0], presence)

    global_off = on("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", True)
    items = []
    for cid, label, key in CHANNELS:
        if cid == "minimal":
            # 最小提示词模式是「启用=更隐私」的开关，方向与关闭键相反，单独判定
            closed = on(key)
            keys = [key]
        else:
            inherited = key == "DISABLE_TELEMETRY" and on("DO_NOT_TRACK")
            closed = global_off or inherited or on(key, cid != "feedback")
            keys = [key, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"]
            if cid == "metrics":
                keys.append("DO_NOT_TRACK")
        evidence = [{"label": k, "value": f"{'已配置' if value(k)[0] is not None else '未配置'} · {value(k)[1]}",
                     "mono": True} for k in keys]
        evidence.append({"label": "依据", "value": DOCS, "mono": False})
        if error:
            evidence.append({"label": "配置读取失败", "value": error, "mono": False})
        fix = None
        if not closed and not error:
            if cid == "minimal":
                fix = {"kind": "json_patch", "file": str(path), "create": True,
                       "title": "启用最小提示词模式（用户配置）", "set": {f"env.{key}": "1"},
                       "risk": "启用后使用最小系统提示词与有限工具集，并跳过 hooks、skills、plugins、MCP、"
                               "自动记忆与 CLAUDE.md 自动发现（这些资产不会被删除）。日常开发受影响；"
                               "一次性脚本场景建议直接用 claude --bare，不必改配置。",
                       "manual": f"编辑 {path}，在 env 中设置 {key}=1；不想用时删掉该字段。"}
            else:
                fix = {"kind": "json_patch", "file": str(path), "create": True,
                       "title": f"关闭{label}（用户配置）", "set": {f"env.{key}": "1"},
                       "risk": "仅修改 Claude Code 用户配置；重启后复查。关闭遥测可能影响 Remote Control 等功能。"
                               "不代表整个 Desktop 应用已关闭上报。新建配置时，撤销需删除新增字段或文件。",
                       "manual": f"编辑 {path}，在 env 中设置 {key}=1；保留其他字段。"}
        if cid == "minimal":
            title = f"{label}：{'已启用' if closed else '状态待核实' if error else '未启用'}"
            detail = ("CLAUDE_CODE_SIMPLE=1 让客户端以最小系统提示词与有限工具集运行，"
                      "跳过 hooks、skills、plugins、MCP、自动记忆与 CLAUDE.md 自动发现，减少随请求送出的环境画像。"
                      "配置检测不等同于行为验证，请以观察哨核对。")
            advice = "日常开发会受功能影响；更看重干净画像时可启用，一次性脚本优先用 claude --bare。"
        else:
            title = f"{label}：{'检测到关闭配置' if closed else '状态待核实' if error else '未检测到关闭配置'}"
            detail = ("按当前官方变量语义检查；尚未验证 Claude 实际进程与网络。"
                      "范围为 CLI / Desktop 的 Code 会话；未合并项目/组织托管配置，不能推断桌面应用整体状态。")
            advice = "预览后可写入官方关闭开关；重启 Claude，再通过观察哨核对连接。"
        items.append({"id": f"cfg.telemetry.{cid}", "category": "behavior",
                      "title": title,
                      "severity": "info", "detail": detail,
                      "evidence": evidence, "advice": advice,
                      "fix": fix, "tags": ["privacy", "config-only"],
                      "configuredOff": closed, "verification": "config-only"})
    items.append({"id": "cfg.telemetry.otel", "category": "behavior", "severity": "info",
                  "title": "OpenTelemetry：" + ("检测到启用配置" if on("CLAUDE_CODE_ENABLE_TELEMETRY") else "未检测到启用配置"),
                  "detail": "用户或组织配置的 OTel 与厂商运营遥测分开检查；不能由 DISABLE_TELEMETRY 推断其关闭。",
                  "evidence": [{"label": "配置来源", "value": value("CLAUDE_CODE_ENABLE_TELEMETRY")[1], "mono": True}],
                  "advice": "组织管理的采集策略应由管理员核实；本工具不自动修改。", "fix": None,
                  "tags": ["privacy", "config-only"], "verification": "config-only"})
    return items
