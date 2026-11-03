"""登录 shell 里 curl 的实际出口。

`netprobe` 测的是本进程的出口，`domainegress` 测的是应用进程按域名分流后的
出口——两者都不代表终端。终端里启动的 `claude` 继承的是 shell 的环境变量：

- curl **不读 macOS 系统代理**。系统代理开着、终端没 `export HTTPS_PROXY`，
  CLI 的请求就从真实地址出去；
- 反过来，shell 里残留的旧代理变量会让终端走一条与浏览器不同的路。

这里用登录 shell（`zsh -ilc` / `bash -ilc`）跑一次写死的 curl，问 Anthropic
API 边缘「你看到我是谁」，再和本次出口探测比对。命令是常量，不接受任何输入；
完整地址只在内存里比对，返回值只有打码后的地址。
"""
from __future__ import annotations

import os
from pathlib import Path

from . import compat, domainegress, netprobe, stun

# 终端里的 Claude Code 实际连的是 API 端点，所以问它比问 claude.ai 更贴近。
TRACE_URL = "https://api.anthropic.com/cdn-cgi/trace"
UA = "ClaudeTower terminal-egress"
MARKER = "__TOWER_ENV__"
TIMEOUT = 10
_PROXY_KEYS = frozenset({
    "http_proxy", "https_proxy", "all_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
})
_SHELLS = {"zsh", "bash", "fish", "sh", "dash"}


def _shell() -> tuple[str, str]:
    raw = os.environ.get("SHELL") or "/bin/zsh"
    path = Path(raw)
    name = path.name
    if (name in _SHELLS and path.is_file() and os.access(path, os.X_OK)):
        return str(path), name
    return "/bin/zsh", "zsh"


def _argv(shell: str, name: str) -> list[str]:
    flag = "-lic" if name == "fish" else ("-lc" if name in ("sh", "dash") else "-ilc")
    script = (
        f"/usr/bin/curl -s --max-time 4 -H 'User-Agent: {UA}' '{TRACE_URL}'; "
        f"printf '\\n{MARKER}\\n'; /usr/bin/env | "
        "/usr/bin/sed -nE 's/^(http_proxy|https_proxy|all_proxy|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)=.*/\\1=present/p'"
    )
    return [shell, flag, script]


def parse_output(text: str) -> tuple[dict | None, bool]:
    """拆出 trace 结果与「shell 里有没有代理变量」；变量值不保留。"""
    head, _, tail = (text or "").partition(MARKER)
    trace = domainegress.parse_trace(head)
    proxy_env = False
    for line in tail.splitlines():
        key, sep, _ = line.partition("=")
        if sep and key.strip() in _PROXY_KEYS:
            proxy_env = True
            break
    return trace, proxy_env


def probe(baseline_ip: str = "", baseline_mask: str = "",
          runner=None) -> dict:
    """跑一次登录 shell；失败时 checked=False，不替调用方下结论。"""
    shell, name = _shell()
    out = {"checked": False, "ipMasked": "", "loc": "", "colo": "",
           "match": None, "proxyEnv": False, "shell": name, "error": ""}
    if not compat.IS_MAC:
        out["error"] = "只在 macOS 上跑登录 shell"
        return out
    run = runner or (lambda cmd: compat.run(cmd, timeout=TIMEOUT))
    try:
        text = run(_argv(shell, name))
    except Exception as exc:  # 注入的 runner 抛错也不能把扫描带倒
        out["error"] = type(exc).__name__
        return out
    trace, proxy_env = parse_output(text or "")
    out["proxyEnv"] = proxy_env
    if trace is None:
        out["error"] = "登录 shell 里没拿到出口" if text else "登录 shell 没有输出"
        return out
    match = None
    if baseline_ip:
        # 地址族不同就是「没法比对」：探测走 v4、终端走 v6 是两条路，
        # 但不能拿 v4 基线给 v6 结果定罪。
        same_family = (":" in trace["ip"]) == (":" in baseline_ip)
        match = (trace["ip"] == baseline_ip) if same_family else None
    elif baseline_mask:
        match = stun.matches_mask(trace["ip"], baseline_mask)
    out.update(checked=True, ipMasked=netprobe._mask_ip(trace["ip"]),
               loc=trace.get("loc") or "", colo=trace.get("colo") or "",
               match=match)
    return out
