#!/usr/bin/env python3
"""跑一遍全部检查。

    python3 tools/test_all.py            # 全部（含真开浏览器的页面测试）
    python3 tools/test_all.py --fast     # 跳过页面测试与分发包检查

每个子测试都是独立进程，一个挂了不影响其它几个跑完——不然修一个问题
要重跑十分钟。
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"

# (脚本, 说明, 是否属于「快」)
SUITES = [
    ("test_release_hygiene.py", "发布卫生规则", True),
    ("check.py", "冒烟检查：地图/关卡/判定/打包/接线", True),
    ("test_restore.py", "备份还原", True),
    ("test_retention.py", "敏感内容不留副本", True),
    ("test_privacy.py", "隐私加固写入", True),
    ("test_ipv6_cfg.py", "IPv6 关闭/恢复状态机", True),
    ("test_proxyfix.py", "多客户端分流规则写入/撤销", True),
    ("test_regioncfg.py", "区域格式（AppleLocale）写入/恢复", True),
    ("test_align.py", "出口对齐编排及恢复", True),
    ("test_proxydiag.py", "独立 HTTP/SOCKS5 代理诊断", True),
    ("test_kernelcheck.py", "内核规则核对（假控制接口 + unix socket）", True),
    ("test_browserprobe.py", "浏览器侧 WebRTC 判定 + 安全 DNS 判定", True),
    ("test_uninstall.py", "卸载器：清单/顺序/废纸篓", True),
    ("test_telemetry.py", "遥测封缄文本", True),
    ("test_security.py", "接口鉴权", True),
    ("test_stun.py", "STUN 解析与泄漏判定", True),
    ("test_findings.py", "五项新检查的判据", True),
    ("test_transport.py", "代理链路/TUN/DNS/IPv6/国家判据", True),
    ("test_proxydns.py", "代理内核 DNS 解析与判定", True),
    ("test_updater.py", "自动更新：检查/校验/安装计划/回滚", True),
    ("test_connection_monitor.py", "实际连接采样与误判边界", True),
    ("test_shield.py", "哨兵：巡检/急停条件/配色", True),
    ("test_shield_baseline.py", "哨兵基线写入", True),
    ("test_page.py", "页面冒烟（真开 Chrome）", False),
]


def run(script: str, label: str) -> tuple[bool, str, float]:
    path = TOOLS / script
    if not path.exists():
        return False, f"找不到 {script}", 0.0
    env = dict(os.environ)
    # 沙箱里注入的 sitecustomize 会拦截 mkdir 之类，子进程一律不带 PYTHONPATH
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    started = time.time()
    proc = subprocess.run([sys.executable, str(path)], cwd=str(ROOT), env=env,
                          capture_output=True, text=True)
    cost = time.time() - started
    if proc.returncode == 0:
        return True, label, cost
    tail = (proc.stdout or "") + (proc.stderr or "")
    bad = [ln for ln in tail.splitlines() if "✗" in ln][:6]
    return False, "\n".join(bad) or tail.strip()[-400:], cost


def main(argv: list[str]) -> int:
    fast = "--fast" in argv
    print(f"Claude Tower · 全量检查{'（快速模式）' if fast else ''}\n")

    results = []
    for script, label, is_fast in SUITES:
        if fast and not is_fast:
            print(f"  · {label}（快速模式跳过）")
            continue
        print(f"  … {label}")
        ok, detail, cost = run(script, label)
        results.append((label, ok, detail, cost))
        mark = "✓" if ok else "✗"
        print(f"  {mark} {label}  ({cost:.1f}s)")
        if not ok:
            for ln in detail.splitlines():
                print(f"      {ln.strip()}")

    # 分发包：有就查，没有就跳过（不该因为「还没打包」判失败）
    dist = sorted((ROOT / "dist").glob("ClaudeTower-*-windows-src.zip"))
    if dist and not fast:
        print("  … Windows 分发包结构")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        proc = subprocess.run([sys.executable, str(TOOLS / "test_win_pkg.py"), str(dist[-1])],
                              cwd=str(ROOT), env=env, capture_output=True, text=True)
        ok = proc.returncode == 0
        detail = "" if ok else "\n".join(
            ln for ln in (proc.stdout or "").splitlines() if "✗" in ln)
        results.append(("Windows 分发包结构", ok, detail, 0.0))
        print(f"  {'✓' if ok else '✗'} Windows 分发包结构  ({dist[-1].name})")
        if not ok:
            for ln in detail.splitlines():
                print(f"      {ln.strip()}")

    failed = [r for r in results if not r[1]]
    total = sum(r[3] for r in results)
    print(f"\n{'='*52}")
    if failed:
        print(f"  ✗ {len(failed)}/{len(results)} 组失败，耗时 {total:.1f}s")
        for label, _, _, _ in failed:
            print(f"    - {label}")
    else:
        print(f"  ✓ 全部通过（{len(results)} 组，耗时 {total:.1f}s）")
    print("=" * 52)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
