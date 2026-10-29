#!/usr/bin/env python3
"""给 Shield 面板拍几张截图。

    python3 tools/shoot-shield.py

不启动真正的菜单栏程序——这个会话里没有 GUI 会话，NSStatusItem 不会落位。
这里直接把 shield.html 丢给无头 Chrome，用 `window.SHIELD.update()` 喂几组
假快照，看的是同一份 CSS、同一份渲染代码。

产物在 build/preview/shield-*.png（build/ 已 gitignore）。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from test_page import CDP, CHROME, CDP_PORT  # noqa: E402

OUT = ROOT / "build" / "preview"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# 面板在 popover 里的真实尺寸。截图要和实际显示一样宽，否则换行位置是假的。
W, H = 366, 798

# 版本号从 plist 读，别在脚本里写死——改了版本还得记得改这里
import plistlib  # noqa: E402

SHIELD_VER = plistlib.loads((ROOT / "tools/Shield-Info.plist").read_bytes()).get(
    "CFBundleShortVersionString", "0.0.0")

BASE = {
    "enabled": True, "level": 1, "claude": True, "tz": "Asia/Taipei",
    "baselineTz": "Asia/Taipei", "tzDrift": False, "paused": False,
    "loginItem": False, "version": SHIELD_VER, "interval": 30,
    "stun": [], "stunForeign": [], "stunChecked": False, "stunLeak": False,
    "egressMask": "5.34.*.136", "maskFresh": True,
    "towerData": True, "towerState": "ok", "environmentReady": True,
    "idleState": "ready", "egressAt": time.time() - 5400, "country": "US",
    "lastAt": time.time(), "hits": [],
    "update": {"repo": "", "configured": False, "autoCheck": True,
               "newer": False, "checkedAt": 0, "error": ""},
    "transportChecked": True, "transportState": "ok",
    "transportLabel": "通 · 212 ms",
    "transportDetail": "两个 HTTPS 目标都完成了 TLS 握手：api.anthropic.com 返回 200，"
                       "claude.ai 返回 200。有状态码就说明请求确实到了对端。",
    "transportAt": time.time() - 90,
}

CASES = [
    ("shield-safe", "TUN 在位、DNS 假地址、UDP 单出口", {
        "verdict": "safe", "title": "守护中",
        "note": "Claude 在运行，出口在位。",
        "tun": True, "tunIface": "utun4", "sysProxy": False,
        "dns": "198.18.2.160", "dnsFake": True, "dnsChecked": True, "dnsSuspect": False,
        "stun": ["5.34.*.136"], "stunForeign": ["5.34.*.136"],
        "stunChecked": True, "stunLeak": False,
        # 安全态不写命中记录（apply 只记 danger/warn），所以这里也留空
        "hits": [],
    }),
    ("shield-dns", "TUN 在位但 DNS 没被接管", {
        "verdict": "warn", "title": "DNS 未接管",
        "note": "出口在位，但 claude.ai 解析成了真实地址（160.79.104.10）——"
                "TUN 开着却没接管 DNS，分流规则可能只做了一半。",
        "tun": True, "tunIface": "utun4", "sysProxy": False,
        "dns": "160.79.104.10", "dnsFake": False, "dnsChecked": True, "dnsSuspect": True,
        "stun": ["5.34.*.136"], "stunForeign": ["5.34.*.136"],
        "stunChecked": True, "stunLeak": False,
        "hits": [
            {"ts": time.time() - 3000, "kind": "warn", "note": "出口存疑"},
            {"ts": time.time() - 60, "kind": "dns",
             "note": "出口在位，但 claude.ai 解析成了真实地址（160.79.104.10）"},
        ],
    }),
    ("shield-stun", "UDP 出口分裂 + 时区漂移", {
        "verdict": "warn", "title": "UDP 出口不一致",
        "note": "境外 STUN 节点给出了两个出口：5.34.*.136 和 112.97.*.112。"
                "同一份规则里一部分 UDP 进了隧道、一部分直连，WebRTC 会从直连那条暴露真实地址。",
        "tun": True, "tunIface": "utun4", "sysProxy": False,
        "dns": "198.18.2.160", "dnsFake": True, "dnsChecked": True, "dnsSuspect": False,
        "stun": ["112.97.*.112", "5.34.*.136"],
        "stunForeign": ["112.97.*.112", "5.34.*.136"],
        "stunChecked": True, "stunLeak": True,
        "tz": "Asia/Shanghai", "tzDrift": True,
        "hits": [
            {"ts": time.time() - 900, "kind": "dns", "note": "DNS 没被接管，已恢复"},
            {"ts": time.time() - 60, "kind": "stun",
             "note": "境外 STUN 节点给出了两个出口：5.34.*.136 和 112.97.*.112"},
        ],
    }),
    ("shield-idle", "Claude 没运行，环境已就绪", {
        "verdict": "idle", "title": "可以启动 Claude",
        "note": "当前环境正常：出口在位，DNS、UDP 出口和时区都对得上。可以启动 Claude 了。",
        "claude": False, "tun": True, "tunIface": "utun4", "sysProxy": False,
        "dns": "198.18.2.160", "dnsFake": True, "dnsChecked": True, "dnsSuspect": False,
        "stun": ["5.34.*.136"], "stunForeign": ["5.34.*.136"],
        "stunChecked": True, "stunLeak": False,
        "idleState": "ready", "environmentReady": True,
        "towerData": True, "towerState": "ok",
        "hits": [],
    }),
    ("shield-blocked", "Claude 没运行，但 UDP 出口分裂", {
        "verdict": "idle", "title": "先别启动 Claude",
        "note": "UDP 出口分裂：境外节点里有的走隧道、有的直连（112.97.*.112）。"
                "先把 UDP 也代理了，再启动 Claude。",
        "claude": False, "tun": True, "tunIface": "utun13", "sysProxy": False,
        "dns": "160.79.104.10", "dnsFake": False, "dnsChecked": True, "dnsSuspect": False,
        "stun": ["112.97.*.112", "5.34.*.136"],
        "stunForeign": ["112.97.*.112", "5.34.*.136"],
        "stunChecked": True, "stunLeak": True,
        "idleState": "blocked", "environmentReady": False,
        "towerData": True, "towerState": "ok",
        "hits": [],
    }),
    ("shield-notower", "只装了 Shield，没有塔的基线", {
        "verdict": "idle", "title": "先让塔扫描一次",
        "note": "哨兵手上没有塔的基线：时区漂移和 UDP 出口都没法比对。"
                "先打开 Claude Tower 扫一次，数据会自动接上。",
        "claude": False, "tun": True, "tunIface": "utun4", "sysProxy": False,
        "dns": "198.18.2.160", "dnsFake": True, "dnsChecked": True, "dnsSuspect": False,
        "stun": ["5.34.*.136"], "stunForeign": ["5.34.*.136"],
        "stunChecked": True, "stunLeak": False,
        "egressMask": "", "maskFresh": False, "egressAt": 0, "country": "",
        "baselineTz": "", "tz": "Asia/Taipei", "tzDrift": False,
        "idleState": "notower", "environmentReady": False,
        "towerData": False, "towerState": "missing",
        "hits": [],
    }),
    ("shield-transport", "传输只通一条（按域名分流的规则漏了 claude.ai）", {
        "verdict": "safe", "title": "守护中",
        "note": "Claude 在运行，出口在位。",
        "tun": True, "tunIface": "utun4", "sysProxy": False,
        "dns": "198.18.2.160", "dnsFake": True, "dnsChecked": True, "dnsSuspect": False,
        "stun": ["5.34.*.136"], "stunForeign": ["5.34.*.136"],
        "stunChecked": True, "stunLeak": False,
        "transportState": "warn", "transportLabel": "一条不通",
        "transportDetail": "claude.ai 超时；另一条是通的。按域名分流的规则常会漏掉"
                           "其中一个域名，先看分流规则里有没有这一条。",
        "transportAt": time.time() - 30,
        "hits": [],
    }),
    ("shield-tls", "传输证书异常", {
        "verdict": "warn", "title": "DNS 未接管",
        "note": "出口在位，但 claude.ai 解析成了真实地址（160.79.104.10）——"
                "TUN 开着却没接管 DNS，分流规则可能只做了一半。",
        "tun": True, "tunIface": "utun4", "sysProxy": False,
        "dns": "160.79.104.10", "dnsFake": False, "dnsChecked": True, "dnsSuspect": True,
        "stun": ["5.34.*.136"], "stunForeign": ["5.34.*.136"],
        "stunChecked": True, "stunLeak": False,
        "transportState": "bad", "transportLabel": "证书异常",
        "transportDetail": "api.anthropic.com 证书异常、claude.ai 证书异常。TLS 没建立起来。"
                           "证书链校验失败时哨兵不会替你放行，因为「点了信任」正是中间人"
                           "需要的那一步；先查代理的证书设置。",
        "transportAt": time.time() - 30,
        "hits": [
            {"ts": time.time() - 120, "kind": "dns", "note": "DNS 没被接管"},
        ],
    }),
    ("shield-takeover", "代理在跑但没接管，持续 30 秒后升级", {
        "verdict": "danger", "title": "代理在跑，但没接管",
        "note": "代理客户端在跑（verge-mihomo），但已经 30 秒没看到 TUN 或系统代理接管"
                "——流量这会儿走的是真实网络。把接管打开，或者直接退出 Claude。",
        "tun": False, "tunIface": "en0", "sysProxy": False,
        "dns": "", "dnsFake": False, "dnsChecked": False, "dnsSuspect": False,
        "clients": ["verge-mihomo"], "takeover": True, "takeoverEscalated": True,
        # L2 武装时周期压到 10 秒，面板显示的必须是这个实际值
        "level": 2, "interval": 10,
        "hits": [
            {"ts": time.time() - 90, "kind": "takeover",
             "note": "代理客户端在跑（verge-mihomo），但已经 30 秒没看到 TUN 或系统代理接管"},
            {"ts": time.time() - 60, "kind": "kill",
             "note": "代理在跑，但没接管；已请求 Claude 退出（pid 4821）"},
        ],
    }),
    ("shield-gate", "闸门档：启动时没出口，直接拦下", {
        "verdict": "idle", "title": "先别启动 Claude",
        "note": "现在没有任何出口：没看到 TUN，也没开系统代理。先开代理再启动 Claude，"
                "否则它的流量全走真实网络。",
        "claude": False, "tun": False, "tunIface": "en0", "sysProxy": False,
        "dns": "", "dnsFake": False, "dnsChecked": False, "dnsSuspect": False,
        "idleState": "blocked", "environmentReady": False,
        "level": 3,
        "hits": [
            {"ts": time.time() - 240, "kind": "gate",
             "note": "出口已断；已请求 Claude 退出（pid 5127）"},
        ],
    }),
    ("shield-danger", "没有任何出口", {
        "verdict": "danger", "title": "出口已断",
        "note": "Claude 在运行，但没有任何出口。这时候它发出的每个包都走真实网络。",
        "tun": False, "tunIface": "en0", "sysProxy": False,
        "dns": "", "dnsFake": False, "dnsChecked": False, "dnsSuspect": False,
        "level": 2, "interval": 10,
        "hits": [
            {"ts": time.time() - 40, "kind": "danger",
             "note": "Claude 在运行，但没有任何出口。"},
            {"ts": time.time() - 30, "kind": "kill", "note": "已请求 Claude 退出（pid 4821）"},
        ],
    }),
]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    profile = Path("/tmp/ccclean-shield-shot")
    subprocess.run(["rm", "-rf", str(profile)], check=False)
    chrome = subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--in-process-gpu",
         "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
         "--force-device-scale-factor=2",
         f"--remote-debugging-port={CDP_PORT}", f"--user-data-dir={profile}",
         f"--window-size={W},{H}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    cdp = None
    try:
        for _ in range(100):
            try:
                raw = OPENER.open(f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=2).read()
                page = next((t for t in json.loads(raw) if t.get("type") == "page"), None)
                if page:
                    cdp = CDP(page["webSocketDebuggerUrl"])
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not cdp:
            print("✗ Chrome 没起来")
            return 1

        cdp.call("Page.enable")
        cdp.call("Runtime.enable")
        cdp.call("Emulation.setDeviceMetricsOverride",
                 {"width": W, "height": H, "deviceScaleFactor": 2, "mobile": False})
        cdp.call("Page.navigate", {"url": (ROOT / "shield/web/shield.html").as_uri()})
        time.sleep(2)

        for name, label, patch in CASES:
            payload = dict(BASE, **patch)
            js = "window.SHIELD.update(%s)" % json.dumps(payload, ensure_ascii=False)
            cdp.call("Runtime.evaluate", {"expression": js, "awaitPromise": True})
            time.sleep(0.35)
            shot = cdp.call("Page.captureScreenshot", {"format": "png"})
            data = shot["result"]["data"]
            import base64
            path = OUT / f"{name}.png"
            path.write_bytes(base64.b64decode(data))
            print(f"✓ {path.relative_to(ROOT)}  （{label}）")
        # 无真实 Swift 桥，捕获消息验证两模式与二次确认，绝不运行急停动作。
        payload = dict(BASE, level=1)
        cdp.call("Runtime.evaluate", {"expression": "window.SHIELD.update(%s)" % json.dumps(payload)})
        checked = cdp.call("Runtime.evaluate", {"expression": """(() => {
          const messages=[];
          window.webkit={messageHandlers:{shield:{postMessage:m=>messages.push(m)}}};
          const buttons=document.querySelectorAll('#seg button');
          const strict=document.querySelector('#seg button[data-lv="2"]');
          strict.click();
          const first=messages.length===0 && strict.textContent.includes('确认开启');
          strict.click();
          const second=messages.length===1 && messages[0].action==='level' && messages[0].value===2;
          document.querySelector('#seg button[data-lv="1"]').click();
          strict.click();
          document.querySelector('#seg button[data-lv="1"]').click();
          const cancelled=!strict.classList.contains('asking') && !strict.textContent.includes('确认开启');
          return buttons.length===2 && first && second && cancelled;
        })()""", "returnByValue": True})
        if checked.get("result", {}).get("result", {}).get("value") is not True:
            raise RuntimeError("两模式或二次确认/取消验证失败")
        print("✓ 两模式、严格二次确认、返回宽松取消待确认均通过")
        return 0
    finally:
        if cdp:
            cdp.close()
        chrome.terminate()
        try:
            chrome.wait(timeout=8)
        except subprocess.TimeoutExpired:
            chrome.kill()


if __name__ == "__main__":
    raise SystemExit(main())
