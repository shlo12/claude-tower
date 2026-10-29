#!/usr/bin/env python3
"""接口鉴权回归测试。

起一个真的 HTTP 服务，然后用各种「不像本应用页面」的方式敲门，
确认每一扇门都关着；再用页面自己的方式敲门，确认都开着。

    python3 tools/test_security.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 8791
BASE = f"http://127.0.0.1:{PORT}"

# 环境里可能设了 http_proxy，urllib 会老老实实把 127.0.0.1 的请求也发过去，
# 拿回来一个 502。这里显式清空代理。
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}" + (f"  —— {detail}" if detail else ""))


def request(method: str, path: str, *, headers=None, body=None):
    """返回 (状态码, 响应体文本)。不抛 4xx/5xx。"""
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with OPENER.open(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def token_from_page() -> str:
    _, html = request("GET", "/")
    m = re.search(r'<meta name="cc-token" content="([^"]+)"', html)
    return m.group(1) if m else ""


def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "app.py"), "--port", str(PORT), "--no-open"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                request("GET", "/api/meta")
                break
            except Exception:
                time.sleep(0.1)
        else:
            print("✗ 服务没起来")
            return 1

        token = token_from_page()
        good = {"Host": f"127.0.0.1:{PORT}", "X-CClean-Token": token}

        print("\n[1] 令牌下发")
        check("首页注入了 cc-token", bool(token), "index.html 里找不到 meta")
        check("令牌长度合理", len(token) >= 32, f"只有 {len(token)} 字符")
        check("/app.js 里没有硬编码令牌", token not in (ROOT / "web/app.js").read_text(encoding="utf-8"))

        print("\n[2] 跨站页面（带 Origin，无令牌）")
        for path, payload in [
            ("/api/clean", {"ids": [], "confirm": "CLEAN"}),
            ("/api/timezone", {"tz": "UTC", "confirm": True}),
            ("/api/kill-claude", {}),
            ("/api/quit", {}),
            ("/api/scan", {}),
            ("/api/profiles", {"name": "x"}),
            ("/api/leaderboard/delete", {"ts": 1}),
            ("/api/tower/reset", {}),
            ("/api/ipv6", {"action": "off", "confirm": True}),
            ("/api/proxyfix", {"action": "apply", "confirm": True}),
            ("/api/region", {"action": "apply", "region": "US", "confirm": True}),
            ("/api/netcfg", {"country": "US"}),
            ("/api/probe/webrtc", {"candidates": []}),
        ]:
            code, _ = request("POST", path, headers={
                "Host": f"127.0.0.1:{PORT}", "Origin": "http://evil.example",
            }, body=payload)
            check(f"POST {path} 被拒", code == 403, f"返回 {code}")

        print("\n[3] 本机来源但没令牌（本地其它程序伪造）")
        for path in ("/api/quit", "/api/clean", "/api/kill-claude"):
            code, _ = request("POST", path, headers={"Host": f"127.0.0.1:{PORT}"}, body={})
            check(f"POST {path} 被拒", code == 403, f"返回 {code}")

        print("\n[4] 令牌错一个字")
        bad = token[:-1] + ("A" if token[-1:] != "A" else "B")
        code, _ = request("POST", "/api/quit",
                          headers={"Host": f"127.0.0.1:{PORT}", "X-CClean-Token": bad}, body={})
        check("POST /api/quit 被拒", code == 403, f"返回 {code}")

        print("\n[5] DNS 重绑定（Host 是外部域名，令牌是对的）")
        for path in ("/api/quit", "/api/clean"):
            code, _ = request("POST", path,
                              headers={"Host": "evil.example", "X-CClean-Token": token}, body={})
            check(f"POST {path} 被拒", code == 403, f"返回 {code}")

        print("\n[6] GET 也不能裸奔")
        for path in ("/api/scan", "/api/report", "/api/backups", "/api/tool/hosts-block",
                     "/api/netcfg"):
            code, _ = request("GET", path, headers={"Host": f"127.0.0.1:{PORT}"})
            check(f"GET {path} 被拒", code == 403, f"返回 {code}")

        print("\n[7] DELETE 也要令牌")
        code, _ = request("DELETE", "/api/profiles?slug=x", headers={"Host": f"127.0.0.1:{PORT}"})
        check("DELETE /api/profiles 被拒", code == 403, f"返回 {code}")

        print("\n[8] 正常页面请求必须放行")
        code, body = request("GET", "/api/meta", headers=good)
        check("GET /api/meta 放行", code == 200, f"返回 {code}")
        code, _ = request("GET", "/api/backups", headers=good)
        check("GET /api/backups 放行", code == 200, f"返回 {code}")
        code, body = request("POST", "/api/scan", headers={**good, "Content-Type": "application/json"},
                             body={"net": False})
        check("POST /api/scan 放行", code == 200, f"返回 {code}")

        # net=False 必须连 ipcheck 都不跑：它会访问外部接口，
        # 这个开关正是测试用来避开真实网络的。
        src = (ROOT / "app.py").read_text(encoding="utf-8")
        m = re.search(r'if path == "/api/scan":(.*?)if path == "/api/preview":', src, re.S)
        body_src = m.group(1) if m else ""
        check("net=False 不触发外部 ipcheck",
              "if net:" in body_src
              and body_src.index("if net:") < body_src.index("ipcheck.check"),
              "ipcheck 仍在 net=False 分支里执行")

        print("\n[9] 静态资源不受影响")
        for path in ("/", "/app.js", "/style.css"):
            code, _ = request("GET", path, headers={"Host": f"127.0.0.1:{PORT}"})
            check(f"GET {path} 正常", code == 200, f"返回 {code}")

        print("\n[10] privacy 接口仍走自己的令牌")
        code, body = request("GET", "/api/privacy", headers={"Host": f"127.0.0.1:{PORT}"})
        check("GET /api/privacy 放行", code == 200, f"返回 {code}")
        check("它自己发一个 token", "token" in body)
        code, _ = request("POST", "/api/privacy",
                          headers={"Host": f"127.0.0.1:{PORT}", "X-CClean-Token": token},
                          body={"action": "enable", "confirm": True})
        check("POST /api/privacy 缺专用令牌被拒", code == 403, f"返回 {code}")

        print("\n[11] ipv6 接口也走自己的令牌")
        code, body = request("GET", "/api/ipv6", headers={"Host": f"127.0.0.1:{PORT}"})
        check("GET /api/ipv6 放行", code == 200, f"返回 {code}")
        check("它自己发一个 token", "token" in body)
        code, _ = request("POST", "/api/ipv6",
                          headers={"Host": f"127.0.0.1:{PORT}", "X-CClean-Token": token},
                          body={"action": "off", "confirm": True})
        check("POST /api/ipv6 缺专用令牌被拒", code == 403, f"返回 {code}")

        print("\n[12] proxyfix 接口也走自己的令牌")
        code, body = request("GET", "/api/proxyfix", headers={"Host": f"127.0.0.1:{PORT}"})
        check("GET /api/proxyfix 放行", code == 200, f"返回 {code}")
        check("它自己发一个 token", "token" in body)
        code, _ = request("POST", "/api/proxyfix",
                          headers={"Host": f"127.0.0.1:{PORT}", "X-CClean-Token": token},
                          body={"action": "apply", "confirm": True})
        check("POST /api/proxyfix 缺专用令牌被拒", code == 403, f"返回 {code}")

        print("\n[13] 预检：服务端不给跨站开口子")
        # 浏览器发自定义头前会先问一句「能不能发」。本服务不实现 do_OPTIONS，
        # BaseHTTPRequestHandler 直接回 501，预检过不去，跨站请求就停在浏览器里。
        code, _ = request("OPTIONS", "/api/quit", headers={
            "Host": f"127.0.0.1:{PORT}",
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-cclean-token,content-type",
        })
        check("OPTIONS 不是 2xx", not (200 <= code < 300), f"返回 {code}")

        print("\n[14] 国家预期接口：读要令牌，非法代码不落盘")
        code, body = request("GET", "/api/netcfg", headers=good)
        check("GET /api/netcfg 放行", code == 200, f"返回 {code}")
        check("返回体里有 country 字段", "country" in body)
        # 只发非法的两位以上代码：校验在写盘之前，真实 HOME 不会被改动
        code, _ = request("POST", "/api/netcfg",
                          headers={**good, "Content-Type": "application/json"},
                          body={"country": "USA"})
        check("非法国家代码返回 400", code == 400, f"返回 {code}")

        print("\n[15] 浏览器实测接口：形状不对直接 400，不写盘也不扫盘")
        code, _ = request("POST", "/api/probe/webrtc",
                          headers={**good, "Content-Type": "application/json"},
                          body={"nope": 1})
        check("缺 candidates 返回 400", code == 400, f"返回 {code}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n{'='*46}\n  通过 {PASS} 项，失败 {FAIL} 项\n{'='*46}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
