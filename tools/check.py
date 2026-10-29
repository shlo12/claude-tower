#!/usr/bin/env python3
"""Claude Tower 冒烟检查：不联网、不改任何文件，几秒跑完。

覆盖五类最容易悄悄坏掉的东西：

  1. 地图   —— 尺寸、入口、连通性、怪物字符数与关卡数是否对得上
  2. 关卡   —— id 唯一、编号连续、总关卡数
  3. 判定   —— 出口漂移分级、备份裁剪、IP 打码
  4. 打包   —— 部署目标、二进制 minos、内置 Python 运行时、符号链接
  5. 接线   —— 版本号是否一致、事件绑定的元素是否真的存在

跑法：python3 tools/check.py
退出码 0 = 全过，1 = 有失败项。
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import cleaner, ipcheck, netprobe, tower  # noqa: E402

FAILED: list[str] = []
PASSED = 0


def check(name: str, ok: bool, detail: str = "") -> bool:
    global PASSED
    if ok:
        PASSED += 1
        print(f"  ✓ {name}")
    else:
        FAILED.append(name)
        print(f"  ✗ {name}" + (f" —— {detail}" if detail else ""))
    return ok


# ------------------------------------------------------------------ 地图

def load_maps() -> dict[str, list[str]]:
    src = (ROOT / "web" / "tower.js").read_text(encoding="utf-8")
    start = src.index("const MAPS = {")
    end = src.index("\n  };", start)
    block = src[start:end]
    maps = {}
    for m in re.finditer(r"(f\d):\s*\[([^\]]*)\]", block, re.S):
        maps[m.group(1)] = re.findall(r"'([^']*)'", m.group(2))
    return maps


def mob_chars() -> str:
    src = (ROOT / "web" / "tower.js").read_text(encoding="utf-8")
    m = re.search(r"const MOB_CHARS = '([^']*)'", src)
    return m.group(1) if m else ""


def level_ids() -> list[str]:
    src = (ROOT / "core" / "tower.py").read_text(encoding="utf-8")
    return re.findall(r'_lv\(\s*"(\d+-\d+)"', src)


def reachable(rows: list[str], blocked: str) -> set[tuple[int, int]]:
    h, w = len(rows), len(rows[0])
    start = next(((x, y) for y, r in enumerate(rows) for x, c in enumerate(r) if c == "E"), None)
    if start is None:
        return set()
    seen = {start}
    q = deque([start])
    while q:
        x, y = q.popleft()
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nx, ny = x + dx, y + dy
            if not (0 <= ny < h and 0 <= nx < w):
                continue
            if rows[ny][nx] in blocked or (nx, ny) in seen:
                continue
            seen.add((nx, ny))
            q.append((nx, ny))
    return seen


def check_maps() -> None:
    print("\n[地图]")
    maps = load_maps()
    mobs_allowed = mob_chars()
    ids = level_ids()
    per_floor: dict[str, int] = {}
    for lid in ids:
        key = "f" + lid.split("-")[0]
        per_floor[key] = per_floor.get(key, 0) + 1

    check("五张地图都在", len(maps) == 5, f"实际 {len(maps)} 张")
    check("MOB_CHARS 不与特殊格冲突", not set(mobs_allowed) & set("#oTEBX*^"), mobs_allowed)

    for fid, rows in maps.items():
        if not rows:
            check(f"{fid} 非空", False)
            continue
        width = len(rows[0])
        check(f"{fid} 每行等宽（{width} 列）", all(len(r) == width for r in rows),
              str([i for i, r in enumerate(rows) if len(r) != width]))
        check(f"{fid} 只有一个入口 E", sum(r.count("E") for r in rows) == 1)

        seen = reachable(rows, "#oT")
        check(f"{fid} 入口能出发", bool(seen))

        mobs = [(c, x, y) for y, r in enumerate(rows) for x, c in enumerate(r) if c in mobs_allowed]
        dead = [(c, x, y) for c, x, y in mobs if (x, y) not in seen]
        check(f"{fid} 怪物都走得到", not dead, str(dead))

        special = [(c, x, y) for y, r in enumerate(rows) for x, c in enumerate(r)
                   if c in "BX" and (x, y) not in seen]
        check(f"{fid} 守卫/楼梯走得到", not special, str(special))

        want = per_floor.get(fid, 0)
        check(f"{fid} 怪物数 = 关卡数（{len(mobs)} / {want}）", len(mobs) == want,
              f"地图 {len(mobs)} 个怪物字符，关卡 {want} 个")


def check_levels() -> None:
    print("\n[关卡]")
    ids = level_ids()
    check("关卡 id 唯一", len(ids) == len(set(ids)),
          str([i for i in set(ids) if ids.count(i) > 1]))
    check("关卡总数 29", len(ids) == 29, f"实际 {len(ids)}")
    nums = [(int(a), int(b)) for a, b in (i.split("-") for i in ids)]
    check("编号从 1-1 开始且逐层递增", nums == sorted(nums) and nums[0] == (1, 1))
    gaps = [(a, b) for (a, b), (c, d) in zip(nums, nums[1:]) if a == c and d != b + 1]
    check("同层编号连续", not gaps, str(gaps))


# ------------------------------------------------------------------ 判定

def check_drift() -> None:
    print("\n[出口漂移分级]")
    origin = ipcheck.drift

    def fake(**kw):
        base = {"enough": True, "count": 3, "total": 3, "windowHours": 24,
                "recent": [], "countries": [], "switches": 0, "asns": [], "spanHours": 1}
        base.update(kw)
        return base

    cases = [
        ("记录不足 → pass", dict(enough=False, count=1, total=1), "pass"),
        ("3 个国家 → high", dict(countries=["US", "JP", "SG"], asns=["1"]), "high"),
        ("2 个国家 → medium", dict(countries=["US", "JP"], asns=["1"], switches=2), "medium"),
        ("同国 3 个 ASN → medium", dict(countries=["US"], asns=["1", "2", "3"]), "medium"),
        ("同国 2 个 ASN → low", dict(countries=["US"], asns=["1", "2"]), "low"),
        ("稳定不变 → pass", dict(countries=["US"], asns=["1"]), "pass"),
    ]
    try:
        for name, fixture, want in cases:
            ipcheck.drift = lambda **kw: fake(**fixture)
            got = tower._probe_egress_drift({}, {})["sev"]
            check(name, got == want, f"实际 {got}")
    finally:
        ipcheck.drift = origin


def check_backup_prune() -> None:
    print("\n[备份裁剪]")
    tmp = Path(tempfile.mkdtemp(prefix="ccclean-check-"))
    origin = cleaner.BACKUP_DIR
    try:
        cleaner.BACKUP_DIR = tmp
        for i in range(25):
            d = tmp / f"202601{i:02d}-120000"
            d.mkdir()
            (d / "manifest.json").write_text(json.dumps({"entries": [1]}))
        (tmp / "20260199-999999").mkdir()          # 没有 manifest，不是我们建的
        (tmp / "notes").mkdir()                    # 名字不合法
        protect = tmp / "20260100-120000"

        removed = cleaner.prune_backups(keep=20, protect=protect)
        left = [p for p in tmp.iterdir()
                if cleaner._BACKUP_NAME.match(p.name) and (p / "manifest.json").exists()]
        check("超过 20 份会裁剪", removed == 4, f"删了 {removed} 份")
        check("裁剪后保留 20 份 + 在用的一份", len(left) == 21, f"剩 {len(left)} 份")
        check("正在使用的备份不删", protect.exists())
        check("没有 manifest 的目录不动", (tmp / "20260199-999999").exists())
        check("非备份命名不动", (tmp / "notes").exists())
    finally:
        cleaner.BACKUP_DIR = origin
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def check_mask() -> None:
    print("\n[IP 打码]")
    masked = netprobe._mask_ip("38.190.176.186")
    check("IPv4 打码", masked != "38.190.176.186" and masked.count(".") == 3, masked)
    check("空值不炸", netprobe._mask_ip("") == "")


# ------------------------------------------------------------------ 版本

def check_version() -> None:
    print("\n[版本号]")
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    m = re.search(r'^VERSION = "([^"]+)"', app, re.M)
    ver = m.group(1) if m else ""
    check("app.py 有 VERSION", bool(ver), ver)
    plist = (ROOT / "tools" / "Info.plist").read_text(encoding="utf-8")
    pm = re.search(r"<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>", plist)
    check("Info.plist 版本与 app.py 一致", pm and pm.group(1) == ver,
          f"plist={pm.group(1) if pm else '?'} app={ver}")

    # 前端只准从后端拿版本号。写死在 HTML 里就会出现「页面显示 v2.9.3、
    # 后端其实是 2.9.5」这种自相矛盾——已经发生过一次。
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    hard = re.findall(r'id="t-ver"[^>]*>\s*v?(\d+\.\d+\.\d+)', html)
    check("index.html 没写死版本号", not hard, f"发现 {', '.join(hard)}")


def check_dom_refs() -> None:
    """顶层 $('#x').addEventListener 绑定的元素必须真的在 HTML 里。

    这类引用写错会直接抛错，让后面所有脚本停摆（净化祭坛那一整块就踩过）。
    动态渲染出来的元素不在此列，所以只看「绑定事件」这一种用法。
    """
    print("\n[DOM 引用]")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    ids = set(re.findall(r'id="([^"]+)"', html))
    dead: list[str] = []
    for name in ("app.js", "tower.js"):
        src = (ROOT / "web" / name).read_text(encoding="utf-8")
        for ref in re.findall(r"\$\('#([\w-]+)'\)\.addEventListener", src):
            if ref not in ids:
                dead.append(f"{name}: #{ref}")
    check("事件绑定都指向真实存在的元素", not dead, ", ".join(dead))


def check_deploy_target() -> None:
    """最低系统版本必须是「编译目标」和「Info.plist」两处一致，而且不能随手抬高。

    这两处各管一段：LSMinimumSystemVersion 由 LaunchServices 查，只负责弹
    「此版本不能与此版本的 macOS 配合使用」；二进制里的 minos 由 dyld 查，
    抬高了连加载都过不去。曾经把它们一起设成 13.0，结果 macOS 12.6 的机器
    双击直接吃闭门羹——代码里根本没用任何 macOS 13 的接口。
    """
    print("\n[最低系统版本]")
    sh = (ROOT / "tools" / "build-app.sh").read_text(encoding="utf-8")
    targets = re.findall(r"-target\s+(\w+)-apple-macosx([\d.]+)", sh)
    check("build-app.sh 找得到两种架构的 -target", len(targets) == 2,
          ", ".join(f"{a}={v}" for a, v in targets) or "一个都没找到")

    versions = {v for _, v in targets}
    check("两种架构的部署目标一致", len(versions) == 1, " / ".join(sorted(versions)))
    target = versions.pop() if len(versions) == 1 else None

    plist = (ROOT / "tools" / "Info.plist").read_text(encoding="utf-8")
    pm = re.search(r"<key>LSMinimumSystemVersion</key>\s*<string>([^<]+)</string>", plist)
    plist_ver = pm.group(1) if pm else ""
    check("Info.plist 与编译目标一致", plist_ver == target,
          f"plist={plist_ver or '?'} target={target or '?'}")

    # 门槛抬得越高，能装的人越少；没有必须的理由就别超 11.0
    check("部署目标不高于 11.0", target is not None and _ver_tuple(target) <= (11, 0),
          f"target={target}")

    # 已经构建过的话，顺手核对二进制里真正写进去的 minos
    bin_path = ROOT / "Claude Tower.app" / "Contents" / "MacOS" / "CCclean"
    if not bin_path.exists():
        return
    for arch in ("arm64", "x86_64"):
        try:
            out = subprocess.run(
                ["vtool", "-show-build", "-arch", arch, str(bin_path)],
                capture_output=True, text=True, timeout=10,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            check(f"二进制 {arch} 的 minos", False, "vtool 跑不起来")
            continue
        mm = re.search(r"minos\s+([\d.]+)", out)
        check(f"二进制 {arch} 的 minos 与 plist 一致", bool(mm) and mm.group(1) == plist_ver,
              f"minos={mm.group(1) if mm else '?'} plist={plist_ver}")


def check_bundled_python() -> None:
    """应用包里必须真的带上两个架构的 Python 运行时。

    这是「对方机器上一个 python3 都没有」时的唯一出路。漏打包的话，
    在开发机上一切正常（有 homebrew python 兜底），发出去就废。
    """
    print("\n[内置 Python]")
    app = ROOT / "Claude Tower.app"
    if not app.exists():
        print("  · 应用还没构建，跳过")
        return

    for arch in ("arm64", "x86_64"):
        bin_path = app / "Contents" / "Resources" / "python" / arch / "bin" / "python3.12"
        if not check(f"{arch} 解释器存在", bin_path.exists(), str(bin_path)):
            continue
        check(f"{arch} 解释器可执行", os.access(bin_path, os.X_OK))
        try:
            out = subprocess.run(["lipo", "-info", str(bin_path)],
                                 capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        check(f"{arch} 解释器架构正确", arch in out, out.strip() or "lipo 无输出")

        try:
            vout = subprocess.run(["vtool", "-show-build", str(bin_path)],
                                  capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            vout = ""
        mm = re.search(r"minos\s+([\d.]+)", vout)
        check(f"{arch} 解释器能在 12.6 上跑", bool(mm) and _ver_tuple(mm.group(1)) <= (12, 6),
              f"minos={mm.group(1) if mm else '?'}")

    # 标准库得在：能启动但 import 不了才是最难查的
    stdlib = app / "Contents" / "Resources" / "python" / "arm64" / "lib" / "python3.12" / "http"
    check("标准库 http 模块已带上", stdlib.exists())

    # 包里不能有符号链接：zip 打包器会直接拒绝，等于打不出包
    links = [str(p.relative_to(app)) for p in app.rglob("*") if p.is_symlink()]
    check("应用包里没有符号链接", not links, ", ".join(links[:3]))


def check_api_guard() -> None:
    """写操作接口必须过闸门。

    这条不是形式主义：`/api/clean`、`/api/quit` 这些接口能删文件、能关进程，
    而服务端口在 8787–8800 之间可枚举。少一个校验，任何本机网页都能替你按下去。
    新加接口时最容易被忘掉，所以放在这里当护栏。
    """
    print("\n[接口闸门]")
    src = (ROOT / "app.py").read_text(encoding="utf-8")

    def body_of(name: str) -> str:
        m = re.search(rf"^    def {name}\(self.*?(?=^    def |\Z)", src, re.M | re.S)
        return m.group(0) if m else ""

    for method in ("do_POST", "do_DELETE"):
        body = body_of(method)
        check(f"{method} 存在", bool(body))
        if not body:
            continue
        first_branch = body.find('path == "/api/')
        guard = body.find("self._guard()")
        check(f"{method} 在第一个路由分支前就校验",
              guard != -1 and (first_branch == -1 or guard < first_branch),
              f"guard@{guard} branch@{first_branch}")

    get_body = body_of("do_GET")
    check("do_GET 在查接口前就校验",
          "self._guard()" in get_body and get_body.find("self._guard()") < get_body.find("_api_get("))

    # 闸门本身得同时看 Host/Origin 和令牌，只查一样都是半扇门
    check("闸门校验 Host/Origin", "def _local_request" in src)
    check("闸门校验会话令牌", "X-CClean-Token" in src)
    check("令牌用常量时间比较", "compare_digest" in src)
    check("令牌注入页面", 'name="cc-token"' in src)
    check("页面脚本会带上令牌", "X-CClean-Token" in (ROOT / "web" / "app.js").read_text(encoding="utf-8"))

    # 前端不该有绕过统一 api() 的裸 fetch 打 /api/（漏带头就会 403）
    for name in ("app.js", "tower.js"):
        js = (ROOT / "web" / name).read_text(encoding="utf-8")
        naked = re.findall(r"fetch\('(/api/[^']*)'\s*,\s*\{[^}]*\}", js)
        bad = [u for u in naked if "ccHeaders" not in js[js.find(u):js.find(u) + 400]]
        check(f"{name} 的裸 fetch 都带了令牌头", not bad, ", ".join(bad))


def check_dnsbl_logic() -> None:
    """DNSBL 五种应答的判定。

    这一项曾经把「解析出东西」一律当成命中，在 fake-ip 环境里 6/6 全红；
    又把「解析失败」一律当成干净，运营商劫持 NXDOMAIN 时全绿。
    两个方向都错，所以这里把每条分支都钉住。
    """
    print("\n[DNSBL 判定]")
    import socket as _socket

    from core import deep

    def raising(errno):
        def _f(name):
            raise _socket.gaierror(errno, "stub")
        return _f

    real = deep.socket.gethostbyname
    try:
        cases = [
            ("127.0.0.4", "hit", "命中：名单回 127.0.0.0/8"),
            ("127.0.0.10", "hit", "命中：127.0.0.10 也算"),
            (raising(_socket.EAI_NONAME), "clean", "NXDOMAIN 算明确否认"),
            (raising(-3), "noanswer", "其它解析错误算无应答，不算干净"),
            ("198.18.0.66", "fake", "198.18.x 是 fake-ip 编造"),
            ("198.19.255.1", "fake", "198.19.x 同属 198.18.0.0/15"),
            ("203.0.113.9", "hijack", "公网地址是 DNS 劫持落地页"),
        ]
        for stub, want, label in cases:
            deep.socket.gethostbyname = stub if callable(stub) else (lambda _n, s=stub: s)
            got, addr = deep._dnsbl_lookup("zen.spamhaus.org", "1.0.0.127")
            check(label, got == want, f"得到 {got}({addr}) 期望 {want}")

        # 全 fake → 必须是 info，不能是 high
        deep.socket.gethostbyname = lambda _n: "198.18.0.66"
        item = deep.check_dnsbl("1.2.3.4")
        check("全 fake-ip 时报「无法实测」而不是命中", item["severity"] == "info", item["severity"])
        check("全 fake-ip 时标题说清楚测不了", "无法实测" in item["title"], item["title"])

        # 真命中 → high
        deep.socket.gethostbyname = lambda _n: "127.0.0.4"
        item = deep.check_dnsbl("1.2.3.4")
        check("真命中报 high", item["severity"] == "high", item["severity"])

        # 全 NXDOMAIN → pass
        deep.socket.gethostbyname = raising(_socket.EAI_NONAME)
        item = deep.check_dnsbl("1.2.3.4")
        check("全否认报 pass", item["severity"] == "pass", item["severity"])

        # 无 IP → info，且不该炸
        item = deep.check_dnsbl(None)
        check("没有出口 IP 时跳过", item["severity"] == "info", item["severity"])
    finally:
        deep.socket.gethostbyname = real


def check_tun_loop() -> None:
    """TUN 回环：节点是域名时也必须能查出来。

    机场给的节点几乎全是域名（hk1.example.com 这种），老代码只认字面量 IP，
    于是这一项在真实配置上从来没报过——看起来「很干净」，其实是没看。
    """
    print("\n[TUN 回环]")
    import socket as _socket

    from core import compat, deep

    sample = """
proxies:
  - name: "HK-01"
    type: ss
    server: 203.0.113.7
    port: 443
  - name: "JP-02"
    type: trojan
    server: node.example.com
    port: 443
  - name: "SG-03"
    server: "203.0.113.8"
dns:
  nameserver:
    - 8.8.8.8
"""
    ips, names = deep._server_hosts(sample)
    check("认出字面量 IP 节点", ips == {"203.0.113.7", "203.0.113.8"}, str(ips))
    check("认出域名节点", names == {"node.example.com"}, str(names))
    check("不把 nameserver 当节点", "8.8.8.8" not in ips, str(ips))

    # 订阅文件几乎全是 flow 风格，块式正则在这里一个都匹配不到
    flow = (
        "proxies:\n"
        "  - {name: HK-01, server: hk1.example.com, port: 443, type: ss}\n"
        "  - {name: JP-02, server: jp1.example.net, port: 443}\n"
        "  - {name: IP-03, server: 203.0.113.20, port: 443}\n"
        "dns:\n"
        "  default-nameserver: [223.5.5.5, 119.29.29.29]\n"
        "  nameserver: [8.8.8.8]\n"
        "# - {name: OLD, server: retired.example.com}\n"
    )
    f_ips, f_names = deep._server_hosts(flow)
    check("flow 风格认得出域名", f_names == {"hk1.example.com", "jp1.example.net"}, str(f_names))
    check("flow 风格认得出 IP", f_ips == {"203.0.113.20"}, str(f_ips))
    check("不把 default-nameserver 当节点", not (f_names | f_ips) & {"223.5.5.5", "119.29.29.29"})
    check("注释掉的节点不算", "retired.example.com" not in f_names, str(f_names))

    check("fake-ip 不能当节点地址", not deep._usable_server_ip("198.18.0.66"))
    check("回环地址不能当节点", not deep._usable_server_ip("127.0.0.1"))
    check("链路本地不能当节点", not deep._usable_server_ip("169.254.1.1"))
    check("公网地址可用", deep._usable_server_ip("198.51.100.9"))

    # 端到端：临时配置 + 打桩，验证「域名节点 → 解析 → 比对排除表」整条链
    tmp = Path(tempfile.mkdtemp(prefix="ccclean-tun-"))
    real = (deep._CLASH_ROOTS, deep.socket.getaddrinfo, compat.tunnel_interfaces,
            compat.proxy_processes, compat.system_proxy, compat.default_route_iface)
    try:
        def write_config(excludes: str) -> None:
            (tmp / "config.yaml").write_text(
                "tun:\n  enable: true\n  route-exclude-address: %s\n"
                "proxies:\n  - name: HK\n    server: node.example.com\n    port: 443\n"
                "  - name: JP\n    server: other.example.net\n    port: 443\n" % excludes,
                encoding="utf-8",
            )

        deep._CLASH_ROOTS = [tmp]
        deep.socket.getaddrinfo = lambda *a, **k: [
            (2, 1, 6, "", ("198.51.100.9", 0)), (2, 1, 6, "", ("198.51.100.10", 0))
        ]
        compat.tunnel_interfaces = lambda: 2
        compat.proxy_processes = lambda keys: ["mihomo"]
        compat.system_proxy = lambda: {}
        compat.default_route_iface = lambda: "utun3"

        write_config("[]")
        loop = [i for i in deep.check_routing() if i["id"] == "net.tun_loop"]
        check("域名节点没在排除表 → 报回环", bool(loop) and loop[0]["severity"] == "medium",
              str([(i["id"], i["severity"]) for i in loop]))
        check("回环项带出解析到的 IP",
              bool(loop) and any("198.51.100.9" in e["value"] for e in loop[0]["evidence"]))

        write_config("['198.51.100.9/32', '198.51.100.10/32']")
        loop = [i for i in deep.check_routing() if i["id"] == "net.tun_loop"]
        check("排除表已覆盖 → 不报回环", not loop, str([i["severity"] for i in loop]))

        # 解析不出来时必须说「测不了」，不能沉默
        def _boom(*a, **k):
            raise _socket.gaierror(_socket.EAI_NONAME, "stub")

        write_config("[]")
        deep.socket.getaddrinfo = _boom
        loop = [i for i in deep.check_routing() if i["id"] == "net.tun_loop"]
        check("解析失败时报「无法实测」", bool(loop) and loop[0]["severity"] == "info",
              str([(i["id"], i["severity"]) for i in loop]))
    finally:
        (deep._CLASH_ROOTS, deep.socket.getaddrinfo, compat.tunnel_interfaces,
         compat.proxy_processes, compat.system_proxy, compat.default_route_iface) = real
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def check_user_consent() -> None:
    """三件「用户说了算」的事。坏了不会报错，只会悄悄替用户做主。

    1. 清理项默认一项都不勾——state.sel 的初值必须是空集合，扫完也不许自动填；
    2. 勇士榜常驻一条作者记录（存活 35 天），只写一次，删掉不复活；
    3. 塔顶通关有演出，且能被 prefers-reduced-motion 关掉。
    """
    print("\n[默认不选 / 作者榜位 / 通关演出]")

    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    tjs = (ROOT / "web" / "tower.js").read_text(encoding="utf-8")
    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")

    check("state.sel 初值是空集合", re.search(r"sel:\s*new Set\(\)", app) is not None)
    check("重新扫描会清掉旧勾选", "state.sel.clear()" in app)
    check("逐项勾选由用户点击触发", 'data-pick' in app and "function togglePick" in app)
    check("确认弹层能逐项移除", "data-unpick" in app)
    check("选择条默认隐藏", re.search(r'id="pickbar"[^>]*hidden', html) is not None)
    check("一键入口都要用户自己按", all(f'id="{i}"' in html for i in ("pick-all", "pick-none", "pick-go")))

    from core import leaderboard

    old_file = leaderboard.BOARD_FILE
    try:
        with tempfile.TemporaryDirectory() as td:
            leaderboard.BOARD_FILE = Path(td) / "leaderboard.json"
            check("新榜单保留作者个人战绩", any(e.get("author") and e.get("days") == 35 for e in leaderboard.list_entries()))
            leaderboard.BOARD_FILE.write_text(json.dumps({"seed": 1, "entries": [
                {"author": True, "name": "作者", "days": 35},
                {"name": "真实用户", "days": 2, "hp": 80, "ts": 123}]}))
            entries = leaderboard.list_entries()
            check("恢复作者个人战绩", any(e.get("author") and e.get("days") == 35 for e in entries))
            check("保留用户录入记录", any(e.get("name") == "真实用户" for e in entries))
            check("重复读取不重复添加作者", len(leaderboard.list_entries()) == 2)
    finally:
        leaderboard.BOARD_FILE = old_file

    check("通关演出层存在", 'id="finisher"' in html)
    check("演出可以跳过", 'id="fn-skip"' in html and "fn-skip" in tjs)
    check("通关时真的会播", "function playFinisher" in tjs and "await playFinisher()" in tjs)
    check("整局只播一次", "finisherPlayed" in tjs)
    check("尊重减少动态效果", "prefers-reduced-motion" in css and "prefers-reduced-motion" in tjs)


def _ver_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (999,)


def check_shield_baseline() -> None:
    """塔写给哨兵的基线。

    坏掉不会报错，只会安静地不生效——所以只能静态盯住：
    写入必须是先读后改、只碰自己那两个键、原子写，而且不能把
    Shield 的开关和命中记录覆盖掉。
    """
    print("\n[哨兵基线]")
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    shield_py = (ROOT / "core/shield.py").read_text(encoding="utf-8")

    check("app.py 引入了 shield", "shield" in app_py.split("from core import", 1)[-1][:400])
    check("/api/shield 已注册", '"/api/shield"' in app_py)
    check("扫描后写基线", "shield.write_baseline(scan)" in app_py)
    check("扫描接口也写基线", "shield.write_baseline(data)" in app_py)

    check("写基线前先读", "data = read()" in shield_py)
    # 只看 write_baseline 的函数体：status() 里读 enabled 是对的，写才是越界
    wb = shield_py.split("def write_baseline", 1)[-1].split("\ndef ", 1)[0]
    check("基线只写自己那几个键",
          'data["baselineTz"]' in wb and 'data["country"]' in wb
          and 'data["egressIP"]' in wb and 'data["egressAt"]' in wb
          and '"enabled"' not in wb and '"hits"' not in wb)
    check("探测不到出口时保留旧值", "if country and data.get" in shield_py)
    check("探测不到出口 IP 时保留旧值", "if egress and data.get" in shield_py)
    # 出口 IP 是给 Shield 比对 STUN 用的，落盘的必须是打码后的那个字段
    check("写的是打码 IP 不是完整 IP", 'net.get("ip")' in wb and 'net.get("ip_raw")' not in wb)
    check("基线原子写", "os.replace(" in shield_py)
    check("状态文件 0600", "0o600" in shield_py)
    check("读坏了不抛异常", "except (OSError, ValueError)" in shield_py)

    # 出征闸门已经撤掉：塔不该再去启动 Claude
    check("塔不再启动 Claude", '"/api/launch"' not in app_py)
    check("塔不再有 gate 模块", not (ROOT / "core/gate.py").exists())


def check_new_findings() -> None:
    """五项新检查的接线。

    检查项产出了、但关卡没接，是最容易漏的一类：清单里看得到，
    战斗结算里看不见——两个数字对不上，玩家只会觉得塔在骗人。
    所以每个 ID 都要在「产出侧」和「消费侧」各出现一次。
    """
    print("\n[新增检查项接线]")
    sc = (ROOT / "core/scanner.py").read_text(encoding="utf-8")
    dp = (ROOT / "core/deep.py").read_text(encoding="utf-8")
    tw = (ROOT / "core/tower.py").read_text(encoding="utf-8")

    produced = {
        "net.reachable": sc,
        "net.webrtc": sc,
        "net.country": sc,
        "locale.client_lang": sc,
        "res.shield": sc,
        "net.pinned": dp,
        "net.proxy_path": dp,
        "net.tun": dp,
        "net.dns_route": dp,
        "net.ipv6": dp,
        "net.proxy_dns": dp,
    }
    for iid, src in produced.items():
        check(f"{iid} 有产出", f'"{iid}"' in src)
        check(f"{iid} 已被关卡消费", f'"{iid}"' in tw)

    # STUN 的判定逻辑要能被单独测，所以必须有一个不碰网络的纯函数
    stun_py = (ROOT / "core/stun.py").read_text(encoding="utf-8")
    check("stun 判定可单测", "def judge(" in stun_py and "def parse(" in stun_py)
    check("stun 只在分裂时报泄漏", "hit and miss" in stun_py)
    check("stun 区分证据不足", '"unknown"' in stun_py and 'state == "leak"' in stun_py)
    check("stun 有 60 秒缓存", "CACHE_TTL = 60" in stun_py and "use_cache" in stun_py)

    # 证据脱敏与「未知不判通过」是这轮最容易回退的两条
    webrtc = sc.split("def _check_webrtc", 1)[-1].split("\ndef ", 1)[0]
    check("STUN 证据打码", "netprobe._mask_ip(ip)" in webrtc)
    check("证据不足不判通过", 'r["state"] != "pass"' in webrtc)
    check("出口未确认不探可达性", "出口地址还没确认" in sc)
    check("客户端语言区分域不存在", "domain_exists" in sc)

    check("分流规则解析可单测", "def classify_rules(" in dp)
    # 系统 DNS 与代理内核 DNS 是两条路径：内核那份必须读、必须分组、必须只认
    # 在跑的客户端，否则一份旧配置会长期替用户背锅。
    pdns_py = (ROOT / "core/proxydns.py").read_text(encoding="utf-8")
    check("代理 DNS 模块只读", not any(
        bad in pdns_py for bad in ("write_text(", "open(", "unlink(", "os.replace(")))
    check("代理 DNS 分三组名单",
          "_DEST_KEYS" in pdns_py and "_BOOT_KEYS" in pdns_py and "_NODE_KEYS" in pdns_py)
    check("节点域名不参与判定", 'domesticNode' in pdns_py and 'rep["domesticNode"]' in dp)
    check("只认运行中的客户端", "ps\", \"-axo\", \"comm=\"" in pdns_py)
    check("helper/service 不算客户端", "_HELPER_HINTS" in pdns_py)
    check("国内解析器名单只一份", "CN_DNS = (" not in tw and "proxydns.CN_DNS_IPS" in tw)
    check("规则解析区分 prepend-rules",
          "prepend-rules" in dp and '"prepend"' in dp)
    check("置顶判定有行为探测", "def _dns_behavior(" in dp and "_behavior_label" in dp)
    check("置顶判定可单测", "def pinned_verdict(" in dp)
    check("不再按 utun 数量判代理", "utun >= 3" not in dp)
    check("哨兵在线优先于安装路径", "if not running and not installed" in sc)
    check("哨兵用 launchctl 看自启", "launchctl" in (ROOT / "core/shield.py").read_text(
        encoding="utf-8"))

    # 这两项都依赖外部命令，Windows 上没有对应实现，必须早退而不是报错
    check("Windows 下不读 defaults 语言域", "compat.IS_WIN" in sc.split(
        "def _client_language_state", 1)[-1].split("\ndef ", 1)[0])


def check_transport_logic() -> None:
    """代理链路 / TUN / DNS / IPv6 / 国家预期这五条判据。

    这几条最容易退化成「一刀切」：把所有没开 TUN 的人都报红、把 DNS 必须
    返回 fake-ip 当硬标准、把 Wi-Fi 的修复建议套到以太网上。全部用注入状态
    测，不碰真实网络，也不改系统设置。
    """
    print("\n[链路判据]")
    from core import compat, deep, netcfg, scanner

    def state(**kw):
        base = {
            "system_proxy_on": False, "system_proxy": {}, "default_iface": "en0",
            "tun_on": False, "fake_route": "", "fake_route_on": False,
            "tunneled": False, "processes": [], "vpns": [], "tun_configured": False,
        }
        base.update(kw)
        return base

    # 代理链路：四种证据任一成立就算有链路
    check("本地进程算代理链路", deep.check_proxy_path(
        state(processes=["mihomo"]))["severity"] == "pass")
    check("系统代理算代理链路", deep.check_proxy_path(
        state(system_proxy_on=True, system_proxy={"server": "127.0.0.1:7890"}))["severity"] == "pass")
    check("TUN 算代理链路", deep.check_proxy_path(
        state(default_iface="utun3", tun_on=True, tunneled=True))["severity"] == "pass")
    check("Shadowrocket 这类 VPN 算代理链路", deep.check_proxy_path(
        state(vpns=["Shadowrocket"]))["severity"] == "pass")
    check("四类都没有才报 high", deep.check_proxy_path(state())["severity"] == "high")

    # TUN：只有「配置开了、却没接管、又没有系统代理」才 high
    check("TUN 未配置时只给 info", deep.check_tun(state())["severity"] == "info")
    check("TUN 已接管时 pass", deep.check_tun(
        state(default_iface="utun3", tun_on=True, tunneled=True))["severity"] == "pass")
    check("配置了 TUN 但系统代理在承载 → info", deep.check_tun(
        state(tun_configured=True, system_proxy_on=True, tunneled=True))["severity"] == "info")
    check("配置了 TUN 且无人接管 → high", deep.check_tun(
        state(tun_configured=True))["severity"] == "high")
    tun_body = (ROOT / "core/deep.py").read_text(encoding="utf-8")
    tun_body = tun_body.split("def check_tun", 1)[-1].split("\ndef ", 1)[0]
    check("TUN 的 high 在「已配置」分支里", tun_body.find('if st["tun_configured"]:') < tun_body.find('"high"'))

    # DNS：不要求 fake-ip；真实地址 + 已接管只提示，真实地址 + 无链路才 high
    check("DNS 全 fake-ip → pass", deep.check_dns_route(
        {"a.com": "fake", "b.com": "fake"}, state())["severity"] == "pass")
    check("DNS 真实地址 + 系统代理 → info", deep.check_dns_route(
        {"a.com": "real", "b.com": "real"},
        state(system_proxy_on=True, tunneled=True))["severity"] == "info")
    check("DNS 真实地址 + 无链路 → high", deep.check_dns_route(
        {"a.com": "real", "b.com": "real"}, state())["severity"] == "high")
    check("DNS 真假混合 → info", deep.check_dns_route(
        {"a.com": "real", "b.com": "fake"}, state())["severity"] == "info")
    check("DNS 未检测 → info", deep.check_dns_route(
        {"a.com": "unchecked"}, state())["severity"] == "info")
    dns_body = (ROOT / "core/deep.py").read_text(encoding="utf-8")
    dns_body = dns_body.split("def check_dns_route", 1)[-1].split("\ndef ", 1)[0]
    check("DNS 先看链路再判 high", dns_body.find('st["tunneled"]') < dns_body.find('"high"'))

    # IPv6：只把 Wi-Fi 判成可一键修；其它接口只给信息
    real = (compat.IS_MAC, compat.ipv6_exposure, compat.wifi_device)
    try:
        compat.IS_MAC = True
        compat.wifi_device = lambda: "en0"
        compat.ipv6_exposure = lambda: {
            "has_default_v6_route": True, "sample": ["2001:db8::1"],
            "default_v6_iface": "en0", "interfaces": {"en0": ["2001:db8::1"]},
        }
        item = deep.check_ipv6()
        check("Wi-Fi 默认 v6 出口 → medium", item["severity"] == "medium", item["severity"])
        check("Wi-Fi 项指向 IPv6 出口入口", "IPv6 出口" in item["advice"], item["advice"])

        compat.ipv6_exposure = lambda: {
            "has_default_v6_route": True, "sample": ["2001:db8::2"],
            "default_v6_iface": "en7", "interfaces": {"en7": ["2001:db8::2"]},
        }
        item = deep.check_ipv6()
        check("非 Wi-Fi 接口 → info", item["severity"] == "info", item["severity"])
        check("非 Wi-Fi 项只说手动处理", "手动处理" in item["advice"], item["advice"])

        compat.ipv6_exposure = lambda: {
            "has_default_v6_route": False, "sample": [], "default_v6_iface": "",
            "interfaces": {},
        }
        check("没有 v6 出口 → pass", deep.check_ipv6()["severity"] == "pass")
    finally:
        compat.IS_MAC, compat.ipv6_exposure, compat.wifi_device = real

    # 国家预期：没设置就完全不出这一项
    check("未设置预期国家 → 不判", scanner._country_expectation("JP", "") is None)
    check("国家一致 → pass", scanner._country_expectation("US", "us")["severity"] == "pass")
    check("国家不一致 → high", scanner._country_expectation("JP", "US")["severity"] == "high")
    check("探不到国家 → info", scanner._country_expectation("", "US")["severity"] == "info")
    check("国家项 ID 是 net.country",
          scanner._country_expectation("JP", "US")["id"] == "net.country")
    try:
        netcfg.set_country("USA")
        check("非法国家代码被拒", False, "USA 被接受")
    except ValueError:
        check("非法国家代码被拒", True)
    check("国家状态文件 0600", "0o600" in (ROOT / "core/netcfg.py").read_text(encoding="utf-8"))

    # Shadowrocket 是 Network Extension，不监听 TCP；只能靠 scutil 的连接状态
    compat_src = (ROOT / "core/compat.py").read_text(encoding="utf-8")
    check("VPN 判活走 scutil --nc list", "scutil" in compat_src and "--nc" in compat_src)
    check("已知代理客户端里有 Shadowrocket", "shadowrocket" in compat_src.lower())
    check("不把公司 VPN 当代理链路", "不把公司 VPN" in compat_src)
    check("系统代理认 SOCKS", '"SOCKSEnable"' in compat_src)
    app_src = (ROOT / "app.py").read_text(encoding="utf-8")
    check("/api/netcfg 已注册", '"/api/netcfg"' in app_src)
    html_src = (ROOT / "web/index.html").read_text(encoding="utf-8")
    check("页面有国家预期卡片", 'id="netcfg-card"' in html_src)


def check_browser_side() -> None:
    """浏览器侧实测：ICE 判定与安全 DNS 判定的接线。

    这两项的共同点是「测不到就必须说测不到」。回退成 pass 会让面板在最该
    怀疑的时候显示绿色，回退成 fail 会让人去改一个本来就对的设置。
    """
    print("\n[浏览器侧实测]")
    bw = (ROOT / "core/browserwebrtc.py").read_text(encoding="utf-8")
    dh = (ROOT / "core/doh.py").read_text(encoding="utf-8")
    sc = (ROOT / "core/scanner.py").read_text(encoding="utf-8")
    tw = (ROOT / "core/tower.py").read_text(encoding="utf-8")
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    js = (ROOT / "web/app.js").read_text(encoding="utf-8")
    tj = (ROOT / "web/tower.js").read_text(encoding="utf-8")

    from core import browserwebrtc as B
    from core import doh as D

    check("ICE 候选按位置取字段", 'parts[6] != "typ"' in bw)
    check("mDNS 主机名不当 IP 存", '.endswith(".local")' in bw)
    check("无基线不下结论", 'if not mask' in bw and '"unknown"' in bw)
    check("基线过期单独一档", '"stale"' in bw and "STALE_AFTER" in bw)
    check("落盘前打码", "_masked(" in bw and "netprobe._mask_ip" in bw)
    check("结果文件 0600", "0o600" in bw)
    check("读坏了不抛异常", "except (OSError, ValueError)" in bw)
    check("候选数量有上限", "MAX_CANDIDATES" in bw and "raw[:MAX_CANDIDATES]" in bw)

    # 判定逻辑本身：几档结论各跑一次，防止改动时静默改变语义
    s = {"host": [], "srflx": ["93.184.216.34"], "relay": [], "mdns": 0, "private": []}
    check("与基线一致 → pass", B.assess(s, "93.184.*.34", 60)["state"] == "pass")
    check("与基线不符 → leak", B.assess(s, "45.33.*.34", 60)["state"] == "leak")
    check("不符但基线过期 → stale",
          B.assess(s, "45.33.*.34", B.STALE_AFTER + 1)["state"] == "stale")
    check("没基线 → unknown", B.assess(s, "", 60)["state"] == "unknown")
    check("只有 mDNS → pass",
          B.assess({"host": [], "srflx": [], "relay": [], "mdns": 2, "private": []},
                   "93.184.*.34", 60)["state"] == "pass")
    check("什么都没测到 → 不算 pass",
          B.assess({"host": [], "srflx": [], "relay": [], "mdns": 0, "private": []},
                   "93.184.*.34", 60)["state"] == "empty")

    check("DoH 查询手搓报文", "def _wire(" in dh and "0x0100" in dh)

    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    eps = D.DOH_ENDPOINTS
    ip_only = all(_is_ip(urlsplit(u).hostname or "") for _, u in eps)
    check("DoH 端点全部按 IP 写", ip_only and len(eps) >= 3,
          ", ".join(u for _, u in eps))
    check("读不到 ≠ 关闭", '"denied"' in dh and "不按通过算" in dh)
    check("开着但不通 → fallback", '"fallback"' in dh)
    check("离线时不报通道可用", "没有验证端点可达性" in dh)
    check("Chrome 读 Local State", 'base / "Local State"' in dh)
    check("配置档 Preferences 不是来源", '"Preferences"' not in dh)
    check("automatic 不折成 off", 'in ("automatic", "race")' in dh)
    check("读失败记为 denied", 'return "", "", "denied"' in dh)
    check("未设置不按关闭算", "KNOWN_MODES" in dh and '"unset"' in dh)
    check("automatic 判 auto",
          D.assess([{"browser": "Chrome", "mode": "automatic"}], [])["state"] == "auto")
    check("unset 判 unknown",
          D.assess([{"browser": "Chrome", "mode": "unset"}], [])["state"] == "unknown")
    check("Firefox 读 network.trr.mode", "network.trr.mode" in dh)

    v6 = {"host": [], "srflx": ["2408:8207:8990:5c10::1"],
          "relay": [], "mdns": 0, "private": []}
    check("IPv6 候选不拿 IPv4 基线定罪",
          B.assess(v6, "93.184.*.34", 60)["state"] == "unknown")

    check("两项都在 scanner 产出", '"net.webrtc_browser"' in sc and '"net.doh"' in sc)
    check("两项都被 2-8 消费", '"net.webrtc_browser"' in tw and '"net.doh"' in tw)
    check("出口基线只有一个来源", "shield.read()" in app.split("def _egress_baseline", 1)[-1][:400])
    check("探针接口要过闸门", '"/api/probe/webrtc"' in app and "browserwebrtc.save(" in app)
    check("探针走 ICE 不走摄像头", "RTCPeerConnection" in js and "getUserMedia(" not in js)
    check("收集有超时兜底", "setTimeout(finish" in js)
    check("实测后重扫", "Tower.reload(true)" in js)
    check("魔镜有实测按钮", "data-probe=" in js)
    check("关卡有实测按钮", "data-act-probe" in tj and 'data-settle-action="probe"' in tj)


def check_uninstaller() -> None:
    """卸载器的三条硬约束：不 rm、不删家目录、自己最后走。"""
    print("\n[卸载器]")
    un = (ROOT / "core/uninstall.py").read_text(encoding="utf-8")
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    js = (ROOT / "web/app.js").read_text(encoding="utf-8")
    html = (ROOT / "web/index.html").read_text(encoding="utf-8")

    from core import uninstall as U

    check("清单顺序固定", U._ORDER[:3] == ["proxyfix", "privacy", "ipv6"])
    check("自己排最后", U._ORDER[-1] == "tower_app")
    check("先停进程再删文件",
          U._ORDER.index("stop") < U._ORDER.index("state")
          and U._ORDER.index("stop") < U._ORDER.index("launchagent"))
    check("先撤改动再删记录",
          U._ORDER.index("proxyfix") < U._ORDER.index("state")
          and U._ORDER.index("privacy") < U._ORDER.index("state"))
    check("一律走废纸篓", "compat.send_to_trash" in un and "shutil.rmtree" not in un)
    check("执行时不重扫磁盘", "_TITLES" in un and "plan()[\"items\"]" not in un.split("def execute", 1)[-1])
    check("结束进程不误伤自己", "p != os.getpid()" in un)
    check("杀进程前核对可执行文件", "proc_pidpath" in un and "_is_shield" in un
          and "_is_watchdog" in un)
    check("身份判据同时用于清单和 kill", un.count("_is_watchdog") >= 3)
    check("文案不再声称不动 ~/.claude", "不会动你的 Claude Code 本身" not in un)
    check("看门狗先于哨兵",
          un.index('_stop([WATCHDOG_NAME], _is_watchdog)')
          < un.index('_stop(["Claude Shield.app'))
    check("LaunchAgent 先 bootout 再移走", "bootout" in un)
    check("确认串是打字确认", U.CONFIRM_WORD == "UNINSTALL" and "UNINSTALL" in un)

    check("GET /api/uninstall 已注册", 'path == "/api/uninstall"' in app)
    block = app.split('path == "/api/uninstall"', 1)[-1].split('path == "/api/clean"', 1)[0]
    check("执行后清缓存", "STATE[\"scan\"] = None" in block)
    check("删了应用包才退出", 'if result.get("quit")' in app)
    check("页面有卸载卡片", 'id="uninstall-card"' in html)
    check("确认前按钮禁用", "uninstall-go" in html and "disabled" in html.split('id="uninstall-go"')[1][:40])
    check("清单渲染带复选框", "data-un=" in js and "uninstallPlan" in js)
    check("切换隐私页时读取清单", "loadUninstall()" in js.split("function switchTab", 1)[-1][:600])

    # 这条是给未来的自己看的：曾经因为只在「执行类」测试里打桩，
    # 另一个类的 execute() 拿着真实路径跑了一次，把开发机的 ~/.ccclean
    # 整个移进了废纸篓。隔离必须在模块级。
    tst = (ROOT / "tools/test_uninstall.py").read_text(encoding="utf-8")
    check("卸载器测试在模块级隔离路径", "def setUpModule" in tst)
    check("隔离覆盖状态目录与废纸篓",
          "U.STATE_DIR = base" in tst and "U.compat.send_to_trash = fake_trash" in tst)
    check("有「隔离仍然生效」的断言", "test_module_isolation_is_active" in tst)


def check_kernelcheck() -> None:
    """内核核对：只问本机回环、只问用户正在跑的那个客户端。"""
    print("\n[内核核对]")
    kc = (ROOT / "core/kernelcheck.py").read_text(encoding="utf-8")
    from core import kernelcheck as K

    check("只接受回环控制接口", K._tcp_endpoint("10.0.0.1:9090") is None)
    check("通配绑定改写为回环",
          K._tcp_endpoint("0.0.0.0:9090") == ("http", "127.0.0.1", 9090))
    check("带凭据的接口被拒", K._tcp_endpoint("http://u:p@127.0.0.1:9090") is None)
    check("Verge 目录才补服务 socket",
          "_is_verge" in kc and "verge=_is_verge(d)" in kc)
    check("非 Verge 目录不加 Verge 路径",
          K._is_verge(Path("com.follow.clash")) is False
          and K._is_verge(Path("/x/clash-verge-rev")) is True)

    st = {"configs": {"mode": "rule"},
          "rules": {"rules": [
              {"type": "Match", "payload": "", "proxy": "DIRECT"},
              {"type": "DomainSuffix", "payload": "claude.ai", "proxy": "Ai+"}]},
          "proxies": {"proxies": {
              "Ai+": {"type": "Selector", "now": "n", "all": ["n"]},
              "n": {"type": "Shadowsocks", "udp": True}}}}
    out = K.assess(st, [("DOMAIN-SUFFIX", "claude.ai")], "Ai+")
    check("MATCH 之后的规则算没写", out["state"] == "mismatch", out.get("reason", ""))


def main() -> int:
    print("Claude Tower · 冒烟检查")
    check_maps()
    check_levels()
    check_drift()
    check_backup_prune()
    check_mask()
    check_dnsbl_logic()
    check_tun_loop()
    check_version()
    check_api_guard()
    check_user_consent()
    check_shield_baseline()
    check_new_findings()
    check_transport_logic()
    check_browser_side()
    check_kernelcheck()
    check_uninstaller()
    check_deploy_target()
    check_bundled_python()
    check_dom_refs()

    print()
    if FAILED:
        print(f"✗ {len(FAILED)} 项失败，{PASSED} 项通过")
        for f in FAILED:
            print(f"  - {f}")
        return 1
    print(f"✓ 全部通过（{PASSED} 项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
