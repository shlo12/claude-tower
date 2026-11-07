#!/usr/bin/env python3
"""CC Tower 冒烟检查：不联网、不改任何文件，几秒跑完。

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

    # 后代选择器同样会炸，而且更难发现：`$('#brand .brand-sub')` 在元素被删掉
    # 之后是 null，对 null 赋 textContent 会抛错，把整个初始化函数停在那一步。
    # 表现是「页面能打开，但所有按钮都没反应」——看起来像 JS 没加载。
    # 类名可能来自静态 HTML，也可能是脚本里拼出来的模板，两边都算存在。
    haystack = html
    for name in ("app.js", "tower.js", "guard.js"):
        haystack += (ROOT / "web" / name).read_text(encoding="utf-8")
    dead = []
    for name in ("app.js", "tower.js", "guard.js"):
        src = (ROOT / "web" / name).read_text(encoding="utf-8")
        for cls in re.findall(r"\$\('#[\w-]+ \.([\w-]+)'\)", src):
            if not re.search(r'class="[^"]*\b' + re.escape(cls) + r'\b', haystack):
                dead.append(f"{name}: .{cls}")
    check("后代选择器指向的类名还在", not dead, ", ".join(dead))


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
    bin_path = ROOT / "CC Tower.app" / "Contents" / "MacOS" / "CCclean"
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
    app = ROOT / "CC Tower.app"
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
        if method == "do_POST" and "self._post()" in body:
            check("POST 维修锁在 finally 中释放", "finally:" in body and "os.close(self._maintenance_fd)" in body)
            body = body_of("_post")
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
          and 'data["enabled"] =' not in wb and 'data["hits"] =' not in wb)
    check("探测不到出口时保留旧值", "if country and data.get" in shield_py)
    check("探测不到出口 IP 时保留旧值", "if egress and data.get" in shield_py)
    # 出口 IP 是给 Shield 比对 STUN 用的，落盘的必须是打码后的那个字段
    check("写的是打码 IP 不是完整 IP", 'net.get("ip")' in wb and 'net.get("ip_raw")' not in wb)
    check("基线原子写", "os.replace(" in shield_py)
    check("状态文件 0600", "0o600" in shield_py)
    check("读坏了不抛异常", "except (OSError, ValueError)" in shield_py)

    # 测到的出口和基线对不上时，两端都不许直接改基线：先记成待确认，
    # 等用户点「是我换的」。悄悄跟着新值走的话，真泄漏会被洗成正常。
    store = (ROOT / "shield/Store.swift").read_text(encoding="utf-8")
    shield_app = (ROOT / "shield/ShieldApp.swift").read_text(encoding="utf-8")
    check("塔不静默覆盖待确认出口", 'data["egressSeen"] = egress' in wb)
    check("哨兵不静默覆盖待确认出口", "cfg.egressSeen = mask" in store)
    check("只有用户确认才换基线", 'case "confirm-egress"' in shield_app
          and "cfg.egressIP = cfg.egressSeen" in store)

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
    # nameserver-policy 只服务国内域名，必须和代理域名的名单分开算
    check("国内域名策略单独解析",
          "def parse_policy(" in pdns_py and '"domesticPolicy"' in pdns_py
          and 'domesticPolicy' in dp and 'pd.get("domesticPolicy")' in tw)
    check("节点域名不参与判定", 'domesticNode' in pdns_py and 'rep["domesticNode"]' in dp)
    check("只认运行中的客户端", "ps\", \"-axo\", \"comm=\"" in pdns_py)
    check("helper/service 不算客户端", "_HELPER_HINTS" in pdns_py)
    check("国内解析器名单只一份", "CN_DNS = (" not in tw and "proxydns.CN_DNS_IPS" in tw)
    # 两家解析器一起挂，内核并行查询、谁先回用谁，探针上的「DNS 出口」就会
    # 在城市甚至国家之间跳。这不是泄漏，但必须能被指出来。
    check("解析器按服务商归组",
          "def provider(" in pdns_py and '"mixedProviders"' in pdns_py
          and 'providers' in dp)
    # 能查出来还得能改：FlClash 的 nameserver 在 plist 的 flutter.config 里，
    # 必须走 defaults（cfprefsd 缓存），且必须先退出客户端（否则退出时刷回旧值）。
    pfix_py = (ROOT / "core/proxyfix.py").read_text(encoding="utf-8")
    dns_apply = pfix_py[pfix_py.index("def _apply_dns("):]
    dns_apply = dns_apply[:dns_apply.index("\ndef ")]
    check("DNS 统一可写入也可撤销",
          "def _apply_dns(" in pfix_py and "def _undo_dns(" in pfix_py)
    check("DNS 设置走 defaults 而非改 plist", '"/usr/bin/defaults"' in pfix_py)
    check("写 DNS 前先退出客户端",
          dns_apply.index("_quit()") < dns_apply.index("_write_settings(cfg)"))
    check("DNS 写完回读校验", "回读不一致" in dns_apply)
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

    # 多源情报交叉验证：单源探针只会给出「一家之说」，而这个地址的归属
    # 本来就可能是有争议的。比对必须是纯函数（能单测），判据必须接进出口检查。
    np_py = (ROOT / "core/netprobe.py").read_text(encoding="utf-8")
    check("多源比对是纯函数", "def consensus(" in np_py and "def _fetch_all(" in np_py)
    check("多源并行而非依次降级", "threading.Thread" in np_py)
    check("多源结果有缓存", "CACHE_TTL" in np_py and "def probe_all(" in np_py)
    # ipapi.is 免费层是扁平结构，只读嵌套会让国家/城市/时区全变成 None
    check("ipapi.is 两种返回形状都认", "loc = data" in np_py)
    check("国名归一成 ISO 码", "def _country_code(" in np_py)
    check("ASN 写法归一", "def _asn_key(" in np_py)
    check("交叉验证接进出口检查", "def _check_ip_consensus(" in sc
          and '"net.ip_consensus"' in sc and '"net.ip_consensus"' in tw)
    # 只有一家时不下结论：说「一致」是编的，说「不一致」也是
    check("单源不下结论", 'count < 2' in sc.split(
        "def _check_ip_consensus", 1)[-1].split("\ndef ", 1)[0])

    # 免管理员的时区/语言对齐：写 shell 启动文件的标记块，必须可撤销，
    # 且块外已有的 TZ/LANG 不能被覆盖（两块配置谁生效不该由工具决定）
    se_py = (ROOT / "core/shellenv.py").read_text(encoding="utf-8")
    check("终端环境可写可撤", "def apply(" in se_py and "def undo(" in se_py)
    check("终端环境只写标记块", "BLOCK0" in se_py and "def strip_block(" in se_py)
    check("块外已有变量就拒绝", "foreign_lines" in se_py and "foreign" in se_py)
    check("终端环境写后回读", "回读不一致" in se_py)
    check("终端环境不猜时区", "_TZ_BY_COUNTRY" in se_py and "推不出" in se_py)
    # 目标国家要跟着实际出口走，不能只看「预期国家」那个配置：这一层修的
    # 就是「时区和出口对不上」，写一个跟出口无关的值等于把不一致换个理由
    # 目标国家：预期国家优先于实际出口。出口是「此刻」，预期是「长期」——
    # 代理关掉的那几分钟里按出口写，会把用户想摆脱的状态原样写回去
    check("终端环境目标不跟着瞬时出口跑",
          '(wanted, "expected") if wanted else (' in se_py
          and '_egress_country(), "egress")' in se_py)
    # 平台闸门要写在入口。靠 shellproxy.rc_path() 返回空来挡是巧合：
    # 换个平台上恰好有 zsh 它就认得了，会去写一个本工具不支持的 rc
    check("终端环境有平台闸门", "_require_mac()" in se_py
          and se_py.count("_require_mac()") >= 3
          and "compat.IS_MAC" in se_py)

    # 扫描要跳过本工具自己写的标记块：不然 shellenv 刚写进去的 export TZ
    # 会被当成用户残留，再给一条「注释掉」的建议，等于拆自己刚搭的东西
    check("扫描跳过自己写的标记块",
          "_managed_spans" in sc and "_MANAGED_RE" in sc
          and "a <= idx < b" in sc)

    # 改完系统设置要重算分数：不重扫，界面会一直显示修之前的结论，
    # 用户会以为没修上，然后去修一个已经修好的问题
    app_js = (ROOT / "web/app.js").read_text(encoding="utf-8")
    check("改完设置会重算分数", "function rescanAfterFix(" in app_js
          and app_js.count("rescanAfterFix();") >= 6)
    check("生成启动器不算改设置",
          "if (action !== 'wrapper') rescanAfterFix();" in app_js)

    # 操作日志是旁路：写失败不能把修复带崩
    hist_py = (ROOT / "core/history.py").read_text(encoding="utf-8")
    check("操作日志是旁路", "except Exception" in hist_py and "return False" in hist_py)
    check("操作日志 0600", "0o600" in hist_py)
    check("操作日志追加式", '"a", encoding="utf-8"' in hist_py and "def _rotate(" in hist_py)
    check("写入动作都挂日志", all(
        f'history.log("{a}"' in (ROOT / "core" / f).read_text(encoding="utf-8")
        for a, f in (("align.apply", "align.py"), ("region.apply", "regioncfg.py"),
                     ("privacy.apply", "privacy.py"),
                     ("shellenv.apply", "shellenv.py"))))


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

    check("清单顺序固定",
          U._ORDER[:6] == ["proxyfix", "proxydns", "sessionapi", "shellproxy", "shellenv", "privacy"])
    # 写进 shell 启动文件的那几行必须能撤，否则卸载后终端时区还被它管着
    check("终端环境变量在卸载清单里",
          "shellenv" in U._ORDER and 'item_id == "shellenv"' in (
              ROOT / "core/uninstall.py").read_text(encoding="utf-8"))
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
          < un.index('_stop(["CC Shield.app'))
    check("LaunchAgent 先 bootout 再移走", "bootout" in un)
    check("确认串是打字确认", U.CONFIRM_WORD == "UNINSTALL" and "UNINSTALL" in un)

    check("GET /api/uninstall 已注册", 'path == "/api/uninstall"' in app)
    block = app.split('path == "/api/uninstall"', 1)[-1].split('path == "/api/clean"', 1)[0]
    check("执行后清缓存", "STATE[\"scan\"] = None" in block)
    check("删了应用包才退出", 'if result.get("quit")' in app)
    check("页面有卸载卡片", 'id="uninstall-card"' in html)
    check("确认前按钮禁用", "uninstall-go" in html and "disabled" in html.split('id="uninstall-go"')[1][:40])
    check("清单渲染带复选框", "data-un=" in js and "uninstallPlan" in js)
    check("设置页读取卸载清单", "if (name === 'settings') { refreshUpdate(); loadUninstall();" in js)

    # 这条是给未来的自己看的：曾经因为只在「执行类」测试里打桩，
    # 另一个类的 execute() 拿着真实路径跑了一次，把开发机的 ~/.ccclean
    # 整个移进了废纸篓。隔离必须在模块级。
    tst = (ROOT / "tools/test_uninstall.py").read_text(encoding="utf-8")
    check("卸载器测试在模块级隔离路径", "def setUpModule" in tst)
    check("隔离覆盖状态目录与废纸篓",
          "U.STATE_DIR = base" in tst and "U.compat.send_to_trash = fake_trash" in tst)
    check("有「隔离仍然生效」的断言", "test_module_isolation_is_active" in tst)


def check_proxy_guard() -> None:
    """失败回落、客户端 v6、终端出口与解析器国家比对。

    这四项都在回答「规则看起来对，实际请求从哪出去」：解析器国家与出口
    国家不一致、终端没继承代理、节点全挂时退到 DIRECT。判据必须可单测，
    且只在拿到证据时才下结论。
    """
    print("\n[回落 / 终端出口 / 国家比对]")
    from core import deep, proxyguard

    pg = (ROOT / "core" / "proxyguard.py").read_text(encoding="utf-8")
    te = (ROOT / "core" / "terminalegress.py").read_text(encoding="utf-8")
    dp = (ROOT / "core" / "deep.py").read_text(encoding="utf-8")
    tw = (ROOT / "core" / "tower.py").read_text(encoding="utf-8")

    check("回落策略模块只读", not any(
        bad in pg for bad in ("write_text(", "open(", "unlink(", "os.replace(")))
    check("回落判定可单测", "def inspect_text(" in pg and "def _walk(" in pg)
    check("回落项有产出并被关卡消费",
          '"net.proxy_fallback"' in dp and '"net.proxy_fallback"' in tw)
    check("终端出口项有产出并被关卡消费",
          '"net.terminal_egress"' in dp and '"net.terminal_egress"' in tw)
    body = dp.split("def check_deep", 1)[-1].split("\ndef ", 1)[0]
    check("一次扫描只读一遍客户端配置", body.count("proxyguard.inspect()") == 1)
    check("终端探测命令是常量",
          "def _argv(" in te and "TRACE_URL" in te and "MARKER" in te)
    check("终端探测值不回传", "proxyEnv" in te and "proxy_env" in te)
    check("终端不拿 v4 基线给 v6 定罪",
          "same_family" in te and 'r.get("match") is None' in dp)
    check("Shield 区分解析器与出口国家",
          "p.dnsResolverCountry !== p.country" in
          (ROOT / "shield" / "web" / "shield.js").read_text(encoding="utf-8"))

    # 逐条跑判据：同一条规则，落到 DIRECT 与落到代理组必须是两个结论。
    def guard(text: str) -> dict:
        return proxyguard.inspect_text(text, "FlClash")

    fallback = """
proxy-groups:
  - name: Fallback
    type: fallback
    proxies:
      - HK
      - DIRECT
rules:
  - MATCH,Fallback
"""
    check("自动回落组含 DIRECT 报中危",
          deep.check_proxy_fallback(guard(fallback))["severity"] == "medium")
    check("最终规则落到 DIRECT 报高危",
          deep.check_proxy_fallback(guard(fallback.replace(
              "MATCH,Fallback", "MATCH,DIRECT")))["severity"] == "high")
    check("select 成员顺序不冒充实际选择",
          deep.check_proxy_fallback(guard("""
proxy-groups:
  - name: Pick
    type: select
    proxies:
      - DIRECT
      - HK
rules:
  - MATCH,Pick
"""))["severity"] != "high")
    check("自动组没有 DIRECT 判通过",
          deep.check_proxy_fallback(guard("""
proxy-groups:
  - name: Pick
    type: url-test
    proxies:
      - HK
      - JP
rules:
  - MATCH,Pick
"""))["severity"] == "pass")
    check("读不到配置不下结论",
          deep.check_proxy_fallback({"checked": False, "note": "x"})["severity"] == "info")
    # 出口漂移和回落是两件事：回落全绿、规则全命中，出口照样可能被自动组换掉。
    drift = """
proxy-groups:
  - name: Auto
    type: url-test
    proxies:
      - HK
      - US
rules:
  - DOMAIN-SUFFIX,claude.ai,Auto
  - MATCH,Auto
"""
    check("Claude 落到自动测速组报中危",
          deep.check_proxy_drift(guard(drift))["severity"] == "medium")
    check("Claude 落到 select 组不会被自动换节点",
          deep.check_proxy_drift(guard(drift.replace(
              "type: url-test", "type: select")))["severity"] == "pass")
    check("自动换节点项有产出", '"net.proxy_drift"' in dp)
    check("出口未确认不发终端请求",
          deep.check_terminal_egress({"available": False})["severity"] == "info")

    # 终端环境：登录 shell 里 Claude 会继承到的时区/语言。
    # 这是「免管理员对齐」唯一的验收方式——塔读自己的进程 env、哨兵读
    # /etc/localtime，两边都绕开了终端，不测就没人知道它到底生没生效。
    te_py = (ROOT / "core" / "terminalegress.py").read_text(encoding="utf-8")
    check("登录 shell 一并读时区语言",
          "_LOCALE_KEYS" in te_py and "def parse_env(" in te_py
          and "@\\\\1=" in te_py)
    check("环境变量只取白名单", "if sep and key in _LOCALE_KEYS" in te_py)
    check("终端环境项有产出并被关卡消费",
          '"locale.shell_env"' in dp and '"locale.shell_env"' in tw)
    check("登录 shell 一次扫描只跑一次",
          "term = _terminal_probe(net_info)" in dp
          and "fn(net_info, term)" in dp
          and dp.count("_terminal_probe(") == 4)

    # 哨兵的实时结论：塔只在自己被按下时看世界，两次之间靠这一份接上
    sc = (ROOT / "core" / "scanner.py").read_text(encoding="utf-8")
    tw = (ROOT / "core" / "tower.py").read_text(encoding="utf-8")
    sh_py = (ROOT / "core" / "shield.py").read_text(encoding="utf-8")
    sw_store = (ROOT / "shield" / "Store.swift").read_text(encoding="utf-8")
    sw_app = (ROOT / "shield" / "ShieldApp.swift").read_text(encoding="utf-8")
    check("哨兵把实时结论写进共享文件",
          "var live: Live?" in sw_store and "func publishLive(" in sw_app)
    check("实时结论打码后才落盘",
          "stunExposed: snap.stunExposed.map(maskAddress)" in sw_app)
    check("塔读得到哨兵的实时结论", "def live() -> dict:" in sh_py and "LIVE_TTL" in sh_py)
    check("过期的实时结论不当现状", '"fresh": age <= LIVE_TTL' in sh_py)
    check("实时结论字段做类型清洗", "def _strs(" in sh_py and "def _int(" in sh_py)
    check("实时结论接入扫描", '"shield.live"' in sc and "_check_shield_live" in sc)
    check("实时结论并进代理关", '"shield.live"' in tw)
    # 泄漏取并集：哨兵十秒看一次，比单次快照更容易撞上分裂
    check("WebRTC 合并哨兵证据", "shield.live() if live is None else live" in sc
          and "s_exposed" in sc)

    from core import proxydns  # noqa: F401  仅确认模块可导入
    rep = {
        "system": ["1.1.1.1"], "systemDomestic": [],
        "clients": [{"name": "X", "mode": "fake-ip", "config": "",
                     "destination": ["1.1.1.1"], "bootstrap": [], "node": [],
                     "policy": []}],
        "domesticDestination": [], "domesticNode": [], "domesticPolicy": [],
        "note": "",
    }
    resolver = {"checked": True, "masked": "1.1.1.1", "country": "US",
                "org": "Cloudflare, Inc."}
    diff = deep.check_proxy_dns(state={"tunneled": True}, report=rep,
                                resolver=resolver,
                                egress={"available": True, "country": "JP"})
    same = deep.check_proxy_dns(state={"tunneled": True}, report=rep,
                                resolver=resolver,
                                egress={"available": True, "country": "US"})
    check("解析器与出口不同国记低危",
          diff["severity"] == "low" and diff["dns"]["countryMismatch"])
    check("解析器与出口同国不新增结论", same["severity"] == "pass")
    noeg = deep.check_proxy_dns(state={"tunneled": True}, report=rep,
                                resolver=resolver, egress={})
    check("没有出口国家不做比对", noeg["dns"]["countryMismatch"] is False)

    # 境外 DoH 不挂 `#PROXY` 时查询从本机 IP 发出，探针看不到这一层。
    relay = dict(rep, unrelayed=["https://1.1.1.1/dns-query"])
    bare = deep.check_proxy_dns(state={"tunneled": True}, report=relay,
                                resolver=resolver, egress={})
    check("境外 DoH 没挂代理后缀记低危",
          bare["severity"] == "low" and "没走代理" in bare["title"])
    check("挂了后缀就不再报",
          deep.check_proxy_dns(state={"tunneled": True}, report=dict(rep, unrelayed=[]),
                               resolver=resolver, egress={})["severity"] == "pass")


def check_third_party_gaps() -> None:
    """浏览器指纹、定位服务、终端代理变量。

    这三项都是「外部探针会看，而我们原来测不到」的东西。共同要求：
    判据可单测、读不到就不下结论、要写的地方只写自己那一块。
    """
    print("\n[浏览器指纹 / 定位服务 / 终端代理]")
    from core import browserwebrtc, location, scanner, shellproxy

    bw_src = (ROOT / "core" / "browserwebrtc.py").read_text(encoding="utf-8")
    lo_src = (ROOT / "core" / "location.py").read_text(encoding="utf-8")
    sp_src = (ROOT / "core" / "shellproxy.py").read_text(encoding="utf-8")
    sc_src = (ROOT / "core" / "scanner.py").read_text(encoding="utf-8")
    tw_src = (ROOT / "core" / "tower.py").read_text(encoding="utf-8")
    js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    app_src = (ROOT / "app.py").read_text(encoding="utf-8")

    # 浏览器指纹：值必须来自浏览器自己，不能拿系统设置替它回答
    check("浏览器指纹只判纯函数", "def assess_fingerprint(" in bw_src)
    check("页面回传语言列表", "navigator.languages" in js)
    check("页面回传时区与区域格式",
          "intlOptions().timeZone" in js and "intlOptions().locale" in js)
    check("扫描项消费浏览器指纹", '"locale.browser"' in sc_src)
    check("关卡消费浏览器指纹", '"locale.browser"' in tw_src)
    zh = browserwebrtc.assess_fingerprint(
        {"languages": ["zh-CN"], "locale": "zh-CN", "timeZone": "Asia/Shanghai"},
        egress_country="US", system_langs=["en-US"], system_tz="Asia/Shanghai")
    check("中文首选语言判为 zh-first", zh["state"] == "zh-first")
    ok = browserwebrtc.assess_fingerprint(
        {"languages": ["en-US"], "locale": "en-US", "timeZone": "Asia/Shanghai"},
        egress_country="US", system_langs=["en-US"], system_tz="Asia/Shanghai")
    check("一致时判为 ok", ok["state"] == "ok")
    empty = browserwebrtc.assess_fingerprint({}, egress_country="US")
    check("没实测过就说没实测", empty["state"] == "no-data")

    # UA：国产浏览器 / 国产设备。语言和时区都能改，UA 只能换浏览器。
    from core import uatraits
    ua_src = (ROOT / "core" / "uatraits.py").read_text(encoding="utf-8")
    check("UA 模块只读", not any(
        bad in ua_src for bad in ("write_text(", "open(", "unlink(", "os.replace(")))
    check("UA 命中微信",
          uatraits.classify_browser(
              "Mozilla/5.0 (iPhone) AppleWebKit/605.1.15 MicroMessenger/8.0.47")
          == "微信 / 企业微信")
    check("普通 Chrome 不误伤",
          uatraits.classify_browser(
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "Chrome/131.0 Safari/537.36") == "")
    check("正则不用 /mi/ 这种过宽写法",
          uatraits.classify_browser(
              "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/131 Safari/537.36 "
              "Vivaldi/6.5") == "")
    check("鸿蒙权重最高",
          uatraits.classify_device("Mozilla/5.0 (Linux; Android 12; HarmonyOS)")[1] == 1.0)
    check("扫描项消费 UA", '"fp.cn_browser"' in sc_src)
    check("关卡消费 UA", '"fp.cn_browser"' in tw_src)
    check("页面回传 UA", "ua: navigator.userAgent" in js)

    # 时区分三档：直接触发 / 受限地区 / 支持地区。混成一档会让人去改真资料。
    from core import rules as rules_mod
    check("中国台湾单列一档",
          "Asia/Taipei" not in rules_mod.GREATER_CHINA_TZ
          and "Asia/Taipei" in rules_mod.SUPPORTED_TZ)

    # 定位服务：只读、要授权、缓存会过期
    check("定位服务不写系统设置",
          "defaults write" not in lo_src and '"write"' not in lo_src)
    check("定位服务走管理员授权", "with administrator privileges" in lo_src)
    check("定位缓存是 0600", "os.fchmod(fd, 0o600)" in lo_src)
    check("定位缓存会过期", "STALE = " in lo_src and "stale" in lo_src)
    check("扫描项消费定位服务", '"dev.location"' in sc_src)
    check("关卡消费定位服务", '"dev.location"' in tw_src)
    check("定位项挂探测按钮", 'probe="location"' in sc_src)
    check("页面按类型分发探测", "probeBtn.dataset.probe === 'location'" in js)
    check("开=1/关=0 解析正确",
          location._parse("1") is True and location._parse("0") is False)
    check("读不出来不当成关着", location._parse("UNKNOWN") is None)

    # 终端代理变量：只写一个块，撤销一字不差
    check("代理块有起止标记",
          "BLOCK0 = " in sp_src and "BLOCK1 = " in sp_src)
    check("写之前备份原文件", "def _backup(" in sp_src)
    check("有别人的代理变量就不写", "foreign_env" in sp_src)
    sample = "# 原有\nexport PATH=x\n"
    check("块能原样摘掉",
          shellproxy.strip_block(sample + shellproxy._block(7890)) == sample)
    check("端口越界被拒", all(
        _raises(ValueError, shellproxy._port, bad) for bad in (0, 70000, "abc")))
    check("扫描项指向写入入口", "终端代理变量" in
          (ROOT / "core" / "deep.py").read_text(encoding="utf-8"))
    check("卡片有端口输入与两个按钮",
          all(k in html for k in ('id="shellproxy-port"', 'id="shellproxy-apply"',
                                  'id="shellproxy-undo"')))
    check("卡片在切换标签时刷新", "refreshShellproxy()" in js)
    check("接口发令牌", '"/api/shellproxy"' in app_src and '"/api/location"' in app_src)


def _raises(exc, fn, *args) -> bool:
    try:
        fn(*args)
    except exc:
        return True
    except Exception:
        return False
    return False


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


def check_tower_wiring() -> None:
    """关卡与扫描结果之间那条线。这里坏掉不会报错，只会「什么都通过」。"""
    from core import uatraits

    # 1. 工具引擎的端口区间：Python 挑一个、Swift 认一个，两边必须一样。
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    m = re.search(r"def _free_port\(start: int = (\d+)\).*?range\(start, start \+ (\d+)\)",
                  app, re.S)
    check("找得到 _free_port 的端口区间", bool(m))
    swift = (ROOT / "shield/ShieldApp.swift").read_text(encoding="utf-8")
    m2 = re.search(r"\((\d+)\.\.\.(\d+)\)\.contains\(port\)", swift)
    check("找得到哨兵的端口白名单", bool(m2))
    if m and m2:
        lo, count = int(m.group(1)), int(m.group(2))
        check("工具引擎端口区间与哨兵一致",
              (lo, lo + count - 1) == (int(m2.group(1)), int(m2.group(2))),
              f"python {lo}..{lo + count - 1} vs swift {m2.group(1)}..{m2.group(2)}")

    # 2. 带后缀的条目要能按前缀取到。这一条坏掉，high 级的凭据泄露会显示成
    #    「未发现凭据残留」——不报错，只是永远绿。
    idx = {
        "cred.shell_keys.zshrc": {"id": "cred.shell_keys.zshrc", "severity": "high",
                                  "fix": {"kind": "shellrc"}},
        "cred.settings.settings_json": {"id": "cred.settings.settings_json",
                                        "severity": "critical", "fix": {"kind": "json_keys"}},
    }
    got = tower._worst(idx, ["cred.shell_keys.*", "cred.settings.*"])
    check("塔能按前缀取到带后缀的条目", bool(got) and got["id"] == "cred.settings.settings_json")
    check("一键修复用的是真实条目 id",
          tower._fixable_ids(idx, ["cred.shell_keys.*"]) == ["cred.shell_keys.zshrc"])
    check("前缀匹配只认整段前缀",
          tower._matches({"a.b": {}}, "a.*") == [{}] and tower._matches({"ab": {}}, "a.*") == [])

    # 3. 每个带后缀的家族都必须被某一关读到。这条是通用形式：
    #    产出 `B.<后缀>` 的家族，关卡里必须出现 `B.*`、`B.xxx` 或 startswith("B")。
    families: set[str] = set()
    for name in ("core/scanner.py", "core/deep.py"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for prefix in re.findall(r'_item\(\s*f"([^"{]+)\{', text):
            families.add(prefix.rstrip("."))
    tw = (ROOT / "core/tower.py").read_text(encoding="utf-8")
    refs = set(re.findall(r'"([a-z][a-z0-9_]*\.[a-z0-9_.*]*)"', tw))
    prefixes = set(re.findall(r'startswith\(\s*"([a-z][a-z0-9_.]*)"', tw))

    def covered(base: str) -> bool:
        return (any(r == base or r == base + ".*" or r.startswith(base + ".") for r in refs)
                or any(base == p or base.startswith(p + ".") for p in prefixes))

    # err.* 是检查本身崩了的提示项，按设计不进关卡。
    orphans = sorted(b for b in families if not b.startswith("err") and not covered(b))
    check("带后缀的条目都有关卡消费", not orphans, "、".join(orphans))
    # 反过来：关卡里裸写家族名永远匹配不上，正是 cred.shell_keys 出过的错。
    # 例外是 `startswith("net.proxy_env")` 这种显式按前缀筛的写法，那是对的。
    bare = sorted(b for b in families if b in refs and b not in prefixes)
    check("关卡没有裸写家族名", not bare, "、".join(bare))

    # 4. 自动换节点的组要进代理关——它扫得出来但没人看，等于白扫。
    check("自动换节点的组进代理关", "net.proxy_drift" in tower._PROXY_EXTRAS)

    # 5. 引擎端口文件只给自己读，且是原子替换（哨兵每 0.25 秒读一次）。
    fn = re.search(r"def _write_runtime.*?(?=\ndef |\nclass |\Z)", app, re.S)
    body = fn.group(0) if fn else ""
    check("runtime.json 只给自己读", "0o600" in body and "0o700" in body)
    check("runtime.json 原子替换", "os.replace" in body)

    # 6. 接口被外部改回时要能收场，不能永久卡在「可恢复」。
    sa = (ROOT / "core/sessionapi.py").read_text(encoding="utf-8")
    check("接口被改回时清记录而不是报错", sa.count("_DISCARDED") >= 2)

    # 7. 过期不等于违规：过期只结束会话，违规才走到杀进程。
    probe = (ROOT / "shield/Probe.swift").read_text(encoding="utf-8")
    check("过期与违规分开判", "static func staleIssue" in probe and "static func contentIssue" in probe)
    running = re.search(r"static func runningIssue.*?\n    \}", probe, re.S)
    body = running.group(0) if running else ""
    check("值守中不再把过期当违规",
          "contentIssue(s)" in body and "admissionIssue(s)" not in body)
    shield = (ROOT / "shield/ShieldApp.swift").read_text(encoding="utf-8")
    check("过期只结束会话不杀进程", "StrictSessionPolicy.staleIssue(snap)" in shield)

    # 8. 国产机型码：OPPO 三代写法都要认，且不能把华硕 VivoBook 当手机。
    check("OPPO 旧机型码识别", uatraits.classify_device("Android 12; PDEM10")[0] == "OPPO")
    check("OPPO 新机型码识别", uatraits.classify_device("Android 13; PFZM10")[0] == "OPPO")
    check("OPPO 三位数字机型码识别", uatraits.classify_device("Android 14; PHK110")[0] == "OPPO")
    check("笔记本不当国产手机",
          uatraits.classify_device("Windows NT 10.0; Win64; x64) ASUS VivoBook")[0] == "")
    check("三星机型码不误判",
          uatraits.classify_device("Android 13; SM-G991B")[0] == "")


def check_tower_chrome() -> None:
    """塔的外壳：一层导航、没有重复标题、和哨兵共用一条结论。

    「太臃肿」不是感觉，是版面被三样东西吃掉：logo 一行、主导航一行、二级
    导航一行（208px），每页开头再写一遍「大标题 + 副标题」（90px），而这一屏
    真正要看的塔只剩不到 800px。这里盯住那三样别再长回来。
    """
    print("\n[塔的外壳]")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")

    topbar = html.split("<header class=\"topbar\">", 1)[1].split("</header>", 1)[0]
    check("主导航在顶栏里", "primary-tabs" in topbar)
    check("内容区不再有第二条主导航", 'class="tabs primary-tabs"' not in html.split("</header>", 1)[1])
    check("顶栏里有哨兵结论灯", 'id="top-verdict"' in topbar)
    guard = (ROOT / "web" / "guard.js").read_text(encoding="utf-8")
    check("结论灯由守护状态驱动", "top-verdict" in guard and "renderVerdict" in guard)

    # 二级页签降级成「贴着内容的下划线」，不再是一条和主导航长得一样的横栏。
    block = css.split(".sub-tabs {", 1)[1].split("}", 1)[0]
    check("二级页签不再是独立横栏", "background: none" in block and "border-bottom" in block)

    # 合并后「结算 / 详情」共用一个面板，页首大标题一并清掉。
    # 注释里可以提到 panel-head（那是在解释为什么删掉它），只看真实标签。
    bare = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    for pid in ("panel-results", "panel-checklist"):
        seg = bare.split(f'id="{pid}"', 1)[1].split("</section>", 1)[0]
        check(f"{pid} 没有重复大标题", "panel-head" not in seg)

    # 主界面是一扇独立窗口，它没有「返回上一层」：那个按钮是「面板长大」
    # 方案留下的，只有面板被拉宽时才需要退回去。
    check("顶栏不再有返回按钮", 'id="btn-back"' not in html)
    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("页面不再靠面板通道判断自己嵌在哪", "in-panel" not in app)


def check_panel_shell() -> None:
    """哨兵的外壳：一个自己控制的 borderless 面板，不是 NSPopover。

    popover 只能有一种尺寸和一种关闭策略，圆角、阴影、Esc 全交给系统，
    连「点别处收起」都要靠 `.transient` 那条固定行为。换成自己的 NSPanel
    之后这些都归自己管，代价是每一条都得自己写对。这里盯住那几条，
    免得哪天又悄悄退回 popover。
    """
    swift = (ROOT / "shield/ShieldApp.swift").read_text(encoding="utf-8")
    # 注释里可以提到 popover（那是在解释为什么不用它），代码里不行。
    body = re.sub(r"^\s*///.*$|^\s*//.*$", "", swift, flags=re.M)
    check("面板不是 NSPopover", "NSPopover" not in body)
    check("有独立的 ShieldPanel 类", "final class ShieldPanel: NSPanel" in swift)
    check("面板能成为 key（否则键盘全丢）",
          re.search(r"override var canBecomeKey: Bool \{ true \}", swift) is not None)
    check("面板无边框且透明底", ".borderless" in swift and "isOpaque = false" in swift)
    check("面板有圆角容器", "cornerRadius" in swift and "masksToBounds = true" in swift)
    # 非激活面板从不把应用激活，所以「一 makeKey 就失焦」——按失焦收起会变成
    # 点一下闪一下就没了。必须用全局鼠标监听判断「点到了别处」。
    check("用全局鼠标监听判断点外面", "addGlobalMonitorForEvents" in swift)
    check("不用失焦收起（非激活面板会闪退）", "windowDidResignKey" not in body)
    check("监听器收起时摘掉", "removeOutsideClickMonitor" in swift)
    check("点图标关面板不会被重新打开", "panelAutoClosedAt" in swift)

    # 宽度只有一个来源。散落的 340 会在改成宽态那天变成一堆对不上的数。
    strays = re.findall(r"\b340\b", body)
    check("窄态宽度只有一处定义", len(strays) <= 1, f"出现 {len(strays)} 次")
    # 高度同理。772 以前在三个地方各写一遍，改一处另外两处就悄悄错开。
    strays = re.findall(r"\b772\b", body)
    check("窄态高度只有一处定义", len(strays) <= 1, f"出现 {len(strays)} 次")

    # 落点算法是纯函数，必须有独立文件并进构建列表，否则测不到。
    check("落点算法独立成文件", (ROOT / "shield/PanelGeometry.swift").exists())
    build = (ROOT / "tools/build-shield.sh").read_text(encoding="utf-8")
    check("落点文件进了构建列表", "PanelGeometry.swift" in build)

    # 1440×900 的笔记本上 Dock 一大，可用高度只剩 750 上下，772 点放不下。
    # 光靠 origin 只能把面板贴到底边，底栏照样掉在屏幕外，所以必须先收尺寸。
    geom = (ROOT / "shield/PanelGeometry.swift").read_text(encoding="utf-8")
    check("面板尺寸会先收进屏幕", "func fitting(" in geom)
    check("定位前先收尺寸", "PanelGeometry.fitting(" in body)


def check_main_window() -> None:
    """主界面必须是**一扇独立的窗口**，不是被拉宽的菜单栏面板。

    用户的原话是「你这不还是展开一个大面板吗」。面板是菜单栏的附属物：
    无标题栏、失焦即收、不能缩放。把它拉宽到 760 之后这些性质一条没变，
    所以手感还是「一个很长的下拉菜单」，而不是「一个程序的主界面」。

    这里盯住三条：
    - 主界面走 NSWindow（有标题栏、能缩放、能最小化），不走 ShieldPanel；
    - 同一个程序里只有一个主窗口，重复打开是换页不是再开一扇；
    - 关掉窗口哨兵还在（不 terminate、不退出应用）。
    """
    swift = (ROOT / "shield/ShieldApp.swift").read_text(encoding="utf-8")
    body = re.sub(r"^\s*///.*$|^\s*//.*$", "", swift, flags=re.M)

    m = re.search(r"func openMainWindow\(", body)
    if not check("有主窗口入口", m is not None):
        return
    # 只取 openMainWindow 本体：到下一个方法为止。
    seg = body[m.start():].split("\n    func ", 1)[0]
    check("主界面是独立窗口", "NSWindow(" in seg)
    check("主界面不是拉宽的面板", "ShieldPanel(" not in seg and "resizePanel(" not in seg)
    check("窗口有标题栏和关闭按钮", ".titled" in seg and ".closable" in seg)
    check("窗口能缩放、能最小化", ".resizable" in seg and ".miniaturizable" in seg)
    check("重复打开是换页不是再开一扇", "if let win = mainWindow" in seg)
    check("主界面不打开别的应用", "openApplication" not in seg and "openTower(" not in seg)

    # 面板只有一种尺寸。以前这里有一个 resizePanel，宽态靠它把同一个面板
    # 拉到 760——那条路正是「大面板」的来源，必须彻底断掉。
    check("面板不再能被改成别的尺寸", "func resizePanel(" not in body)

    # 关窗不等于退出：哨兵要留在菜单栏。窗口自己收引用，引擎跟着收。
    willclose = body.split("func windowWillClose(", 1)
    check("关窗只清引用不退出应用",
          len(willclose) == 2 and "terminate" not in willclose[1].split("\n    func ", 1)[0])
    check("关掉最后一扇窗不退出",
          re.search(r"applicationShouldTerminateAfterLastWindowClosed[^{]*\{\s*false",
                    body) is not None)

    # 两扇窗各有自己的 webView：共用一份会在关掉一扇时让另一扇白屏。
    check("主窗口有独立的 webView", "var mainWebView: WKWebView?" in swift)

    # 只剩一套状态：老的「工具窗口」和「面板长大」两套状态都得清干净，
    # 否则两套状态会打架（一个说宽、一个说窄，窗口尺寸就会来回跳）。
    for dead in ("showingTools", "toolHost", "ownsToolHost", "toolTimer",
                 "toolOrigin", "toolTicks", "showTools", "pollTools",
                 "toolsUnavailable", "closeTools", "wideMode", "wideView"):
        check(f"旧窗口状态已删除：{dead}", dead not in body)

    # 尺寸由外壳决定，不由页面决定。页面能改窗口尺寸，等于把「谁说了算」
    # 交回给内容——那正是「什么都往哨兵里塞」的起点。
    check("页面不能改窗口尺寸", 'case "tool-size"' not in body)
    # 页面那一侧也不能再上报尺寸：外壳不再听，上报就只是每帧一次无用 IPC。
    panel_js = (ROOT / "web/panel.js").read_text(encoding="utf-8")
    check("维护页不再上报尺寸", "tool-size" not in panel_js)

    # 入口接线：点「打开主界面」开窗；页面里的「返回」回体检页，不关窗
    # （窗口自己有标题栏和关闭按钮）。
    check("打开主界面开主窗口",
          re.search(r'case "opentower":\s*\n\s*openMainWindow\(', body) is not None)
    check("页面返回回体检页",
          re.search(r'case "back-panel":\s*\n\s*if source == \.main', body) is not None)

    # 真窗口就得有真窗口的快捷键：没有主菜单，⌘W / ⌘Q 一律无效，
    # 用户第一次想关窗就会发现按了没反应。
    check("有主菜单（⌘W 才有用）", "NSApp.mainMenu" in body)

    # 超时按时间算。以前数 tick（100 × 0.25 秒），定时器被 RunLoop 拖慢就数不准。
    check("引擎超时按截止时刻算", "engineDeadline" in body)
    check("引擎状态是显式枚举", "enum EngineState" in swift)


def check_panel_scroll() -> None:
    """面板变矮时，顶栏和底栏必须还在，滚的只能是中间。

    场景是 1440×900 的笔记本 + 大 Dock：可用高度只剩七百出头，772 点放不下，
    `PanelGeometry.fitting` 会把面板收矮。如果这时整页跟着滚，底栏（瞭望/戒严、
    退出）就被推到屏幕外——用户看着面板却点不到最要紧的两个按钮。
    纯结构断言，真正的高度关系由 `test_panel_geometry.py` 算。
    """
    html = (ROOT / "shield/web/shield.html").read_text(encoding="utf-8")
    css = (ROOT / "shield/web/shield.css").read_text(encoding="utf-8")

    check("中间内容有独立滚动区", '<div class="scroll">' in html)
    head = html.split("<header>", 1)[0]
    check("顶栏在滚动区之外", '<div class="scroll">' not in head)
    body_after = html.split("</header>", 1)[1]
    check("滚动区从头栏之后开始", body_after.index('<div class="scroll">')
          < body_after.index("<footer>"), "滚动区必须包住 footer 之前的内容")
    # footer 必须落在滚动区闭合之后：先找 /.scroll 标记，再看 footer 的位置。
    if "<!-- /.scroll -->" in html:
        tail = html.split("<!-- /.scroll -->", 1)[1]
        check("底栏在滚动区之外", "<footer>" in tail)
    else:
        check("滚动区有闭合标记", False, "缺 <!-- /.scroll --> 注释")

    block = css.split(".scroll {", 1)[1].split("}", 1)[0] if ".scroll {" in css else ""
    check("滚动区可纵向滚动", "overflow-y: auto" in block)
    check("滚动区能压缩（min-height: 0）", "min-height: 0" in block,
          "不写这条，flex 子项会被内容撑开，滚不动")
    wrap = css.split(".wrap {", 1)[1].split("}", 1)[0]
    check("外壳固定一屏高", "height: 100vh" in wrap)
    # height:auto + min-height:100vh 会把底栏推下去，正是要防的那种写法。
    check("外壳没有被改成随内容长高", "height: auto" not in wrap)


def main() -> int:
    print("CC Tower · 冒烟检查")
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
    check_proxy_guard()
    check_third_party_gaps()
    check_browser_side()
    check_kernelcheck()
    check_uninstaller()
    check_tower_wiring()
    check_panel_shell()
    check_main_window()
    check_tower_chrome()
    check_panel_scroll()
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
