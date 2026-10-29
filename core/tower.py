"""魔塔 · 关卡模型、战斗结算与闯关进度。

设计要点
--------
- 塔分 5 层：城门（系统地基）→ 档案室（本地指纹）→ 边境（网络出口）
  → 封印室（行为与隔离）→ 塔顶（Claude 本体）。
- 每层有若干小关，每关守着一只怪物；小关全部击杀后，层守卫才会现身。
- **出招 = 对那一项做一次真实检测**，检测通过才算击杀，打不死就会掉血。
- 怪物强度只由风险等级和层数决定；打不过时的反击很重，按防御递减但保底 24 点。
  初始 160 血，每杀一只 +8 血上限并回复 18 点，打空的容错更高。
- 每层只掉一件装备，清空本层小怪时解锁，守卫不再额外掉装备。
- 血量归零后必须回城休整，不能继续出招；回城回满血，阵亡次数记在战绩里。
- 关卡状态完全由当前检测结果推导。环境变脏时怪物会复活，修好后再打一次。

这个文件比较长，按下面的顺序排（搜分隔线注释可跳转）：

    关卡定义      FLOORS —— 五层、每层的小关、怪物、探针绑定
    探针工具      _worst / _from_items / _act 等，把 scan 结果翻译成关卡结论
    各关探针      _probe_*，一关一个函数，彼此独立
    深层检测关    _*_probe，从 deep.py 的结果里取数
    进度存储      tower.json 的读写
    挑战历史      tour-history.json、战报导出
    存活时长      从安装时间推断账号存活多久
    结算          build / fight / sweep / boss / final
    自动演示      preview，给前端跑一遍无副作用的演示

探针之间不共享状态，唯一的耦合是「工具」那一组构造函数。
拆文件的话，最自然的一刀在「各关探针」之前，但那样工具函数要跟着搬家，
收益不大——所以暂时保持单文件，靠上面的目录导航。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
import urllib.request
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from . import cleaner, compat, ipcheck, isolation, proxydns

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
TOWER_FILE = STATE_DIR / "tower.json"
TOUR_FILE = STATE_DIR / "tour-history.json"
TOUR_KEEP = 80

SEV_RANK = {"pass": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

MONSTER_HP = 100
EXP_KILL = 30
EXP_HURT = 8
EXP_BOSS = 100
EXP_FINAL = 300
EXP_STEP = 60
MAX_LEVEL = 12

# ---- 三属性模型（魔塔式）------------------------------------------------
# 初始属性、每击杀一只小关的成长、击杀回复
BASE_STAT = {"hp": 160, "atk": 10, "def": 2}
PER_KILL = {"hp": 8, "atk": 2, "def": 2}
HEAL_KILL = 18
HEAL_BOSS = 60

# 怪物强度：只有中危及以上才会真的打人（低危在判定上算通过）
STRENGTH = {"pass": 0, "info": 0, "low": 0, "medium": 85, "high": 125, "critical": 170}
# 每上一层，怪物强度 +20%
FLOOR_SCALE = 0.2
# 打不过时的反击：足够让勇者见底或倒下，而不是掉一层血皮
DAMAGE_SCALE = 1.25
MIN_DAMAGE = 24

# 一层一件装备：清空本层小关时解锁
FLOOR_GEAR = {
    "f1": ("锈蚀短剑", "atk", 8),
    "f2": ("墨影斗篷", "def", 8),
    "f3": ("边境护符", "hp", 40),
    "f4": ("缄默法杖", "atk", 14),
}

STAT_LABEL = {"atk": "攻击", "def": "防御", "hp": "生命"}

TITLES = [
    (2, "见习勇者"),
    (4, "塔中行者"),
    (6, "老练猎人"),
    (8, "魔塔宿将"),
    (10, "屠龙者"),
    (12, "传说勇士"),
]

# ---------------------------------------------------------------- 关卡定义


def _lv(no, title, name, kind, tint, brief, how, probe):
    return {
        "id": no,
        "no": no,
        "title": title,
        "monster": {"name": name, "kind": kind, "tint": tint},
        "brief": brief,
        "how": how,
        "probe": probe,
    }


FLOORS = [
    {
        "id": "f1",
        "no": 1,
        "name": "城门",
        "subtitle": "系统地基",
        "tint": "#5b6fa8",
        "story": "塔的第一道门。守门人只看三件事：你在哪个时区、说什么语言、这台机器叫什么名字。",
        "boss": {"id": "b1", "name": "铁门卫", "kind": "warden", "tint": "#8fa3d9"},
        "levels": [],
    },
    {
        "id": "f2",
        "no": 2,
        "name": "档案室",
        "subtitle": "本地指纹",
        "tint": "#7b5aa8",
        "story": "塔里的书记官保存着每一个来访者的档案：身份标识、对话历史、旧钥匙、旧身份。",
        "boss": {"id": "b2", "name": "档案长 · 墨影", "kind": "shade", "tint": "#8a63c4"},
        "levels": [],
    },
    {
        "id": "f3",
        "no": 3,
        "name": "边境",
        "subtitle": "网络出口",
        "tint": "#a8763a",
        "story": "出塔的关口。税吏会核对你的来路：从哪个 IP 来、是不是机房、有没有夹带代理。",
        "boss": {"id": "b3", "name": "边境总督 · 灰烬", "kind": "colossus", "tint": "#c08a3e"},
        "levels": [],
    },
    {
        "id": "f4",
        "no": 4,
        "name": "封印室",
        "subtitle": "行为与隔离",
        "tint": "#3a8c7a",
        "story": "塔里最安静的一层。封印不靠设备，靠你怎么用——频率、作息、隔离、收尾。",
        "boss": {"id": "b4", "name": "封印祭司 · 缄默", "kind": "mage", "tint": "#3fa896"},
        "levels": [],
    },
    {
        "id": "f5",
        "no": 5,
        "name": "塔顶",
        "subtitle": "BOSS",
        "tint": "#b4453f",
        "story": "塔顶只有一位。它不问你从哪来，只看你这一路留下的痕迹够不够少。",
        "boss": {"id": "b5", "name": "Claude · 塔主", "kind": "claude", "tint": "#e8736a"},
        "levels": [],
    },
]


# ---------------------------------------------------------------- 探针工具


def _idx(scan):
    return {i.get("id"): i for i in (scan.get("items") or [])}


def _worst(idx, ids):
    best = None
    for i in ids:
        it = idx.get(i)
        if not it:
            continue
        if best is None or SEV_RANK.get(it.get("severity"), 0) > SEV_RANK.get(best.get("severity"), 0):
            best = it
    return best


def _blank(value="未发现相关问题", detail=""):
    return {"sev": "pass", "value": value, "detail": detail, "evidence": [], "advice": "", "fix": None, "fixIds": []}


def _fixable_ids(idx, ids):
    out = []
    for iid in ids:
        it = idx.get(iid) or {}
        fix = it.get("fix")
        if fix and fix.get("kind") != "manual" and iid not in out:
            out.append(iid)
    return out


def _from_items(idx, ids, empty_value="未发现相关问题", empty_detail=""):
    it = _worst(idx, ids)
    if not it:
        return _blank(empty_value, empty_detail)
    return {
        "sev": it.get("severity") or "info",
        "value": it.get("title") or "",
        "detail": it.get("detail") or "",
        "evidence": (it.get("evidence") or [])[:6],
        "advice": it.get("advice") or "",
        "fix": it.get("fix"),
        "fixIds": _fixable_ids(idx, ids),
    }


def _act(kind, label=None, **extra):
    """一键动作：结算页/战斗结算上的「去处理」按钮。

    kind: open(系统设置面板) / profile(一键建档) / tour(去挑战)
          / site(打开检测网站) / goto(跳页签) / openfile(打开文件)
          / probe(在浏览器里跑一次实测)
    """
    return {"kind": kind, "label": label, **extra}


CN_HOST_HINTS = (
    "huawei", "xiaomi", "redmi", "honor", "lenovo", "meizu", "zte",
    "oppo", "vivo", "realme", "oneplus", "nubia", "transsion", "tecno", "infinix",
)


def _probe_tz(scan, ctx):
    idx = _idx(scan)
    it = _worst(idx, ["locale.tz", "net.tz_mismatch", "locale.tz_env"])
    tz = (scan.get("system") or {}).get("timezone") or "未知"
    if not it:
        return _blank(f"系统时区 {tz}，没有命中任何判定名单")
    out = _from_items(idx, ["locale.tz", "net.tz_mismatch", "locale.tz_env"])
    if out["sev"] == "pass":
        out["value"] = f"系统时区 {tz}，没有命中判定名单"
    else:
        out["act"] = _act("open", label="打开「日期与时间」设置", pane="datetime")
    return out


def _probe_lang(scan, ctx):
    idx = _idx(scan)
    lang = (scan.get("system") or {}).get("locale") or "未知"
    out = _from_items(idx, ["locale.lang", "locale.client_lang"],
                      f"语言环境 {lang}，与出口区域无明显冲突")
    if out["sev"] != "pass":
        worst = _worst(idx, ["locale.lang", "locale.client_lang"]) or {}
        if worst.get("id") == "locale.client_lang":
            # 客户端语言在它自己的设置里，系统「语言与地区」改不到
            out["act"] = _act("goto", label="去魔镜看客户端语言", tab="findings")
        else:
            out["act"] = _act("open", label="打开「语言与地区」设置", pane="region")
    return out


def _probe_host(scan, ctx):
    host = (scan.get("system") or {}).get("hostname") or ""
    low = host.lower()
    hit = next((h for h in CN_HOST_HINTS if h in low), None)
    cjk = bool(re.search(r"[\u4e00-\u9fff]", host))
    ev = [{"label": "主机名", "value": host or "（空）", "mono": True}]
    if hit or cjk:
        reason = f"含品牌词 {hit}" if hit else "含中文字符"
        return {
            "sev": "medium",
            "value": f"主机名带有明显地域特征（{reason}）",
            "detail": "主机名会随 mDNS / DHCP 广播，部分站点也能通过本地网络读到。它不影响 Claude 的接口判定，但会让整台机器的画像更「像国内设备」。",
            "evidence": ev,
            "advice": "把主机名改成中性英文，例如 mbp-01 或 studio-a。系统设置 → 通用 → 共享 → 本地主机名。",
            "fix": None,
            "act": _act("open", label="打开「共享」设置", pane="sharing"),
        }
    return {
        "sev": "pass",
        "value": f"主机名 {host or '（空）'}，没有明显地域特征",
        "detail": "主机名没有品牌词或中文，属于中性命名。",
        "evidence": ev,
        "advice": "",
        "fix": None,
    }


_clock_cache = {"at": 0.0, "data": None}


def _clock_skew():
    now = time.time()
    if _clock_cache["data"] and now - _clock_cache["at"] < 300:
        return _clock_cache["data"]
    skew = None
    try:
        req = urllib.request.Request(
            "https://ipwho.is/",
            headers={"User-Agent": "CCclean/1.2", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            date = resp.headers.get("Date")
        if date:
            remote = parsedate_to_datetime(date).timestamp()
            skew = int(round(time.time() - remote))
    except Exception:
        skew = None
    data = {"skew": skew, "at": now}
    _clock_cache.update(at=now, data=data)
    return data


def _probe_clock(scan, ctx):
    info = _clock_skew()
    skew = info.get("skew")
    if skew is None:
        return {
            "sev": "info",
            "value": "读不到网络时间，本项跳过",
            "detail": "出口网络不可用或响应太慢，无法比对系统时钟。",
            "evidence": [],
            "advice": "网络恢复后重打一次即可。",
            "fix": None,
        }
    a = abs(skew)
    ev = [{"label": "与网络时间偏差", "value": f"{skew:+d} 秒", "mono": True}]
    if a <= 60:
        return {"sev": "pass", "value": f"与网络时间相差 {skew:+d} 秒", "detail": "系统时钟是准的。", "evidence": ev, "advice": "", "fix": None}
    if a <= 300:
        return {
            "sev": "low",
            "value": f"与网络时间相差 {skew:+d} 秒",
            "detail": "偏差在 5 分钟以内，一般不触发判定，但请求签名与日志时间会对不上。",
            "evidence": ev,
            "advice": "打开「系统设置 → 通用 → 日期与时间」，勾选自动设置时间。",
            "fix": None,
            "act": _act("open", label="打开「日期与时间」设置", pane="datetime"),
        }
    return {
        "sev": "medium",
        "value": f"与网络时间相差 {skew:+d} 秒",
        "detail": "时钟偏差超过 5 分钟。除了日志时间错乱，部分接口会直接拒绝请求。",
        "evidence": ev,
        "advice": "打开「系统设置 → 通用 → 日期与时间」，勾选自动设置时间，必要时换一个时间服务器。",
        "fix": None,
    }


def _f2_act(out):
    """档案室层的兜底动作：能自动清的走 fixIds，不能的一键去魔镜看明细。"""
    if out.get("sev") != "pass" and not out.get("fixIds"):
        out["act"] = _act("goto", label="去魔镜看明细", tab="findings")
    return out


def _probe_identity(scan, ctx):
    idx = _idx(scan)
    return _f2_act(
        _from_items(
            idx,
            ["fp.identity_fields", "fp.claude_json", "fp.email_domain",
             "fp.fonts", "fp.gpu", "fp.vm"],
            "身份标识字段已清空",
        )
    )


def _probe_session(scan, ctx):
    idx = _idx(scan)
    ids = ["fp.projects_meta", "fp.telemetry", "fp.history_jsonl", "fp.session-env",
           "fp.file-history", "fp.sessions",
           "res.telemetry.telemetry", "res.telemetry.statsig", "res.telemetry.logs", "res.telemetry.cache"]
    return _f2_act(_from_items(idx, ids, "没有发现会话与遥测残留"))


def _probe_cred(scan, ctx):
    return _f2_act(_from_items(_idx(scan), ["cred.legacy_file", "cred.shell_keys"], "未发现凭据残留"))


def _probe_residue(scan, ctx):
    idx = _idx(scan)
    return _f2_act(_from_items(
        idx,
        ["res.desktop", "res.ide_ext", "res.install", "res.inspector",
         "res.versions", "res.stale", "cli.claude_code"],
        "没有旧客户端残留"))


def _probe_launch(scan, ctx):
    return _f2_act(_from_items(_idx(scan), ["res.launchagents", "res.shield"],
                               "没有开机自启的 Claude 相关项"))


def _probe_relay(scan, ctx):
    out = _from_items(_idx(scan), ["marker.base_url"], "未设置 ANTHROPIC_BASE_URL")
    if out["sev"] != "pass":
        out["act"] = _act("goto", label="去魔镜定位来源", tab="findings")
    return out


def _probe_ip(scan, ctx):
    ip = ctx.get("ip") or {}
    if not ip.get("available"):
        return {
            "sev": "info",
            "value": "出口纯净度接口不可用，本项跳过",
            "detail": ip.get("reason") or "无法连接 ip.net.coffee。",
            "evidence": [],
            "advice": "网络恢复后重打一次；也可以手动打开 ip.net.coffee/claude 看一眼。",
            "fix": None,
        }
    trust = ip.get("trustScore")
    flags = [k for k in ("vpn", "proxy", "tor", "abuser") if ip.get(k)]
    ev = [
        {"label": "出口 IP", "value": ip.get("ipMasked") or ip.get("ip") or "未知", "mono": True},
        {"label": "信任评分", "value": f"{trust} / 100" if isinstance(trust, (int, float)) else "未知", "mono": True},
        {"label": "归属", "value": f"{ip.get('country') or '?'} / {ip.get('city') or '?'}"},
        {"label": "ASN", "value": f"{ip.get('asn') or '?'} {ip.get('companyName') or ''}".strip(), "mono": True},
    ]
    if flags:
        names = {"vpn": "VPN", "proxy": "代理", "tor": "Tor", "abuser": "滥用记录"}
        return {
            "sev": "high",
            "value": "命中风险标记：" + "、".join(names[f] for f in flags),
            "detail": "出口被打上风险标记后，新账号会直接继承这份风险分。",
            "evidence": ev,
            "advice": "换一个干净的住宅出口，别在这个 IP 上继续操作。",
            "fix": None,
            "act": _act("site", label="打开检测网站"),
        }
    if isinstance(trust, (int, float)) and trust < 70:
        return {
            "sev": "medium",
            "value": f"信任评分偏低（{trust} / 100）",
            "detail": "评分低于 70 说明这个出口在共享池里被用得比较多。",
            "evidence": ev,
            "advice": "优先换住宅出口；换不了就把并发降下来，别在同一时间跑批量任务。",
            "fix": None,
            "act": _act("site", label="打开检测网站"),
        }
    return {
        "sev": "pass",
        "value": f"信任评分 {trust} / 100，没有命中风险标记" if isinstance(trust, (int, float)) else "没有命中风险标记",
        "detail": "出口在 IP 侧是干净的。",
        "evidence": ev,
        "advice": "",
        "fix": None,
    }


def _probe_egress(scan, ctx):
    out = _from_items(_idx(scan), ["net.egress", "net.country"], "出口不是机房类型")
    if out["sev"] != "pass":
        out["act"] = _act("open", label="打开「网络」设置", pane="network")
    return out


def _probe_egress_drift(scan, ctx):
    """出口 IP 漂移：短时间里跨国家 / 跨 ASN 换出口，是「异地瞬移」的直接证据。"""
    d = ipcheck.drift()
    hours = d.get("windowHours") or 24

    if not d.get("enough"):
        return {
            "sev": "pass",
            "value": f"出口记录 {d.get('count', 0)} 条，还看不出漂移",
            "detail": "第一次记录只是起点。工具每次检测都会记下出口 IP，攒够两条以上才能比对有没有跳变。"
            "这一项要跑上几天才有意义。",
            "evidence": [{"label": "记录条数", "value": str(d.get("count", 0)), "mono": True}],
            "advice": "",
            "fix": None,
        }

    countries = d.get("countries") or []
    asns = d.get("asns") or []
    ev = [
        {"label": "窗口", "value": f"最近 {hours} 小时 · {d.get('count')} 条记录", "mono": True},
        {"label": "国家", "value": " → ".join(countries) if countries else "未知", "mono": True},
        {"label": "ASN", "value": f"{len(asns)} 个" + (f"（{', '.join(asns[:3])}）" if asns else ""), "mono": True},
        {"label": "跨度", "value": f"{d.get('spanHours')} 小时", "mono": True},
    ]
    for r in (d.get("recent") or [])[-3:]:
        ev.append({
            "label": r.get("at") or "",
            "value": f"{r.get('ip') or '?'} · {r.get('country') or '?'} {r.get('city') or ''}".strip(),
            "mono": True,
        })

    if len(countries) >= 3:
        sev, value = "high", f"{hours} 小时里从 {len(countries)} 个国家出去过"
        detail = ("同一个账号在一天内跨三个以上国家登录，在风控里几乎等同于「多人共用」或「代理池轮换」。"
                  "这时候单次 IP 的信任评分已经没有意义了——跳变本身就是最强的信号。")
        advice = "先停下来。选定一个出口固定住，至少稳定几天再动；这段时间别再换节点、别开自动选路。"
    elif len(countries) == 2:
        sev, value = "medium", f"{hours} 小时里在两个国家之间跳了 {d.get('switches')} 次"
        detail = ("两地切换比跨国三地轻，但仍然是可观测的漂移。"
                  "机场的「自动选择延迟最低节点」是主要元凶——它会在你不知情的时候把出口换掉。")
        advice = "把节点固定成手动选择，关掉自动选路与负载均衡；确实要换地区，隔一天再登录。"
    elif len(asns) >= 3:
        sev, value = "medium", f"同一国家内换了 {len(asns)} 个 ASN"
        detail = ("国家没变，但出口在多个 ASN 之间轮换。这通常是共享代理池的特征："
                  "你看起来还在同一个国家，服务端看到的是几批不同的人。")
        advice = "换一个独享的静态住宅出口，别用共享池里的自动分配节点。"
    elif len(asns) == 2:
        sev, value = "low", "出口在同一个国家内换过一次 ASN"
        detail = "同城换机房属于常见情况，权重不高，但仍是可观测的变化。"
        advice = "能固定就固定；固定不了也不用紧张，这一项权重很低。"
    else:
        sev, value = "pass", f"{hours} 小时内出口稳定在 {countries[0] if countries else '同一地区'}"
        detail = "出口没有跳变。稳定的出口比「评分很高的出口」更值钱。"
        advice = ""

    return {
        "sev": sev,
        "value": value,
        "detail": detail,
        "evidence": ev,
        "advice": advice,
        "fix": None,
    }


def _probe_proxy(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["net.proxy", "net.reachable", "net.proxy_path", "net.dns_route"]
                      + sorted(i for i in idx if i.startswith("net.proxy_env")),
                      "没有检测到系统代理")

    pitem = idx.get("net.proxy_dns") or {}
    pd = pitem.get("dns") if isinstance(pitem.get("dns"), dict) else {}
    route = idx.get("net.dns_route") or {}
    hijacked = "已被代理接管" in (route.get("title") or "")
    system = [str(x) for x in (pd.get("system") or []) if x]
    sys_dom = [str(x) for x in (pd.get("systemDomestic") or []) if x]
    proxy_dom = [str(x) for x in (pd.get("domesticDestination") or []) if x]
    node_dom = [str(x) for x in (pd.get("domesticNode") or []) if x]
    proxy_live = SEV_RANK.get(pitem.get("severity"), 0) >= SEV_RANK["medium"]

    if not pd:
        # 深层检测没产出时退回旧路径：只看扫描到的系统 DNS 文本
        dns = idx.get("net.dns") or {}
        blob = (dns.get("title") or "") + " " + " ".join(
            str(e.get("value")) for e in (dns.get("evidence") or [])
        )
        sys_dom = [d for d in sorted(proxydns.CN_DNS_IPS) if d in blob]
        system = sys_dom
        hijacked = False

    sys_hit = bool(sys_dom) and not hijacked

    if not sys_hit and not proxy_live:
        if sys_dom and hijacked:
            out["value"] = ("DNS 已被代理接管（系统配置的 "
                            + "、".join(sys_dom[:2]) + " 不生效）")
            out["detail"] = ("系统 DNS 里有国内解析器，但 TUN 已经把 DNS 查询接管，"
                             "这些地址不参与实际解析。")
        elif proxy_dom:
            out["value"] = "代理内核 DNS 里有国内解析器，但当前没接管流量"
            out["detail"] = ("客户端配置里的 nameserver 含国内解析器，但它现在没有接管流量；"
                             "打开 TUN 或系统代理后才会生效。")
            if SEV_RANK.get(out.get("sev"), 0) < SEV_RANK["info"]:
                out["sev"] = "info"
        if out.get("sev") != "pass" and not out.get("act"):
            out["act"] = _act("open", label="打开「网络」设置", pane="network")
        return out

    system_names = "、".join(sys_dom[:2])
    proxy_names = "、".join(proxydns.label(v) for v in proxy_dom[:3])
    if sys_hit and proxy_live:
        value = f"系统 DNS 与代理 DNS 都在用国内解析器（{system_names} / {proxy_names}）"
        detail = ("TUN 接管后真正解析域名的是代理内核；系统配置和内核 nameserver 里的"
                  "国内解析器都能看到你访问的域名。")
    elif sys_hit:
        value = f"系统 DNS 走的是国内解析器（{system_names}）"
        detail = "系统 DNS 指向国内解析器，流量没被 TUN 接管时，域名会直接发给它。"
    else:
        value = f"代理内核 DNS 走的是国内解析器（{proxy_names}）"
        if hijacked:
            detail = ("TUN 接管时 macOS 的系统 DNS 设置不参与解析，"
                      "真正查域名的是客户端内核的 nameserver。")
        else:
            detail = ("系统代理模式里，应用把域名交给代理客户端，解析发生在客户端内核；"
                      "macOS 的 DNS 只影响不走代理的流量。")
        detail += "这一条比系统设置更隐蔽。"
        if system:
            detail += f"系统里设的是 {'、'.join(system[:2])}，挡不住这条路径。"
    if proxy_live and node_dom:
        detail += "「节点域名用」那一组只解析代理节点地址，不算泄漏，可以保留。"

    advice = []
    if sys_hit:
        advice.append("把系统 DNS 改成与出口地区一致的服务（1.1.1.1 / 8.8.8.8）")
    if proxy_live:
        advice.append("在客户端 DNS 设置里删掉 nameserver 里的国内解析器，只留境外 DoH/IP；"
                      "节点域名解析可以继续用国内")

    evidence = []
    if system:
        evidence.append({"label": "系统 DNS", "value": "、".join(system[:3]), "mono": True})
    if sys_hit:
        evidence.append({"label": "系统里命中的国内解析器", "value": "、".join(sys_dom[:3]),
                         "mono": True})
    if proxy_dom:
        evidence.append({"label": "代理解析域名用", "value": "、".join(proxy_dom[:4]),
                         "mono": True})
    if node_dom:
        evidence.append({"label": "代理节点域名用（不算泄漏）",
                         "value": "、".join(node_dom[:4]), "mono": True})
    if hijacked:
        evidence.append({"label": "DNS 链路", "value": "TUN 已接管", "mono": True})

    return {
        "sev": "medium",
        "value": value,
        "detail": detail,
        "evidence": evidence,
        "advice": "；".join(advice),
        "fix": None,
        "fixIds": [],
        "act": (_act("open", label="打开「网络」设置", pane="network") if sys_hit
                else _act("goto", label="去魔镜看 DNS 证据", tab="findings")),
    }


def _probe_hosts(scan, ctx):
    out = _from_items(_idx(scan), ["marker.hosts"], "hosts 与配置里没有黑名单痕迹")
    if out["sev"] != "pass":
        out["act"] = _act("openfile", label=f"打开 {compat.hosts_path().name} 文件", file=str(compat.hosts_path()))
    return out


def _account_emails() -> set:
    """主环境里出现过的账号邮箱数（粗略判断是不是多账号共用一台机器）。"""
    from . import scanner

    return scanner._account_emails()


def _main_env_dirty(scan) -> list:
    """主环境的指纹/凭据/残留面还有没有未清的东西。"""
    return [
        it for it in (scan.get("items") or [])
        if it.get("category") in ("fingerprint", "credential", "residue")
        and it.get("severity") in ("critical", "high", "medium")
    ]


def _probe_isolation(scan, ctx):
    profiles = ctx.get("profiles") or []
    if profiles:
        return {
            "sev": "pass",
            "value": f"已有 {len(profiles)} 个隔离配置档",
            "detail": "隔离档有独立的配置目录与启动脚本，切换时不会污染主环境。",
            "evidence": [{"label": "配置档", "value": ", ".join(p.get("slug") or p.get("name") or "?" for p in profiles[:6])}],
            "advice": "",
            "fix": None,
        }
    accounts = _account_emails()
    dirty = _main_env_dirty(scan)
    if len(accounts) <= 1 and not dirty:
        return {
            "sev": "pass",
            "value": "单账号且主环境干净，隔离档不是刚需",
            "detail": "分身档的核心价值是多账号指纹隔离；你只有一个账号、主环境又没残留的话，建它只是多一道可选防护。",
            "evidence": [{"label": "账号", "value": f"{len(accounts)} 个" if accounts else "未登录或本机未识别"}],
            "advice": "",
            "fix": None,
        }
    why = []
    if len(accounts) > 1:
        why.append(f"机器上出现过 {len(accounts)} 个账号")
    if dirty:
        why.append(f"主环境还有 {len(dirty)} 项指纹/残留未清")
    return {
        "sev": "medium",
        "value": "还没有隔离配置档",
        "detail": "；".join(why) + "。共用同一个 ~/.claude 目录时，userID / anonymousId 不会随账号切换而重置。",
        "evidence": (
            [{"label": "账号", "value": f"{len(accounts)} 个", "mono": True}]
            + [{"label": "未清项", "value": it.get("title", "")[:40]} for it in dirty[:3]]
        ),
        "advice": "到「分身术」建一个配置档，之后用它的 run.sh 启动，就不会碰到主环境。",
        "fix": None,
        "act": _act("profile", label="一键建隔离配置档"),
    }


def _probe_profile_script(scan, ctx):
    """隔离配置档建了不等于能跑——run.sh 缺失或没权限时等于没建。"""
    profiles = ctx.get("profiles") or []
    if not profiles:
        accounts = _account_emails()
        dirty = _main_env_dirty(scan)
        if len(accounts) <= 1 and not dirty:
            return {
                "sev": "pass",
                "value": "没有分身档也无妨（单账号+主环境干净）",
                "detail": "没有需要检查的启动脚本；要用分身档时，这一关才会真的查 run.sh。",
                "evidence": [],
                "advice": "",
                "fix": None,
            }
        return {
            "sev": "medium",
            "value": "还没有隔离配置档，无从检查启动脚本",
            "detail": "这一只和上一关同源：先去「分身术」建一个配置档。",
            "evidence": [],
            "advice": "到「分身术」页建一个配置档。",
            "fix": None,
            "act": _act("profile", label="一键建隔离配置档"),
        }
    bad = []
    for p in profiles:
        slug = p.get("slug") or p.get("name") or "?"
        script = (p.get("script") or "").replace("~", str(HOME))
        if not script or not Path(script).exists() or not os.access(script, os.X_OK):
            bad.append(slug)
    if bad:
        return {
            "sev": "medium",
            "value": f"{len(bad)} / {len(profiles)} 个配置档的启动脚本不可用",
            "detail": "run.sh 缺失或没有执行权限，隔离档启动不了等于没建。",
            "evidence": [{"label": "不可用", "value": ", ".join(bad)}],
            "advice": "重建这些配置档，或检查 ~/.ccclean/profiles/ 下 run.sh 的权限。",
            "fix": None,
            "act": _act("profile", label="一键重建配置档"),
        }
    return {
        "sev": "pass",
        "value": f"{len(profiles)} 个配置档的启动脚本都可执行",
        "detail": "每个隔离档的 run.sh 都在，随时可以直接启动。",
        "evidence": [{"label": "配置档", "value": ", ".join(p.get("slug") or p.get("name") or "?" for p in profiles[:6])}],
        "advice": "",
        "fix": None,
    }


def _docker_bin():
    for p in ("/opt/homebrew/bin/docker", "/usr/local/bin/docker", "/usr/bin/docker"):
        if Path(p).exists():
            return p
    return shutil.which("docker")


def _probe_docker(scan, ctx):
    """需要整机沙箱时得有 docker；没声明沙箱的配置档本项直接放行。"""
    profiles = ctx.get("profiles") or []
    want = [p.get("slug") or p.get("name") or "?" for p in profiles if p.get("docker")]
    docker = _docker_bin()
    if docker:
        return {
            "sev": "pass",
            "value": "docker 可用，沙箱配置档可以整机打包",
            "detail": "机器上找得到 docker，声明走沙箱的配置档能正常构建。",
            "evidence": [{"label": "docker", "value": docker, "mono": True}]
            + ([{"label": "沙箱配置档", "value": ", ".join(want)}] if want else []),
            "advice": "",
            "fix": None,
        }
    if want:
        return {
            "sev": "medium",
            "value": f"配置档声明走沙箱，但本机找不到 docker（{len(want)} 个）",
            "detail": "沙箱模式依赖 docker；没有它，这些配置档跑不起来。",
            "evidence": [{"label": "受影响", "value": ", ".join(want)}],
            "advice": "装 Docker Desktop 后重打；或在「分身术」把配置档改回本机 run.sh 模式。",
            "fix": None,
            "act": _act("goto", label="去分身术改配置档", tab="isolation"),
        }
    return {
        "sev": "info",
        "value": "没有找到 docker；当前也没有配置档声明走沙箱",
        "detail": "本机 run.sh 模式不需要 docker。以后要整机沙箱时再装也不迟。",
        "evidence": [],
        "advice": "需要整机沙箱时装 Docker Desktop。",
        "fix": None,
    }


def _probe_cleanse(scan, ctx):
    """净化火印：可净化残留不清完，这一关不放行。

    凡是工具能收的残留（fix 非 manual 的检测项）都算拦路，
    清完（环境里没有可净化项）才放行——净化火印记的是「没有残留」，
    结算卡片和战斗浮层都提供「直接清理」，走同一条预览 → CLEAN 确认 → 按保留策略清理。
    """
    pending = [i for i in (scan.get("items") or [])
               if (i.get("fix") or {}).get("kind") not in (None, "manual")]
    if pending:
        rank = max(SEV_RANK.get(i.get("severity"), 1) for i in pending)
        sev = ("critical" if rank >= SEV_RANK["critical"]
               else "high" if rank >= SEV_RANK["high"]
               else "medium")
        return {
            "sev": sev,
            "value": f"还有 {len(pending)} 项可净化残留没处理",
            "detail": "先预览路径与体积，输入 CLEAN 确认。缓存、诊断日志及凭据不留副本，不可还原；其他项目按清单处理。残留不清完，这一关不放行。",
            "evidence": [{"label": "待净化", "value": "、".join((i.get("title") or i.get("id") or "?") for i in pending[:5])}],
            "advice": "在这张卡上点「直接清理」，或到结算页处理；预览中会标出不留副本、不可还原的项目。",
            "fix": None,
            "fixIds": [i.get("id") for i in pending if i.get("id")],
        }
    backups = [b for b in cleaner.list_backups() if b.get("entries")]
    if backups:
        last = backups[0]
        return {
            "sev": "pass",
            "value": f"已清干净，留下过 {len(backups)} 次净化火印",
            "detail": "净化留下操作清单；敏感操作只记类型和结果，不保存原文。",
            "evidence": [
                {"label": "最近一次", "value": f"{last.get('id')}（{last.get('entries')} 项）"},
                {"label": "备份目录", "value": last.get("path") or "~/.ccclean/backups", "mono": True},
            ],
            "advice": "",
            "fix": None,
        }
    return {
        "sev": "pass",
        "value": "环境里没有可净化残留",
        "detail": "没有可净化的残留，这一关直接放行。",
        "evidence": [],
        "advice": "",
        "fix": None,
    }


def _probe_tour(scan, ctx):
    """挑战足迹：先完整推演一遍全塔，才谈得上「封印」。"""
    info = tour_info()
    if info["count"]:
        last = info.get("last") or {}
        return {
            "sev": "pass",
            "value": f"已完成 {info['count']} 次全塔挑战",
            "detail": "挑战是只读推演：走遍全部关卡看一遍结果，不改动真实进度。",
            "evidence": ([{"label": "最近一次", "value": last.get("at") or "-"}] if last else []),
            "advice": "",
            "fix": None,
        }
    return {
        "sev": "medium",
        "value": "还没有完整挑战过这座塔",
        "detail": "封印之前先推演一遍：哪只怪打不动、哪层会拦路，挑战一次全知道。",
        "evidence": [],
        "advice": "到「结算」页点「开始全塔挑战」。",
        "fix": None,
        "act": _act("tour", label="开始全塔挑战"),
    }


# -------------------------------------------------- 深层检测关（deep.py 供给）

def _launchd_env_probe(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["sys.launchd_env"], "launchd 全局环境干净")
    if out["sev"] != "pass":
        out["act"] = _act("goto", label="去魔镜看变量明细", tab="findings")
    return out


def _markers_probe(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["fp.markers"], "客户端未检出标记特征")
    if out["sev"] == "high":
        out["act"] = _act("goto", label="去魔镜看渲染证据", tab="findings")
    return out


def _rhythm_probe(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["fp.rhythm"], "没有可分析的会话节奏")
    if out["sev"] != "pass":
        out["act"] = _act("goto", label="去魔镜看画像数据", tab="findings")
    return out


def _browser_probe(scan, ctx):
    idx = _idx(scan)
    ids = ["res.browser", "net.webrtc_browser", "net.doh"]
    out = _from_items(idx, ids, "浏览器里未发现 Claude 集成")
    if out["sev"] != "pass":
        wb = idx.get("net.webrtc_browser") or {}
        # 只有「还没测 / 测了没结论」时才把实测按钮推到最前面：这时再跑一次
        # 就是正确的下一步。已经测出泄漏或内网暴露时，重复跑只会得到同一个
        # 结论，该做的是去看证据和改代理。
        if wb.get("severity") == "info" and wb.get("probe"):
            out["act"] = _act("probe", label="在本机浏览器里实测")
        else:
            out["act"] = _act("goto", label="去魔镜看浏览器残留", tab="findings")
    return out


def _routing_probe(scan, ctx):
    idx = _idx(scan)
    ids = ["net.routing", "net.tun_loop", "net.pinned", "net.webrtc",
           "net.proxy_path", "net.tun"]
    out = _from_items(idx, ids, "分流链路干净")
    if out["sev"] != "pass":
        worst = _worst(idx, ids) or {}
        if worst.get("id") in ("net.routing", "net.tun_loop", "net.pinned", "net.tun"):
            out["act"] = _act("goto", label="去魔镜看配置证据", tab="findings")
        elif worst.get("id") == "net.proxy_path":
            out["act"] = _act("goto", label="去魔镜看链路证据", tab="findings")
        else:
            # UDP 泄漏改的是客户端的规则，没有能一键打开的系统面板
            out["act"] = _act("goto", label="去魔镜看探测结果", tab="findings")
    return out


def _dnsbl_probe(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["net.dnsbl"], "出口 IP 未命中黑名单")
    if out["sev"] != "pass":
        out["act"] = _act("open", label="打开「网络」设置换出口", pane="network")
    return out


def _mitm_probe(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["net.mitm"], "未发现 TLS 拦截型根证书")
    if out["sev"] != "pass":
        out["act"] = _act("openfile", label="打开「钥匙串访问」" if compat.IS_MAC else "打开证书管理器", file="/Library/Keychains/System.keychain" if compat.IS_MAC else "certmgr")
    return out


def _ipv6_probe(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["net.ipv6"], "无 IPv6 直出泄露面")
    if out["sev"] != "pass":
        out["act"] = _act("goto", label="去设置里关闭 IPv6", tab="privacy", focus="ipv6")
    return out


def _permissions_probe(scan, ctx):
    idx = _idx(scan)
    out = _from_items(idx, ["cfg.permissions"], "未发现高危权限配置")
    if out["sev"] != "pass":
        out["act"] = _act("openfile", label="打开 settings.json 收紧", file=str(HOME / ".claude" / "settings.json"))
    return out


# 把小关挂到楼层上
_F1 = [
    _lv("1-1", "系统时区", "时区幽灵", "ghost", "#7c9cff",
        "时区是被公开验证的第一条判定路径。命中 Asia/Shanghai 时，即使网络在海外也会被标记。",
        ["系统设置 → 通用 → 日期与时间 → 时区，改成与出口城市一致",
         "改完点「重新出招」，确认不再命中名单"],
        _probe_tz),
    _lv("1-2", "语言与区域", "语言傀儡", "puppet", "#9c7cff",
        "系统语言、区域、键盘布局与输入法，四个来源会一起进入请求与设备画像；"
        "Claude 客户端还有自己独立的语言设置，不会跟着系统走。",
        ["系统设置 → 通用 → 语言与地区，把首选语言改成英文",
         "键盘 → 输入法：不需要的中文输入源删掉",
         "终端里的 LANG / LC_ALL 也统一",
         "客户端设置里单独再改一次界面语言"],
        _probe_lang),
    _lv("1-3", "主机铭牌", "铭牌石像", "statue", "#8c9cc4",
        "主机名会随 mDNS / DHCP 广播，带品牌词或中文时，整台机器的画像更「像国内设备」。",
        ["系统设置 → 通用 → 共享 → 本地主机名，改成中性英文",
         "例如 mbp-01、studio-a"],
        _probe_host),
    _lv("1-4", "时钟同步", "沙漏精灵", "imp", "#c4a86a",
        "时钟偏差过大会让日志时间对不上，部分接口直接拒绝请求。",
        ["系统设置 → 通用 → 日期与时间，勾选自动设置时间",
         "偏差超过 5 分钟时换一个时间服务器"],
        _probe_clock),
    _lv("1-5", "环境刻印", "刻印守卫", "sentinel", "#8a94ff",
        "持久层环境变量（launchd/注册表）会注入所有进程，绕过 shell 启动文件的检查。",
        ["逐个确认变量来源",
         "是启动项写回的要连启动项一起处理"],
        _launchd_env_probe),
]

_F2 = [
    _lv("2-1", "身份指纹", "指纹史莱姆", "slime", "#a86ac4",
        "userID、machineID、anonymousId 这些字段写在本地配置里，换账号不会自动重置；"
        "注册邮箱的域名本身也是一条线索。除了这些字段，机器本身也在说话——"
        "随办公软件装进来的中文字体、虚拟显卡的型号字符串、hypervisor 标记，"
        "都是能读到且不易改的区分度。",
        ["到「清理」页勾选「身份标识字段」",
         "含密钥或令牌的配置不留副本；其他配置按清单备份",
         "邮箱不对的话，换 Gmail / iCloud / Outlook 重新注册",
         "不用的中文字体在字体册里停用",
         "别在虚拟机里长期当主力机跑"],
        _probe_identity),
    _lv("2-2", "会话与遥测", "回声幽灵", "echo", "#8a7cc4",
        "对话历史、遥测事件、会话状态会把你的行为完整地留在本地。",
        ["遥测、缓存和日志直接删除，不留副本；会话记录按清单处理",
         "有要留的对话先自己导出"],
        _probe_session),
    _lv("2-3", "凭据与密钥", "密钥看守", "warden", "#c47c8a",
        "钥匙串条目、明文 API Key、旧版凭据文件，都是可以直接关联到账号的东西。",
        ["勾选凭据类项目；钥匙串条目删除后需要重新 claude login",
         "Shell 密钥赋值行会真正移除，不留副本，无法还原"],
        _probe_cred),
    _lv("2-4", "旧客户端残留", "旧日残影", "shade", "#6a6a8c",
        "桌面端、IDE 插件、旧版检查器留下的数据目录，都是独立的身份来源。"
        "另外 CLI 也值得看一眼：桌面版内置一份、npm 装一份、Homebrew 再装一份，"
        "PATH 里先命中的那份才生效，升级了却没变化通常就是这里。",
        ["彻底退出 Claude 桌面端（⌘Q）再清理",
         "IDE 插件目录按需处理",
         "只留一份 Claude Code CLI，其余卸掉"],
        _probe_residue),
    _lv("2-5", "启动项与后台", "不眠哨兵", "sentinel", "#5a7c9c",
        "开机自启的代理或同步进程会在你不注意的时候把环境写回去；"
        "而哨兵是唯一一个会在你离开之后还替你盯着出口的东西。",
        ["检查 LaunchAgents 里是否有 Claude 相关项",
         "停用不需要的自启项",
         "确认哨兵已安装并在运行"],
        _probe_launch),
    _lv("2-6", "标记刻痕", "刻痕妖雾", "fog", "#b48cff",
        "客户端二进制里带着环境标记的实现代码，会话内容里也可能已渲染出隐形标记。",
        ["标记由客户端写入，删文件删不掉",
         "触发条件（中转地址、CN 时区）才是真正要掐断的"],
        _markers_probe),
    _lv("2-7", "会话画像", "画像魔镜", "mirror", "#6fd3d8",
        "会话时间戳构成的节奏画像——爆发、昼夜分布、间隔——是判断「人在敲还是脚本在跑」的依据。",
        ["日均过高或凌晨占比过大都算命中画像",
         "crontab/shell 历史里的批量调用也会留下痕迹"],
        _rhythm_probe),
    _lv("2-8", "浏览器回声", "回声蝠", "echo", "#8fb7ff",
        "浏览器有自己一套网络栈：扩展、原生消息宿主、站点数据，还有 WebRTC 与安全 DNS——系统代理管不到它们。",
        ["扩展从浏览器扩展页卸载",
         "站点数据与原生消息 manifest 按路径清理",
         "点「在本机浏览器里实测」，让浏览器自己报一遍 ICE 候选",
         "安全 DNS 开着但端点不通时，浏览器会静默退回明文"],
        _browser_probe),
]

_F3 = [
    _lv("3-1", "中转地址", "伪装商人", "merchant", "#d9a86a",
        "ANTHROPIC_BASE_URL 指向非官方地址时，请求会带上中转方的特征。",
        ["检查环境变量与 settings.json 里的 base_url",
         "非必要不要走中转"],
        _probe_relay),
    _lv("3-2", "出口纯净度", "边境税吏", "taxman", "#c4a06a",
        "ip.net.coffee 的信任评分与风险标记，是判断出口能不能用的直接依据。",
        ["点「打开检测网站」在浏览器里核对一遍",
         "重点看 VPN / 代理 / Tor / 滥用记录四项"],
        _probe_ip),
    _lv("3-3", "出口类型", "机房巨像", "colossus", "#b08a5a",
        "机房 IP 上的长连接与高频请求，最容易被判为非人为操作。",
        ["能换住宅出口就换",
         "换不了就降低并发、拉长请求间隔"],
        _probe_egress),
    _lv("3-4", "代理与 DNS", "泄密管道", "pipe", "#a8763a",
        "系统代理和 DNS 会把真实位置泄露出去，即使流量走的是海外出口。"
        "TUN 接管后真正解析域名的是代理内核，系统 DNS 设置只是表面；两边都要看。",
        ["检查系统代理与系统 DNS 设置",
         "再看代理客户端的 DNS：nameserver 里删掉国内解析器",
         "节点域名（proxy-server-nameserver）用国内解析不暴露访问域名",
         "claude.ai 与 api.anthropic.com 实际连一次，确认不是黑洞"],
        _probe_proxy),
    _lv("3-5", "黑名单痕迹", "黑名单之眼", "eye", "#c48a4a",
        "hosts 与配置文件里残留的国内域名、中转域名，本身就是一条证据链。",
        ["检查 /etc/hosts 里是否有异常条目",
         "检查 shell 配置里的域名变量"],
        _probe_hosts),
    _lv("3-6", "分流法阵", "法阵术士", "mage", "#7c9cff",
        "这一层没有「全对」的答案，只有取舍。「加置顶规则」和「别留 Claude 专属规则」是同一件事的两面："
        "留着不漏流量，但配置里就多一条「很在意 Claude 出口」的痕迹；删掉痕迹干净，"
        "但订阅规则集一旦更新出一条直连，请求会安静地死在半路。"
        "UDP 又是另一回事——它常常整条绕开隧道，跟规则写没写没关系。",
        ["先分清规则是你写的，还是订阅塞进来的",
         "要防误伤就加置顶规则，接受多一条画像信号",
         "不要为了「干净」把保命的置顶规则删掉",
         "TUN 全接管时所有流量都过代理，注意节点跳变"],
        _routing_probe),
    _lv("3-7", "暗哨名录", "名录之眼", "eye", "#ff9b6b",
        "公开滥用黑名单记着这个出口地址干过的事——共用出口的人留下的案底会算到你头上。",
        ["命中黑名单的出口不建议继续用",
         "换节点后重跑确认清零"],
        _dnsbl_probe),
    _lv("3-8", "截听之证", "截听石像", "statue", "#e8736a",
        "钥匙串里的抓包类根证书意味着 HTTPS 流量能被中途解开——包括发给 Claude 的。",
        ["打开钥匙串访问核对每个根证书",
         "不认识的直接删或改回默认信任"],
        _mitm_probe),
    _lv("3-9", "IPv6 暗门", "暗门影", "shade", "#6b7bd4",
        "代理只接管 v4 时，客户端走 v6 会绕开伪装直接从真实 ISP 出去。",
        ["去「隐私设置 → IPv6 出口」关闭 Wi-Fi 的 IPv6（需管理员授权）",
         "关闭后断开重连 Wi-Fi 再检测；随时可恢复为 Automatic"],
        _ipv6_probe),
    _lv("3-10", "出口漂移", "瞬移残影", "wraith", "#6f8fd8",
        "同一个账号在一天里从两个以上国家出去，就是风控眼里最典型的「异地瞬移」。"
        "单次 IP 再干净，跳变本身也是信号——这一项看的是历史，不是此刻。",
        ["选定一个出口就固定住，别在一天里换城市",
         "关掉机场的自动选路与负载均衡，改手动固定",
         "确实要换地区，隔一天再登录"],
        _probe_egress_drift),
]

_F4 = [
    _lv("4-1", "隔离环境", "分身术士", "mage", "#6ec9b6",
        "独立的配置目录能让多账号互不污染，是唯一能从根上解决指纹串号的办法。",
        ["到「隔离环境」页建一个配置档",
         "以后用它的 run.sh 启动"],
        _probe_isolation),
    _lv("4-2", "启动脚本", "守卷书吏", "notary", "#8ac46a",
        "配置档建了不等于能跑——run.sh 缺失或没权限时，启动脚本直接罢工。",
        ["检查 ~/.ccclean/profiles/ 下各档的 run.sh",
         "缺了就重建配置档"],
        _probe_profile_script),
    _lv("4-3", "沙箱引擎", "炉心魔像", "colossus", "#c08a3e",
        "需要整机沙箱时得有 docker；没声明沙箱的配置档不需要它。",
        ["装了 Docker 再来重打",
         "或者把沙箱档改回本机 run.sh 模式"],
        _probe_docker),
    _lv("4-4", "净化火印", "灰烬看守", "warden", "#c47c8a",
        "发现残留只是第一步，真正走过一次「预览 → CLEAN 确认 → 按保留策略清理」才算完成这条流程。",
        ["在结算卡片或战斗浮层点「直接清理」，输入 CLEAN 确认",
         "环境本就干净的话本关自动放行"],
        _probe_cleanse),
    _lv("4-5", "挑战足迹", "挑战之眼", "eye", "#7c9cff",
        "先完整推演一遍全塔，才知道自己的环境到底走到了哪一步。",
        ["到「结算」页点「开始全塔挑战」",
         "挑战只读检测，不改动真实进度"],
        _probe_tour),
    _lv("4-6", "权限裂隙", "裂隙恶魔", "demon", "#e05c8a",
        "bypassPermissions 与通配放行让客户端不再确认就执行命令——你未必记得开过它。",
        ["bypassPermissions 只在完全信任的目录用",
         "通配 allow 规则收紧到具体命令"],
        _permissions_probe),
]

FLOORS[0]["levels"] = _F1
FLOORS[1]["levels"] = _F2
FLOORS[2]["levels"] = _F3
FLOORS[3]["levels"] = _F4

TOTAL_LEVELS = sum(len(f["levels"]) for f in FLOORS[:4])


# ---------------------------------------------------------------- 进度存储


def _read_json(path, fallback):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return json.loads(json.dumps(fallback))


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_run():
    data = _read_json(TOWER_FILE, {})
    run = data.get("run") or {}
    run.setdefault("startedAt", time.time())
    run.setdefault("finishedAt", None)
    run.setdefault("levels", {})
    run.setdefault("bosses", {})
    run.setdefault("final", {})
    return run


def _save_run(run):
    _write_json(TOWER_FILE, {"run": run})


def reset():
    _write_json(TOWER_FILE, {"run": {
        "startedAt": time.time(), "finishedAt": None,
        "levels": {}, "bosses": {}, "final": {},
        "hp": BASE_STAT["hp"], "deaths": 0,
    }})
    return {"ok": True}


# ---------------------------------------------------------------- 挑战历史


_TOUR_LOCK = threading.Lock()


def _load_tour_data():
    data = _read_json(TOUR_FILE, {})
    tours = data.get("tours") if isinstance(data, dict) else None
    tours = [x for x in tours if isinstance(x, dict)] if isinstance(tours, list) else []
    total = data.get("total") if isinstance(data, dict) else None
    if not isinstance(total, int) or total < len(tours):
        total = len(tours)
    return {"version": 1, "total": total, "tours": tours}


def _tour_brief(rec):
    if not isinstance(rec, dict):
        return None
    keys = ("id", "no", "ts", "at", "cleared", "defeated", "total", "deaths",
            "clearedFloors", "bosses", "failedCount", "skipped")
    return {k: rec.get(k) for k in keys}


def tour_info():
    with _TOUR_LOCK:
        data = _load_tour_data()
    tours = data["tours"]
    return {
        "count": data["total"],
        "kept": len(tours),
        "last": _tour_brief(tours[-1]) if tours else None,
    }


def _clampi(value, lo=0, hi=999999):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return lo


def _text(value, limit=400):
    return str(value or "")[:limit]


def _clean_failed(raw):
    out = []
    for x in (raw or [])[:60]:
        if not isinstance(x, dict):
            continue
        monster = x.get("monster") if isinstance(x.get("monster"), dict) else {}
        fix_ids = [str(i)[:80] for i in (x.get("fixIds") or []) if i][:24]
        how_raw = x.get("how")
        if isinstance(how_raw, list):
            how = [_text(h, 200) for h in how_raw][:8]
        elif how_raw:
            how = [_text(how_raw, 300)]
        else:
            how = []
        out.append({
            "id": _text(x.get("id"), 24),
            "title": _text(x.get("title"), 120),
            "floorId": _text(x.get("floorId"), 8),
            "floorNo": _clampi(x.get("floorNo"), 0, 9),
            "floorName": _text(x.get("floorName"), 40),
            "monster": {"name": _text(monster.get("name"), 80), "kind": _text(monster.get("kind"), 24)},
            "sev": _text(x.get("sev"), 16),
            "value": _text(x.get("value"), 240),
            "detail": _text(x.get("detail"), 500),
            "advice": _text(x.get("advice"), 500),
            "how": how,
            "fixIds": list(dict.fromkeys(fix_ids)),
            "act": (
                {k: _text(x["act"].get(k), 64) for k in ("kind", "pane", "tab", "file", "label")
                 if x["act"].get(k)}
                if isinstance(x.get("act"), dict) else None
            ),
        })
    return out


def record_tour(summary, skipped=False):
    """把一次挑战的结算快照写入挑战历史；不触碰真实闯关进度。"""
    summary = summary if isinstance(summary, dict) else {}
    failed = _clean_failed(summary.get("failedDetail"))
    gear = []
    for g in (summary.get("gear") or [])[:6]:
        if isinstance(g, dict):
            gear.append({
                "name": _text(g.get("name"), 60),
                "label": _text(g.get("label"), 12),
                "value": _clampi(g.get("value"), 0, 999),
                "floor": _clampi(g.get("floor"), 0, 9),
            })
    floor_results = []
    for f in (summary.get("floorResults") or [])[:5]:
        if isinstance(f, dict):
            floor_results.append({
                "id": _text(f.get("id"), 8),
                "no": _clampi(f.get("no"), 0, 9),
                "name": _text(f.get("name"), 40),
                "defeated": _clampi(f.get("defeated"), 0, TOTAL_LEVELS),
                "count": _clampi(f.get("count"), 0, TOTAL_LEVELS),
                "cleared": bool(f.get("cleared")),
            })
    ts = time.time()
    with _TOUR_LOCK:
        data = _load_tour_data()
        no = data["total"] + 1
        rec = {
            "id": f"{int(ts * 1000)}-{no}",
            "no": no,
            "ts": round(ts, 3),
            "at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
            "cleared": bool(summary.get("cleared")),
            "defeated": _clampi(summary.get("defeated"), 0, TOTAL_LEVELS),
            "total": _clampi(summary.get("total"), 0, TOTAL_LEVELS) or TOTAL_LEVELS,
            "deaths": _clampi(summary.get("deaths"), 0, 999),
            "clearedFloors": _clampi(summary.get("clearedFloors"), 0, 4),
            "bosses": _clampi(summary.get("bosses"), 0, 4),
            "failedCount": len(failed),
            "skipped": bool(skipped),
            "failed": failed,
            "gear": gear,
            "floors": floor_results,
        }
        tours = (data["tours"] + [rec])[-TOUR_KEEP:]
        _write_json(TOUR_FILE, {"version": 1, "total": no, "tours": tours})
    out = _tour_brief(rec) or {}
    out.update({"failed": failed, "gear": gear, "floors": floor_results})
    return out


def history_payload():
    with _TOUR_LOCK:
        data = _load_tour_data()
    return {
        "count": data["total"],
        "kept": len(data["tours"]),
        "tours": list(reversed(data["tours"])),
    }


def tour_record(tid):
    """按 id 取一条完整挑战记录（含明细），找不到返回 None。"""
    with _TOUR_LOCK:
        data = _load_tour_data()
    for rec in data["tours"]:
        if str(rec.get("id")) == str(tid):
            return rec
    return None


# ---------------------------------------------------------------- 存活时长


_TIME_KEYS = ("firstStartTime", "installTime", "createdAt", "created_at",
              "startTime", "firstUseAt", "since", "installedAt")


def _parse_ts(v):
    if isinstance(v, (int, float)):
        n = float(v)
        if n > 1e12:      # 毫秒
            n /= 1000.0
        if 1e9 < n < time.time() + 86400:
            return n
        return None
    if isinstance(v, str):
        s = v.strip()
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.timestamp()
            return dt.timestamp()
        except Exception:
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return time.mktime(time.strptime(s[:19], fmt))
            except Exception:
                continue
    return None


def _pack(ts, source):
    days = max(0, int((time.time() - ts) // 86400))
    return {
        "days": days,
        "since": time.strftime("%Y-%m-%d", time.localtime(ts)),
        "source": source,
    }


def survival():
    """尽力从本地痕迹推断「这段 Claude 生涯已经活了多久」。"""
    traces = []
    cj = HOME / ".claude.json"
    if cj.exists():
        try:
            data = json.loads(cj.read_text(encoding="utf-8", errors="replace"))
            for k in _TIME_KEYS:
                ts = _parse_ts(data.get(k))
                if ts:
                    return _pack(ts, f"~/.claude.json · {k}")
        except Exception:
            pass
        try:
            traces.append(cj.stat().st_mtime)
        except Exception:
            pass

    base = HOME / ".claude"
    if base.exists():
        n = 0
        for p in base.rglob("*"):
            n += 1
            if n > 4000:
                break
            try:
                if p.is_file():
                    traces.append(p.stat().st_mtime)
            except Exception:
                continue

    if traces:
        return _pack(min(traces), "本地最早痕迹")
    return {"days": None, "since": None, "source": None}


# ---------------------------------------------------------------- 结算


def _title_for(level):
    for th, name in TITLES:
        if level <= th:
            return name
    return TITLES[-1][1]


def _strength(sev, floor_no):
    """怪物强度：随层数递增，只有中危以上才真的会打人。"""
    base = STRENGTH.get(sev, 0)
    if not base:
        return 0
    return int(round(base * (1 + FLOOR_SCALE * (floor_no - 1))))


def _damage(strength, dfn):
    """受到的伤害：防御越高掉得越少，但永远保底 24 点。

    用 dfn/(dfn+80) 而不是简单相减，是为了让防御一直有用、又不会被堆到免伤。
    打不过检测时的反击要够重：多数中高危会打掉半管以上，塔顶的怪能直接把人打倒。
    """
    if strength <= 0:
        return 0
    return max(MIN_DAMAGE, int(round(strength * DAMAGE_SCALE * (1 - dfn / (dfn + 80)))))


def _split(total, parts):
    """把一次掉血拆成几段，用于战斗演出的多回合。"""
    if total <= 0 or parts <= 0:
        return []
    step = total // parts
    out = [step] * parts
    out[-1] += total - step * parts
    return out


def build(scan, ip=None, persist=True):
    idx = _idx(scan)
    ctx = {
        "ip": ip if ip is not None else ipcheck.check(),
        "profiles": isolation.list_profiles(),
    }
    run = _load_run()

    # 先跑一遍探针，拿到每关的实时结论（关卡状态不落盘）
    raw = []
    for f in FLOORS[:4]:
        rows = []
        for lv in f["levels"]:
            p = lv["probe"](scan, ctx)
            sev = p.get("sev") or "info"
            ok = SEV_RANK.get(sev, 1) <= SEV_RANK["low"]
            rec = run["levels"].get(lv["id"]) or {}
            fought = bool(rec.get("fought"))
            rows.append({
                "lv": lv, "probe": p, "sev": sev, "ok": ok,
                "fought": fought, "defeated": fought and ok,
                "revived": bool(rec.get("ok")) and not ok,
            })
        raw.append(rows)

    defeated_total = sum(1 for rows in raw for r in rows if r["defeated"])
    total = sum(len(rows) for rows in raw)

    # ---- 装备：清空本层小怪，解锁本层唯一的一件 ----
    gear = []
    for f, rows in zip(FLOORS[:4], raw):
        if not all(r["defeated"] for r in rows):
            continue
        item = FLOOR_GEAR.get(f["id"])
        if item:
            name, stat, val = item
            gear.append({
                "name": name, "stat": stat, "value": val,
                "label": STAT_LABEL.get(stat, stat),
                "floor": f["no"], "floorId": f["id"],
            })

    bonus = {"atk": 0, "def": 0, "hp": 0}
    for g in gear:
        bonus[g["stat"]] = bonus.get(g["stat"], 0) + g["value"]

    atk = BASE_STAT["atk"] + PER_KILL["atk"] * defeated_total + bonus["atk"]
    dfn = BASE_STAT["def"] + PER_KILL["def"] * defeated_total + bonus["def"]
    hp_max = BASE_STAT["hp"] + PER_KILL["hp"] * defeated_total + bonus["hp"]

    hp = run.get("hp")
    if not isinstance(hp, (int, float)):
        hp = hp_max
    hp = int(max(0, min(hp_max, hp)))
    if persist and run.get("hp") != hp:
        run["hp"] = hp
        _save_run(run)

    exp = 0
    for rows in raw:
        for r in rows:
            if r["fought"]:
                exp += EXP_KILL if r["defeated"] else EXP_HURT
    power = atk * 10 + dfn * 8

    floors = []
    for f, rows in zip(FLOORS[:4], raw):
        lv_out = []
        for r in rows:
            lv = r["lv"]
            p = r["probe"]
            lv_out.append({
                "id": lv["id"],
                "no": lv["no"],
                "title": lv["title"],
                "monster": lv["monster"],
                "brief": lv["brief"],
                "how": lv["how"],
                "sev": r["sev"],
                "ok": r["ok"],
                "fought": r["fought"],
                "defeated": r["defeated"],
                "revived": r["revived"],
                "atk": atk,
                "def": dfn,
                "monsterHp": MONSTER_HP,
                "strength": _strength(r["sev"], f["no"]),
                "value": p.get("value") or "",
                "detail": p.get("detail") or "",
                "evidence": p.get("evidence") or [],
                "advice": p.get("advice") or "",
                "fix": p.get("fix"),
                "fixIds": p.get("fixIds") or [],
                "act": p.get("act"),
            })

        all_defeated = all(r["defeated"] for r in rows)
        b = f["boss"]
        boss_fought = bool((run["bosses"].get(b["id"]) or {}).get("fought"))
        boss = {
            "id": b["id"],
            "name": b["name"],
            "kind": b["kind"],
            "tint": b["tint"],
            "hp": MONSTER_HP * len(f["levels"]),
            "atk": atk,
            "unlocked": all_defeated,
            "defeated": boss_fought and all_defeated,
        }
        floors.append({
            "id": f["id"],
            "no": f["no"],
            "name": f["name"],
            "subtitle": f["subtitle"],
            "tint": f["tint"],
            "story": f["story"],
            "levels": lv_out,
            "boss": boss,
            "cleared": boss["defeated"],
            "progress": sum(1 for x in lv_out if x["defeated"]),
            "count": len(lv_out),
        })

    final_def = FLOORS[4]["boss"]
    final_unlocked = all(fl["boss"]["defeated"] for fl in floors)
    final = {
        "id": final_def["id"],
        "name": final_def["name"],
        "kind": final_def["kind"],
        "tint": final_def["tint"],
        "hp": MONSTER_HP * total,
        "atk": power,
        "unlocked": final_unlocked,
        "defeated": bool((run.get("final") or {}).get("fought")) and final_unlocked,
    }

    level = min(MAX_LEVEL, 1 + exp // EXP_STEP)
    exp_in = exp % EXP_STEP
    current = next((fl["id"] for fl in floors if not fl["cleared"]), "f5" if final_unlocked else floors[0]["id"])

    started = run.get("startedAt") or time.time()
    finished = run.get("finishedAt")
    duration = int((finished or time.time()) - started)

    # 出过至少一次招（小关 / 守卫 / 塔主，无论输赢）就算闯过塔，
    # 用于解锁魔镜、祭坛这些工具页签
    fought_any = bool(
        any((rec or {}).get("fought") for rec in run["levels"].values())
        or any((rec or {}).get("fought") for rec in run["bosses"].values())
        or (run.get("final") or {}).get("fought")
    )
    tours = tour_info()
    unlocked = fought_any or tours["count"] > 0

    return {
        "floors": floors,
        "final": final,
        "gear": gear,
        "unlocked": unlocked,
        "stats": {"atk": atk, "def": dfn, "hpMax": hp_max, "bonus": bonus},
        "hud": {
            "hp": hp,
            "hpMax": hp_max,
            "atk": atk,
            "def": dfn,
            "power": power,
            "exp": exp,
            "expIn": exp_in,
            "expNeed": EXP_STEP,
            "expPct": round(exp_in / EXP_STEP * 100) if EXP_STEP else 0,
            "level": level,
            "title": _title_for(level),
            "defeated": defeated_total,
            "total": total,
            "deaths": int(run.get("deaths") or 0),
        },
        "current": current,
        "cleared": final["defeated"],
        "tour": {
            "count": tours["count"],
            "kept": tours["kept"],
            "last": tours["last"],
            "firstRun": tours["count"] == 0 and not fought_any,
        },
        "survival": survival(),
        "run": {
            "startedAt": started,
            "finishedAt": finished,
            "durationSec": duration,
        },
    }


def _diff_unlocked(before, after):
    out = []
    bmap = {lv["id"]: lv for fl in before["floors"] for lv in fl["levels"]}
    for fl in after["floors"]:
        for lv in fl["levels"]:
            if lv["id"] in bmap and lv["defeated"] and not bmap[lv["id"]]["defeated"]:
                out.append(lv["id"])
        if fl["boss"]["unlocked"] and not next(x for x in before["floors"] if x["id"] == fl["id"])["boss"]["unlocked"]:
            out.append(fl["boss"]["id"])
    if after["final"]["unlocked"] and not before["final"]["unlocked"]:
        out.append(after["final"]["id"])
    return out


def fight(scan, level_id, ip=None):
    before = build(scan, ip)
    if before["hud"]["hp"] <= 0:
        return {"ok": False, "error": "你已倒下，先回城休整"}
    target = None
    floor_no = 1
    for fl in before["floors"]:
        for lv in fl["levels"]:
            if lv["id"] == level_id:
                target = lv
                floor_no = fl["no"]
                break
    if not target:
        return {"ok": False, "error": "塔里没有这一关"}

    hud0 = before["hud"]
    killed = target["ok"]
    strength = target.get("strength") or _strength(target["sev"], floor_no)
    dmg = 0 if killed else _damage(strength, hud0["def"])
    heal = HEAL_KILL if killed else 0

    run = _load_run()
    rec = run["levels"].setdefault(level_id, {})
    rec["fought"] = True
    rec["at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    rec["ok"] = target["ok"]

    hp_before = hud0["hp"]
    hp_max_before = hud0["hpMax"]
    if killed:
        run["hp"] = min(hp_max_before, hp_before + heal)
    else:
        run["hp"] = max(0, hp_before - dmg)
    dead = run["hp"] <= 0
    if dead:
        run["deaths"] = int(run.get("deaths") or 0) + 1
    _save_run(run)

    after = build(scan, ip)
    had = {g["name"] for g in before.get("gear") or []}
    gear_new = [g for g in (after.get("gear") or []) if g["name"] not in had]
    # 新装备抬高了血量上限，把增量补进当前血量，否则越打越亏
    delta = after["hud"]["hpMax"] - hp_max_before
    if delta > 0 and not dead:
        run["hp"] = min(after["hud"]["hpMax"], run["hp"] + delta)
        _save_run(run)
        after["hud"]["hp"] = run["hp"]

    return {
        "ok": True,
        "battle": {
            "kind": "level",
            "id": level_id,
            "monster": target["monster"],
            "monsterHp": MONSTER_HP,
            "monsterAtk": strength,
            "atk": hud0["atk"],
            "def": hud0["def"],
            "dmg": dmg,
            "hits": _split(dmg, 3 if dmg >= 30 else 1),
            "heal": heal,
            "killed": killed,
            "dead": dead,
            "hpAfter": after["hud"]["hp"],
            "exp": EXP_KILL if killed else EXP_HURT,
            "probe": {
                "sev": target["sev"],
                "value": target["value"],
                "detail": target["detail"],
                "evidence": target["evidence"],
                "advice": target["advice"],
            },
            "hudBefore": hud0,
            "hud": after["hud"],
            "levelUp": after["hud"]["level"] > hud0["level"],
            "unlocked": _diff_unlocked(before, after),
            "gearNew": gear_new,
            "revived": target["revived"],
            "act": target.get("act"),
            "fixIds": target.get("fixIds") or [],
        },
        "state": after,
    }


def heal(scan, ip=None):
    """阵亡或重伤后回城休整：血量回满，阵亡次数已经记在 run 里。"""
    d = build(scan, ip)
    run = _load_run()
    run["hp"] = d["hud"]["hpMax"]
    _save_run(run)
    return {"ok": True, "state": build(scan, ip)}


def sweep(scan, floor_id, ip=None):
    before = build(scan, ip)
    floor = next((f for f in before["floors"] if f["id"] == floor_id), None)
    if not floor:
        return {"ok": False, "error": "没有这一层"}
    ids = [lv["id"] for lv in floor["levels"] if lv["ok"] and not lv["defeated"]]
    if not ids:
        return {"ok": True, "ids": [], "state": before}
    run = _load_run()
    for lid in ids:
        rec = run["levels"].setdefault(lid, {})
        rec["fought"] = True
        rec["at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        rec["ok"] = True
    hp = run.get("hp")
    if isinstance(hp, (int, float)):
        run["hp"] = min(before["hud"]["hpMax"], int(hp) + HEAL_KILL * len(ids))
    _save_run(run)
    after = build(scan, ip)
    return {"ok": True, "ids": ids, "state": after}


def retry_floor(scan, floor_id, ip=None):
    """重闯本层：把这一层的小关和守卫记录全部清掉，怪物重新站回地图上。
    属性/装备是按击杀数派生的，自然会跟着回落，重新杀回来再涨回来。"""
    floor = next((f for f in FLOORS if f["id"] == floor_id), None)
    if not floor:
        return {"ok": False, "error": "没有这一层"}
    run = _load_run()
    for lv in floor["levels"]:
        run["levels"].pop(lv["id"], None)
    run["bosses"].pop(floor["boss"]["id"], None)
    _save_run(run)
    return {"ok": True, "state": build(scan, ip)}


def fight_boss(scan, boss_id, ip=None):
    before = build(scan, ip)
    if before["hud"]["hp"] <= 0:
        return {"ok": False, "error": "你已倒下，先回城休整"}
    floor = next((f for f in before["floors"] if f["boss"]["id"] == boss_id), None)
    if not floor:
        return {"ok": False, "error": "没有这个守卫"}
    if not floor["boss"]["unlocked"]:
        return {"ok": False, "error": "先把本层的小关全部清掉，守卫才会现身"}
    run = _load_run()
    run["bosses"][boss_id] = {"fought": True, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    hp = run.get("hp")
    if isinstance(hp, (int, float)):
        run["hp"] = min(before["hud"]["hpMax"], int(hp) + HEAL_BOSS)
    _save_run(run)
    after = build(scan, ip)
    had = {g["name"] for g in before.get("gear") or []}
    return {
        "ok": True,
        "battle": {
            "kind": "boss",
            "gearNew": [g for g in (after.get("gear") or []) if g["name"] not in had],
            "id": boss_id,
            "monster": {"name": floor["boss"]["name"], "kind": floor["boss"]["kind"], "tint": floor["boss"]["tint"]},
            "monsterHp": floor["boss"]["hp"],
            "monsterAtk": 0,
            "atk": before["hud"]["atk"],
            "def": before["hud"]["def"],
            "dmg": 0,
            "hits": [],
            "heal": HEAL_BOSS,
            "killed": True,
            "dead": False,
            "hpAfter": after["hud"]["hp"],
            "exp": EXP_BOSS,
            "probe": {
                "sev": "pass",
                "value": f"{floor['name']} · 全部 {floor['count']} 关已清",
                "detail": floor["story"],
                "evidence": [{"label": lv["title"], "value": lv["value"]} for lv in floor["levels"]],
                "advice": "",
            },
            "hudBefore": before["hud"],
            "hud": after["hud"],
            "levelUp": after["hud"]["level"] > before["hud"]["level"],
            "unlocked": _diff_unlocked(before, after),
            "revived": False,
        },
        "state": after,
    }


def fight_final(scan, ip=None):
    before = build(scan, ip)
    if before["hud"]["hp"] <= 0:
        return {"ok": False, "error": "你已倒下，先回城休整"}
    if not before["final"]["unlocked"]:
        return {"ok": False, "error": "四层守卫还没全部倒下"}
    run = _load_run()
    run["final"] = {"fought": True, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    if not run.get("finishedAt"):
        run["finishedAt"] = time.time()
    _save_run(run)
    after = build(scan, ip)
    return {
        "ok": True,
        "battle": {
            "kind": "final",
            "id": before["final"]["id"],
            "monster": {"name": before["final"]["name"], "kind": "claude", "tint": before["final"]["tint"]},
            "monsterHp": before["final"]["hp"],
            "monsterAtk": 0,
            "atk": before["hud"]["atk"],
            "def": before["hud"]["def"],
            "dmg": 0,
            "hits": [],
            "heal": 0,
            "killed": True,
            "dead": False,
            "hpAfter": after["hud"]["hp"],
            "exp": EXP_FINAL,
            "probe": {
                "sev": "pass",
                "value": "魔塔通关",
                "detail": "四层守卫全部倒下，塔顶的灯灭了。",
                "evidence": [],
                "advice": "",
            },
            "hudBefore": before["hud"],
            "hud": after["hud"],
            "levelUp": after["hud"]["level"] > before["hud"]["level"],
            "unlocked": [],
            "revived": False,
        },
        "state": after,
    }


# ------------------------------------------------------------------ 自动演示

def _sim_hud(st):
    level = min(MAX_LEVEL, 1 + st["exp"] // EXP_STEP)
    exp_in = st["exp"] % EXP_STEP
    return {
        "hp": st["hp"],
        "hpMax": st["hpMax"],
        "atk": st["atk"],
        "def": st["def"],
        "power": st["atk"] * 10 + st["def"] * 8,
        "exp": st["exp"],
        "expIn": exp_in,
        "expNeed": EXP_STEP,
        "expPct": round(exp_in / EXP_STEP * 100) if EXP_STEP else 0,
        "level": level,
        "title": _title_for(level),
        "defeated": st["kills"],
        "total": st["total"],
        "deaths": st["deaths"],
    }


def _sim_probe(lv):
    return {
        "sev": lv.get("sev") or "info",
        "value": lv.get("value") or "",
        "detail": lv.get("detail") or "",
        "evidence": (lv.get("evidence") or [])[:6],
        "advice": lv.get("advice") or "",
    }


def preview(scan, ip=None):
    """全塔挑战的纯推演：从初始属性走遍四层与塔顶，不读写真实存档。

    规则不变：检测通过才打得动，没通过的检测就是打不动的怪物。
    为了让一次挑战能看到全部问题，演出不会在第一处失败停下：
    失败的怪原地留在场上、勇者挨一下反击，然后继续下一只；
    本层没全部通过时层主保持封印，四层没全部清空时塔主保持封印。
    挑战不是真实进度，每层之间会在营地补满生命，推演结果也不会写盘。
    """
    live = build(scan, ip, persist=False)
    total = live["hud"]["total"]
    st = {
        "hp": BASE_STAT["hp"],
        "hpMax": BASE_STAT["hp"],
        "atk": BASE_STAT["atk"],
        "def": BASE_STAT["def"],
        "exp": 0,
        "kills": 0,
        "deaths": 0,
        "total": total,
    }
    gear = []
    failed_all = [
        {
            "id": lv["id"],
            "title": lv["title"],
            "floorId": floor["id"],
            "floorNo": floor["no"],
            "floorName": floor["name"],
            "monster": lv["monster"],
            "sev": lv["sev"],
            "value": lv["value"],
            "detail": lv["detail"],
            "advice": lv["advice"],
            "how": lv["how"],
            "fixIds": lv.get("fixIds") or [],
            "act": lv.get("act"),
        }
        for floor in live["floors"]
        for lv in floor["levels"]
        if not lv["ok"]
    ]
    floors_out = []
    first_blocked = None
    bosses_killed = 0

    def apply_level(lv, floor_id):
        # 上一只怪把勇者打倒后，下一只上场前由营地救起；死亡已经计入。
        rescued = st["hp"] <= 0
        if rescued:
            st["hp"] = st["hpMax"]
        hud0 = _sim_hud(st)
        hp0 = st["hp"]
        atk0, dfn0 = st["atk"], st["def"]
        killed = bool(lv["ok"])
        dmg = 0
        heal = 0
        dead = False
        exp_gain = 0
        if killed:
            st["kills"] += 1
            exp_gain = EXP_KILL
            st["exp"] += EXP_KILL
            st["atk"] += PER_KILL["atk"]
            st["def"] += PER_KILL["def"]
            st["hpMax"] += PER_KILL["hp"]
            heal = HEAL_KILL
            st["hp"] = min(st["hpMax"], st["hp"] + PER_KILL["hp"] + heal)
        else:
            exp_gain = EXP_HURT
            st["exp"] += EXP_HURT
            dmg = _damage(lv.get("strength") or 0, dfn0)
            st["hp"] = max(0, st["hp"] - dmg)
            dead = st["hp"] <= 0
            if dead:
                st["deaths"] += 1
        hud1 = _sim_hud(st)
        return {
            "type": "fight",
            "kind": "level",
            "floor": floor_id,
            "id": lv["id"],
            "title": lv["title"],
            "monster": lv["monster"],
            "monsterHp": MONSTER_HP,
            "monsterAtk": lv.get("strength") or 0,
            "atk": atk0,
            "def": dfn0,
            "dmg": dmg,
            "hits": _split(dmg, 3 if dmg >= 30 else 1),
            "heal": heal,
            "killed": killed,
            "dead": dead,
            "rescued": rescued,
            "hpBefore": hp0,
            "hpAfter": st["hp"],
            "exp": exp_gain,
            "probe": _sim_probe(lv),
            "hudBefore": hud0,
            "hud": hud1,
            "levelUp": hud1["level"] > hud0["level"],
            "gearNew": [],
            "revived": False,
        }

    def apply_camp(floor):
        healed = max(0, st["hpMax"] - st["hp"])
        st["hp"] = st["hpMax"]
        return {
            "type": "camp",
            "floor": floor["id"],
            "floorNo": floor["no"],
            "heal": healed,
            "hud": _sim_hud(st),
        }

    def apply_gear(floor):
        item = FLOOR_GEAR.get(floor["id"])
        if not item:
            return None
        name, stat, val = item
        g = {
            "name": name, "stat": stat, "value": val,
            "label": STAT_LABEL.get(stat, stat),
            "floor": floor["no"], "floorId": floor["id"],
        }
        gear.append(g)
        if stat == "hp":
            st["hpMax"] += val
            st["hp"] = min(st["hpMax"], st["hp"] + val)
        else:
            st[stat] = st.get(stat, 0) + val
        return {
            "type": "gear",
            "floor": floor["id"],
            "gear": g,
            "gearAll": list(gear),
            "hud": _sim_hud(st),
        }

    def apply_boss(floor):
        b = floor["boss"]
        hud0 = _sim_hud(st)
        hp0 = st["hp"]
        st["exp"] += EXP_BOSS
        st["hp"] = min(st["hpMax"], st["hp"] + HEAL_BOSS)
        hud1 = _sim_hud(st)
        return {
            "type": "boss",
            "kind": "boss",
            "floor": floor["id"],
            "id": b["id"],
            "monster": {"name": b["name"], "kind": b["kind"], "tint": b["tint"]},
            "monsterHp": b["hp"],
            "monsterAtk": 0,
            "atk": hud0["atk"],
            "def": hud0["def"],
            "dmg": 0,
            "hits": [],
            "heal": HEAL_BOSS,
            "killed": True,
            "dead": False,
            "hpBefore": hp0,
            "hpAfter": st["hp"],
            "exp": EXP_BOSS,
            "probe": {
                "sev": "pass",
                "value": f"{floor['name']} · 全部 {floor['count']} 关已清",
                "detail": floor["story"],
                "evidence": [
                    {"label": lv["title"], "value": lv["value"]}
                    for lv in floor["levels"]
                ],
                "advice": "",
            },
            "hudBefore": hud0,
            "hud": hud1,
            "levelUp": hud1["level"] > hud0["level"],
            "gearNew": [],
            "revived": False,
        }

    def apply_boss_seal(floor, failed_ids):
        b = floor["boss"]
        return {
            "type": "boss_seal",
            "kind": "boss",
            "floor": floor["id"],
            "floorNo": floor["no"],
            "floorName": floor["name"],
            "id": b["id"],
            "monster": {"name": b["name"], "kind": b["kind"], "tint": b["tint"]},
            "monsterHp": b["hp"],
            "monsterAtk": 0,
            "dmg": 0,
            "hits": [],
            "killed": False,
            "dead": False,
            "failed": failed_ids,
            "probe": {
                "sev": "info",
                "value": f"本层还有 {len(failed_ids)} 项检测没通过",
                "detail": "层主被本层未通过的检测封印着，无法挑战。",
                "advice": "把本层每一关都打通，层主才会解封。",
            },
            "hud": _sim_hud(st),
        }

    def apply_final():
        fdef = FLOORS[4]["boss"]
        hud0 = _sim_hud(st)
        hp0 = st["hp"]
        st["exp"] += EXP_FINAL
        hud1 = _sim_hud(st)
        return {
            "type": "final",
            "kind": "final",
            "floor": "f5",
            "id": fdef["id"],
            "monster": {"name": fdef["name"], "kind": "claude", "tint": fdef["tint"]},
            "monsterHp": MONSTER_HP * total,
            "monsterAtk": 0,
            "atk": hud0["atk"],
            "def": hud0["def"],
            "dmg": 0,
            "hits": [],
            "heal": 0,
            "killed": True,
            "dead": False,
            "hpBefore": hp0,
            "hpAfter": st["hp"],
            "exp": EXP_FINAL,
            "probe": {
                "sev": "pass",
                "value": "魔塔通关",
                "detail": "四层守卫全部倒下，塔顶的灯灭了。",
                "evidence": [],
                "advice": "",
            },
            "hudBefore": hud0,
            "hud": hud1,
            "levelUp": hud1["level"] > hud0["level"],
            "gearNew": [],
            "revived": False,
        }

    def apply_final_seal():
        fdef = FLOORS[4]["boss"]
        blocked_floors = [
            {
                "no": f["no"],
                "name": f["name"],
                "failed": [lv["id"] for lv in f["levels"] if not lv["ok"]],
            }
            for f in floors_out
            if not f["cleared"]
        ]
        return {
            "type": "final_seal",
            "kind": "final",
            "floor": "f5",
            "id": fdef["id"],
            "monster": {"name": fdef["name"], "kind": "claude", "tint": fdef["tint"]},
            "monsterHp": MONSTER_HP * total,
            "monsterAtk": 0,
            "dmg": 0,
            "hits": [],
            "killed": False,
            "dead": False,
            "failedFloors": blocked_floors,
            "probe": {
                "sev": "info",
                "value": "四层没有全部清空，塔主仍在封印之后",
                "detail": "塔顶的最后一盏灯还亮着。",
                "advice": "把四层的层主都打倒，才能挑战 Claude。",
            },
            "hud": _sim_hud(st),
        }

    for floor in live["floors"]:
        start = _sim_hud(st)
        events = []
        if floor["no"] > 1:
            events.append(apply_camp(floor))

        floor_failed = []
        for lv in floor["levels"]:
            ev = apply_level(lv, floor["id"])
            events.append(ev)
            if not ev["killed"]:
                floor_failed.append({
                    "id": lv["id"],
                    "title": lv["title"],
                    "floorId": floor["id"],
                    "floorNo": floor["no"],
                    "floorName": floor["name"],
                    "monster": lv["monster"],
                    "sev": lv["sev"],
                    "value": lv["value"],
                    "detail": lv["detail"],
                    "advice": lv["advice"],
                    "how": lv["how"],
                    "fixIds": lv.get("fixIds") or [],
                    "act": lv.get("act"),
                })

        floor_block = None
        if floor_failed:
            first = floor_failed[0]
            floor_block = {
                "floorId": floor["id"],
                "floorNo": floor["no"],
                "floorName": floor["name"],
                "levelId": first["id"],
                "levelTitle": first["title"],
                "monsterName": first["monster"]["name"],
                "sev": first["sev"],
                "value": first["value"],
                "detail": first["detail"],
                "advice": first["advice"],
                "fixIds": first.get("fixIds") or [],
                "how": first.get("how"),
                "floorFailed": [x["id"] for x in floor_failed],
            }
            if first_blocked is None:
                first_blocked = dict(floor_block)
            events.append(apply_boss_seal(floor, [x["id"] for x in floor_failed]))
        else:
            g = apply_gear(floor)
            if g:
                events.append(g)
            events.append(apply_boss(floor))
            bosses_killed += 1

        floors_out.append({
            "id": floor["id"],
            "no": floor["no"],
            "name": floor["name"],
            "subtitle": floor["subtitle"],
            "tint": floor["tint"],
            "story": floor["story"],
            "count": floor["count"],
            "levels": [
                {
                    "id": lv["id"],
                    "title": lv["title"],
                    "monster": lv["monster"],
                    "ok": lv["ok"],
                    "sev": lv["sev"],
                    "value": lv["value"],
                    "fixIds": lv.get("fixIds") or [],
                    "how": lv["how"],
                }
                for lv in floor["levels"]
            ],
            "events": events,
            "cleared": not floor_failed,
            "blocked": floor_block,
            "failed": [x["id"] for x in floor_failed],
            "start": start,
            "end": _sim_hud(st),
        })

    all_clear = len(floors_out) == len(live["floors"]) and all(f["cleared"] for f in floors_out)
    final_event = apply_final() if all_clear else None
    final_seal_event = None if all_clear else apply_final_seal()

    return {
        "ok": True,
        "mode": "tour",
        "base": dict(BASE_STAT),
        "floors": floors_out,
        "final": final_event,
        "finalSeal": final_seal_event,
        "summary": {
            "tour": True,
            "cleared": all_clear,
            "defeated": st["kills"],
            "total": total,
            "deaths": st["deaths"],
            "failedCount": len(failed_all),
            "failed": [x["id"] for x in failed_all],
            "failedDetail": failed_all,
            "blocked": first_blocked,
            "clearedFloors": sum(1 for f in floors_out if f["cleared"]),
            "bosses": bosses_killed,
            "gear": gear,
            "hud": _sim_hud(st),
            "floorResults": [
                {
                    "id": f["id"],
                    "no": f["no"],
                    "name": f["name"],
                    "defeated": f["count"] - len(f["failed"]),
                    "count": f["count"],
                    "cleared": f["cleared"],
                }
                for f in floors_out
            ],
        },
    }
