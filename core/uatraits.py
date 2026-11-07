"""UA 里的国产浏览器与国产设备特征。

`browserwebrtc` 早就把 `navigator.userAgent` 收下来了，但一直只存不用。
UA 是网页最先拿到、也最容易被忽略的一层：用户把系统语言改成英文、把时区
改成纽约、把出口换到美西，只要还开着微信内置浏览器或夸克，UA 里那串
`MicroMessenger` / `Quark` 就把中文区这件事重新说了一遍。

这一层和字体是互补的：字体说明「这台机器装了中文软件」，UA 说明
「你现在用的这个浏览器是国产的」。两个都不需要联网，也不需要额外权限。

只做两件事，都不下结论——严重程度由调用方按场景决定：

- `classify_browser()`：UA 里是不是国产浏览器 / 应用内 WebView；
- `classify_device()`：UA（以及 UA-CH 的 model）里是不是国产设备品牌。

正则一律带边界或足够长的特征串。`/mi/` 会匹配到 "Mozilla"，这种写法在
本项目里是禁止的——宁可漏报也不能让每台机器都命中。
"""
from __future__ import annotations

import re

# 国产浏览器与国内 App 的内置 WebView。顺序即优先级：
# 微信/钉钉这类「App 内打开」比独立浏览器更能说明使用场景。
_BROWSERS: tuple[tuple[str, str], ...] = (
    (r"micromessenger|wxwork", "微信 / 企业微信"),
    (r"dingtalk", "钉钉"),
    (r"alipayclient", "支付宝"),
    (r"aweme|bytedancewebview|toutiaomicroapp|newsarticle", "抖音 / 今日头条"),
    (r"xiaohongshu|xhsminiapp", "小红书"),
    (r"\bbilibili\b", "哔哩哔哩"),
    (r"weibo", "微博"),
    (r"quark", "夸克"),
    (r"ucbrowser|ucweb", "UC 浏览器"),
    (r"mqqbrowser|qqbrowser|\bqq/", "QQ 浏览器"),
    (r"baiduboxapp|bidubrowser|baidubrowser", "百度"),
    (r"miuibrowser|mibrowser|xiaomi/", "小米浏览器"),
    (r"huaweibrowser", "华为浏览器"),
    (r"heytapbrowser|oppobrowser", "OPPO 浏览器"),
    (r"vivobrowser", "vivo 浏览器"),
    (r"sogoumobilebrowser|\bmetasr\b|\bse 2\.x\b", "搜狗"),
    (r"360se|360ee|qihoobrowser|\bqhbrowser\b", "360 浏览器"),
    (r"2345explorer|2345browser", "2345"),
    (r"lbbrowser", "猎豹"),
    (r"theworld", "世界之窗"),
    (r"maxthon", "遨游"),
)

# 国产设备品牌。(特征, 名称, 权重)：鸿蒙是决定性的，也卖全球的品牌低一些。
_DEVICES: tuple[tuple[str, str, float], ...] = (
    (r"harmonyos|openharmony", "鸿蒙", 1.0),
    (r"huawei|\bhonor\b", "华为 / 荣耀", 0.8),
    (r"meizu", "魅族", 0.8),
    (r"nubia|\bzte\b", "中兴 / 努比亚", 0.7),
    # 小米的机型码有两种形态：M2101K7AG 这类旧码，和 2211133C 这类新码。
    # 两者都只在真机 UA / UA-CH model 里出现，普通浏览器串里不会有。
    (r"xiaomi|redmi|\bpoco\b|\bm2\d{3}[a-z0-9]+\b|\b2\d{6,7}[a-z]{1,3}\b",
     "小米 / 红米", 0.6),
    # OPPO 的机型码有三代写法：PD 系（PDEM10）、P+两位字母+M 系（PFZM10 /
    # PEWM00）、P+两位字母+三位数字（PHK110 / PJV110）。以前只写了 PD 系，
    # Find X / Reno 这些主力机型全漏。反过来的风险是误伤：SM-（三星）、
    # VOG-（华为）、LE/IN（一加）、RMX（真我）都不以 P 开头，实测不冲突。
    (r"\boppo\b|\bp[a-z]{2}(?:m\d{2}|\d{3})\b", "OPPO", 0.6),
    # `\bvivo\b` 不能写成裸 `vivo`：华硕 VivoBook 的 UA 里就有，那是笔记本。
    (r"\bvivo\b|\bv2\d{3}[a-z]{1,2}\b", "vivo", 0.6),
    (r"realme|\brmx\d{4}\b", "真我", 0.6),
    (r"oneplus", "一加", 0.6),
    (r"\blenovo\b|\bzuk\b", "联想", 0.5),
)

MAX_UA = 1024

_BROWSER_RES = tuple((re.compile(p, re.I), name) for p, name in _BROWSERS)
_DEVICE_RES = tuple((re.compile(p, re.I), name, score) for p, name, score in _DEVICES)


def _clean(ua: str) -> str:
    return str(ua or "")[:MAX_UA]


def classify_browser(ua: str) -> str:
    """UA 命中哪个国产浏览器 / App 内 WebView；没命中返回空串。"""
    text = _clean(ua)
    if not text:
        return ""
    for pattern, name in _BROWSER_RES:
        if pattern.search(text):
            return name
    return ""


def classify_device(ua: str) -> tuple[str, float]:
    """UA（可含 UA-CH 的 model）命中哪个国产设备品牌。返回 (名称, 权重)。"""
    text = _clean(ua)
    if not text:
        return "", 0.0
    for pattern, name, score in _DEVICE_RES:
        if pattern.search(text):
            return name, score
    return "", 0.0


def classify(ua: str) -> dict:
    """一次算完，给面板用。`ua` 为空时一律返回「没命中」，不猜。"""
    text = _clean(ua)
    device, score = classify_device(text)
    return {
        "ua": text,
        "checked": bool(text),
        "browser": classify_browser(text),
        "device": device,
        "deviceScore": score,
    }


def describe(result: dict) -> str:
    """一行摘要，写进证据里。"""
    parts = []
    if result.get("browser"):
        parts.append(f"浏览器 {result['browser']}")
    if result.get("device"):
        parts.append(f"设备 {result['device']}")
    return " · ".join(parts)
