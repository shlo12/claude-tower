"""静态规则：严重度权重、风险名单、分类定义、建议文案。"""

# ---------- 严重度 ----------
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "pass"]

SEVERITY_LABEL = {
    "critical": "高危",
    "high": "偏高",
    "medium": "中等",
    "low": "偏低",
    "info": "信息",
    "pass": "通过",
}

# 扣分权重（pass / info 不扣分）
WEIGHTS = {
    "critical": 18,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
    "pass": 0,
}

CATEGORY_META = {
    "fingerprint": {"label": "身份指纹", "desc": "跨账号可复用的设备/用户标识与本地会话残留", "icon": "finger"},
    "credential": {"label": "凭据与密钥", "desc": "Keychain 令牌、API Key、账号登录态", "icon": "key"},
    "marker": {"label": "隐蔽标记面", "desc": "客户端会上报的环境特征：中转地址、时区、区域关键词", "icon": "radar"},
    "network": {"label": "网络出口", "desc": "出口 IP 类型、地理归属、DNS 与代理链路", "icon": "globe"},
    "locale": {"label": "系统一致性", "desc": "时区、语言、区域设置是否与出口自洽", "icon": "clock"},
    "residue": {"label": "客户端残留", "desc": "桌面端、IDE 插件、全局安装与其他客户端痕迹", "icon": "box"},
    "device": {"label": "设备标识", "desc": "硬件级标识，只读展示（不可通过清理改变）", "icon": "chip"},
    "behavior": {"label": "行为与权限", "desc": "高危权限配置与隐私开关状态", "icon": "shield"},
}

# ---------- 时区 ----------
# Claude Code 客户端被公开分析出的判定条件：系统时区命中下列值即被视为中国用户
CN_TRIGGER_TZ = {"Asia/Shanghai", "Asia/Urumqi", "Asia/Chongqing", "Asia/Harbin", "PRC"}
# 同一时区带（UTC+8），不直接触发标记，但会造成"时区与出口地理不一致"的信号
GREATER_CHINA_TZ = {"Asia/Hong_Kong", "Asia/Macau", "Asia/Taipei"}

# ---------- 中转地址域名特征 ----------
OFFICIAL_HOSTS = {"api.anthropic.com", "claude.ai", "console.anthropic.com"}

# 公开分析报告提到客户端内置了约 147 个域名/关键词，以下为其中被公开讨论的高频特征
DOMAIN_RULES = [
    ("中国国家顶级域", [".cn"]),
    ("国内互联网厂商", [
        "baidu", "alibaba", "aliyun", "bytedance", "byted", "tencent", "huawei",
        "xiaomi", "jd.com", "meituan", "pinduoduo", "163.com", "qq.com",
        "sina", "sohu", "bilibili", "zhihu", "csdn",
    ]),
    ("国内大模型/AI 实验室", [
        "deepseek", "zhipu", "bigmodel", "moonshot", "kimi", "qwen", "dashscope",
        "minimax", "baichuan", "stepfun", "sensetime", "iflytek", "doubao",
        "volces", "volcengine", "hunyuan", "ernie", "siliconflow", "modelscope",
    ]),
    ("API 中转/代理服务", [
        "api2d", "closeai", "openai-sb", "oneapi", "new-api", "newapi", "aihubmix",
        "packycode", "packy", "yunwu", "apifox", "gptapi", "aiproxy", "chatanywhere",
        "ohmygpt", "gptgod", "geekai", "ppio", "302.ai", "laozhang", "dmnode",
        "relay", "proxyapi", "api-proxy",
    ]),
]

# ---------- 判定话术 ----------
VERDICT = [
    (90, "环境干净", "当前没有发现明显的关联信号，保持固定出口与固定设备即可。"),
    (80, "基本干净", "存在少量残留，属于可接受范围，建议顺手清掉指纹字段。"),
    (65, "需要处理", "有几项会稳定暴露环境特征，建议按优先级逐项处理。"),
    (50, "风险偏高", "多个维度同时指向同一身份，建议做一次完整清理。"),
    (0, "建议重建环境", "关联信号密集，最稳妥的做法是清理后使用全新的隔离配置目录。"),
]

DISCLAIMER = (
    "本工具只做本地环境自检与清理，不修改任何服务端数据，也不承诺规避平台风控。"
    "所有清理动作都在本机执行。缓存、诊断日志和凭据不留副本，不可还原；其他项目按预览清单处理。"
)


def verdict_for(score: int):
    for threshold, title, text in VERDICT:
        if score >= threshold:
            return title, text
    return "建议重建环境", ""


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"
