#!/usr/bin/env python3
"""Claude Shield 的静态与运行时检查。

不启动界面、不真的终止任何进程：这里只验证「开关条件写对了」「配色没跑偏」
「构建产物能用」，以及跑一次 --probe-dump 确认巡检至少不会崩。
"""
import json
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHIELD = ROOT / "shield"
# 用户拿到的是嵌在塔里的那一份；仓库根目录的单独构建只作为开发时的退路
NESTED = ROOT / "Claude Tower.app" / "Contents" / "Resources" / "Claude Shield.app"
APP = NESTED if NESTED.exists() else ROOT / "Claude Shield.app"
BIN = APP / "Contents/MacOS/Shield"


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def css_vars(text: str) -> dict:
    """:root 里的自定义属性。只取第一段 :root，够用。"""
    m = re.search(r":root\s*\{(.*?)\}", text, re.S)
    if not m:
        return {}
    out = {}
    for name, value in re.findall(r"--([\w-]+)\s*:\s*([^;]+);", m.group(1)):
        out[name] = re.sub(r"\s+", " ", value.strip())
    return out


class ProbeTests(unittest.TestCase):
    def test_probe_dump_is_valid_json_with_known_verdict(self):
        if not BIN.exists():
            self.skipTest("还没构建 Claude Shield.app")
        r = subprocess.run([str(BIN), "--probe-dump"], capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        for key in ("verdict", "title", "note", "claude", "tun", "sysProxy",
                    "clients", "tz", "baselineTz", "egressMask", "maskFresh",
                    "towerData", "towerState", "environmentReady", "idleState",
                    "egressAt", "country", "at", "interval"):
            self.assertIn(key, data)
        self.assertIn(data["verdict"], ("idle", "safe", "warn", "danger"))
        self.assertIn(data["towerState"], ("missing", "stale", "ok"))
        self.assertIn(data["idleState"], ("notower", "stale", "blocked", "ready"))
        self.assertIsInstance(data["claude"], bool)
        self.assertIsInstance(data["clients"], list)
        # 时区必须能读出来，读不到就说明 /etc/localtime 的解析退化了
        self.assertTrue(data["tz"])
        # 这个输出经常被重定向到文件，落盘的不能是完整真实地址
        for key in ("stun", "stunForeign"):
            for ip in data.get(key, []):
                self.assertIn("*", ip, f"--probe-dump 的 {key} 漏了未打码地址")

    def test_tun_matches_kernel_route_for_public_ips(self):
        """FlClash 的 TUN 不改 default，而是把 0/0 拆成更细的前缀。
        用同样的内核查找核对：公网多数走 utun，面板就必须说已接管。"""
        if not BIN.exists():
            self.skipTest("还没构建 Claude Shield.app")
        r = subprocess.run([str(BIN), "--probe-dump"], capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        hits = []
        for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            p = subprocess.run(["/sbin/route", "-n", "get", "-inet", ip],
                               capture_output=True, text=True, timeout=5)
            iface = gateway = ""
            for line in p.stdout.splitlines():
                t = line.strip()
                if t.startswith("interface:"):
                    iface = t.split(":", 1)[1].strip()
                elif t.startswith("gateway:"):
                    gateway = t.split(":", 1)[1].strip()
            if iface:
                hits.append((iface, gateway))
        if not hits:
            self.skipTest("本机没有可读的 IPv4 路由")
        tunnels = [i for i, g in hits
                   if i.startswith("utun") or g.startswith(("198.18.", "198.19."))]
        self.assertEqual(data["tun"], len(tunnels) >= 2,
                         f"路由表说 {hits}，面板却给出 tun={data['tun']}")
        if len(tunnels) >= 2:
            self.assertEqual(data["tunIface"], tunnels[0])

    def test_probe_never_shells_out_through_sh(self):
        src = read(SHIELD / "Probe.swift")
        self.assertNotIn("/bin/sh", src)
        self.assertNotIn("shell", src.lower().replace("shells", ""))

    def test_probe_uses_absolute_binary_paths(self):
        src = read(SHIELD / "Probe.swift")
        calls = re.findall(r'sh\("([^"]+)"', src)
        self.assertTrue(calls)
        for path in calls:
            self.assertTrue(path.startswith("/"), f"{path} 不是绝对路径")

    def test_probe_has_hard_timeout(self):
        src = read(SHIELD / "Probe.swift")
        self.assertIn("DispatchSemaphore", src)
        self.assertIn("p.terminate()", src)


HARNESS = r'''
import Foundation

// 断言失败就打印并累计，最后用退出码表态。
var bad = 0
func ok(_ cond: Bool, _ msg: String) {
    if !cond { print("FAIL: " + msg); bad += 1 }
}

// ---- isFakeIP ----
ok(Probe.isFakeIP("198.18.2.160"), "198.18/16 应算 fake-ip")
ok(Probe.isFakeIP("198.19.0.1"), "198.19/16 应算 fake-ip")
ok(!Probe.isFakeIP("198.17.1.1"), "198.17 不在 198.18.0.0/15 里")
ok(!Probe.isFakeIP("198.20.1.1"), "198.20 不在 198.18.0.0/15 里")
ok(!Probe.isFakeIP("160.79.104.10"), "真实地址不该被当成 fake-ip")
ok(!Probe.isFakeIP(""), "空串不该被当成 fake-ip")

// ---- 子进程输出：先排空再等退出 ----
// `ps -axo comm=` 在本机有 100KB+，超过管道缓冲后子进程会卡在 write 上。
// 先等退出再读就是死等，2 秒超时后拿到空串——进程检测会永远「没看到」。
let bulk = Probe.sh("/usr/bin/seq", ["1", "20000"], timeout: 3)
ok(bulk.split(separator: "\n").count == 20000,
   "sh 必须并发排空管道，大输出不能卡死")

// ---- 路由分类：default 留在 Wi-Fi、公网走 utun 也算接管 ----
ok(Probe.isTunnel(iface: "utun13", gateway: "198.18.0.1"), "utun + fake-ip 网关应算隧道")
ok(Probe.isTunnel(iface: "en0", gateway: "198.18.0.1"), "网关落在 198.18 也算隧道")
ok(Probe.isTunnel(iface: "utun4", gateway: "192.168.1.1"), "网卡名是 utun 就算隧道")
ok(!Probe.isTunnel(iface: "en0", gateway: "192.168.0.1"), "普通 Wi-Fi 不该算隧道")
ok(!Probe.isTunnel(iface: "", gateway: ""), "空值不该算隧道")

func snap(claude: Bool = true, tun: Bool = false, proxy: Bool = false,
          clients: [String] = [], dnsIP: String = "", fake: Bool = false,
          checked: Bool = false) -> Snapshot {
    var s = Snapshot()
    s.claudeRunning = claude
    s.tunUp = tun
    s.sysProxy = proxy
    s.proxyClients = clients
    s.dnsIP = dnsIP
    s.dnsFake = fake
    s.dnsChecked = checked
    return s
}

// ---- 主判定矩阵 ----
ok(snap(claude: false, tun: true, fake: true, checked: true).verdict == .idle,
   "Claude 没跑就是待命，哪怕出口有问题")
ok(snap(tun: true, fake: true, checked: true).verdict == .safe, "TUN + fake-ip 应守护中")
ok(snap(proxy: true, fake: true, checked: true).verdict == .safe, "系统代理 + fake-ip 应守护中")
ok(snap(tun: false, proxy: false, clients: []).verdict == .danger, "无出口无代理进程应报警")
ok(snap(tun: false, proxy: false, clients: ["mihomo"]).verdict == .warn,
   "有代理进程但没接管，只提醒不下死结论")

// Claude 没运行时，主状态回答的是「能不能启动」，不能被网络异常抢成
// 「UDP 出口不一致」那种在跑时的标题。
var idleLeak = Snapshot()
idleLeak.claudeRunning = false
idleLeak.baselineTz = "Asia/Taipei"
idleLeak.tz = "Asia/Taipei"
idleLeak.sysProxy = true
idleLeak.egressMask = "5.34.*.136"
idleLeak.maskFresh = true
idleLeak.stunChecked = true
idleLeak.stunForeign = ["5.34.220.136", "112.97.32.112"]
ok(idleLeak.stunLeak, "这个样例本身应该是泄漏，否则测不到标题分支")
ok(idleLeak.verdict == .idle, "Claude 没运行，判定必须是待命")
ok(idleLeak.idleState == .blocked, "UDP 分裂应挡住启动")
ok(idleLeak.title == "先别启动 Claude", "待命标题应回答能不能启动，而不是复述 UDP 异常")
ok(idleLeak.note.contains("UDP"), "要说明是 UDP 出口分裂挡住了启动")

var idleDns = Snapshot()
idleDns.claudeRunning = false
idleDns.baselineTz = "Asia/Taipei"
idleDns.tz = "Asia/Taipei"
idleDns.egressMask = "5.34.*.136"
idleDns.maskFresh = true
idleDns.tunUp = true
idleDns.dnsIP = "160.79.104.10"
idleDns.dnsChecked = true
ok(idleDns.dnsSuspect, "这个样例本身应是 DNS 存疑")
ok(idleDns.idleState == .blocked, "DNS 没接管应挡住启动")
ok(idleDns.title == "先别启动 Claude", "待命标题不能被 DNS 异常改成在跑时的标题")
ok(idleDns.note.contains("DNS"), "要说明是 DNS 没接管挡住了启动")

// ---- 待命就绪：缺塔 / 过期 / 可启动 ----
var noTower = Snapshot()
noTower.claudeRunning = false
noTower.sysProxy = true   // 先排掉「没有出口」，单独测缺塔
ok(noTower.idleState == .notower, "没有塔的基线必须是 notower")
ok(noTower.title == "先让塔扫描一次", "缺塔基线时应让用户先去扫描")
ok(noTower.note.contains("塔"), "缺塔基线时要说明为什么要扫描")
ok(!noTower.environmentReady, "缺塔基线不能算环境就绪")

var ready = Snapshot()
ready.claudeRunning = false
ready.baselineTz = "Asia/Taipei"
ready.tz = "Asia/Taipei"
ready.tunUp = true
ready.egressMask = "5.34.*.136"
ready.maskFresh = true
ready.dnsIP = "198.18.2.160"
ready.dnsFake = true
ready.dnsChecked = true
ready.stunChecked = true
ready.stunForeign = ["5.34.220.136"]
ok(ready.hasTowerData && ready.towerFresh, "这份样例应有可用基线")
ok(ready.idleState == .ready, "出口、DNS、UDP、时区都对得上时应判 ready")
ok(ready.title == "可以启动 Claude", "环境正常时应直接告诉用户可以启动")
ok(ready.note.contains("可以启动"), "就绪说明要落到「可以启动」")
ok(ready.environmentReady, "就绪样例的 environmentReady 应为 true")

var stale = ready
stale.maskFresh = false
ok(stale.idleState == .stale, "基线过期不能判就绪")
ok(stale.title == "基线过期了", "过期时标题要指向重新扫描")
ok(!stale.environmentReady, "基线过期不能算环境就绪")

var noExitIdle = ready
noExitIdle.tunUp = false
ok(noExitIdle.idleState == .blocked, "没有出口必须挡住启动")
ok(noExitIdle.title == "先别启动 Claude", "没有出口时标题要明确拦住")
ok(noExitIdle.note.contains("出口"), "要说明是出口不在")
ok(!noExitIdle.environmentReady, "没有出口不能算环境就绪")

var tzBad = ready
tzBad.tz = "Asia/Shanghai"
ok(tzBad.idleState == .blocked, "时区漂移也要挡住启动")
ok(tzBad.note.contains("时区"), "要说明是时区对不上")

// ---- DNS 判据：只在 TUN 在位时成立 ----
let dnsBad = snap(tun: true, dnsIP: "160.79.104.10", fake: false, checked: true)
ok(dnsBad.dnsSuspect, "TUN 在位却拿到真实地址，应判 DNS 存疑")
ok(dnsBad.verdict == .warn, "DNS 存疑只降到 warn，不能直接 danger")
ok(dnsBad.note.contains("160.79.104.10"), "提示里要带上解析到的地址，否则用户无从查起")
// 出口那一行明明还是绿的，标题说「出口存疑」会自相矛盾
ok(dnsBad.title == "DNS 未接管", "DNS 存疑要有自己的标题，不能沿用「出口存疑」")

// 系统代理模式拿到真实地址是正常的：系统代理本来就不管 DNS
let proxyReal = snap(proxy: true, dnsIP: "160.79.104.10", fake: false, checked: true)
ok(!proxyReal.dnsSuspect, "系统代理模式下不该因为 DNS 没被接管而报警")
ok(proxyReal.verdict == .safe, "系统代理 + 真实解析应仍是守护中")

// 查不到不等于泄漏：不能因为一次超时就报警
let noDns = snap(tun: true, checked: false)
ok(!noDns.dnsSuspect, "没查成不该判存疑")
ok(noDns.verdict == .safe, "没查成时保持原判")

// 出口不在时一律不判 DNS
let noExit = snap(tun: false, proxy: false, dnsIP: "1.1.1.1", fake: false, checked: true)
ok(!noExit.dnsSuspect, "出口不在时 DNS 判据不参与")
ok(noExit.verdict == .danger, "出口不在仍应是 danger")

// ---- STUN 响应解析 ----
// 手搓一个响应包。位运算这块最容易写错，但真发 UDP 的测试在 CI 上不可靠。
func stunPacket(_ ip: String, txn: [UInt8], xor: Bool) -> [UInt8] {
    var p: [UInt8] = [0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42] + txn
    var oct = ip.split(separator: ".").map { UInt8($0)! }
    if xor {
        let c: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
        for i in 0..<4 { oct[i] ^= c[i] }
    }
    p += [0x00, xor ? 0x20 : 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00] + oct
    return p
}

let txn: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
ok(Probe.parseStun(stunPacket("5.34.220.136", txn: txn, xor: true), txn: txn) == "5.34.220.136",
   "XOR-MAPPED-ADDRESS 解析错了")
ok(Probe.parseStun(stunPacket("112.97.32.112", txn: txn, xor: true), txn: txn) == "112.97.32.112",
   "高位字节的 XOR 没处理对")
ok(Probe.parseStun(stunPacket("1.2.3.4", txn: txn, xor: false), txn: txn) == "1.2.3.4",
   "老版 MAPPED-ADDRESS 也该认")
// 事务 ID 对不上：UDP 不保证来源，不能把别人的包当成自己的
let other: [UInt8] = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]
ok(Probe.parseStun(stunPacket("5.34.220.136", txn: other, xor: true), txn: txn) == nil,
   "事务 ID 不匹配必须丢弃")
var broken = stunPacket("5.34.220.136", txn: txn, xor: true)
broken[1] = 0x11   // 不是 Success Response
ok(Probe.parseStun(broken, txn: txn) == nil, "非成功响应必须丢弃")

// ---- 打码地址比对 ----
ok(Probe.matchesMask("5.34.220.136", "5.34.*.136"), "同 /16 + 同末段应算命中")
ok(Probe.matchesMask("5.34.7.136", "5.34.*.136"), "第三段是通配的")
ok(!Probe.matchesMask("5.35.220.136", "5.34.*.136"), "第二段不同不该命中")
ok(!Probe.matchesMask("5.34.220.137", "5.34.*.136"), "末段不同不该命中")
ok(!Probe.matchesMask("::1", "5.34.*.136"), "IPv6 不该拿去对 IPv4 掩码")

// ---- 证据打码 ----
ok(Probe.maskIP("5.34.220.136") == "5.34.*.136", "STUN 结果落盘/上面板前必须打码")
ok(Probe.maskIP("112.97.32.112") == "112.97.*.112", "国内真实地址也不能原样露出")
ok(Probe.maskIP("::1") == "::1", "非 IPv4 原样返回，不崩")

// ---- 泄漏判定：只报「分裂」 ----
func leak(_ foreign: [String], mask: String = "5.34.*.136",
          fresh: Bool = true, checked: Bool = true) -> Bool {
    var s = Snapshot()
    s.egressMask = mask
    s.maskFresh = fresh
    s.stunChecked = checked
    s.stunForeign = foreign
    return s.stunLeak
}

ok(!leak(["5.34.220.136"]), "只有一个且对得上，不该报")
ok(leak(["5.34.220.136", "112.97.32.112"]), "一通一直连，这才是泄漏")
ok(!leak(["9.9.9.9", "8.8.8.8"]), "全部对不上多半是基线过期，不能报")
ok(!leak(["5.34.220.136", "112.97.32.112"], fresh: false), "基线过期不参与判定")
ok(!leak(["5.34.220.136", "112.97.32.112"], mask: ""), "没有基线不参与判定")
ok(!leak(["5.34.220.136", "112.97.32.112"], mask: "2408:****"), "IPv6 基线没法比对")
ok(!leak(["5.34.220.136", "112.97.32.112"], checked: false), "没探到不参与判定")

// 泄漏时标题要单独给，别沿用「出口存疑」
var leakSnap = Snapshot()
leakSnap.claudeRunning = true
leakSnap.egressMask = "5.34.*.136"
leakSnap.maskFresh = true
leakSnap.stunChecked = true
leakSnap.stunForeign = ["5.34.220.136", "112.97.32.112"]
ok(leakSnap.title == "UDP 出口不一致", "泄漏要有自己的标题")

// ---- 时区修复的入参校验 ----
// 时区名会拼进 osascript 的提权字符串，不校验等于自己开个注入口子
ok(TzFix.isSafe("Asia/Taipei"), "正常时区名应放行")
ok(TzFix.isSafe("America/Argentina/Buenos_Aires"), "多级时区名应放行")
ok(!TzFix.isSafe(""), "空串不放行")
ok(!TzFix.isSafe("Asia/Taipei; rm -rf /"), "分号不放行")
ok(!TzFix.isSafe("Asia/Taipei\" & do shell script \"x"), "引号不放行")
ok(!TzFix.isSafe("-settimezone"), "不能以减号开头，否则会被当成参数")
ok(!TzFix.isSafe("Asia Taipei"), "空格不放行")

// ---- 塔留下的设置：只读、只比对 ----
// IPv6 记录里那个服务还关着才算数；读不到模式不参与判定。
ok(!Probe.ipv6NeedsFix(modes: [:]), "没有记录时不参与判定")
ok(!Probe.ipv6NeedsFix(modes: ["Wi-Fi": "Off"]), "还关着就不该报漂移")
ok(!Probe.ipv6NeedsFix(modes: ["Wi-Fi": "关闭"]), "中文模式名也要认")
ok(Probe.ipv6NeedsFix(modes: ["Wi-Fi": "Automatic"]), "又回到 Automatic 就是漂移")
ok(Probe.ipv6NeedsFix(modes: ["Wi-Fi": "Off", "USB LAN": "Automatic"]),
   "记录里任何一个服务被打开都要报")

// 规则清单只比 TYPE,payload，三种客户端的写法都要能认出来。
ok(Probe.ruleKey("  - DOMAIN-SUFFIX,claude.ai,PROXY") == "DOMAIN-SUFFIX,claude.ai",
   "YAML 列表项应归一成规则对")
ok(Probe.ruleKey("  \"DST-PORT,443,PROXY\",") == "DST-PORT,443",
   "Script.js 的带引号写法应归一成规则对")
ok(Probe.ruleKey("rules:") == nil, "YAML 的键不是规则")
ok(Probe.ruleKey("# DOMAIN-SUFFIX,claude.ai,PROXY") == nil, "注释不算数")
ok(Probe.ruleKey("DOMAIN-SUFFIX,claude.ai") == "DOMAIN-SUFFIX,claude.ai",
   "塔记下的规则对本身也要能归一")

var guardSpec = RuleGuard()
guardSpec.path = NSTemporaryDirectory() + "ccclean-guard-\(getpid()).yaml"
guardSpec.rules = ["DOMAIN-SUFFIX,claude.ai", "DST-PORT,443"]
let guardText = "rules:\n  - DOMAIN-SUFFIX,claude.ai,PROXY\n  - \"DST-PORT,443,DIRECT\"\n"
try? guardText.write(toFile: guardSpec.path, atomically: true, encoding: .utf8)
let g1 = Probe.checkRuleGuard(guardSpec)
ok(g1.checked && !g1.drift, "规则都还在时不该报漂移")
// 策略名被客户端重写不算漂移：塔自己核对运行时配置也只比前两段
ok(g1.missing.isEmpty, "规则对上时 missing 应为空")
try? FileManager.default.removeItem(atPath: guardSpec.path)
let g2 = Probe.checkRuleGuard(guardSpec)
ok(g2.checked && g2.drift && g2.missing.count == 2,
   "规则文件不在了必须报漂移（ClashX 订阅更新就是这样）")
var noRules = RuleGuard()
noRules.path = "/tmp/whatever"
ok(!Probe.checkRuleGuard(noRules).checked, "没有规则清单时不参与判定")

// 待命降频：Claude 没在跑时 5 分钟一次，在跑时保持原来的频率。
ok(Probe.idleProbeTTL >= 240 && Probe.idleProbeTTL <= 600,
   "待命时的探测周期应落在 5 分钟量级")
ok(Probe.activeProbeTTL <= 60, "Claude 在跑时 DNS 不该被拖慢")
ok(Probe.stunActiveTTL <= 60, "Claude 在跑时 STUN 仍应一分钟一次")

// ---- 传输诊断：只看「几条到达」 ----
// 判定是纯函数，这里构造结果直接跑，不发一个包出去。
func tr(_ apiStatus: Int, _ apiErr: String, _ webStatus: Int, _ webErr: String,
        checked: Bool = true) -> Probe.TransportResult {
    var r = Probe.TransportResult()
    r.checked = checked
    r.at = 1_700_000_000
    var a = Probe.TransportEndpoint()
    a.status = apiStatus
    a.error = apiErr
    a.seconds = 0.12
    var w = Probe.TransportEndpoint()
    w.status = webStatus
    w.error = webErr
    w.seconds = 0.26
    r.api = a
    r.web = w
    return r
}

var tv = Probe.transportVerdict(tr(200, "", 200, ""))
ok(tv.state == "ok", "两条都到就是通")
ok(tv.label.contains("ms"), "通的标签要带耗时：" + tv.label)
ok(tv.label.contains("260"), "取两条里慢的那条，不是平均：" + tv.label)
ok(tv.detail.contains("200"), "要写出返回码，证明请求真的到了对端")

// 401 / 403 也算到达：这一测本来就不带凭据
ok(tr(401, "", 403, "").api.reached, "有状态码就算到达，401 不是失败")

tv = Probe.transportVerdict(tr(401, "", 0, "timeout"))
ok(tv.state == "warn", "只到一条是存疑，不是断")
ok(tv.label == "一条不通", "标签要直说一条不通：" + tv.label)
ok(tv.detail.contains("claude.ai") && tv.detail.contains("超时"),
   "要点名是哪条、为什么：" + tv.detail)

tv = Probe.transportVerdict(tr(0, "timeout", 0, "connect"))
ok(tv.state == "bad", "两条都不到就是断")
ok(tv.label == "不通", "普通失败说「不通」：" + tv.label)

tv = Probe.transportVerdict(tr(0, "tls", 0, "timeout"))
ok(tv.state == "bad", "证书异常也是断")
ok(tv.label == "证书异常", "证书失败要单独说，不能和超时混成一句：" + tv.label)
ok(tv.detail.contains("信任"), "要讲清为什么哨兵不替你放行")

// 没测过不能默认通过
tv = Probe.transportVerdict(tr(0, "", 0, "", checked: false))
ok(tv.state == "off", "没测过留空，不判通过")
ok(tv.label.isEmpty, "没测过不该有结论")

// 错误码 → 人话
ok(Probe.transportErrorLabel("timeout") == "超时", "超时要能说人话")
ok(Probe.transportErrorLabel("tls") == "证书异常", "证书要能说人话")
ok(Probe.transportErrorLabel("dns") == "解析失败", "DNS 要能说人话")
ok(Probe.transportErrorLabel("") == "无响应", "空错误码说无响应")

exit(bad == 0 ? 0 : 1)
'''


class DnsTests(unittest.TestCase):
    """DNS 判据的真实逻辑测试。

    不用字符串匹配去猜条件写没写对——Probe.swift 只依赖 Foundation，
    把它和一个生成的 main.swift 编在一起，直接跑断言。
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.tmp = tempfile.mkdtemp(prefix="shield-dns-")
        d = Path(cls.tmp)
        (d / "Probe.swift").write_text(read(SHIELD / "Probe.swift"), encoding="utf-8")
        (d / "TzFix.swift").write_text(read(SHIELD / "TzFix.swift"), encoding="utf-8")
        (d / "main.swift").write_text(HARNESS, encoding="utf-8")
        cls.bin = d / "harness"
        r = subprocess.run(
            ["/usr/bin/swiftc", "-O", str(d / "Probe.swift"), str(d / "TzFix.swift"),
             str(d / "main.swift"), "-o", str(cls.bin)],
            capture_output=True, text=True, timeout=180,
        )
        cls.build_err = r.stderr if r.returncode else ""

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_verdict_matrix(self):
        if not self.bin.exists():
            self.fail("测试桩没编出来：" + self.build_err[:800])
        r = subprocess.run([str(self.bin)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, "判定矩阵有反例：\n" + r.stdout + r.stderr)

    def test_dns_only_probed_when_exit_ready(self):
        """出口不在时查 DNS，等于我们自己去泄漏一次。"""
        src = read(SHIELD / "Probe.swift")
        m = re.search(r"if s\.exitReady \{(.*?)\n        \}", src, re.S)
        self.assertIsNotNone(m, "DNS 探测不在 exitReady 分支里")
        self.assertIn("dnsProbe(", m.group(1))

    def test_dig_has_timeout(self):
        src = read(SHIELD / "Probe.swift")
        m = re.search(r'sh\("/usr/bin/dig",[^)]*timeout:\s*([\d.]+)\)', src)
        self.assertIsNotNone(m, "dig 调用缺少显式超时")
        self.assertLessEqual(float(m.group(1)), 5.0)

    def test_stun_only_probed_when_exit_ready(self):
        """出口不在时打 STUN，等于自己把真实地址送到对方服务器上。"""
        src = read(SHIELD / "Probe.swift")
        m = re.search(r"if s\.exitReady \{(.*?)\n        \}", src, re.S)
        self.assertIsNotNone(m, "探测不在 exitReady 分支里")
        self.assertIn("stunProbe(", m.group(1))

    def test_stun_judges_only_foreign_nodes(self):
        """国内节点回真实地址是分流规则的正确结果，拿它判泄漏会天天误报。"""
        src = read(SHIELD / "Probe.swift")
        m = re.search(r"var stunLeak: Bool \{(.*?)\n    \}", src, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("stunForeign", body)
        self.assertNotIn("stunAll", body, "判定不能看国内节点的结果")
        # 只报「分裂」，不报「不符」：全不符多半是基线过期
        self.assertIn("hit && miss", body)

    def test_stun_cache_is_short(self):
        """每 30 秒打 4 个服务器太吵，但缓存太久就失去监测意义。
        Claude 没在跑时放宽到 5 分钟，在跑时仍是一分钟。"""
        src = read(SHIELD / "Probe.swift")
        m = re.search(r"static let stunActiveTTL: TimeInterval = (\d+)", src)
        self.assertIsNotNone(m, "STUN 的运行期缓存不见了")
        self.assertLessEqual(int(m.group(1)), 300)
        self.assertLessEqual(int(m.group(1)), 60, "Claude 在跑时 STUN 不该被拖慢")
        m = re.search(r"static let idleProbeTTL: TimeInterval = (\d+)", src)
        self.assertIsNotNone(m, "待命降频常量不见了")
        self.assertGreaterEqual(int(m.group(1)), 240)

    def test_idle_probe_can_be_forced_fresh(self):
        """面板打开和「立即巡检」必须看到现在，而不是最多 5 分钟前的缓存。"""
        src = read(SHIELD / "Probe.swift")
        self.assertIn("forceFresh", src)
        self.assertIn("dropProbeCaches()", src)
        app = read(SHIELD / "ShieldApp.swift")
        self.assertIn("probeNow(forceFresh: true)", app)
        self.assertIn("probeNow(forceStun: true, forceFresh: true)", app)

    def test_rule_guard_only_compares_rule_pairs(self):
        """整文件哈希会被客户端自己重写配置误伤；只比规则对。"""
        src = read(SHIELD / "Probe.swift")
        m = re.search(r"static func checkRuleGuard.*?\n    \}", src, re.S)
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertIn("ruleKey", body)
        self.assertNotIn("sha", body.lower())
        # 文件不在了要算漂移：ClashX 订阅更新就是整份重写
        self.assertIn("contents(atPath", body)

    def test_tzfix_requires_admin_and_validates(self):
        src = read(SHIELD / "TzFix.swift")
        self.assertIn("with administrator privileges", src)
        self.assertIn("isSafe(", src)
        # 校验必须在拼字符串之前，否则等于把注入口子开在自己的提权路径上
        self.assertLess(src.index("guard isSafe(tz)"), src.index("do shell script"))


class GateTests(unittest.TestCase):
    """L2 是有破坏性的，开关条件必须一条不少。"""

    def setUp(self):
        self.src = read(SHIELD / "ShieldApp.swift")

    def test_level2_requires_all_four_conditions(self):
        m = re.search(r"if cfg\.enabled[^\n]*snap\.verdict == \.danger", self.src)
        self.assertIsNotNone(m, "L2 的触发条件被改动了")
        cond = m.group(0)
        for token in ("cfg.enabled", "!paused", "cfg.level >= 2", "snap.verdict == .danger"):
            self.assertIn(token, cond)

    def test_level2_only_fires_on_danger(self):
        # warn 是「有代理进程但没看到接管」，不能据此杀进程
        self.assertNotIn("snap.verdict == .warn, cfg.level >= 2", self.src)

    def test_kill_has_cooldown(self):
        self.assertIn("lastKill", self.src)
        m = re.search(r"now - lastKill > (\d+)", self.src)
        self.assertIsNotNone(m, "冷却判断不见了")
        self.assertGreaterEqual(int(m.group(1)), 30)

    def test_kill_prefers_graceful_terminate(self):
        self.assertIn("app.terminate()", self.src)
        # 先 terminate 再 forceTerminate，不能一上来就强杀
        self.assertLess(self.src.index("app.terminate()"), self.src.index("app.forceTerminate()"))

    def test_kill_falls_back_to_bundle_path(self):
        """巡检按进程路径认 Claude，急停若只认 bundle id，两边对不上时
        就会「面板说危险、急停说没找到进程」——最坏的一种静默失效。"""
        killer = self.src.split("enum Killer", 1)[1]
        self.assertIn("claudefordesktop", killer)
        self.assertIn("bundleURL?.path", killer, "急停缺少按路径兜底的退路")
        self.assertIn("/Claude.app", killer)
        # 别把自己的包也认成 Claude
        self.assertIn("Claude Shield.app", killer)

    def test_idle_state_does_not_notify(self):
        """Claude 没跑时网络异常只上面板；弹通知会让人以为 Claude 那边出事了。"""
        parts = self.src.split("if snap.claudeRunning {", 1)
        self.assertEqual(len(parts), 2, "缺少 claudeRunning 的通知闸门")
        inner = parts[1].split("} else {", 1)[0]
        self.assertIn("snap.dnsSuspect", inner)
        self.assertIn("snap.stunLeak", inner)
        self.assertIn("notify(", inner)
        tail = parts[1].split("} else {", 1)[1].split("\n        }", 1)[0]
        self.assertIn("lastDnsSuspect = false", tail)
        self.assertIn("lastStunLeak = false", tail)

    def test_paused_state_skips_action(self):
        self.assertIn("var paused: Bool", self.src)
        self.assertIn("cfg.pausedUntil >", self.src)

    def test_hits_are_deduped(self):
        store = read(SHIELD / "Store.swift")
        self.assertIn("300", store)
        self.assertIn("last.kind == kind", store)

    def test_missing_tower_baseline_notifies_once(self):
        """只装了哨兵时，面板有横幅；Claude 在跑时还要喊一次。
        但每 30 秒喊一次等于逼用户关通知，所以只喊一次。"""
        self.assertIn("notifiedNoTower", self.src)
        self.assertIn(
            "} else if snap.claudeRunning, cfg.enabled, !paused, !notifiedNoTower {",
            self.src)
        self.assertIn('kind: "notower"', self.src)
        self.assertIn("notifiedNoTower = true", self.src)
        # 基线接上后要把标志复位，下次真的丢了还能再提醒
        self.assertIn("notifiedNoTower = false", self.src)

    # ---- 动手之后必须留痕、必须说清楚 ----

    def test_every_kill_is_recorded_even_inside_dedupe_window(self):
        """命中记录对同一种状态有 5 分钟去重，但「杀过一次」不能被吞掉：
        冷却 60 秒意味着十分钟里可能杀十次，只剩一条记录等于没记。"""
        store = read(SHIELD / "Store.swift")
        self.assertIn("force: Bool = false", store)
        self.assertIn("if !force, let last = cfg.hits.last", store)
        i = self.src.index('Store.appendHit(&cfg, kind: "kill"')
        self.assertIn("force: true", self.src[i:i + 200])

    def test_kill_result_separates_success_from_failure(self):
        """「已请求退出」和「没找到进程」混成一句话，就是把失败报成成功。"""
        killer = self.src.split("enum Killer", 1)[1]
        self.assertIn("enum Outcome", killer)
        for case in ("case requested(", "case forced(", "case notFound", "case refused("):
            self.assertIn(case, killer)
        self.assertIn("case .requested, .forced: return true", killer)
        self.assertIn("case .notFound, .refused: return false", killer)
        # 三种失败各有各的标题，不能共用一句
        self.assertIn("该终止 Claude，但没找到进程", killer)
        self.assertIn("Claude 拒绝退出，请手动关掉", killer)

    def test_kill_notification_is_not_the_still_running_one(self):
        """L2 杀完之后还说「Claude 还在运行」，正好把最该知道的事说反了。"""
        line = 'notify(title: snap.connections.direct > 0 ?'
        self.assertEqual(self.src.count(line), 1)
        self.assertGreater(self.src.index(line),
                           self.src.index("} else if snap.verdict == .danger"))
        tail = self.src.split("if let outcome = killed {", 1)[1]
        self.assertIn("notify(title: outcome.title", tail.split("}", 1)[0])

    def test_kill_notification_carries_the_reason(self):
        """通知正文要有「为什么」和「结果」两截：只写「已终止」等于没说原因。"""
        self.assertIn('body: "\\(snap.title)。\\(outcome.note)"', self.src)

    # ---- 客户端在跑但没接管 ----

    def test_takeover_only_escalates_after_a_grace_period(self):
        """客户端重启内核、切换接管模式时会短暂没有接管。
        一看到就判危险是误杀，所以要持续一段才升级。"""
        probe = read(SHIELD / "Probe.swift")
        m = re.search(r"static let takeoverGrace: TimeInterval = (\d+)", probe)
        self.assertIsNotNone(m, "持续时长阈值不见了")
        self.assertGreaterEqual(int(m.group(1)), 15, "太短等于没有去抖")
        self.assertIn("guard missing, since > 0 else { return false }", probe)
        self.assertIn(">= takeoverGrace", probe)
        self.assertIn("return takeoverEscalated ? .danger : .warn", probe)
        # 不能退回「认到客户端就算安全」的老逻辑
        self.assertNotIn("if !proxyClients.isEmpty { return .warn }", probe)

    def test_takeover_grace_is_time_based_not_tick_based(self):
        """按轮次计数会被「立即巡检」打乱：连点三次就是三轮，然后杀掉无辜进程。"""
        self.assertNotIn("takeoverStreak", self.src)
        self.assertIn("if takeoverSince == 0 { takeoverSince = snap.at.timeIntervalSince1970 }",
                      self.src)
        self.assertIn("takeoverSince = 0", self.src)

    def test_level2_polls_at_ten_seconds(self):
        """L2 的窗口就是「隧道断了到进程被杀」的那段裸奔时间。"""
        m = re.search(r"var effectiveInterval[\s\S]{0,500}?\n    \}", self.src)
        self.assertIsNotNone(m, "周期计算不见了")
        body = m.group(0)
        self.assertIn("cfg.level >= 2", body)
        self.assertIn("min(base, 10)", body)
        # 周期没变就不能重建计时器，否则每轮把计时器推倒，永远等不到下一次
        self.assertIn("if !force, secs == scheduledSecs", self.src)

    # ---- 启动闸门（第三档） ----

    def test_gate_listens_for_launch_instead_of_polling(self):
        """待命时 30 秒一轮，靠轮询最多晚半分钟才反应——那已经不算「拦在启动前」。"""
        self.assertIn("NSWorkspace.didLaunchApplicationNotification", self.src)
        self.assertIn("@objc func appDidLaunch(", self.src)
        self.assertIn("NSWorkspace.applicationUserInfoKey", self.src)
        self.assertIn("Killer.isClaude(app)", self.src)

    def test_gate_requires_strict_mode(self):
        body = self.src.split("@objc func appDidLaunch(", 1)[1][:600]
        self.assertIn("cfg.level >= 2", body)
        self.assertIn("!paused", body)
        # 闸门自己再跑一轮，也不能绕过同样的开关
        self.assertIn("cfg.level >= 2", self.src.split("func gateCheck(", 1)[1][:400])

    def test_gate_only_blocks_when_it_is_sure(self):
        """缺基线、基线过期是「判不了」，判不了就不拦——
        拿自己的无知去阻止用户干活，比漏一次更糟。"""
        body = self.src.split("func gateDecide(", 1)[1][:2500]
        self.assertIn("snap.idleState == .blocked", body)
        self.assertNotIn(".notower", body)
        self.assertNotIn(".stale", body)

    def test_gate_kill_is_recorded_and_announced(self):
        body = self.src.split("func gateDecide(", 1)[1][:2500]
        self.assertIn("Killer.stop()", body)
        self.assertIn('kind: "gate"', body)
        self.assertIn("force: true", body)
        self.assertIn('notify(title: "Claude 启动检查未通过"', body)
        # 拦下来的理由要进通知正文，不能只说「没让启动」
        self.assertIn('body: "\\(snap.title)。\\(outcome.note)"', body)

    def test_gate_does_not_go_through_apply(self):
        """apply 会再记一条 danger、再喊一句「Claude 还在运行」，
        和闸门刚发的那条正好打架。"""
        body = self.src.split("func gateDecide(", 1)[1][:2500]
        self.assertNotIn("apply(snap)", body)
        self.assertIn("publish(snap)", body)

    def test_gate_waits_before_judging(self):
        """刚启动那一两秒客户端可能正在切 TUN，立刻下结论会误拦。"""
        m = re.search(r"static let gateDelay: TimeInterval = ([\d.]+)", self.src)
        self.assertIsNotNone(m, "闸门的等待时长不见了")
        self.assertGreaterEqual(float(m.group(1)), 1.0)
        self.assertLessEqual(float(m.group(1)), 10.0, "等太久就不算拦在启动前了")

    def test_two_modes_and_legacy_migration(self):
        store = read(SHIELD / "Store.swift")
        self.assertIn("if level < 1 || level > 2 { level = 1 }", store)
        self.assertIn("lv >= 1, lv <= 2", self.src)
        js = read(SHIELD / "web" / "shield.js")
        self.assertIn("if (lv >= 2) {", js)
        self.assertNotIn("data-lv=\"3\"", read(SHIELD / "web" / "shield.html"))
        self.assertIn("if level == 3 { level = 2 }", store)


VERDICT_HARNESS = r'''
import Foundation

var rows: [[String: Any]] = []
func row(_ name: String, _ s: Snapshot) {
    rows.append(["case": name, "verdict": s.verdict.rawValue,
                 "title": s.title, "note": s.note,
                 "idleState": s.idleState.rawValue])
}

// 1 什么都没有：Claude 在跑，既没 TUN 也没系统代理，也没认到客户端
var bare = Snapshot()
bare.claudeRunning = true
row("bare", bare)

// 2 认到了客户端但没接管，还没到升级时间
var takeover = bare
takeover.proxyClients = ["verge-mihomo"]
row("takeover", takeover)

// 3 同上，但持续够久，已经升级
var escalated = takeover
escalated.takeoverMissing = true
escalated.takeoverEscalated = true
row("escalated", escalated)

// 4 TUN 在位，DNS 没接管
var dns = bare
dns.tunUp = true
dns.tunIface = "utun13"
dns.dnsChecked = true
dns.dnsFake = false
dns.dnsIP = "1.2.3.4"
row("dns", dns)

// 5 TUN 在位、DNS 正常、UDP 出口分裂
var stun = bare
stun.tunUp = true
stun.dnsChecked = true
stun.dnsFake = true
stun.egressMask = "5.34.*.136"
stun.maskFresh = true
stun.stunChecked = true
stun.stunForeign = ["5.34.9.136", "23.1.2.3"]
row("stun", stun)

// 6 待命：Claude 没在跑
row("idle", Snapshot())

// 7 升级标记还挂着，但出口回来了——不能继续判危险
var back = takeover
back.tunUp = true
back.takeoverEscalated = true
row("escalated-but-up", back)

// 8 闸门要判的三种状态：拦、不拦（判不了）、不拦（可以启动）
var notower = Snapshot()
notower.tunUp = true
row("gate-notower", notower)

var ready = Snapshot()
ready.tunUp = true
ready.baselineTz = "Asia/Taipei"
ready.tz = "Asia/Taipei"
ready.egressMask = "5.34.*.136"
ready.maskFresh = true
ready.dnsChecked = true
ready.dnsFake = true
row("gate-ready", ready)

// 9 去抖边界
let now = Date()
var edges: [[String: Any]] = []
for (label, ago) in [("never", -1.0), ("0s", 0.0), ("1s", 1.0), ("29s", 29.0),
                     ("30s", 30.0), ("300s", 300.0)] {
    let since = ago < 0 ? 0 : now.timeIntervalSince1970 - ago
    edges.append(["case": label,
                  "escalated": Probe.escalatedTakeover(missing: true, since: since, now: now)])
}
edges.append(["case": "not-missing",
              "escalated": Probe.escalatedTakeover(
                  missing: false, since: now.timeIntervalSince1970 - 300, now: now)])

let data = try! JSONSerialization.data(withJSONObject: ["rows": rows, "edges": edges],
                                       options: [.sortedKeys])
print(String(data: data, encoding: .utf8)!)
'''


class VerdictTests(unittest.TestCase):
    """把 Snapshot 造出来，直接问它「这一刻该说什么」。

    判定矩阵是这套东西的核心：说错一句，用户要么白紧张一场，要么以为
    有人在守、其实没人。所以不靠读源码，真的编译出来跑一遍。
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.tmp = tempfile.mkdtemp(prefix="shield-verdict-")
        d = Path(cls.tmp)
        (d / "Probe.swift").write_text(read(SHIELD / "Probe.swift"), encoding="utf-8")
        # 多文件编译时只有 main.swift 能写顶层语句
        (d / "main.swift").write_text(VERDICT_HARNESS, encoding="utf-8")
        cls.bin = d / "verdict"
        r = subprocess.run(
            ["/usr/bin/swiftc", "-O", str(d / "Probe.swift"), str(d / "main.swift"),
             "-o", str(cls.bin)],
            capture_output=True, text=True, timeout=240,
        )
        cls.build_err = r.stderr if r.returncode else ""
        cls.rows, cls.edges = {}, {}
        if cls.bin.exists():
            r = subprocess.run([str(cls.bin)], capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                data = json.loads(r.stdout)
                cls.rows = {row["case"]: row for row in data["rows"]}
                cls.edges = {row["case"]: row["escalated"] for row in data["edges"]}
            else:
                cls.build_err += r.stderr

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        if not self.rows:
            self.fail("判定桩没编出来：" + self.build_err[:800])

    def test_bare_state_is_danger(self):
        self.assertEqual(self.rows["bare"]["verdict"], "danger")
        self.assertEqual(self.rows["bare"]["title"], "出口已断")

    def test_client_running_without_takeover_stays_warn(self):
        self.assertEqual(self.rows["takeover"]["verdict"], "warn")
        self.assertEqual(self.rows["takeover"]["title"], "出口存疑")

    def test_sustained_takeover_failure_becomes_danger(self):
        """客户端在跑却没接管，流量就是直连。以前这一档只提醒，等于漏。"""
        row = self.rows["escalated"]
        self.assertEqual(row["verdict"], "danger")
        self.assertEqual(row["title"], "代理在跑，但没接管")
        self.assertIn("真实网络", row["note"])
        self.assertIn("verge-mihomo", row["note"])

    def test_escalation_yields_to_a_working_exit(self):
        """出口回来了就该恢复正常，不能让上一轮的升级标记继续挂着。"""
        self.assertEqual(self.rows["escalated-but-up"]["verdict"], "safe")
        self.assertEqual(self.rows["escalated-but-up"]["title"], "守护中")

    def test_dns_and_stun_keep_their_own_wording(self):
        self.assertEqual(self.rows["dns"]["verdict"], "warn")
        self.assertEqual(self.rows["dns"]["title"], "DNS 未接管")
        self.assertEqual(self.rows["stun"]["verdict"], "warn")
        self.assertEqual(self.rows["stun"]["title"], "UDP 出口不一致")

    def test_idle_answers_whether_it_is_safe_to_start(self):
        self.assertEqual(self.rows["idle"]["verdict"], "idle")
        self.assertEqual(self.rows["idle"]["title"], "先别启动 Claude")

    def test_takeover_grace_boundary(self):
        """29 秒不动手，30 秒才动手。手动重测不该把时间线算成轮次。"""
        self.assertFalse(self.edges["never"])
        self.assertFalse(self.edges["0s"])
        self.assertFalse(self.edges["1s"])
        self.assertFalse(self.edges["29s"])
        self.assertTrue(self.edges["30s"])
        self.assertTrue(self.edges["300s"])
        # 状态没命中时，就算时间再久也不升级
        self.assertFalse(self.edges["not-missing"])

    def test_gate_blocks_only_on_blocked(self):
        """闸门只在「确定不能启动」时动手：
        没出口 → 拦；缺基线（判不了）→ 不拦；一切就绪 → 不拦。"""
        self.assertEqual(self.rows["bare"]["idleState"], "blocked")
        self.assertEqual(self.rows["gate-notower"]["idleState"], "notower")
        self.assertEqual(self.rows["gate-ready"]["idleState"], "ready")


class LifecycleTests(unittest.TestCase):
    """常驻但不自启、不自动改时区：这两件事都只能由用户点。"""

    def setUp(self):
        self.src = read(SHIELD / "ShieldApp.swift")

    def test_closing_last_window_does_not_quit(self):
        m = re.search(
            r"func applicationShouldTerminateAfterLastWindowClosed[^{]*\{\s*(.*?)\s*\}",
            self.src, re.S)
        self.assertIsNotNone(m, "缺少关闭窗口的生命周期判断")
        self.assertIn("false", m.group(1))

    def test_launch_does_not_auto_start_or_fix_timezone(self):
        m = re.search(r"func applicationDidFinishLaunching.*?\n    \}", self.src, re.S)
        self.assertIsNotNone(m)
        body = m.group(0)
        # 用带括号的调用名：installed() 只是只读，install() 才是动系统
        self.assertNotIn("LoginItem.install(", body)
        self.assertNotIn("LoginItem.toggle", body)
        self.assertNotIn("TzFix.restore", body)

    def test_timezone_fix_only_from_user_action(self):
        self.assertEqual(self.src.count("TzFix.restore("), 1,
                         "时区恢复只能有一个入口，且必须是用户点击")
        m = re.search(r'case "fixtz":(.*?)case ', self.src, re.S)
        self.assertIsNotNone(m)
        self.assertIn("TzFix.restore(", m.group(1))

    def test_login_item_only_via_toggle(self):
        self.assertIn("LoginItem.toggle()", self.src)
        m = re.search(r"static func toggle\(\) \{(.*?)\n    \}", self.src, re.S)
        self.assertIsNotNone(m)
        self.assertIn("install()", m.group(1), "自启只能由面板开关写入")


class StoreTests(unittest.TestCase):
    def test_legacy_modes_decode_and_encode_as_two_modes(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="shield-mode-") as td:
            d = Path(td)
            (d / "main.swift").write_text('''import Foundation
struct RuleGuard: Codable {}
for (old, expected) in [(1,1),(2,2),(3,2),(0,1),(4,1)] {
    let data = "{\\"level\\":\\(old),\\"enabled\\":false,\\"pausedUntil\\":123,\\"baselineTz\\":\\"Etc/UTC\\"}".data(using:.utf8)!
    let cfg = try JSONDecoder().decode(Config.self, from:data)
    precondition(cfg.level == expected && !cfg.enabled && cfg.pausedUntil == 123 && cfg.baselineTz == "Etc/UTC")
    let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(cfg)) as! [String:Any]
    precondition(encoded["level"] as! Int == expected)
}
print("mode migration passed")
''')
            built = subprocess.run(["/usr/bin/swiftc", str(SHIELD / "Store.swift"), str(d / "main.swift"),
                                    "-o", str(d / "modes")], capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            run = subprocess.run([str(d / "modes")], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_log_rotates(self):
        store = read(SHIELD / "Store.swift")
        self.assertIn("maxLogBytes", store)
        self.assertIn('appendingPathExtension("1")', store)

    def test_state_file_is_owner_only(self):
        store = read(SHIELD / "Store.swift")
        self.assertIn("0o600", store)

    def test_missing_keys_do_not_break_decoding(self):
        store = read(SHIELD / "Store.swift")
        # Tower 写出的文件可能缺字段，每个键都要 decodeIfPresent
        self.assertGreaterEqual(store.count("decodeIfPresent"), 8)

    def test_interval_and_level_are_clamped(self):
        store = read(SHIELD / "Store.swift")
        self.assertIn("if interval < 5", store)
        # 三档：只观察 / 断了就停 / 不让启动
        self.assertIn("if level < 1 || level > 2", store)

    def test_probe_reloads_tower_baseline_each_time(self):
        """塔在 Shield 运行期间刚扫过一次，不能等哨兵重启才看见。"""
        src = read(SHIELD / "ShieldApp.swift")
        m = re.search(r"func probeNow\(.*?\n    \}", src, re.S)
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertIn("Store.loadBaseline()", body)
        for field in ("baselineTz", "country", "egressIP", "egressAt"):
            self.assertIn(f"cfg.{field} = disk.{field}", body)

    def test_baseline_loader_only_reads_tower_keys(self):
        """重读基线不能顺手把 Shield 自己的开关和命中记录盖掉。"""
        store = read(SHIELD / "Store.swift")
        m = re.search(r"static func loadBaseline\(\) -> Baseline \{(.*?)\n    \}",
                      store, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        for field in ("baselineTz", "country", "egressIP", "egressAt", "ruleGuard"):
            self.assertIn(f"cfg.{field}", body)
        self.assertNotIn("cfg.enabled", body)
        self.assertNotIn("cfg.hits", body)

    def test_rule_guard_is_owned_by_tower(self):
        """塔撤销修复时会删掉 ruleGuard；Shield 保存自己的开关时必须跟盘走，
        否则会把内存里的旧清单写回去，永远报「规则不见了」。"""
        store = read(SHIELD / "Store.swift")
        self.assertIn("trimmed.ruleGuard = disk.ruleGuard", store)
        app = read(SHIELD / "ShieldApp.swift")
        self.assertIn("cfg.ruleGuard = disk.ruleGuard", app)


class UiTests(unittest.TestCase):
    def test_tokens_match_tower(self):
        tower = css_vars(read(ROOT / "web/style.css"))
        panel = css_vars(read(SHIELD / "web/shield.css"))
        shared = set(panel) & set(tower)
        self.assertGreaterEqual(len(shared), 10, "共享的 token 太少，可能改名字了")
        drift = {k: (panel[k], tower[k]) for k in shared if panel[k] != tower[k]}
        self.assertEqual(drift, {}, "Shield 的配色和 Tower 不一致")

    def test_panel_loads_its_own_assets(self):
        html = read(SHIELD / "web/shield.html")
        self.assertIn('href="shield.css"', html)
        self.assertIn('src="shield.js"', html)

    def test_takeover_hit_has_its_own_label(self):
        """命中记录里「代理未接管」和「出口已断」是两件事：
        前者客户端还在跑，后者连客户端都没有。混成一条会让人查错方向。"""
        js = read(SHIELD / "web" / "shield.js")
        self.assertIn("h.kind === 'takeover' ? '代理未接管'", js)
        self.assertIn("h.kind === 'gate' ? '拦下启动'", js)
        # 三种「动过手 / 流量真漏了」的记录都用红色，和「只是提醒」分开
        cls = next(line for line in js.splitlines() if "var cls =" in line)
        for kind in ("kill", "takeover", "gate"):
            self.assertIn(f"h.kind === '{kind}'", cls)
        self.assertIn("'danger'", cls)

    def test_open_tower_is_always_on_the_panel(self):
        """塔关掉之后，哨兵面板是用户唯一还开着的窗口。入口不能只在
        「缺基线」横幅里出现——那时用户已经看不到基线以外的路了。"""
        html = read(SHIELD / "web/shield.html")
        self.assertIn('id="btn-open"', html)
        # 顶栏右上角：版本号在塔按钮左边，页脚不再重复版本
        header = html.split("<header>", 1)[1].split("</header>", 1)[0]
        self.assertIn('id="btn-open"', header)
        self.assertIn('id="ver"', header)
        self.assertLess(header.index('id="ver"'), header.index('id="btn-open"'))
        footer = html.split("<footer>", 1)[1].split("</footer>", 1)[0]
        self.assertNotIn('id="ver"', footer)
        # 像素塔图标：塔尖、檐口、拱门，和 app 图标一个形；方角、关抗锯齿
        self.assertIn("<svg", header)
        self.assertIn('shape-rendering="crispEdges"', header)
        self.assertIn('width="11" height="14"', header, "塔要竖着长，不是城墙")
        path = header.split('fill-rule="evenodd" d="', 1)[1].split('"', 1)[0]
        self.assertGreaterEqual(path.count("M"), 3, "外轮廓 + 窗 + 门三段闭合线")
        js = read(SHIELD / "web/shield.js")
        self.assertIn("$('#btn-open').addEventListener", js)
        self.assertIn("action: 'opentower'", js)
        css = read(SHIELD / "web/shield.css")
        self.assertIn("header button.open", css)
        self.assertIn("header button.open .icon", css)
        # 「打开塔」在顶栏常驻，不挤进工具那一排。工具排是等宽网格，
        # 列数必须等于按钮数——多一个少一个都会挤成半格。
        acts = css.split(".acts {", 1)[1].split("}", 1)[0]
        html = read(SHIELD / "web/shield.html")
        row = html.split('class="acts"', 1)[1].split("</div>", 1)[0]
        tools = re.findall(r'id="(btn-[\w-]+)"', row)
        cols = re.search(r"repeat\((\d+), 1fr\)", acts)
        self.assertIsNotNone(cols, f"工具按钮要用等宽网格：{acts!r}")
        self.assertEqual(int(cols.group(1)), len(tools),
                         f"工具按钮 {len(tools)} 个（{'、'.join(tools)}），"
                         f"网格却是 {cols.group(1)} 列")
        self.assertNotIn("btn-open", tools, "「打开塔」在顶栏，不占工具这一排")

    def test_panel_escapes_dynamic_text(self):
        js = read(SHIELD / "web/shield.js")
        self.assertIn("function esc(", js)
        self.assertIn("esc(h.note)", js)

    def test_level2_needs_second_click(self):
        js = read(SHIELD / "web/shield.js")
        self.assertIn("pendingLv2", js)
        self.assertIn("确认开启", js)

    def test_mode_tiles_explain_what_the_level_does(self):
        """光写「只观察 / 断了就停」，用户看不出来哪一档会真动手。
        两行标签、待确认态、二次确认的计时器都得在，而且 JS 不能把
        整块 textContent 抹掉——那会把说明文字一起写没。"""
        html = read(SHIELD / "web/shield.html")
        css = read(SHIELD / "web/shield.css")
        js = read(SHIELD / "web/shield.js")
        for lv in ("1", "2"):
            self.assertIn(f'data-lv="{lv}" data-name=', html)
        self.assertEqual(html.count('class="lv-title"'), 2)
        self.assertEqual(html.count('class="lv-sub"'), 2)
        self.assertIn('.seg button.on[data-lv="2"]', css)
        self.assertIn(".seg button.asking", css)
        self.assertIn("resetSegLabels", js)
        # 4 秒确认窗口里来一次重绘，不能把「确认开启」擦回默认文案
        self.assertIn("if (!pendingLv2) resetSegLabels();", js)
        # 只针对模式卡片这一段：别处（诊断传输按钮）改写自己的 textContent 是正常的，
        # 但模式卡片是「标题 + 说明」两行，整块写 textContent 会把说明抹掉。
        seg = js.split("document.querySelectorAll('#seg button').forEach", 1)[1]
        seg = seg.split("$('#btn-now')", 1)[0]
        self.assertNotIn("b.textContent", seg, "模式卡片不能整块写 textContent")

    def test_observe_icon_is_a_crisp_pixel_eye(self):
        """只观察的眼睛要和顶栏的塔同一套画法：行内像素 SVG、关抗锯齿。
        旧版是 1.5px 椭圆描边 + 径向渐变瞳，2x 下边缘是平滑的，
        夹在像素元素里很扎眼。"""
        html = read(SHIELD / "web/shield.html")
        css = read(SHIELD / "web/shield.css")
        btn = html.split('data-lv="1"', 1)[1].split("</button>", 1)[0]
        self.assertIn('class="ic-eye"', btn)
        self.assertIn('shape-rendering="crispEdges"', btn)
        self.assertIn('width="17" height="11"', btn)
        path = btn.split('fill-rule="evenodd" d="', 1)[1].split('"', 1)[0]
        self.assertGreaterEqual(path.count("M"), 3, "外轮廓 + 内圈 + 瞳三段闭合线")
        self.assertNotIn('data-lv="1"]::before', css, "眼睛不能再回到 CSS 椭圆")

    def test_production_uses_popover_not_window(self):
        src = read(SHIELD / "ShieldApp.swift")
        self.assertIn("NSPopover()", src)
        # 预览窗口只能在 previewMode 分支里建
        self.assertIn("if previewMode {", src)
        self.assertIn("buildPreviewWindow()", src)

    # 巡检实际看的每一项都必须在面板上有一行。少了一行不是「省地方」，
    # 而是「看得到结论、看不到依据」——用户没法判断该去查哪一层。
    MONITORED = ["f-claude", "f-route", "f-tun", "f-proxy", "f-connections",
                 "f-egress", "f-dns", "f-udp", "f-transport",
                 "f-tz", "f-btz", "f-at", "f-update"]

    def test_panel_lists_every_monitored_field(self):
        html = read(SHIELD / "web/shield.html")
        for fid in self.MONITORED:
            self.assertIn(f'id="{fid}"', html, f"面板缺少 {fid} 这一行")
        # 旧的合并行已经拆开，留着会让人以为还有一路数据没显示
        self.assertNotIn('id="f-exit"', html)

    def test_panel_drops_proxy_process_row(self):
        """进程名是启发式：认不出来时写「没看到」会让用户以为代理没开。
        出口看路由和系统代理就够了，这一行不再上屏。"""
        html = read(SHIELD / "web/shield.html")
        self.assertNotIn("代理进程", html)
        self.assertNotIn('id="f-clients"', html)
        self.assertIn("公网路由", html)
        js = read(SHIELD / "web/shield.js")
        self.assertNotIn("f-clients", js)
        self.assertNotIn("clientsKnown", js)

    def test_every_panel_row_is_actually_rendered(self):
        """HTML 里写了行、JS 里忘了填，是最坏的一种：永远显示「—」，
        看起来像「没数据」，其实是「没接线」。"""
        html = read(SHIELD / "web/shield.html")
        js = read(SHIELD / "web/shield.js")
        rows = re.findall(r'id="(f-[\w-]+)"', html)
        self.assertEqual(sorted(rows), sorted(self.MONITORED))
        for fid in rows:
            self.assertIn(f"$('#{fid}')", js, f"{fid} 在 HTML 里有行，JS 里没渲染")

    def test_every_row_has_a_status_mark(self):
        """一行黑字既可能是「好」也可能是「没查」，必须用 ✓ / ! / × / – 表态。"""
        css = read(SHIELD / "web/shield.css")
        for st in ("ok", "warn", "bad"):
            self.assertIn(f'[data-st="{st}"]::before', css)
        self.assertIn('content: "✓"', css)
        self.assertIn('content: "×"', css)
        # 空心细边框在暗底上太弱，必须是实心圆底 + 光晕才扫得出来
        ok_block = css.split('[data-st="ok"]::before', 1)[1].split("}", 1)[0]
        self.assertIn("background: var(--pass)", ok_block)
        self.assertIn("box-shadow", ok_block)
        bad_block = css.split('[data-st="bad"]::before', 1)[1].split("}", 1)[0]
        self.assertIn("background: var(--critical)", bad_block)
        js = read(SHIELD / "web/shield.js")
        self.assertIn("li.dataset.st", js)
        self.assertIn("st === 'warn'", js)
        self.assertIn("st === 'bad'", js)

    def test_payload_carries_baseline_freshness(self):
        """面板要显示「多久以前记的」「哪国出口」。字段不推过去，
        JS 只能退化成「有基线」，说不清它还值不值得信。"""
        src = read(SHIELD / "ShieldApp.swift")
        for key in ('"maskFresh"', '"egressAt"', '"country"'):
            self.assertIn(key, src)
        js = read(SHIELD / "web/shield.js")
        self.assertIn("p.maskFresh", js)
        self.assertIn("p.egressAt", js)
        self.assertIn("p.country", js)

    def test_missing_tower_data_shows_a_banner(self):
        """只装了 Shield、没装塔时，面板不能看起来一切正常。
        除了状态标题，还要有一条常驻横幅和一个能直接打开塔的按钮。"""
        html = read(SHIELD / "web/shield.html")
        self.assertIn('id="tower-warn"', html)
        self.assertIn('id="btn-tower"', html)
        js = read(SHIELD / "web/shield.js")
        self.assertIn("p.towerState", js)
        self.assertIn("tower-warn", js)
        self.assertIn("action: 'opentower'", js)
        src = read(SHIELD / "ShieldApp.swift")
        self.assertIn("com.ccclean.app", src)
        self.assertIn('case "opentower"', src)
        for key in ('"towerData"', '"towerState"', '"environmentReady"', '"idleState"'):
            self.assertIn(key, src, f"payload 缺 {key}，面板没法判断能不能启动")

    def test_idle_prompt_says_what_to_do(self):
        """待命时不能只说「没在守」：正常就给可启动，异常就给出拦路的那一项。"""
        src = read(SHIELD / "Probe.swift")
        for title in ("可以启动 Claude", "先别启动 Claude", "先让塔扫描一次"):
            self.assertIn(f'return "{title}"', src)
        self.assertIn("var idleState: IdleState", src)
        self.assertIn("var environmentReady: Bool", src)

    def test_drift_and_autostart_banners_are_wired(self):
        """IPv6 / 规则漂移、自启失效都必须能在面板上看见，
        而且按钮要接到真实动作上（打开塔 / 重装启动项）。"""
        html = read(SHIELD / "web/shield.html")
        for fid in ("drift-warn", "btn-drift", "login-warn", "btn-relogin"):
            self.assertIn(f'id="{fid}"', html, f"面板缺少 {fid}")
        js = read(SHIELD / "web/shield.js")
        for key in ("p.ipv6Drift", "p.ruleDrift", "p.ruleMissing", "p.loginBroken"):
            self.assertIn(key, js, f"面板没读 {key}")
        self.assertIn("action: 'opentower'", js)
        self.assertIn("action: 'login'", js)
        src = read(SHIELD / "ShieldApp.swift")
        for key in ('"ipv6Checked"', '"ipv6Drift"', '"ruleChecked"',
                    '"ruleDrift"', '"ruleMissing"', '"loginBroken"'):
            self.assertIn(key, src, f"payload 缺 {key}")

    def test_autostart_survival_is_checked_not_just_presence(self):
        """plist 在但指向旧位置时，开机静默起不来——只看文件存在会漏掉。"""
        src = read(SHIELD / "ShieldApp.swift")
        self.assertIn("PropertyListSerialization", src)
        self.assertIn("pointsHere", src)
        self.assertIn("ProgramArguments", src)
        # 失效时点一下是「修」，不能把残留启动项删掉
        m = re.search(r'case "login":(.*?)case "log"', src, re.S)
        self.assertIsNotNone(m)
        self.assertIn("LoginItem.install()", m.group(1))

    def test_panel_has_room_for_all_rows(self):
        """12 行指标 + 缺塔横幅 + 模式 + 按钮 + 最近，744 装不下。"""
        src = read(SHIELD / "ShieldApp.swift")
        m = re.search(r"makeWebView\(NSSize\(width: 340, height: (\d+)\)\)", src)
        self.assertIsNotNone(m)
        self.assertGreaterEqual(int(m.group(1)), 770)
        shot = read(ROOT / "tools/shoot-shield.py")
        m = re.search(r"W, H = (\d+), (\d+)", shot)
        self.assertIsNotNone(m)
        self.assertGreaterEqual(int(m.group(2)), 795, "截图高度没跟着面板一起加")


class TransportTests(unittest.TestCase):
    """传输诊断的接线。

    判定逻辑本身在 DnsTests 的 Swift 桩里跑（纯函数，不发网络）；这里只管
    「面板那一行有没有真的接上」——少推一个字段，那一行就永远显示「还没测」，
    看起来像没数据，其实是没接线。
    """

    def setUp(self):
        self.html = read(SHIELD / "web/shield.html")
        self.js = read(SHIELD / "web/shield.js")
        self.app = read(SHIELD / "ShieldApp.swift")
        self.probe = read(SHIELD / "Probe.swift")

    def test_panel_has_a_transport_row_and_button(self):
        self.assertIn('id="f-transport"', self.html)
        self.assertIn('id="btn-transport"', self.html)
        self.assertIn("传输", self.html)

    def test_payload_carries_every_transport_field(self):
        for key in ("transportChecked", "transportState", "transportLabel",
                    "transportDetail", "transportAt"):
            self.assertIn(f'"{key}": snap.', self.app, f"payload 缺 {key}")

    def test_panel_renders_the_row(self):
        self.assertIn("$('#f-transport')", self.js)
        self.assertIn("p.transportChecked", self.js)
        self.assertIn("p.transportLabel", self.js)

    def test_button_posts_and_is_disabled_without_exit(self):
        self.assertIn("action: 'transport'", self.js)
        self.assertIn("bt.disabled = true", self.js, "出口不在时按钮要禁用")
        self.assertIn('case "transport"', self.app, "Swift 侧没接这个动作")

    def test_targets_are_fixed_and_carry_no_credentials(self):
        """目标写死、只发 HEAD、不带凭据——否则哨兵就是个现成的扫描器，
        或者一个会顺手泄露账号的探针。"""
        m = re.search(r"static let transportTargets = \[(.*?)\]", self.probe, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertEqual(body.count("https://"), 2, "只有两个固定目标")
        self.assertIn("api.anthropic.com", body)
        self.assertIn("claude.ai", body)
        self.assertIn('req.httpMethod = "HEAD"', self.probe, "只发 HEAD，不下载正文")
        self.assertIn('setValue("", forHTTPHeaderField: "Authorization")', self.probe,
                      "不能带凭据")
        self.assertIn("httpCookieStorage = nil", self.probe)

    def test_transport_never_enters_the_verdict(self):
        """一次握手成功证明不了之后每个包都安全，失败也不该终止 Claude。"""
        m = re.search(r"var verdict: Verdict \{(.*?)\n    \}", self.probe, re.S)
        self.assertIsNotNone(m)
        self.assertNotIn("transport", m.group(1))

    def test_probe_runs_only_when_exit_ready(self):
        """出口不在时去连 Anthropic，测的是「这条路本身不通」，没有意义。"""
        block = self.probe.split("if s.exitReady {", 1)[1].split("} else {", 1)[0]
        self.assertIn("transportProbe(", block)
        self.assertIn("transportProbe(force:", self.probe)

    def test_probe_dump_exposes_transport(self):
        """--probe-dump 是端到端自检，新探针也要能在那儿看到。"""
        main = read(SHIELD / "main.swift")
        for key in ("transportChecked", "transportState", "transportLabel",
                    "transportDetail", "transportAt"):
            self.assertIn(f'"{key}"', main)
        self.assertIn("forceTransport: true", main)


class IconTests(unittest.TestCase):
    """菜单栏图标的静态检查。

    用户的要求是「没事一个样、有事另一个样」，落到代码上是三件事：
    四态齐全、上色的两态必须关掉 template、换了图必须同时换 tooltip。
    """

    def setUp(self):
        self.src = read(SHIELD / "ShieldIcon.swift")
        self.app = read(SHIELD / "ShieldApp.swift")

    def test_four_states_exist(self):
        for case in ("case idle", "case safe", "case warn", "case danger"):
            self.assertIn(case, self.src)

    def test_template_only_for_uncolored_states(self):
        """template 带不了颜色：上色的两种必须关掉，否则橙红会被涂成灰白。"""
        m = re.search(r"static func isTemplate\(_ state: ShieldIconState\) -> Bool \{(.*?)\n    \}",
                      self.src, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn(".idle", body)
        self.assertIn(".safe", body)
        self.assertNotIn(".warn", body, "上色的状态不能开 template")
        self.assertNotIn(".danger", body, "上色的状态不能开 template")

    def test_colors_match_panel(self):
        """菜单栏说「金」、面板也必须是同一个金，否则像两个程序。

        取的是面板状态卡那两个 token（`.state[data-v=...]`），不是严重度色阶。
        """
        tokens = css_vars(read(SHIELD / "web/shield.css"))
        for token, swift in (("gold", "warnColor"), ("critical", "dangerColor")):
            hexv = tokens[token].lstrip("#")
            want = [int(hexv[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            m = re.search(rf"{swift} = NSColor\(calibratedRed: ([\d.]+), "
                          r"green: ([\d.]+), blue: ([\d.]+)", self.src)
            self.assertIsNotNone(m, f"{swift} 找不到")
            for got, expect, ch in zip(m.groups(), want, "rgb"):
                self.assertAlmostEqual(float(got), expect, places=2,
                                       msg=f"{swift} 的 {ch} 和 --{token} (#{hexv}) 对不上")
        # 状态色不能借用严重度色阶：两套语义混用，改一处另一处会跟着错
        css = read(SHIELD / "web/shield.css")
        self.assertIn('.state[data-v="warn"] h1   { color: var(--gold); }', css)
        self.assertNotIn("warnColor = NSColor(calibratedRed: 0.910", self.src)

    def test_icon_and_tooltip_always_change_together(self):
        """菜单栏显示红叉、悬停却写着「守护中」，比画错还糟。"""
        body = re.search(r"func paintIcon\(_ state: ShieldIconState, tooltip: String\) \{(.*?)\n    \}",
                         self.app, re.S)
        self.assertIsNotNone(body)
        self.assertIn("button?.image =", body.group(1))
        self.assertIn("toolTip", body.group(1))
        # 除了 paintIcon 自己，任何地方都不许直接改 image
        rest = self.app.replace(body.group(0), "")
        self.assertNotIn("button?.image =", rest,
                         "有地方绕过 paintIcon 直接换图，tooltip 会留在旧状态")

    def test_icon_follows_verdict_and_idle_state(self):
        m = re.search(r"func iconState\(_ snap: Snapshot\) -> ShieldIconState \{(.*?)\n    \}",
                      self.app, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        for case in (".safe", ".warn", ".danger"):
            self.assertIn(f"return {case}", body)
        # Claude 没在跑时，图标要和面板一样按 idleState 改写
        self.assertIn("snap.idleState == .ready ? .safe : .warn", body)
        js = read(SHIELD / "web/shield.js")
        self.assertIn("p.idleState === 'ready'", js)
        self.assertIn("idleState !== 'ready'", js)
        self.assertIn("v = 'safe'", js)
        self.assertIn("v = 'warn'", js)

    def test_guard_off_and_paused_draw_idle(self):
        """用户主动关掉/暂停时不该顶着红叉——那是擦不掉的噪音。"""
        m = re.search(r"func iconState\(_ snap: Snapshot\) -> ShieldIconState \{(.*?)\n    \}",
                      self.app, re.S)
        body = m.group(1)
        self.assertIn("if !cfg.enabled { return .idle }", body)
        self.assertIn("if paused { return .idle }", body)

    def test_build_script_compiles_icon_source(self):
        self.assertIn("shield/ShieldIcon.swift", read(ROOT / "tools/build-shield.sh"))

    def test_icon_is_drawn_not_imported(self):
        """图标是画出来的，不是 png——仓库里不该有菜单栏素材。"""
        self.assertIn("NSImage(size:", self.src)
        self.assertNotIn("NSImage(named:", self.src)
        self.assertEqual(list((SHIELD / "web").glob("*.png")), [])


# 把四种状态各画一遍，回读像素。交给 Python 断言的性质见 IconRenderTests。
ICON_HARNESS = r'''
import AppKit

// 36×36 采样：2 倍够看出挖空，又不至于慢。
let n = 36

func name(_ s: ShieldIconState) -> String {
    switch s {
    case .idle: return "idle"
    case .safe: return "safe"
    case .warn: return "warn"
    case .danger: return "danger"
    }
}

func sample(_ state: ShieldIconState) -> [String: Any] {
    // calibratedRGB：用 deviceRGB 会被转一次色彩空间，#e8813a 出来是 #ee944a，
    // 那样就只能比「差不多是橙的」，比不出「和面板是同一个橙」。
    guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: n, pixelsHigh: n,
                                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                     isPlanar: false, colorSpaceName: .calibratedRGB,
                                     bytesPerRow: 0, bitsPerPixel: 0) else {
        return ["error": "bitmap"]
    }
    rep.size = ShieldIcon.size
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    ShieldIcon.draw(state)
    NSGraphicsContext.restoreGraphicsState()

    var mask = ""
    var opaque = 0
    var dark = 0
    var minX = n, maxX = -1, minY = n, maxY = -1
    var hist: [String: Int] = [:]
    for y in 0..<n {
        for x in 0..<n {
            let c = rep.colorAt(x: x, y: y) ?? NSColor.clear
            let a = c.alphaComponent
            if a >= 0.5 {
                // K = 墨迹/黑，C = 上色盾面。两者都算「有东西」，但形状
                // 差异要分开看：金底上的深色叹号是墨，不是挖出来的洞。
                let luma = 0.2126 * c.redComponent + 0.7152 * c.greenComponent
                    + 0.0722 * c.blueComponent
                if luma < 0.35 { mask += "K"; dark += 1 } else { mask += "C" }
                opaque += 1
                minX = min(minX, x); maxX = max(maxX, x)
                minY = min(minY, y); maxY = max(maxY, y)
                // 只统计接近全不透明的：边缘半透明像素会被预乘拉暗
                if a >= 0.98 {
                    let key = String(format: "%02x%02x%02x",
                                     Int(c.redComponent * 255 + 0.5),
                                     Int(c.greenComponent * 255 + 0.5),
                                     Int(c.blueComponent * 255 + 0.5))
                    hist[key, default: 0] += 1
                }
            } else {
                mask += "."
            }
        }
    }

    // 顶部往下 10%~22% 的横条：实心盾这里是满的，空心盾只剩左右两条边
    var bandOpaque = 0, bandTotal = 0
    if maxY > minY {
        let h = maxY - minY + 1
        let start = minY + h / 10
        for y in start..<(start + max(1, h / 8)) {
            for x in minX...maxX {
                bandTotal += 1
                let c = rep.colorAt(x: x, y: y) ?? NSColor.clear
                if c.alphaComponent >= 0.5 { bandOpaque += 1 }
            }
        }
    }

    return [
        "state": name(state),
        "template": ShieldIcon.isTemplate(state),
        "coverage": Double(opaque) / Double(n * n),
        "dark": dark,
        "band": bandTotal > 0 ? Double(bandOpaque) / Double(bandTotal) : 0.0,
        "dominant": hist.max { $0.value < $1.value }?.key ?? "",
        "bbox": [minX, minY, maxX, maxY],
        "mask": mask,
    ]
}

var out: [[String: Any]] = []
for s in [ShieldIconState.idle, .safe, .warn, .danger] { out.append(sample(s)) }
let data = try! JSONSerialization.data(withJSONObject: out, options: [.sortedKeys])
print(String(data: data, encoding: .utf8)!)
'''


class IconRenderTests(unittest.TestCase):
    """真的把图标画出来，再回读像素。

    不比对像素长什么样——那只会在调形状时变成噪音。测的是几条改坏了
    就会出事的性质：实心/空心没搞反、上色的是面板那两个色、四种彼此
    分得开、图形没溢出画布。
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.tmp = tempfile.mkdtemp(prefix="shield-icon-")
        d = Path(cls.tmp)
        (d / "ShieldIcon.swift").write_text(read(SHIELD / "ShieldIcon.swift"), encoding="utf-8")
        # 多文件编译时只有 main.swift 能写顶层语句
        (d / "main.swift").write_text(ICON_HARNESS, encoding="utf-8")
        cls.bin = d / "iconharness"
        r = subprocess.run(
            ["/usr/bin/swiftc", "-O", str(d / "ShieldIcon.swift"), str(d / "main.swift"),
             "-o", str(cls.bin)],
            capture_output=True, text=True, timeout=180,
        )
        cls.build_err = r.stderr if r.returncode else ""
        cls.rows = {}
        if cls.bin.exists():
            r = subprocess.run([str(cls.bin)], capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                cls.rows = {row["state"]: row for row in json.loads(r.stdout)}
            else:
                cls.build_err += r.stderr

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        if not self.rows:
            self.fail("图标桩没编出来：" + self.build_err[:800])

    def test_all_four_states_rendered(self):
        self.assertEqual(sorted(self.rows), ["danger", "idle", "safe", "warn"])

    def test_template_flag_matches_state(self):
        for state, expect in (("idle", True), ("safe", True),
                              ("warn", False), ("danger", False)):
            self.assertEqual(self.rows[state]["template"], expect, state)

    def test_idle_is_hollow_and_the_rest_are_solid(self):
        """待命画空心、其余画实心——这是「两种 UI 样式」最直观的差别。"""
        self.assertLess(self.rows["idle"]["band"], 0.65, "待命态应该是空心的")
        for state in ("safe", "warn", "danger"):
            self.assertGreater(self.rows[state]["band"], 0.90, f"{state} 应该是实心的")

    def test_warning_states_use_panel_colors(self):
        tokens = css_vars(read(SHIELD / "web/shield.css"))
        for state, token in (("warn", "gold"), ("danger", "critical")):
            self.assertEqual(self.rows[state]["dominant"], tokens[token].lstrip("#").lower(),
                             f"{state} 的主色和面板 --{token} 不一致")
        # 不上色的两种必须是纯黑：系统会按明暗重新染色，画灰的会发糊
        for state in ("idle", "safe"):
            self.assertEqual(self.rows[state]["dominant"], "000000", state)

    def test_states_are_visually_distinct(self):
        """四种状态两两之间至少要有 8% 的图形差异，否则等于没换样式。"""
        masks = {k: v["mask"] for k, v in self.rows.items()}
        for a, b in (("idle", "safe"), ("idle", "warn"), ("idle", "danger"),
                     ("safe", "warn"), ("safe", "danger"), ("warn", "danger")):
            diff = sum(1 for x, y in zip(masks[a], masks[b]) if x != y)
            union = sum(1 for x, y in zip(masks[a], masks[b]) if x != "." or y != ".")
            self.assertGreater(diff / max(union, 1), 0.08, f"{a} 和 {b} 长得太像")

    def test_glyph_stays_inside_canvas(self):
        """菜单栏图标压到画布边上会被裁掉一块，看起来像渲染坏了。"""
        for state, row in self.rows.items():
            minx, miny, maxx, maxy = row["bbox"]
            self.assertGreaterEqual(minx, 1, state)
            self.assertGreaterEqual(miny, 1, state)
            self.assertLessEqual(maxx, 34, state)
            self.assertLessEqual(maxy, 34, state)
            self.assertGreater(row["coverage"], 0.12, f"{state} 画得太小或没画出来")
            # 上色态把符号画成墨迹（不再是洞），面积比挖空版高：warn 约 0.54。
            # 画布 18×18=324pt²，bbox 26×30 最多 0.60；到 0.58 以上才是糊满。
            self.assertLess(row["coverage"], 0.58, f"{state} 糊满画布了")

    def test_warning_glyphs_are_ink_not_holes(self):
        """金色 / 红色盾面上的符号必须用墨迹画，不能挖空。

        挖空透出来的是菜单栏底色：浅色栏上金底对白只有 1.7:1，2x 下
        「!」读不出来（用户连续两次反馈）。墨迹压在金底上约 9:1。
        这条在挖空版上会报 0 个深色像素，正好拦住回退。
        """
        for state in ("warn", "danger"):
            self.assertGreater(self.rows[state]["dark"], 60,
                               f"{state} 的符号不像墨迹（深色像素 {self.rows[state]['dark']}）")

    def test_shield_fills_enough_of_its_slot(self):
        """盾面外接矩形至少占 18pt 画布的 55%。

        1.6.1 之前盾只有 11pt 宽，36×36 采样下外接矩形 22×28（47.5%），
        真机菜单栏里糊成一团金色——那一版照样通过了上面几条性质测试。
        把「够大」写成硬底线：新几何 26×30（60%），掉回 55% 以下就说明
        又缩回去了。
        """
        for state, row in self.rows.items():
            minx, miny, maxx, maxy = row["bbox"]
            frac = (maxx - minx + 1) * (maxy - miny + 1) / (36 * 36)
            self.assertGreater(frac, 0.55, f"{state} 盾面只占画布 {frac:.1%}")


class PackagingTests(unittest.TestCase):
    def test_menu_bar_only(self):
        plist = plistlib.loads((ROOT / "tools/Shield-Info.plist").read_bytes())
        self.assertTrue(plist.get("LSUIElement"), "LSUIElement 必须为 true，否则会占 Dock")
        self.assertEqual(plist["CFBundleIdentifier"], "com.ccclean.shield")

    def test_login_item_does_not_resurrect_after_quit(self):
        src = read(SHIELD / "ShieldApp.swift")
        self.assertIn("<key>KeepAlive</key><false/>", src)

    def test_login_item_removes_only_its_own_plist(self):
        src = read(SHIELD / "ShieldApp.swift")
        m = re.search(r"static func uninstall\(\) \{(.*?)\n    \}", src, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("removeItem(at: plistURL)", body)
        self.assertNotIn("LaunchAgents\")", body)

    def test_build_script_makes_universal_binary(self):
        src = read(ROOT / "tools/build-shield.sh")
        self.assertIn("arm64", src)
        self.assertIn("x86_64", src)
        self.assertIn("lipo -create", src)

    def test_built_app_exists_and_is_fat(self):
        if not BIN.exists():
            self.skipTest("还没构建 Claude Shield.app")
        r = subprocess.run(["lipo", "-info", str(BIN)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("arm64", r.stdout)
        self.assertIn("x86_64", r.stdout)

    def test_build_script_bundles_watchdog_for_both_arches(self):
        src = read(ROOT / "tools/build-shield.sh")
        self.assertIn("shield/watchdog/main.swift", src)
        self.assertIn("ShieldWatchdog", src)
        m = re.search(r"lipo -create -output \"\$CONTENTS/MacOS/ShieldWatchdog\"", src)
        self.assertIsNotNone(m, "看门狗必须和主程序一样做成通用二进制")
        self.assertIn('chmod +x "$CONTENTS/MacOS/ShieldWatchdog"', src)

    def test_built_app_has_fat_watchdog(self):
        wd = APP / "Contents/MacOS/ShieldWatchdog"
        if not wd.exists():
            self.skipTest("还没构建 Claude Shield.app")
        r = subprocess.run(["lipo", "-info", str(wd)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("arm64", r.stdout)
        self.assertIn("x86_64", r.stdout)
        self.assertTrue(wd.stat().st_mode & 0o111, "看门狗没有可执行位")


class BundledAppTests(unittest.TestCase):
    """一个下载、一个图标、两个进程：哨兵住在塔的 Resources 里。"""

    def test_tower_build_embeds_shield_before_signing(self):
        src = read(ROOT / "tools/build-app.sh")
        call = 'build-shield.sh" "$CONTENTS/Resources/Claude Shield.app"'
        self.assertIn(call, src)
        self.assertLess(src.index(call), src.index("codesign --force --deep"),
                        "先嵌进资源再签名，否则外层签名一加上就失效")

    def test_release_ships_a_single_package(self):
        src = read(ROOT / "tools/make-release.sh")
        self.assertNotIn("ClaudeShield-", src)
        self.assertNotIn('"shield":', src)
        # 清单里仍然写着包内哨兵的版本，方便面板展示
        self.assertIn('"shieldVersion": shield_version', src)

    def test_built_tower_contains_nested_shield(self):
        tower = ROOT / "Claude Tower.app"
        if not tower.exists():
            self.skipTest("还没构建 Claude Tower.app")
        nested = tower / "Contents" / "Resources" / "Claude Shield.app"
        self.assertTrue(nested.is_dir(), "塔的应用包里必须有哨兵")
        plist = plistlib.loads((nested / "Contents/Info.plist").read_bytes())
        self.assertEqual(plist["CFBundleIdentifier"], "com.ccclean.shield")
        self.assertTrue(plist.get("LSUIElement"))

    def test_tower_starts_bundled_shield(self):
        src = read(ROOT / "tools/CCcleanApp.swift")
        self.assertIn('appendingPathComponent("Claude Shield.app")', src)
        self.assertIn('"com.ccclean.shield"', src)
        self.assertIn("startShieldIfNeeded()", src)

    def test_shield_wakes_its_host_by_path(self):
        """嵌套的 .app 不一定被 LaunchServices 注册，打开塔必须按路径来。"""
        src = read(SHIELD / "ShieldApp.swift")
        m = re.search(r"static func hostBundle\(\) -> URL\? \{(.*?)\n    \}", src, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("deletingLastPathComponent()", body)
        self.assertIn('Bundle(path: host.path)?.bundleIdentifier == bundleID', body)
        # 路径优先，bundle id 只做开发态回退
        r = re.search(r"static func resolve\(\).*?\n    \}", src, re.S)
        self.assertIsNotNone(r)
        resolved = r.group(0)
        self.assertIn("hostBundle()", resolved)
        self.assertIn("registeredBundle()", resolved)
        self.assertLess(resolved.index("hostBundle"), resolved.index("registeredBundle"))

    def test_tower_path_flag_prints_the_branch_it_would_take(self):
        """两条分支可能指向同一个 .app，只看「塔起来了」分不清走的是哪条。
        安装好的产物必须能自己把答案说出来，而且说的就是面板会用的那次解析。"""
        if not BIN.exists():
            self.skipTest("还没构建 Claude Shield.app")
        r = subprocess.run([str(BIN), "--tower-path"], capture_output=True,
                           text=True, timeout=15)
        self.assertEqual(r.returncode, 0, r.stderr)
        fields = dict(line.split("=", 1) for line in r.stdout.strip().splitlines()
                      if "=" in line)
        host = ROOT / "Claude Tower.app"
        self.assertEqual(fields.get("host"), str(host))
        self.assertEqual(fields.get("chosen"), "host")
        self.assertEqual(fields.get("path"), str(host))
        # 面板里记下的也是这条分支，排障时不用猜
        src = read(SHIELD / "ShieldApp.swift")
        self.assertIn('Store.log("open tower: via=\\(target.source.rawValue)', src)
        self.assertIn("TowerHost.resolve()", src)


def watchdog_binary() -> Path | None:
    for p in (APP / "Contents/MacOS/ShieldWatchdog", SHIELD / "watchdog/ShieldWatchdog"):
        if p.exists():
            return p
    return None


class WatchdogStaticTests(unittest.TestCase):
    """看门狗必须在 Shield 之外活着，只靠心跳判断对方还在不在。"""

    def setUp(self):
        self.parent = read(SHIELD / "Watchdog.swift")
        self.child = read(SHIELD / "watchdog/main.swift")
        self.app = read(SHIELD / "ShieldApp.swift")

    def test_parent_beats_every_ten_seconds(self):
        self.assertIn("withTimeInterval: 10, repeats: true", self.parent)
        self.assertIn('"--interval", "10"', self.parent)
        self.assertIn("writeHeartbeat()", self.parent)
        # 只在定时器里 ensure 不够：用户可能手动杀过看门狗，下一轮心跳要补回来
        self.assertIn("ensure(exe)", self.parent)

    def test_heartbeat_uses_awake_time_not_wall_clock(self):
        """合盖一夜回来，墙上时间会让心跳看起来「过期 8 小时」，
        看门狗就会误杀一个刚醒来的哨兵。"""
        self.assertIn('"uptime": ProcessInfo.processInfo.systemUptime', self.parent)
        self.assertIn("ProcessInfo.processInfo.systemUptime", self.child)
        self.assertNotIn("time.time()", self.parent)

    def test_single_instance_uses_flock(self):
        self.assertIn("flock(lockFD, LOCK_EX | LOCK_NB)", self.child)
        self.assertIn("watchdog.lock", self.child)

    def test_stop_marker_is_scoped_to_current_parent(self):
        """上一轮崩溃留下的停止文件不能让新看门狗提前下班。"""
        self.assertIn("watchdog.stop", self.child)
        m = re.search(r"if let stop = stopRequested\(\) \{(.*?)\n    \}", self.child, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("hb!.pid == stop", body)
        self.assertIn("!alive(stop)", body)
        self.assertIn("removeItem(at: stopURL)", body)

    def test_hung_parent_is_terminated_then_relaunched(self):
        self.assertIn("parent unresponsive", self.child)
        self.assertIn("kill(hb.pid, SIGTERM)", self.child)
        self.assertIn("kill(hb.pid, SIGKILL)", self.child)
        self.assertIn("opts.hangAfter", self.child)

    def test_pid_identity_is_verified_before_signalling(self):
        """kill(pid, 0) 只看号不看人：父进程死后号会被回收给别的进程，
        照着号去 SIGTERM 就是杀无关的人。"""
        self.assertIn("proc_pidpath", self.child)
        self.assertIn('"exe":', read(SHIELD / "Watchdog.swift"))
        self.assertIn("alive(hb.pid, expecting: hb.exe)", self.child)
        m = re.search(r"func alive\(_ pid: pid_t.*?\n\}", self.child, re.S)
        self.assertIsNotNone(m, "alive() 不见了")
        self.assertIn("executablePath", m.group(0))

    def test_relaunch_passes_restored_flag(self):
        self.assertIn('"-a", app.path, "--args", "--restored"', self.child)
        self.assertIn('["--restored"]', self.child)
        self.assertIn("relaunch attempt", self.child)

    def test_quit_and_shutdown_stop_the_watchdog(self):
        m = re.search(r"func applicationWillTerminate.*?\n    \}", self.app, re.S)
        self.assertIsNotNone(m, "缺少退出钩子")
        self.assertIn("Watchdog.stop()", m.group(0))
        self.assertIn("willPowerOffNotification", self.app)
        # 看门狗不是常驻登录项：退出后不许自己复活
        self.assertNotIn("LaunchAgents", self.parent)
        self.assertIn("KeepAlive", self.app)

    def test_restored_launch_is_recorded_and_announced(self):
        self.assertIn('CommandLine.arguments.contains("--restored")', self.app)
        self.assertIn('kind: "restart"', self.app)
        self.assertIn("哨兵已自动恢复", self.app)

    def test_watchdog_uses_absolute_paths_and_no_shell(self):
        self.assertNotIn("/bin/sh", self.child)
        for path in re.findall(r'URL\(fileURLWithPath: "(/[^"]+)"', self.child):
            self.assertTrue(path.startswith("/"), path)
        self.assertIn("/usr/bin/osascript", self.child)
        self.assertIn("/usr/bin/open", self.child)


class WatchdogRuntimeTests(unittest.TestCase):
    """真跑一次看门狗：kill -9 掉假父进程，它必须在宽限期后重新拉起。

    只用临时目录和 /bin/sleep 假父进程，不碰已安装的 Shield，也不杀任何
    真实进程。"""

    def setUp(self):
        self.exe = watchdog_binary()
        if self.exe is None:
            self.skipTest("还没构建 ShieldWatchdog")

    def _run(self, td: Path, helper: Path, heartbeat_age: float = 0,
             parent: subprocess.Popen | None = None, exe: str = ""):
        td.mkdir(parents=True, exist_ok=True)
        hb = {"pid": parent.pid, "uptime": time.monotonic() - heartbeat_age}
        if exe:
            hb["exe"] = exe
        (td / "shield-heartbeat.json").write_text(json.dumps(hb))
        return subprocess.Popen(
            [str(self.exe), "--dir", str(td), "--relaunch", str(helper),
             "--interval", "1", "--hang-after", "15", "--no-notify"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _helper(self, td: Path) -> tuple[Path, Path]:
        marker = td / "relaunched.txt"
        helper = td / "helper.sh"
        helper.write_text(f'#!/bin/sh\nprintf "%s" "$*" > "{marker}"\n')
        helper.chmod(0o755)
        return helper, marker

    def _wait(self, marker: Path, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if marker.exists():
                return True
            time.sleep(0.2)
        return False

    def _stop(self, wd: subprocess.Popen, td: Path, pid: int):
        (td / "watchdog.stop").write_text(str(pid))
        try:
            wd.wait(timeout=6)
        except subprocess.TimeoutExpired:
            wd.kill()
            wd.wait()
            self.fail("看门狗没有响应停止信号")

    def test_kill_9_parent_is_relaunched(self):
        with tempfile.TemporaryDirectory() as td_str:
            td = Path(td_str)
            helper, marker = self._helper(td)
            parent = subprocess.Popen(["/bin/sleep", "60"])
            wd = self._run(td, helper, parent=parent)
            try:
                time.sleep(1.0)
                parent.kill()
                parent.wait()
                self.assertTrue(self._wait(marker, 15),
                                "父进程被 kill -9 后看门狗没有重新拉起")
                self.assertIn("--restored", marker.read_text())
                log = (td / "shield.log").read_text()
                self.assertIn("parent gone", log)
                self.assertIn("relaunch attempt 1", log)
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait()
                self._stop(wd, td, parent.pid)

    def test_stale_heartbeat_gets_sigterm(self):
        with tempfile.TemporaryDirectory() as td_str:
            td = Path(td_str)
            helper, marker = self._helper(td)
            parent = subprocess.Popen(["/bin/sleep", "60"])
            wd = self._run(td, helper, heartbeat_age=90, parent=parent)
            try:
                self.assertTrue(self._wait(marker, 15),
                                "心跳过期后看门狗没有重启哨兵")
                parent.wait(timeout=5)
                log = (td / "shield.log").read_text()
                self.assertIn("parent heartbeat stale", log)
                self.assertIn("parent unresponsive; terminate", log)
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait()
                self._stop(wd, td, parent.pid)

    def test_recycled_pid_is_never_signalled(self):
        """父进程死后 PID 被系统回收给别的进程时，看门狗不能照着号去杀。

        这里让心跳写一个真实存活、但可执行文件对不上的 pid：看门狗必须
        认定「父进程已经不在了」并重新拉起，同时一根手指都不许碰那个进程。
        """
        with tempfile.TemporaryDirectory() as td_str:
            td = Path(td_str)
            helper, marker = self._helper(td)
            stranger = subprocess.Popen(["/bin/sleep", "60"])
            wd = self._run(td, helper, heartbeat_age=90, parent=stranger,
                           exe="/Applications/Claude Shield.app/Contents/MacOS/Shield")
            try:
                self.assertTrue(self._wait(marker, 15), "父进程不在时看门狗没有重新拉起")
                time.sleep(0.5)
                self.assertIsNone(stranger.poll(), "看门狗杀了一个号被回收的无关进程")
                log = (td / "shield.log").read_text()
                self.assertIn("reused by another process", log)
                self.assertNotIn("parent unresponsive; terminate", log)
            finally:
                if stranger.poll() is None:
                    stranger.kill()
                    stranger.wait()
                self._stop(wd, td, stranger.pid)

    def test_stop_marker_ends_watchdog_without_relaunch(self):
        with tempfile.TemporaryDirectory() as td_str:
            td = Path(td_str)
            helper, marker = self._helper(td)
            parent = subprocess.Popen(["/bin/sleep", "60"])
            wd = self._run(td, helper, parent=parent)
            try:
                time.sleep(0.8)
                self._stop(wd, td, parent.pid)
                time.sleep(1.0)
                self.assertFalse(marker.exists(), "正常退出时看门狗不该重新拉起")
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait()

    def test_second_instance_exits_quietly(self):
        """父进程 ensure() 可能和正在交接的旧看门狗撞车，第二个必须安静退出。"""
        with tempfile.TemporaryDirectory() as td_str:
            td = Path(td_str)
            helper, marker = self._helper(td)
            parent = subprocess.Popen(["/bin/sleep", "60"])
            wd = self._run(td, helper, parent=parent)
            try:
                time.sleep(0.8)
                rival = subprocess.Popen(
                    [str(self.exe), "--dir", str(td), "--relaunch", str(helper),
                     "--interval", "1", "--hang-after", "15", "--no-notify"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                rival.wait(timeout=5)
                self.assertEqual(rival.returncode, 0)
                self.assertIsNone(wd.poll(), "第一个看门狗被第二个挤掉了")
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait()
                self._stop(wd, td, parent.pid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
