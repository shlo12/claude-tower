import Foundation

/// 塔在分流修复后留下的「这批规则应该长什么样」。
///
/// 只记规则对（`TYPE,payload`），不记整份文件哈希：三个客户端都会在
/// 日常运行里重写配置的其它部分（FlClash 重启后按数据库重新生成配置、
/// 订阅更新会重写 YAML），整文件哈希一改就报警等于天天误报。
/// 规则对消失或被改名才是要抓的那种漂移。
struct RuleGuard: Codable {
    var client = ""
    var name = ""
    var path = ""
    var rules: [String] = []
    var at: Double = 0
}

/// 一次巡检的快照。所有字段都只描述「这一刻」，不缓存任何历史判断——
/// 上一次的结论留在 Store 里，这里的每个值都必须重新读。
struct Snapshot {
    var at = Date()
    var connections = ConnectionAudit()
    var claudeRunning = false
    var tunUp = false
    var tunIface = ""
    var sysProxy = false
    var proxyClients: [String] = []
    /// 认到了代理客户端，但既没 TUN 也没系统代理——这一刻流量是直连的。
    /// 和「什么都没认出来」不是一回事：那说明代理确实没开，这说明代理开着
    /// 却没接管。以前这两种都只提醒，等于把「客户端在跑」当成了「流量安全」。
    var takeoverMissing = false
    /// 上面那条已经持续了 `Probe.takeoverGrace` 秒，判定升级成 danger。
    /// 客户端重启、切换接管模式的那几秒会短暂没有接管，一上来就杀是误杀。
    var takeoverEscalated = false
    var tz = ""
    var baselineTz = ""
    /// claude.ai 解析到的地址。空表示这次没查（出口不在）或没查成。
    var dnsIP = ""
    var dnsFake = false
    var dnsChecked = false
    /// STUN 打回来的公网地址。`stunAll` 含国内节点，`stunForeign` 只有境外的。
    var stunAll: [String] = []
    var stunForeign: [String] = []
    var stunChecked = false
    /// 塔记下的打码出口地址（`1.2.*.4`）。空表示塔没跑过或没拿到。
    var egressMask = ""
    /// 塔记的那个出口还新鲜吗。过期的不能拿来下结论。
    var maskFresh = false
    /// 塔关过 IPv6 之后留下的记录，现在还算不算数。
    var ipv6Checked = false
    var ipv6Drift = false
    var ipv6Services: [String] = []
    /// 塔做过分流修复后留下的规则清单，现在还在不在。
    var guardChecked = false
    var guardDrift = false
    var guardName = ""
    var guardMissing: [String] = []
    /// 到 Anthropic 的 HTTPS 传输有没有真的走通。`off` 表示出口不在或没测。
    var transportChecked = false
    var transportState = "off"   // ok / warn / bad / off
    var transportLabel = ""
    var transportDetail = ""
    var transportAt = 0.0

    /// 塔有没有留下基线。只看这两个键：时区漂移要用 baselineTz，
    /// UDP 比对要用 egressMask。两个都空，说明塔没扫过或没写成功。
    var hasTowerData: Bool { !baselineTz.isEmpty || !egressMask.isEmpty }

    /// 基线完整且没过期。缺时区、缺出口、超过 24 小时，都不算。
    var towerFresh: Bool { !baselineTz.isEmpty && !egressMask.isEmpty && maskFresh }

    /// 「缺塔 / 基线过期 / 可用」三态，面板拿它决定横幅说什么。
    var towerState: String {
        if !hasTowerData { return "missing" }
        return towerFresh ? "ok" : "stale"
    }

    /// Claude 没运行时，主状态只回答一件事：现在能不能启动。
    /// 出口和 DNS 不依赖塔，先判；时区与 UDP 必须有基线才判得了。
    var idleState: IdleState {
        if connections.direct > 0 { return .blocked }
        if !exitReady { return .blocked }
        if dnsSuspect { return .blocked }
        if !hasTowerData { return .notower }
        if !towerFresh { return .stale }
        if stunLeak { return .blocked }
        if tzDrift { return .blocked }
        return .ready
    }

    /// 环境是否已经可以承载 Claude。和 idleState 分开写：Claude 在跑时
    /// 也要能回答这个问题（面板横幅、日志都用得上）。
    var environmentReady: Bool {
        towerFresh && exitReady && connections.direct == 0 && !dnsSuspect && !stunLeak && !tzDrift
    }

    /// Tower 写入的基线时区与当前不一致，说明配置被改过（软件更新最常见）。
    var tzDrift: Bool { !baselineTz.isEmpty && !tz.isEmpty && tz != baselineTz }

    /// 有没有一条「确定的」出口。TUN 或系统代理任一成立就算在位。
    var exitReady: Bool { tunUp || sysProxy }

    /// 出口在位，但 TUN 模式下 DNS 没拿到假地址。
    ///
    /// 只在 TUN 在位时成立：TUN 接管了网络层，同一个客户端理应也接管 DNS 层，
    /// 拿不到 fake-ip 就是「劫持没生效」。系统代理则相反——它本来就不管 DNS，
    /// 拿不到假地址是正常的，拿它当证据会天天误报。
    /// 实测过：本机没开 TUN、系统 DNS 还是 8.8.8.8，dig 照样回 198.18.2.160。
    /// 所以「DNS 服务器是公共 DNS」根本不能当判据，只有解析结果本身算数。
    var dnsSuspect: Bool { tunUp && dnsChecked && !dnsFake }

    /// UDP 出口和 HTTP 出口不是同一个——也就是 WebRTC 泄漏。
    ///
    /// 判据是「分裂」而不是「不符」：境外节点里必须**同时**有一个对上基线、
    /// 一个对不上，才算泄漏。
    ///
    /// 为什么不直接「有一个不符就报」：实测过，开着系统代理时两个境外
    /// STUN 节点会给出两个不同地址（一个代理出口、一个国内真实地址）
    /// ——分流规则把其中一个送去了直连。
    /// 这种按目的地分流的差异太常见，见一个报一个，用户两天就学会无视通知了。
    ///
    /// 而「全部对不上」多半是基线过期（换节点、重拨），不是泄漏，也不能报。
    /// 只有「一部分通、一部分不通」才确实说明 UDP 被有选择地放了出去。
    var stunLeak: Bool {
        guard maskFresh, !egressMask.isEmpty, !egressMask.contains(":"),
              stunChecked, stunForeign.count >= 2 else { return false }
        let hit = stunForeign.contains { Probe.matchesMask($0, egressMask) }
        let miss = stunForeign.contains { !Probe.matchesMask($0, egressMask) }
        return hit && miss
    }

    var verdict: Verdict {
        if !claudeRunning { return .idle }
        if connections.direct > 0 { return .danger }
        if exitReady {
            // 出口在位还要再看两眼：规则只做了一半的时候，主状态会显示
            // 「守护中」，但域名解析或 UDP 已经绕出去了。
            if dnsSuspect { return .warn }
            if stunLeak { return .warn }
            return .safe
        }
        // 有代理进程但没看到接管：可能是我们没认出来的客户端，也可能是规则没生效。
        // 这种状态不下死结论，只提醒——误报成「危险」会让人很快学会无视通知。
        //
        // 但「连续几轮都没接管」要另算：客户端开着、TUN 关着、系统代理也关着，
        // 流量就是直连，这时候还停在提醒等于漏。所以按轮次升级，
        // 前两轮仍给客户端一个自我纠正的机会（切模式、重启内核）。
        if !proxyClients.isEmpty {
            return takeoverEscalated ? .danger : .warn
        }
        return .danger
    }

    /// 面板上那句话。dnsSuspect / stunLeak 时 verdict 都是 warn，但原因和
    /// 「出口存疑」不一样，用 Verdict 的固定文案会说错话，这里单独盖掉。
    var title: String {
        // Claude 没在跑时，标题回答的是「现在能不能启动」。DNS / STUN 的异常
        // 只在「有人在被守」的时候才拿来当标题——否则会出现「Claude 未运行，
        // 标题却写着 UDP 出口不一致」，用户根本不知道该看哪一句。
        if !claudeRunning {
            switch idleState {
            case .notower: return "先让塔扫描一次"
            case .stale:   return "基线过期了"
            case .blocked: return "先别启动 Claude"
            case .ready:   return "可以启动 Claude"
            }
        }
        if connections.direct > 0 { return "发现 Claude 公网物理路由" }
        if dnsSuspect { return "DNS 未接管" }
        if stunLeak { return "UDP 出口不一致" }
        // 带上 verdict 判断：升级标记只描述「曾经持续没接管」，
        // 出口回来了它可能还挂着，那时候标题必须跟着 verdict 走。
        if takeoverEscalated, verdict == .danger { return "代理在跑，但没接管" }
        return verdict.title
    }

    var note: String {
        if !claudeRunning { return idleNote }
        if connections.direct > 0 { return connections.detail }
        if dnsSuspect {
            return "出口在位，但 claude.ai 解析成了真实地址（\(dnsIP)）——TUN 开着却没接管 DNS，分流规则可能只做了一半。"
        }
        if stunLeak {
            let good = stunForeign.filter { Probe.matchesMask($0, egressMask) }
                .map(Probe.maskIP).joined(separator: "、")
            let bad = stunForeign.filter { !Probe.matchesMask($0, egressMask) }
                .map(Probe.maskIP).joined(separator: "、")
            return "境外 STUN 节点给出了两个出口：\(good) 和 \(bad)。同一份规则里一部分 UDP 进了隧道、一部分直连，WebRTC 会从直连那条暴露真实地址。"
        }
        if takeoverEscalated, verdict == .danger {
            return "代理客户端在跑（\(proxyClients.prefix(3).joined(separator: "、"))），但已经 \(Int(Probe.takeoverGrace)) 秒没看到 TUN 或系统代理接管——流量这会儿走的是真实网络。把接管打开，或者直接退出 Claude。"
        }
        return verdict.note
    }

    /// 待命态的说明。每一句都要落到「先做什么」，而不是只说「现在没在守」。
    private var idleNote: String {
        switch idleState {
        case .notower:
            return "哨兵手上没有塔的基线：时区漂移和 UDP 出口都没法比对。先打开 Claude Tower 扫一次，数据会自动接上。"
        case .stale:
            return "塔记的基线超过 24 小时（或还缺出口/时区），不再拿来比对 UDP。去塔里再扫一次再启动 Claude。"
        case .ready:
            return "当前环境正常：出口在位，DNS、UDP 出口和时区都对得上。可以启动 Claude 了。"
        case .blocked:
            if !exitReady {
                return proxyClients.isEmpty
                    ? "现在没有任何出口：没看到 TUN，也没开系统代理。先开代理再启动 Claude，否则它的流量全走真实网络。"
                    : "代理进程在跑，但没看到 TUN 或系统代理接管。先把接管打开再启动 Claude。"
            }
            if dnsSuspect {
                return "出口在位，但 claude.ai 解析成了真实地址（\(dnsIP)）——TUN 开着却没接管 DNS。先把 DNS 接管修好再启动 Claude。"
            }
            if stunLeak {
                let bad = stunForeign.filter { !Probe.matchesMask($0, egressMask) }
                    .map(Probe.maskIP).joined(separator: "、")
                return "UDP 出口分裂：境外节点里有的走隧道、有的直连（\(bad)）。先把 UDP 也代理了，再启动 Claude。"
            }
            return "当前时区 \(tz) 和塔记的 \(baselineTz) 不一致。先按下面的按钮改回去，再启动 Claude。"
        }
    }
}

/// Claude 没运行时，面板要回答的不是「网络现在什么样」，而是「能不能启动」。
enum IdleState: String {
    case notower, stale, blocked, ready
}

enum Verdict: String {
    case idle, safe, warn, danger

    var title: String {
        switch self {
        case .idle:   return "待命"
        case .safe:   return "守护中"
        case .warn:   return "出口存疑"
        case .danger: return "出口已断"
        }
    }

    var note: String {
        switch self {
        case .idle:
            return "Claude 没在运行。"
        case .safe:
            return "Claude 在运行，出口在位。"
        case .warn:
            return "Claude 在运行，代理进程还在，但没看到 TUN 或系统代理接管。"
        case .danger:
            return "Claude 在运行，但没有任何出口。这时候它发出的每个包都走真实网络。"
        }
    }
}

enum Probe {

    /// 认得的代理客户端。面板不展示：进程名只是启发式，认不出来时写「没看到」
    /// 会让人误以为代理没开。这里只留作安全信号——出口没接管但有客户端在跑，
    /// 头两轮停在提醒，连续几轮都没接管才升级（见 `takeoverTicks`）。
    static let proxyKeywords = [
        "mihomo", "clash", "sing-box", "singbox", "surge", "shadowrocket",
        "v2ray", "xray", "trojan", "hysteria", "naive", "tuic", "juicity",
        "verge", "stash", "quantumult", "loon",
    ]

    /// 待命时把 DNS / STUN 降到 5 分钟一次：Claude 没在跑的时候，
    /// 每 30 秒解析一次 claude.ai、打一遍 STUN，只是在替用户制造流量。
    static let idleProbeTTL: TimeInterval = 300
    /// Claude 在跑时 DNS 每轮都查（区间就是巡检周期），STUN 仍是 60 秒一次。
    static let activeProbeTTL: TimeInterval = 30
    static let stunActiveTTL: TimeInterval = 60

    /// 「认到了客户端，但没接管」持续多久才升级成 danger。
    ///
    /// 按时间而不是按轮次：轮次会被「立即巡检」这类手动重测打乱——连点三次
    /// 会在几秒内凑满三轮，然后杀一个完全无辜的进程。客户端重启内核、
    /// 切换 TUN 开关一般 3~10 秒，给到 30 秒足够它自己纠正回来。
    static let takeoverGrace: TimeInterval = 30

    /// 「客户端在跑、但没接管」持续够久了吗。
    ///
    /// 单独抽出来是为了能测：`run()` 里的系统读数没法在测试里造，
    /// 但这条规则可以——喂两个时间点就能验边界。
    static func escalatedTakeover(missing: Bool, since: TimeInterval, now: Date) -> Bool {
        guard missing, since > 0 else { return false }
        return now.timeIntervalSince1970 - since >= takeoverGrace
    }

    static func run(baselineTz: String, egressMask: String = "", maskFresh: Bool = false,
                    ruleGuard: RuleGuard? = nil, forceStun: Bool = false,
                    forceFresh: Bool = false, forceTransport: Bool = false,
                    takeoverSince: TimeInterval = 0) -> Snapshot {
        var s = Snapshot()
        s.baselineTz = baselineTz
        s.egressMask = egressMask
        s.maskFresh = maskFresh
        let procs = processList()
        s.claudeRunning = procs.contains { $0.contains("/Claude.app/Contents/MacOS/Claude") }
        s.proxyClients = proxyHits(procs)

        let route = publicRoute()
        s.tunIface = route.iface
        s.tunUp = route.tun
        s.sysProxy = systemProxyOn()
        s.connections = ConnectionMonitor.run(tunActive: s.tunUp)
        // 「客户端在跑、但没接管」要持续一段才升级成危险。
        // takeoverSince 是第一次看到它的时刻（0 表示还没看到过）。
        s.takeoverMissing = s.claudeRunning && !s.exitReady && !s.proxyClients.isEmpty
        s.takeoverEscalated = escalatedTakeover(missing: s.takeoverMissing,
                                                since: takeoverSince, now: s.at)
        s.tz = currentTz()
        // 这两项不联网、也不改系统：只读塔留下的记录，再看一眼现在是不是还那样。
        // 写回（关 IPv6、重新应用规则）仍然只在塔里做，哨兵没有提权路径。
        let ipv6 = ipv6Check()
        s.ipv6Checked = ipv6.checked
        s.ipv6Drift = ipv6.drift
        s.ipv6Services = ipv6.services
        let guardCheck = checkRuleGuard(ruleGuard)
        s.guardChecked = guardCheck.checked
        s.guardDrift = guardCheck.drift
        s.guardName = ruleGuard?.name ?? ""
        s.guardMissing = guardCheck.missing
        // 出口不在的时候绝不查 DNS、绝不打 STUN。
        // 查一次就是把 claude.ai 明文送出去，打一次 STUN 就是把真实地址
        // 送到对方服务器上——为了证明「没有泄漏」而制造一次泄漏，这种事不能做。
        if s.exitReady {
            // 缓存按「出口长什么样」分桶：换网卡、开关系统代理之后，
            // 旧结果描述的是另一条路，不能拿来充数。
            let key = "\(s.tunUp)|\(s.sysProxy)|\(s.tunIface)"
            let d = dnsProbe(force: forceFresh, idle: !s.claudeRunning,
                             key: key)
            s.dnsIP = d.ip
            s.dnsFake = d.fake
            s.dnsChecked = d.checked
            let st = stunProbe(force: forceStun || forceFresh,
                               idle: !s.claudeRunning, key: key)
            s.stunAll = st.all
            s.stunForeign = st.foreign
            s.stunChecked = st.checked
            // 传输诊断只回答「这一刻能不能把 HTTPS 送出去」，不进 verdict：
            // 一次握手成功证明不了之后每个包都安全，失败也不该直接终止 Claude。
            let tr = transportProbe(force: forceTransport || forceFresh,
                                    idle: !s.claudeRunning, key: key)
            let tv = transportVerdict(tr)
            s.transportChecked = tr.checked
            s.transportState = tv.state
            s.transportLabel = tv.label
            s.transportDetail = tv.detail
            s.transportAt = tr.at
        } else {
            dropProbeCaches()
        }
        return s
    }

    // MARK: - 读进程表

    /// 一次 `ps` 拿全表再本地匹配。逐个 `pgrep` 会 fork 十几次，
    /// 30 秒一次巡检没必要那么贵。
    static func processList() -> [String] {
        sh("/bin/ps", ["-axo", "comm="])
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    static func proxyHits(_ procs: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for p in procs {
            let low = p.lowercased()
            guard let hit = proxyKeywords.first(where: { low.contains($0) }) else { continue }
            // 同一客户端的多个子进程只报一次
            guard seen.insert(hit).inserted else { continue }
            out.append(hit)
        }
        return out
    }

    // MARK: - 读路由

    /// 公网流量实际走哪张网卡。
    ///
    /// 不能只看 `default`：FlClash / mihomo 这类 TUN 客户端不改默认路由，
    /// 而是把 0/0 拆成 1、2/7、4/6 … 128.0/1 一串更具体的前缀全指向 utun，
    /// 让 `default` 继续留在 Wi-Fi 上。只看 default 会把「已接管」误判成直连。
    /// 这里让内核按最长前缀匹配一次，不发任何包。
    static func publicRoute() -> (tun: Bool, iface: String) {
        var tunIface = ""
        var tunHits = 0
        var directIface = ""
        var directHits = 0
        for ip in ["1.1.1.1", "8.8.8.8", "9.9.9.9"] {
            let r = routeLookup(ip)
            guard !r.iface.isEmpty else { continue }
            if isTunnel(iface: r.iface, gateway: r.gateway) {
                tunHits += 1
                if tunIface.isEmpty { tunIface = r.iface }
            } else {
                directHits += 1
                if directIface.isEmpty { directIface = r.iface }
            }
        }
        // 分流规则可能把某一个测试地址放直连；多数走隧道就算接管。
        if tunHits >= 2 { return (true, tunIface) }
        if directHits > 0 { return (false, directIface) }
        return defaultRoute()
    }

    static func isTunnel(iface: String, gateway: String) -> Bool {
        iface.hasPrefix("utun") || gateway.hasPrefix("198.18.") || gateway.hasPrefix("198.19.")
    }

    static func routeLookup(_ ip: String) -> (iface: String, gateway: String) {
        let out = sh("/sbin/route", ["-n", "get", "-inet", ip])
        var iface = ""
        var gateway = ""
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("interface:") {
                iface = t.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
            } else if t.hasPrefix("gateway:") {
                gateway = t.dropFirst("gateway:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        return (iface, gateway)
    }

    /// 路由查不到时的退路：只看默认路由。
    static func defaultRoute() -> (tun: Bool, iface: String) {
        let out = sh("/usr/sbin/netstat", ["-rn", "-f", "inet"])
        for line in out.split(separator: "\n") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.first == "default", cols.count >= 4 else { continue }
            let iface = cols.last!
            let gateway = cols.count > 1 ? cols[1] : ""
            return (isTunnel(iface: iface, gateway: gateway), iface)
        }
        return (false, "")
    }

    // MARK: - 读系统代理

    /// `scutil --proxy` 是系统代理开关的唯一真相。有人不用 TUN 只用系统代理，
    /// 这时 TUN 判定会漏，得靠这一路兜住。
    static func systemProxyOn() -> Bool {
        let out = sh("/usr/sbin/scutil", ["--proxy"])
        for line in out.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            if ["HTTPEnable", "HTTPSEnable", "SOCKSEnable"].contains(parts[0]), parts[1] == "1" {
                return true
            }
        }
        return false
    }

    // MARK: - 读时区

    static func currentTz() -> String {
        guard let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: "/etc/localtime") else {
            return TimeZone.current.identifier
        }
        guard let r = dest.range(of: "zoneinfo/") else { return TimeZone.current.identifier }
        return String(dest[r.upperBound...])
    }

    // MARK: - 读塔留下的设置

    static let ipv6StatePath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".ccclean", isDirectory: true)
        .appendingPathComponent("ipv6-state.json")

    /// 塔关过 Wi-Fi 的 IPv6 之后会留下 `ipv6-state.json`。哨兵只读它，
    /// 再问一次这个服务现在是什么模式：记录里那个服务不在 Off，就说明
    /// 有人（系统更新、另一个工具、手动设置）把它打开了。
    ///
    /// 没有记录、或者服务改名读不到，都算「不适用」，不报警——
    /// 读不到不等于被改过。
    static func ipv6Check() -> (checked: Bool, drift: Bool, services: [String]) {
        guard let data = try? Data(contentsOf: ipv6StatePath),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let recorded = root["services"] as? [String: Any], !recorded.isEmpty else {
            return (false, false, [])
        }
        var modes: [String: String] = [:]
        for name in recorded.keys.sorted() {
            let mode = ipv6Mode(name)
            if !mode.isEmpty { modes[name] = mode }
        }
        guard !modes.isEmpty else { return (false, false, []) }
        return (true, ipv6NeedsFix(modes: modes), modes.keys.sorted())
    }

    /// 只改 Wi-Fi 是塔的口径；这里只回答「记录里的服务还关着吗」。
    static func ipv6NeedsFix(modes: [String: String]) -> Bool {
        modes.values.contains { !isIPv6Off($0) }
    }

    static func isIPv6Off(_ mode: String) -> Bool {
        ["off", "关闭"].contains(mode.trimmingCharacters(in: .whitespaces).lowercased())
    }

    static func ipv6Mode(_ service: String) -> String {
        let out = sh("/usr/sbin/networksetup", ["-getinfo", service])
        for line in out.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0].lowercased() == "ipv6" {
                return parts[1].trimmingCharacters(in: .whitespaces)
            }
        }
        return ""
    }

    /// 塔写下的分流规则还在不在。
    ///
    /// 只比规则对（`TYPE,payload`），和塔自己核对运行时配置的口径一致：
    /// 客户端可能按分组重写策略名，把第三段也比进去会把「客户端规范化了
    /// 写法」报成漂移。文件不在了同样算漂移——那正是 ClashX 订阅更新
    /// 会做的事。
    static func checkRuleGuard(_ spec: RuleGuard?) -> (checked: Bool, drift: Bool, missing: [String]) {
        guard let g = spec, !g.path.isEmpty, !g.rules.isEmpty else {
            return (false, false, [])
        }
        guard let data = FileManager.default.contents(atPath: g.path),
              let text = String(data: data, encoding: .utf8) else {
            return (true, true, g.rules)
        }
        var have = Set<String>()
        for line in text.split(separator: "\n") {
            if let key = ruleKey(String(line)) { have.insert(key) }
        }
        let missing = g.rules.filter { rule in
            guard let key = ruleKey(rule) else { return false }
            return !have.contains(key)
        }
        return (true, !missing.isEmpty, missing)
    }

    /// 把一行配置归一成 `TYPE,payload`。
    ///
    /// 三个客户端的写法各不相同：Clash 系的 YAML 是
    /// `- DOMAIN-SUFFIX,claude.ai,PROXY`，Verge 的 Script.js 是
    /// `"DOMAIN-SUFFIX,claude.ai,PROXY",`。引号、列表短横、缩进都要剥掉。
    static func ruleKey(_ line: String) -> String? {
        var t = line.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("-") {
            t = String(t.dropFirst()).trimmingCharacters(in: .whitespaces)
        }
        let parts = t.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) }
        guard parts.count >= 2 else { return nil }
        let kind = parts[0]
        // 规则类型是 `DOMAIN-SUFFIX` / `DST-PORT` 这种全大写带连字符的写法，
        // 用它把 YAML 的键、注释和正文里的普通句子挡在外面。
        guard kind.count >= 3, kind.contains("-"),
              kind.uppercased() == kind,
              kind.allSatisfy({ $0.isLetter || $0 == "-" }) else { return nil }
        let payload = parts[1].lowercased()
        guard !payload.isEmpty else { return nil }
        return "\(kind),\(payload)"
    }

    // MARK: - 读 DNS

    /// claude.ai 解析成什么。
    ///
    /// 这是唯一能看出「DNS 层有没有被接管」的现成办法：TUN 客户端都会在 DNS 层
    /// 返回假地址（fake-ip），拿到假地址说明劫持在工作；拿到真实地址说明没接管。
    ///
    /// 三种结果要分开：
    /// - 拿到假地址 → checked=true, fake=true
    /// - 拿到真地址 → checked=true, fake=false（可疑，但也可能是 redir-host）
    /// - 查不到/超时 → checked=false，**不降级**。网络抖一下就报警，
    ///   用户会很快学会无视通知，那这套东西就废了。
    private static let dnsLock = NSLock()
    private static var dnsCache: (at: Date, key: String, idle: Bool,
                                  ip: String, fake: Bool, checked: Bool)?

    /// Claude 没在跑时缓存 5 分钟：没人被守的时候每 30 秒解析一次，
    /// 只是在替用户制造流量。面板打开和「立即巡检」会绕过缓存。
    static func dnsProbe(force: Bool = false, idle: Bool = false,
                         key: String = "") -> (ip: String, fake: Bool, checked: Bool) {
        let ttl = idle ? idleProbeTTL : activeProbeTTL
        dnsLock.lock()
        if !force, let c = dnsCache, c.key == key, c.idle == idle,
           Date().timeIntervalSince(c.at) < ttl {
            dnsLock.unlock()
            return (c.ip, c.fake, c.checked)
        }
        dnsLock.unlock()

        let out = sh("/usr/bin/dig", ["+short", "+time=2", "+tries=1", "claude.ai"], timeout: 3.0)
        // +short 只输出地址，但 CNAME 链也会混进来，所以只认第一段像 IP 的行
        let ip = out.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty && $0.first.map { $0.isNumber } == true } ?? ""
        let result = ip.isEmpty ? ("", false, false) : (ip, isFakeIP(ip), true)
        dnsLock.lock()
        dnsCache = (Date(), key, idle, result.0, result.1, result.2)
        dnsLock.unlock()
        return result
    }

    /// fake-ip 网段。Clash / sing-box / Surge 默认都落在 198.18.0.0/15，
    /// 所以两个 /16 都算。有人自定义成 10.x 的认不出来——认不出来就当真实地址，
    /// 宁可多提醒一次，也不要因为「不认识」而漏掉。
    static func isFakeIP(_ ip: String) -> Bool {
        ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.")
    }

    // MARK: - 打 STUN（WebRTC 泄漏）

    /// 并发打几个 STUN 服务器，拿回它们看到的我们的公网地址。
    ///
    /// 这是唯一能验证「UDP 有没有进隧道」的办法：TUN 只代理 TCP 的时候，
    /// STUN 会走物理网卡出去，打回来的就是真实地址。
    ///
    /// 结果在 Claude 运行时缓存 60 秒、待命时缓存 5 分钟。每 30 秒一轮
    /// 都打 4 个服务器太吵，而出口的变化不会比一分钟更快；待命时更没必要。
    private static let stunLock = NSLock()
    private static var stunCache: (at: Date, key: String, idle: Bool, result: StunResult)?

    /// 出口消失时把缓存一起扔掉。出口重新出现后如果还留着上一次的结果，
    /// 面板会拿一条已经不存在的路去下结论。
    static func dropProbeCaches() {
        dnsLock.lock()
        dnsCache = nil
        dnsLock.unlock()
        stunLock.lock()
        stunCache = nil
        stunLock.unlock()
        transportLock.lock()
        transportCache = nil
        transportLock.unlock()
    }

    static func stunProbe(force: Bool = false, idle: Bool = false,
                          key: String = "") -> StunResult {
        let ttl = idle ? idleProbeTTL : stunActiveTTL
        stunLock.lock()
        if !force, let c = stunCache, c.key == key, c.idle == idle,
           Date().timeIntervalSince(c.at) < ttl {
            stunLock.unlock()
            return c.result
        }
        stunLock.unlock()

        // 分两类，这个区分很关键：
        //
        // 国内节点看到的「真实地址」是正常的——分流规则本来就把国内域名放直连，
        // 一个国内的 STUN 服务器回你家里的电信 IP，那是正确答案，不是泄漏。
        // 实测过：开着系统代理时 stun.miwifi.com 回 112.97.32.112（国内电信），
        // 同时境外节点回 5.34.220.136（代理出口）。
        //
        // 所以只有**境外**节点的结果才用来判泄漏：往境外发 UDP 却拿回真实地址，
        // 才说明 UDP 没进隧道。国内节点留着只做展示，让人看清分流是怎么走的。
        // nextcloud 特意选 443：置顶规则只罩 STUN 端口，443 这条单独量 UDP
        // 有没有从别的端口溜出去。
        let servers: [(String, UInt16, Bool)] = [
            ("stun.miwifi.com", 3478, false),
            ("stun.chat.bilibili.com", 3478, false),
            ("stun.qq.com", 3478, false),
            ("stun1.l.google.com", 19302, true),
            ("stun.freeswitch.org", 3478, true),
            ("stun.nextcloud.com", 443, true),
        ]
        var all = Set<String>()
        var foreign = Set<String>()
        let lock = NSLock()
        let group = DispatchGroup()
        let until = Date().addingTimeInterval(5)

        for (host, port, isForeign) in servers {
            DispatchQueue.global(qos: .utility).async(group: group) {
                guard let ip = stunQuery(host, port, until: until) else { return }
                lock.lock()
                all.insert(ip)
                if isForeign { foreign.insert(ip) }
                lock.unlock()
            }
        }
        // 多等 2 秒是给 DNS 解析留的余量；拿不到的服务器就当它没回，
        // 不因为一个节点超时就把整轮判成失败
        _ = group.wait(timeout: .now() + 7)

        let out = StunResult(all: all.sorted(), foreign: foreign.sorted(), checked: !all.isEmpty)
        stunLock.lock()
        stunCache = (Date(), key, idle, out)
        stunLock.unlock()
        return out
    }

    /// 一次 STUN 探测的结果。
    struct StunResult {
        /// 所有服务器看到的地址，含国内节点。只用来展示，不用来判泄漏。
        var all: [String] = []
        /// 只有境外节点看到的。这才是判泄漏的依据。
        var foreign: [String] = []
        var checked = false
    }

    /// 一次 RFC 5389 Binding 请求。返回服务器看到的我们的地址。
    static func stunQuery(_ host: String, _ port: UInt16, until: Date) -> String? {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_DGRAM,
                             ai_protocol: IPPROTO_UDP, ai_addrlen: 0,
                             ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let info = res else { return nil }
        defer { freeaddrinfo(res) }

        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        // 接收超时按剩余时间算，不写死——四个并发同时开跑，谁先回谁先算
        let left = max(0.2, until.timeIntervalSinceNow)
        var tv = timeval(tv_sec: Int(left), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Binding Request：类型 0x0001、长度 0、magic cookie、12 字节事务 ID
        var req = [UInt8](repeating: 0, count: 20)
        req[1] = 0x01
        req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42
        for i in 8..<20 { req[i] = UInt8.random(in: 0...255) }

        let sent = req.withUnsafeBytes { buf in
            sendto(fd, buf.baseAddress, 20, 0, info.pointee.ai_addr, info.pointee.ai_addrlen)
        }
        guard sent == 20 else { return nil }

        var resp = [UInt8](repeating: 0, count: 512)
        let n = recv(fd, &resp, resp.count, 0)
        guard n >= 20 else { return nil }
        return parseStun(Array(resp[0..<n]), txn: Array(req[8..<20]))
    }

    /// 解析一条 STUN 响应。单独拆出来是为了能拿构造好的包做单元测试——
    /// 真发 UDP 的测试在 CI 上不可靠，而位运算这块恰恰最需要测。
    static func parseStun(_ resp: [UInt8], txn: [UInt8]) -> String? {
        let n = resp.count
        guard n >= 20, resp[0] == 0x01, resp[1] == 0x01 else { return nil }
        // 事务 ID 必须对得上：UDP 不保证来源，可能收到别的会话的包
        guard Array(resp[8..<20]) == txn else { return nil }

        var pos = 20
        while pos + 4 <= n {
            let atype = Int(resp[pos]) << 8 | Int(resp[pos + 1])
            let alen = Int(resp[pos + 2]) << 8 | Int(resp[pos + 3])
            let v = pos + 4
            if v + alen > n { break }
            // 0x0020 = XOR-MAPPED-ADDRESS（RFC 5389），0x0001 = 老版 MAPPED-ADDRESS
            if (atype == 0x0020 || atype == 0x0001), alen >= 8, resp[v + 1] == 0x01 {
                var octets = Array(resp[(v + 4)..<(v + 8)])
                if atype == 0x0020 {
                    let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
                    for i in 0..<4 { octets[i] ^= cookie[i] }
                }
                return "\(octets[0]).\(octets[1]).\(octets[2]).\(octets[3])"
            }
            // 属性按 4 字节对齐，末尾补零不计入 alen
            pos = v + alen + ((4 - alen % 4) % 4)
        }
        return nil
    }

    // MARK: - 传输诊断

    /// 两个固定目标：一个 API 域名、一个网页域名。只发 HEAD，
    /// 不下载正文——这一步要证明的是「TLS 和 HTTP 能不能到达对端」，
    /// 不是去取内容。目标写死，不接受用户输入，免得哨兵被拿来扫别的站。
    static let transportTargets = [
        "https://api.anthropic.com/v1/models",
        "https://claude.ai/",
    ]
    /// Claude 在跑时两分钟一测。握手成功只描述那一刻，缓存太久会拿旧结论充数；
    /// 每轮巡检都发两个 HEAD 又没必要。待命时跟 DNS / STUN 一样降到 5 分钟。
    static let transportActiveTTL: TimeInterval = 120
    private static let transportLock = NSLock()
    private static var transportCache: (at: Date, key: String, idle: Bool,
                                        result: TransportResult)?

    struct TransportEndpoint {
        var target = ""
        var status = 0
        var error = ""      // timeout / tls / dns / offline / connect / other
        var seconds = 0.0
        /// 拿到了状态码就算到达。401/403 也能证明请求真的到了对端，
        /// 只是没带凭据——这一测本来就不带凭据。
        var reached: Bool { status > 0 && error.isEmpty }
    }

    struct TransportResult {
        var checked = false
        var api = TransportEndpoint()
        var web = TransportEndpoint()
        var at = 0.0
    }

    struct TransportVerdict {
        var state = "off"   // ok / warn / bad / off
        var label = ""
        var detail = ""
    }

    /// 把 URLSession 的错误码收敛成面板能说人话的几类。
    static func classifyTransportError(_ error: Error) -> String {
        guard let e = error as? URLError else { return "other" }
        switch e.code {
        case .timedOut:
            return "timeout"
        case .cannotFindHost, .dnsLookupFailed:
            return "dns"
        case .notConnectedToInternet, .networkConnectionLost:
            return "offline"
        case .cannotConnectToHost:
            return "connect"
        case .secureConnectionFailed, .serverCertificateUntrusted,
             .serverCertificateHasBadDate, .serverCertificateNotYetValid,
             .serverCertificateHasUnknownRoot, .clientCertificateRejected:
            return "tls"
        default:
            return "other"
        }
    }

    static func transportErrorLabel(_ code: String) -> String {
        switch code {
        case "timeout": return "超时"
        case "tls":     return "证书异常"
        case "dns":     return "解析失败"
        case "offline": return "本机离线"
        case "connect": return "连不上"
        case "other":   return "出错"
        default:        return "无响应"
        }
    }

    /// 纯函数，测试拿构造好的结果直接跑，不发网络。
    ///
    /// 判定只看「几条到达」：
    /// - 两条都到 → ok
    /// - 只有一条 → warn（按域名分流的规则漏了这个域名，最常见）
    /// - 一条都不到 → bad；其中只要有一条栽在证书上，单独标「证书异常」，
    ///   因为那正是中间人最想要的状态，不能和普通超时混成一句话。
    static func transportVerdict(_ r: TransportResult) -> TransportVerdict {
        var v = TransportVerdict()
        guard r.checked else { return v }
        let eps: [(String, TransportEndpoint)] = [
            ("api.anthropic.com", r.api),
            ("claude.ai", r.web),
        ]
        let ok = eps.filter { $0.1.reached }
        let bad = eps.filter { !$0.1.reached }

        if bad.isEmpty {
            let slowest = max(r.api.seconds, r.web.seconds)
            let ms = Int((slowest * 1000).rounded())
            v.state = "ok"
            v.label = "通 · \(ms) ms"
            v.detail = "两个 HTTPS 目标都完成了 TLS 握手：api.anthropic.com 返回 "
                + "\(r.api.status)，claude.ai 返回 \(r.web.status)。有状态码就说明请求确实到了对端。"
            return v
        }

        let reasons = bad.map { name, ep in
            "\(name) \(ep.error.isEmpty ? "无响应" : transportErrorLabel(ep.error))"
        }.joined(separator: "、")

        if ok.isEmpty {
            v.state = "bad"
            if bad.contains(where: { $0.1.error == "tls" }) {
                v.label = "证书异常"
                v.detail = "\(reasons)。TLS 没建立起来。证书链校验失败时哨兵不会替你放行，"
                    + "因为「点了信任」正是中间人需要的那一步；先查代理的证书设置。"
            } else {
                v.label = "不通"
                v.detail = "\(reasons)。两个目标都没连上，Claude 就算能启动也到不了 Anthropic。"
            }
            return v
        }

        v.state = "warn"
        v.label = "一条不通"
        v.detail = "\(reasons)；另一条是通的。按域名分流的规则常会漏掉其中一个域名，"
            + "先看分流规则里有没有这一条。"
        return v
    }

    /// 用当前系统路径（TUN 或系统代理）打两个 HEAD。不指定代理、不带 Cookie、
    /// 不带 Authorization、不覆盖证书校验——测的就是 Claude 会走的那条路。
    static func transportProbe(force: Bool = false, idle: Bool = false,
                               key: String = "") -> TransportResult {
        let ttl = idle ? idleProbeTTL : transportActiveTTL
        transportLock.lock()
        if !force, let c = transportCache, c.key == key, c.idle == idle,
           Date().timeIntervalSince(c.at) < ttl {
            transportLock.unlock()
            return c.result
        }
        transportLock.unlock()

        let lock = NSLock()
        let group = DispatchGroup()
        var eps = [TransportEndpoint](repeating: TransportEndpoint(),
                                      count: transportTargets.count)
        for (i, target) in transportTargets.enumerated() {
            DispatchQueue.global(qos: .utility).async(group: group) {
                let ep = requestTransport(target)
                lock.lock()
                eps[i] = ep
                lock.unlock()
            }
        }
        // 单条请求自身 6 秒超时，多给 2 秒让两条并发都收尾。
        _ = group.wait(timeout: .now() + 8)

        var out = TransportResult()
        out.checked = true
        out.at = Date().timeIntervalSince1970
        out.api = eps[0]
        out.web = eps.count > 1 ? eps[1] : TransportEndpoint()
        transportLock.lock()
        transportCache = (Date(), key, idle, out)
        transportLock.unlock()
        return out
    }

    private static func requestTransport(_ target: String) -> TransportEndpoint {
        var ep = TransportEndpoint()
        ep.target = target
        guard let url = URL(string: target) else {
            ep.error = "other"
            return ep
        }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 6
        cfg.timeoutIntervalForResource = 8
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.urlCache = nil
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .never
        cfg.httpCookieStorage = nil
        // Probe 只依赖 Foundation（测试会把它单独编译），别在这里引用
        // ShieldApp 里的版本号。
        cfg.httpAdditionalHeaders = ["User-Agent": "ClaudeShield transport-check"]
        let session = URLSession(configuration: cfg)
        var req = URLRequest(url: url)
        req.httpMethod = "HEAD"
        req.timeoutInterval = 6
        req.cachePolicy = .reloadIgnoringLocalCacheData
        // 显式不带凭据：这一测只回答路通不通，不碰用户的账号。
        req.setValue("", forHTTPHeaderField: "Cookie")
        req.setValue("", forHTTPHeaderField: "Authorization")

        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var status = 0
        var failure: Error?
        let started = Date()
        let task = session.dataTask(with: req) { _, resp, err in
            lock.lock()
            if let h = resp as? HTTPURLResponse { status = h.statusCode }
            failure = err
            lock.unlock()
            sem.signal()
        }
        task.resume()

        if sem.wait(timeout: .now() + 8) == .timedOut {
            task.cancel()
            session.invalidateAndCancel()
            ep.error = "timeout"
            ep.seconds = Date().timeIntervalSince(started)
            return ep
        }
        session.finishTasksAndInvalidate()
        lock.lock()
        let code = status
        let err = failure
        lock.unlock()
        ep.seconds = Date().timeIntervalSince(started)
        if code > 0 {
            ep.status = code
        } else if let e = err {
            ep.error = classifyTransportError(e)
        } else {
            ep.error = "other"
        }
        return ep
    }

    /// 把 IPv4 打码成 `1.2.*.4`。日志和面板都不该留下完整真实地址——
    /// 检测泄漏的日志自己变成泄漏，是这类工具最容易犯的错。
    static func maskIP(_ ip: String) -> String {
        let p = ip.split(separator: ".")
        guard p.count == 4 else { return ip }
        return "\(p[0]).\(p[1]).*.\(p[3])"
    }

    /// 比对打码地址：`1.2.*.4` 对上 `1.2.3.4`。
    ///
    /// 塔只肯写打码后的地址，第三段是通配的。能对上首两段和末段，
    /// 已经足够认出「这是不是同一个出口」——比把完整 IP 落到磁盘上划算。
    static func matchesMask(_ ip: String, _ mask: String) -> Bool {
        let a = ip.split(separator: "."), b = mask.split(separator: ".")
        guard a.count == 4, b.count == 4 else { return false }
        for i in 0..<4 {
            if b[i] == "*" { continue }
            if a[i] != b[i] { return false }
        }
        return true
    }

    // MARK: - 跑命令

    /// 硬超时。巡检在后台线程跑，但一条卡住的命令会拖住整轮，
    /// 下一轮就会和这一轮叠在一起——所以宁可直接放弃这次读取。
    @discardableResult
    static func sh(_ path: String, _ args: [String] = [], timeout: TimeInterval = 2.0) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run() } catch { return "" }
        // 必须在等退出之前把管道排空。`ps -axo comm=` 在这台机器上有 100KB+，
        // 超过管道缓冲后子进程会卡在 write 上，等它退出再读就是死等。
        let buf = NSMutableData()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            buf.append(pipe.fileHandleForReading.readDataToEndOfFile())
            done.signal()
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            return ""
        }
        p.waitUntilExit()
        return String(data: buf as Data, encoding: .utf8) ?? ""
    }
}

// 只审计本机连接元数据；不抓包、不解密、不写目标 IP 或命令行到磁盘。
// TUN 路由是线索，不是代理策略的证据，因此永远不会被标成「全部已代理」。
struct ConnectionAudit {
    var state = "unknown"
    var observed = 0
    var localProxy = 0
    var direct = 0
    var unknown = 0
    var detail = "未确认：尚未采样"
}

enum ConnectionMonitor {
    struct ProcessInfo {
        var pid: Int
        var parent: Int
        var path: String
    }
    struct SocketInfo {
        var pid: Int
        var proto: String
        var name: String
        var state: String
    }
    struct Endpoint: Hashable {
        var host: String
        var port: Int
    }

    static func processes(_ text: String) -> [ProcessInfo] {
        text.split(separator: "\n").compactMap { line in
            let parts = line.split(maxSplits: 2, whereSeparator: { $0 == " " || $0 == "\t" })
            guard parts.count == 3, let pid = Int(parts[0]), let parent = Int(parts[1]) else { return nil }
            return ProcessInfo(pid: pid, parent: parent, path: String(parts[2]))
        }
    }

    static func claudePIDs(_ ps: [ProcessInfo]) -> Set<Int> {
        // 不用「包含 Claude」：否则哨兵本身和无关终端也会被纳入。
        var ids = Set(ps.filter { $0.path.contains("/Claude.app/Contents/") }.map { $0.pid })
        for _ in 0..<32 {
            let more = Set(ps.filter { ids.contains($0.parent) }.map { $0.pid })
            let merged = ids.union(more)
            if merged == ids { break }
            ids = merged
        }
        return ids
    }

    static func supportedClient(_ path: String) -> Bool {
        let p = path.lowercased()
        return ["clash verge.app/contents/", "clash verge rev.app/contents/",
                "flclash.app/contents/", "shadowrocket.app/contents/", "surge.app/contents/",
                "clash-verge-service", "verge-mihomo", "com.liguangming.shadowrocket"].contains { p.contains($0) }
    }

    static func sockets(_ text: String) -> [SocketInfo] {
        var out: [SocketInfo] = []
        var pid = 0, proto = "", name = "", state = ""
        func flush() {
            if pid > 0, !name.isEmpty { out.append(SocketInfo(pid: pid, proto: proto, name: name, state: state)) }
            proto = ""; name = ""; state = ""
        }
        for raw in text.split(separator: "\n") {
            let line = String(raw)
            if line.hasPrefix("p") { flush(); pid = Int(line.dropFirst()) ?? 0 }
            else if line.hasPrefix("f") { flush() }
            else if line.hasPrefix("P") { proto = String(line.dropFirst()) }
            else if line.hasPrefix("n") { name = String(line.dropFirst()) }
            else if line.hasPrefix("TST=") { state = String(line.dropFirst(4)) }
        }
        flush()
        return out
    }

    static func endpoint(_ text: String) -> Endpoint? {
        guard let colon = text.lastIndex(of: ":"), let port = Int(text[text.index(after: colon)...]),
              port > 0, port <= 65535 else { return nil }
        let host = String(text[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard !host.isEmpty else { return nil }
        return Endpoint(host: host, port: port)
    }

    static func isLoopback(_ host: String) -> Bool {
        host == "::1" || host.hasPrefix("127.") || host.hasPrefix("::ffff:127.")
    }

    static func isPublic(_ host: String) -> Bool {
        let h = host.lowercased()
        if h.contains(":") {
            // 只把全球单播 IPv6 当成公网；ULA/link-local/映射 IPv4 都保留未确认。
            return h.first == "2" || h.first == "3"
        }
        let a = h.split(separator: ".").compactMap { Int($0) }
        guard a.count == 4, a.allSatisfy({ $0 >= 0 && $0 < 256 }) else { return false }
        if [0, 10, 127].contains(a[0]) || a[0] >= 224 { return false }
        if a[0] == 169 && a[1] == 254 || a[0] == 192 && a[1] == 168 { return false }
        if a[0] == 172 && (16...31).contains(a[1]) || a[0] == 100 && (64...127).contains(a[1]) { return false }
        if a[0] == 198 && (a[1] == 18 || a[1] == 19) { return false }
        return true
    }

    static func classify(_ rows: [SocketInfo], claude: Set<Int>, clients: Set<Int>,
                         routes: [String: String], tunActive: Bool = false) -> ConnectionAudit {
        var result = ConnectionAudit()
        let listeners = rows.filter { clients.contains($0.pid) && $0.proto == "TCP" && $0.state == "LISTEN" }
            .compactMap { endpoint($0.name) }
        for row in rows where claude.contains(row.pid) {
            let pair = row.name.components(separatedBy: "->")
            // 未连接 UDP socket 没有目标，不能当成「没有泄漏」。
            if row.proto == "UDP" && pair.count != 2 { result.unknown += 1; continue }
            guard pair.count == 2, let dest = endpoint(pair[1]) else { continue }
            result.observed += 1
            // lsof 的箭头不区分主动连接与已接受连接。命中本进程监听端口的
            // 入站会话不能被误报为 Claude 主动绕过代理。
            if row.proto == "TCP", let local = endpoint(pair[0]), rows.contains(where: {
                $0.pid == row.pid && $0.state == "LISTEN" && endpoint($0.name)?.port == local.port
            }) {
                result.unknown += 1
                continue
            }
            if row.proto == "TCP", isLoopback(dest.host), listeners.contains(where: {
                $0.port == dest.port && ($0.host == dest.host || $0.host == "*"
                    || $0.host == "0.0.0.0" || $0.host == "::")
            }) {
                result.localProxy += 1
            } else if !tunActive, isPublic(dest.host), let iface = routes[dest.host],
                      iface.hasPrefix("en") || iface.hasPrefix("pdp_ip") {
                // 只报告「当前物理路由」，不把 utun 的存在当成该连接的代理证明。
                result.direct += 1
            } else {
                result.unknown += 1
            }
        }
        if result.direct > 0 {
            result.state = "direct"
            result.detail = "未见 TUN，发现 \(result.direct) 条公网连接的当前路由直达物理网卡；戒严将请求退出 Claude"
        } else if result.observed > 0, result.unknown == 0 {
            result.state = "local"
            result.detail = "本次观察到 \(result.localProxy) 条连接到受支持客户端的本地 TCP 端口；不代表全时段无直连"
        } else {
            result.detail = "未确认：观察到 \(result.observed) 条连接、\(result.unknown) 项证据不足（含 TUN、UDP 或未知本地端口）；不能证明全部走代理"
        }
        return result
    }

    static func run(tunActive: Bool) -> ConnectionAudit {
        let ps = processes(Probe.sh("/bin/ps", ["-axo", "pid=,ppid=,comm="]))
        let claude = claudePIDs(ps)
        guard !claude.isEmpty else { return ConnectionAudit(detail: "未确认：未发现 Claude 桌面进程") }
        let clients = Set(ps.filter { supportedClient($0.path) }.map { $0.pid })
        let ids = claude.union(clients).sorted().map(String.init).joined(separator: ",")
        let text = Probe.sh("/usr/sbin/lsof", ["-nP", "-a", "-p", ids, "-i", "-FpfPnT"], timeout: 3)
        guard !text.isEmpty else { return ConnectionAudit(detail: "未确认：未取得连接快照，可能无活动连接、权限不足或采样超时") }
        let rows = sockets(text)
        let hosts = Set(rows.filter { claude.contains($0.pid) }.compactMap { row -> String? in
            let p = row.name.components(separatedBy: "->")
            guard p.count == 2, let dest = endpoint(p[1]), isPublic(dest.host) else { return nil }
            return dest.host
        })
        var routes: [String: String] = [:]
        // 限制每轮开销。超出上限的目标保持未确认，绝不默认为已代理。
        for host in hosts.sorted().prefix(12) {
            let family = host.contains(":") ? "-inet6" : "-inet"
            let text = Probe.sh("/sbin/route", ["-n", "get", family, host], timeout: 0.3)
            for line in text.split(separator: "\n") {
                let s = line.trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("interface:") { routes[host] = s.dropFirst(10).trimmingCharacters(in: .whitespaces) }
            }
        }
        // PID 可能在采样期间退出并被复用；路径与父进程均未变才使用该轮证据。
        let after = processes(Probe.sh("/bin/ps", ["-axo", "pid=,ppid=,comm="]))
        let stable = Set(ps.filter { before in after.contains {
            $0.pid == before.pid && $0.path == before.path && $0.parent == before.parent
        }}.map { $0.pid })
        guard claude.isSubset(of: stable), clients.isSubset(of: stable) else {
            return ConnectionAudit(detail: "未确认：采样期间进程发生变化，等待下一轮")
        }
        return classify(rows, claude: claude, clients: clients, routes: routes, tunActive: tunActive)
    }
}
