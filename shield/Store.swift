import Foundation

/// 与 Tower 共用的状态文件。
///
/// 基线（时区、出口国家、打码出口）两边都会写：塔在扫描后写一次，
/// 哨兵每天自己用 Claude 边缘的 trace 结果续期，这样不开塔也不会过期。
/// 时区基线仍然只有塔能建——哨兵分不清「该是哪个时区」。
/// 写到同一个出口时按时间取新的那份，谁都不整套覆盖对方。
struct Config: Codable {
    var version = 1
    var enabled = true
    /// 1 = 宽松，仅提醒；2 = 严格，启动后检查 + 运行中急停（需用户显式开启）
    var level = 1
    var baselineTz = ""
    var country = ""
    /// 打码后的出口地址（`1.2.*.4`）。拿它跟 STUN 结果比对，
    /// 判断 UDP 出口和 HTTP 出口是不是同一个。
    var egressIP = ""
    /// 这个出口最后一次被确认/续期的时间。过期了就不敢拿它下结论。
    var egressAt: Double = 0
    /// 测到了、但和基线对不上的出口。等用户确认后才替换基线——
    /// 静默跟着新值走，真泄漏也会被记成「正常」。
    var egressSeen = ""
    var egressSeenAt: Double = 0
    var egressSeenCountry = ""
    var clients: [String] = []
    var interval = 30
    /// 暂停到这个时间戳之前不再巡检
    var pausedUntil: Double = 0
    var hits: [Hit] = []
    /// 塔写下的分流规则清单。Shield 只读，每次巡检重新核对这些规则还在不在。
    var ruleGuard: RuleGuard?
    /// 用户想不想开机自启。nil 是老版本留下的文件：按「已装 plist」补，
    /// 不替用户猜一个他从来没选过的偏好。
    var loginIntent: Bool?

    struct Hit: Codable {
        var ts: Double
        var kind: String
        var note: String
    }

    init() {}

    /// Tower 写出的文件不一定带齐字段（旧版本、手写、或只写了基线），
    /// 所以每个键都要容错——一个缺字段不该让整个 Shield 起不来。
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = (try? c.decodeIfPresent(Int.self, forKey: .version)) ?? 1
        enabled = (try? c.decodeIfPresent(Bool.self, forKey: .enabled)) ?? true
        level = (try? c.decodeIfPresent(Int.self, forKey: .level)) ?? 1
        baselineTz = (try? c.decodeIfPresent(String.self, forKey: .baselineTz)) ?? ""
        country = (try? c.decodeIfPresent(String.self, forKey: .country)) ?? ""
        egressIP = (try? c.decodeIfPresent(String.self, forKey: .egressIP)) ?? ""
        egressAt = (try? c.decodeIfPresent(Double.self, forKey: .egressAt)) ?? 0
        egressSeen = (try? c.decodeIfPresent(String.self, forKey: .egressSeen)) ?? ""
        egressSeenAt = (try? c.decodeIfPresent(Double.self, forKey: .egressSeenAt)) ?? 0
        egressSeenCountry = (try? c.decodeIfPresent(String.self, forKey: .egressSeenCountry)) ?? ""
        clients = (try? c.decodeIfPresent([String].self, forKey: .clients)) ?? []
        interval = (try? c.decodeIfPresent(Int.self, forKey: .interval)) ?? 30
        pausedUntil = (try? c.decodeIfPresent(Double.self, forKey: .pausedUntil)) ?? 0
        hits = (try? c.decodeIfPresent([Hit].self, forKey: .hits)) ?? []
        ruleGuard = try? c.decodeIfPresent(RuleGuard.self, forKey: .ruleGuard)
        loginIntent = try? c.decodeIfPresent(Bool.self, forKey: .loginIntent)
        // 巡检周期设下限：1 秒一次会把 ps/netstat 变成常驻负载
        if interval < 5 { interval = 5 }
        if level == 3 { level = 2 } // 旧 L3 合并到严格模式；旧 L2 保持为 2
        if level < 1 || level > 2 { level = 1 }
    }
}

/// 基线那几个键。Shield 每次巡检都要重读一遍：塔可能在 Shield
/// 运行期间刚扫过一次，启动时缓存的旧值会让「没有基线」的提醒一直挂着。
struct Baseline {
    var baselineTz = ""
    var country = ""
    var egressIP = ""
    var egressAt: Double = 0
    var egressSeen = ""
    var egressSeenAt: Double = 0
    var egressSeenCountry = ""
    var ruleGuard: RuleGuard?
}

enum Store {
    static let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ccclean", isDirectory: true)
    static var fileURL: URL { dir.appendingPathComponent("shield.json") }
    static var logURL: URL { dir.appendingPathComponent("shield.log") }

    private static let maxLogBytes = 256 * 1024
    private static let maxHits = 50

    static func ensureDir() {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
    }

    static func load() -> Config {
        guard let data = try? Data(contentsOf: fileURL),
              let cfg = try? JSONDecoder().decode(Config.self, from: data) else {
            return Config()
        }
        if let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           raw["level"] as? Int == 3 {
            save(cfg) // 把旧档位持久化成两模式的规范值，不丢基线与命中记录。
        }
        return cfg
    }

    /// 只取塔写的那几个键。面板每轮巡检都调一次，所以这里不能顺带
    /// 把 Shield 自己的开关读回来——暂停、级别、命中记录都归 Shield 管。
    static func loadBaseline() -> Baseline {
        guard let data = try? Data(contentsOf: fileURL),
              let cfg = try? JSONDecoder().decode(Config.self, from: data) else {
            return Baseline()
        }
        return Baseline(baselineTz: cfg.baselineTz, country: cfg.country,
                        egressIP: cfg.egressIP, egressAt: cfg.egressAt,
                        egressSeen: cfg.egressSeen, egressSeenAt: cfg.egressSeenAt,
                        egressSeenCountry: cfg.egressSeenCountry,
                        ruleGuard: cfg.ruleGuard)
    }

    static func save(_ cfg: Config) {
        var trimmed = cfg
        if trimmed.hits.count > maxHits {
            trimmed.hits = Array(trimmed.hits.suffix(maxHits))
        }
        // 写之前把盘上的基线读回来。
        // Shield 只在启动时加载一次，之后每记一条命中就整份写回——这中间
        // 塔完全可能更新了基线，不读回来就会用启动时的旧值把它盖掉。
        //
        // 出口那一组两边都写，按「最后一次确认/测到」的时间取新的那份；
        // 其他键各有归属：时区与规则清单归塔，开关与命中记录归哨兵。
        if let data = try? Data(contentsOf: fileURL),
           let disk = try? JSONDecoder().decode(Config.self, from: data) {
            if !disk.baselineTz.isEmpty { trimmed.baselineTz = disk.baselineTz }
            if egressStamp(disk) > egressStamp(trimmed) {
                trimmed.egressIP = disk.egressIP
                trimmed.egressAt = disk.egressAt
                trimmed.country = disk.country
                trimmed.egressSeen = disk.egressSeen
                trimmed.egressSeenAt = disk.egressSeenAt
                trimmed.egressSeenCountry = disk.egressSeenCountry
            }
            // 规则清单整份归塔管：塔撤销修复时会把 key 删掉，这里必须跟着
            // 变成 nil，否则哨兵会把自己内存里的旧清单又写回去，永远报漂移。
            trimmed.ruleGuard = disk.ruleGuard
        }
        write(trimmed)
    }

    private static func write(_ cfg: Config) {
        ensureDir()
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? enc.encode(cfg) else { return }
        try? data.write(to: fileURL, options: .atomic)
        // 里面有时区和出口国家，虽然算不上秘密，也没必要给同机其他用户读
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    // MARK: - 出口基线

    /// 自测出口的续期周期。比对只信任 24 小时以内的基线，20 小时续一次，
    /// 留出一轮失败重试的余量——网络抖一下不该让比对能力掉线一天。
    static let egressRenew: Double = 20 * 3600

    enum EgressUpdate: String {
        case skipped, adopted, refreshed, cleared, pending
    }

    private static func egressStamp(_ cfg: Config) -> Double {
        max(cfg.egressAt, cfg.egressSeenAt)
    }

    /// 纯逻辑，不碰磁盘：测试直接喂 Config 和时间点。
    ///
    /// 测到的出口和基线不同时**不**覆盖基线，只记成待确认。基线是
    /// 「UDP 出口该长什么样」的参照，跟着新值悄悄走的话，真泄漏会被
    /// 当成正常。只有用户点「是我换的」才替换（`confirmEgress`）。
    ///
    /// 只收 IPv4 打码地址：STUN 比对是按 IPv4 掩码做的，IPv6 记进来
    /// 只会让这一项永远「没法比对」。
    static func applyEgress(_ cfg: inout Config, mask: String, country: String,
                            at: Double) -> EgressUpdate {
        guard mask.contains("*"), !mask.contains(":") else { return .skipped }
        let country = country.uppercased()
        if cfg.egressIP.isEmpty {
            cfg.egressIP = mask
            cfg.egressAt = at
            if !country.isEmpty { cfg.country = country }
            clearSeen(&cfg, at: at)
            return .adopted
        }
        if mask == cfg.egressIP {
            var out: EgressUpdate = .skipped
            if !cfg.egressSeen.isEmpty {
                clearSeen(&cfg, at: at)
                out = .cleared
            }
            if at - cfg.egressAt >= egressRenew {
                cfg.egressAt = at
                if !country.isEmpty { cfg.country = country }
                if out == .skipped { out = .refreshed }
            }
            return out
        }
        if cfg.egressSeen == mask { return .skipped }
        cfg.egressSeen = mask
        cfg.egressSeenAt = at
        cfg.egressSeenCountry = country
        return .pending
    }

    /// 用户确认「这个新出口是我自己换的」，才把待确认的地址升成基线。
    static func confirmEgress(_ cfg: inout Config, at: Double) -> Bool {
        guard !cfg.egressSeen.isEmpty else { return false }
        cfg.egressIP = cfg.egressSeen
        cfg.egressAt = at
        if !cfg.egressSeenCountry.isEmpty { cfg.country = cfg.egressSeenCountry }
        clearSeen(&cfg, at: at)
        return true
    }

    private static func clearSeen(_ cfg: inout Config, at: Double) {
        cfg.egressSeen = ""
        cfg.egressSeenCountry = ""
        // 时间戳留着当水印：别的写入方拿着更旧的待确认记录时，
        // 不能把「已经确认过」的状态又盖回去。
        cfg.egressSeenAt = at
    }

    /// 读盘、按规则更新、整份写回。盘上那份已经是最新，只需要换掉出口
    /// 那几个键，其余键（开关、命中记录、规则清单）原样保留。
    @discardableResult
    static func recordEgress(_ cfg: inout Config, mask: String, country: String,
                             at: Double) -> EgressUpdate {
        // 塔可能刚扫过，比内存里的新。先把它并进来再判，免得用旧基线做决定。
        // 只并塔写的那几个键：读坏了就跳过，不能拿默认值把内存里的基线清空。
        if let data = try? Data(contentsOf: fileURL),
           let disk = try? JSONDecoder().decode(Config.self, from: data) {
            if !disk.baselineTz.isEmpty { cfg.baselineTz = disk.baselineTz }
            if egressStamp(disk) > egressStamp(cfg) {
                cfg.egressIP = disk.egressIP
                cfg.egressAt = disk.egressAt
                cfg.country = disk.country
                cfg.egressSeen = disk.egressSeen
                cfg.egressSeenAt = disk.egressSeenAt
                cfg.egressSeenCountry = disk.egressSeenCountry
            }
            cfg.ruleGuard = disk.ruleGuard
        }
        let update = applyEgress(&cfg, mask: mask, country: country, at: at)
        guard update != .skipped else { return update }
        write(cfg)
        return update
    }

    /// 追加一条命中记录。同一种状态在 5 分钟内反复出现只记一次——
    /// 巡检 30 秒一次，出口断了十分钟就会堆二十条一样的，日志就没法看了。
    ///
    /// `force` 给「动过手」用：终止 Claude 是必须留痕的动作，一分钟冷却之后
    /// 又杀了一次，就该有第二条记录。杀了三次只剩一条，等于没记。
    static func appendHit(_ cfg: inout Config, kind: String, note: String,
                          force: Bool = false) {
        let now = Date().timeIntervalSince1970
        if !force, let last = cfg.hits.last, last.kind == kind, now - last.ts < 300 { return }
        cfg.hits.append(Config.Hit(ts: now, kind: kind, note: note))
        if cfg.hits.count > maxHits { cfg.hits = Array(cfg.hits.suffix(maxHits)) }
    }

    /// 滚动日志：超过 256KB 轮转一次，只留一代。
    /// 我们自己刚把「不留副本」做完，不能转头写一个无限长的日志。
    static func log(_ line: String) {
        ensureDir()
        if let attrs = try? FileManager.default.attributesOfItem(atPath: logURL.path),
           let size = attrs[.size] as? Int, size > maxLogBytes {
            let old = logURL.appendingPathExtension("1")
            try? FileManager.default.removeItem(at: old)
            try? FileManager.default.moveItem(at: logURL, to: old)
        }
        let stamp = ISO8601DateFormatter().string(from: Date())
        guard let data = "\(stamp) \(line)\n".data(using: .utf8) else { return }
        if let fh = try? FileHandle(forWritingTo: logURL) {
            fh.seekToEndOfFile()
            fh.write(data)
            try? fh.close()
        } else {
            try? data.write(to: logURL, options: .atomic)
        }
    }
}
