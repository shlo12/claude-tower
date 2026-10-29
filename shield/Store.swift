import Foundation

/// 与 Tower 共用的状态文件。Tower 写基线（时区、出口国家、识别到的客户端），
/// Shield 只读基线、写自己的开关与命中记录——单向依赖，不会互相覆盖。
struct Config: Codable {
    var version = 1
    var enabled = true
    /// 1 = 宽松，仅提醒；2 = 严格，启动后检查 + 运行中急停（需用户显式开启）
    var level = 1
    var baselineTz = ""
    var country = ""
    /// 塔写下的打码出口地址（`1.2.*.4`）。拿它跟 STUN 结果比对，
    /// 判断 UDP 出口和 HTTP 出口是不是同一个。
    var egressIP = ""
    /// 塔记录这个出口的时间。过期了就不敢拿它下结论。
    var egressAt: Double = 0
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

/// 塔写的那几个键。Shield 每次巡检都要重读一遍：塔可能在 Shield
/// 运行期间刚扫过一次，启动时缓存的旧值会让「没有基线」的提醒一直挂着。
struct Baseline {
    var baselineTz = ""
    var country = ""
    var egressIP = ""
    var egressAt: Double = 0
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
                        ruleGuard: cfg.ruleGuard)
    }

    static func save(_ cfg: Config) {
        ensureDir()
        var trimmed = cfg
        if trimmed.hits.count > maxHits {
            trimmed.hits = Array(trimmed.hits.suffix(maxHits))
        }
        // 写之前把塔刚写的基线读回来。
        // Shield 只在启动时加载一次，之后每记一条命中就整份写回——这中间
        // 塔完全可能更新了出口 IP，不读回来就会用启动时的旧值把它盖掉。
        // 基线那几个键是塔的，我们只能读不能盖。
        if let data = try? Data(contentsOf: fileURL),
           let disk = try? JSONDecoder().decode(Config.self, from: data) {
            if !disk.baselineTz.isEmpty { trimmed.baselineTz = disk.baselineTz }
            if !disk.country.isEmpty { trimmed.country = disk.country }
            if !disk.egressIP.isEmpty { trimmed.egressIP = disk.egressIP }
            if disk.egressAt > trimmed.egressAt { trimmed.egressAt = disk.egressAt }
            // 规则清单整份归塔管：塔撤销修复时会把 key 删掉，这里必须跟着
            // 变成 nil，否则哨兵会把自己内存里的旧清单又写回去，永远报漂移。
            trimmed.ruleGuard = disk.ruleGuard
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? enc.encode(trimmed) else { return }
        try? data.write(to: fileURL, options: .atomic)
        // 里面有时区和出口国家，虽然算不上秘密，也没必要给同机其他用户读
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
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
