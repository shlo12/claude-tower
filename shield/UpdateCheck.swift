import Cocoa
import Foundation

/// 自动更新在哨兵这一侧只做「发现」。
///
/// 真正危险的三步——下载、校验、换掉正在运行的 .app——全在塔里做：
/// 只有塔带 Python，也只有塔知道自己的安装路径。哨兵常驻，所以由它
/// 按间隔查 GitHub；查到新版就在面板上亮一行，点「去塔里更新」写一个
/// 请求标记并打开塔，后面的确认、备份、回滚都由塔负责。
///
/// 文件分工：
///   ~/.ccclean/update.json        塔写：仓库、是否自动检查、检查间隔
///   ~/.ccclean/shield-update.json 哨兵写：自己最近一次检查的结果
///   ~/.ccclean/update-request.json 哨兵写、塔读一次即删
///
/// 这里不存 token、不存公网地址；只存版本号和错误原因。
enum UpdateCheck {

    struct Config {
        var repo = ""
        var autoCheck = true
        var checkHours = 12.0
    }

    struct Result: Codable {
        var at: Double = 0
        var repo = ""
        var newer = false
        var version = ""
        var shieldVersion = ""
        var minMacOS = ""
        var error = ""
    }

    static var configURL: URL { Store.dir.appendingPathComponent("update.json") }
    static var resultURL: URL { Store.dir.appendingPathComponent("shield-update.json") }
    static var requestURL: URL { Store.dir.appendingPathComponent("update-request.json") }

    private static let allowedHosts: Set<String> = [
        "api.github.com", "github.com",
        "objects.githubusercontent.com", "release-assets.githubusercontent.com",
    ]
    private static let manifestName = "update-manifest.json"
    private static let lock = NSLock()
    private static var running = false

    // MARK: - 读配置

    static func readConfig() -> Config {
        var cfg = Config()
        guard let data = try? Data(contentsOf: configURL),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return cfg
        }
        cfg.repo = (obj["repo"] as? String) ?? ""
        cfg.autoCheck = (obj["autoCheck"] as? Bool) ?? true
        if let hours = obj["checkHours"] as? Double, hours > 0 { cfg.checkHours = hours }
        if let hours = obj["checkHours"] as? Int, hours > 0 { cfg.checkHours = Double(hours) }
        return cfg
    }

    static func readResult() -> Result {
        guard let data = try? Data(contentsOf: resultURL),
              let r = try? JSONDecoder().decode(Result.self, from: data) else {
            return Result()
        }
        return r
    }

    /// 给面板的一行。页面不读文件，所有状态都从这里推过去。
    static func payload() -> [String: Any] {
        let cfg = readConfig()
        let r = readResult()
        return [
            "repo": cfg.repo,
            "configured": !cfg.repo.isEmpty,
            "autoCheck": cfg.autoCheck,
            "newer": r.newer,
            "version": r.version,
            "shieldVersion": r.shieldVersion,
            "checkedAt": r.at,
            "error": r.error,
        ]
    }

    // MARK: - 检查

    /// 到点才查。启动后调用一次，之后每小时问一次「到点了吗」。
    static func startIfDue(force: Bool = false) {
        let cfg = readConfig()
        guard !cfg.repo.isEmpty, cfg.autoCheck || force else { return }
        let last = readResult()
        let hours = max(1.0, min(168.0, cfg.checkHours))
        if !force, last.repo == cfg.repo, last.at > 0,
           Date().timeIntervalSince1970 - last.at < hours * 3600 {
            return
        }
        checkNow()
    }

    static func checkNow() {
        lock.lock()
        if running {
            lock.unlock()
            return
        }
        running = true
        lock.unlock()

        DispatchQueue.global(qos: .utility).async {
            defer {
                lock.lock()
                running = false
                lock.unlock()
            }
            let cfg = readConfig()
            guard !cfg.repo.isEmpty, validRepo(cfg.repo) else {
                save(Result(at: now(), repo: cfg.repo))
                return
            }
            check(cfg)
        }
    }

    private static func check(_ cfg: Config) {
        var result = Result(at: now(), repo: cfg.repo)
        let release = fetch("https://api.github.com/repos/\(cfg.repo)/releases/latest")
        guard let releaseData = release.data,
              let releaseObj = try? JSONSerialization.jsonObject(with: releaseData) as? [String: Any] else {
            result.error = release.error.isEmpty ? "更新服务器返回的不是合法 JSON" : release.error
            keepKnownVersions(&result)
            save(result)
            finish(result)
            return
        }
        if (releaseObj["draft"] as? Bool) == true || (releaseObj["prerelease"] as? Bool) == true {
            result.error = "最新 Release 不可用"
            keepKnownVersions(&result)
            save(result)
            finish(result)
            return
        }
        guard let tag = releaseObj["tag_name"] as? String,
              let version = normalized(tag) else {
            result.error = "Release 版本号无效"
            keepKnownVersions(&result)
            save(result)
            finish(result)
            return
        }
        var manifestURL = ""
        for item in (releaseObj["assets"] as? [[String: Any]]) ?? [] {
            if (item["name"] as? String) == manifestName {
                manifestURL = (item["browser_download_url"] as? String) ?? ""
            }
        }
        guard !manifestURL.isEmpty else {
            result.error = "Release 缺少 \(manifestName)"
            keepKnownVersions(&result)
            save(result)
            finish(result)
            return
        }
        let manifest = fetch(manifestURL)
        guard let manifestData = manifest.data,
              let obj = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any],
              (obj["schema"] as? Int) == 1 else {
            result.error = manifest.error.isEmpty ? "更新清单格式不认识" : manifest.error
            keepKnownVersions(&result)
            save(result)
            finish(result)
            return
        }
        guard let shieldVersion = normalized((obj["shieldVersion"] as? String) ?? ""),
              normalized((obj["version"] as? String) ?? "") == version else {
            result.error = "更新清单与 Release 不一致"
            keepKnownVersions(&result)
            save(result)
            finish(result)
            return
        }
        let minMacOS = (obj["minMacOS"] as? String) ?? "11.0"
        if let need = osTuple(minMacOS), !osAtLeast(need) {
            result.error = "新版要求 macOS \(minMacOS) 或更高"
            keepKnownVersions(&result)
            save(result)
            finish(result)
            return
        }
        let towerCurrent = installedTowerVersion()
        let shieldCurrent = ShieldVersion.value
        result.version = version
        result.shieldVersion = shieldVersion
        result.minMacOS = minMacOS
        // 没装塔时不拿「任意版本都算新」来自欺：面板会一直亮着更新，
        // 可安装那一步必须由塔来做。只有哨兵自己落后才算数。
        let towerNewer = !towerCurrent.isEmpty && isNewer(version, towerCurrent)
        let shieldNewer = isNewer(shieldVersion, shieldCurrent)
        result.newer = towerNewer || shieldNewer
        save(result)
        finish(result)
    }

    /// 网络失败时别把上一次「有新版本」的结论抹掉：离线一次就撤掉按钮，
    /// 用户会以为更新没了。错误照样记，面板会把它显示在上次结果旁边。
    private static func keepKnownVersions(_ result: inout Result) {
        let last = readResult()
        guard last.repo == result.repo, last.newer else { return }
        result.newer = true
        result.version = last.version
        result.shieldVersion = last.shieldVersion
        result.minMacOS = last.minMacOS
    }

    private static func finish(_ result: Result) {
        Store.log("update check: newer=\(result.newer) version=\(result.version) shield=\(result.shieldVersion) error=\(result.error)")
        DispatchQueue.main.async {
            (NSApplication.shared.delegate as? AppDelegate)?.push()
        }
    }

    // MARK: - 请求标记

    /// 塔读一次就删。内容不重要，存在本身就是「请把页面滚到更新卡片」。
    @discardableResult
    static func writeRequest() -> Bool {
        Store.ensureDir()
        let payload: [String: Any] = ["at": now(), "from": "shield"]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
            return false
        }
        do {
            try data.write(to: requestURL, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                   ofItemAtPath: requestURL.path)
            return true
        } catch {
            Store.log("update request failed: \(error.localizedDescription)")
            return false
        }
    }

    // MARK: - 存档

    private static func save(_ result: Result) {
        Store.ensureDir()
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? enc.encode(result) else { return }
        try? data.write(to: resultURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                               ofItemAtPath: resultURL.path)
    }

    // MARK: - 网络

    private static func fetch(_ urlString: String) -> (data: Data?, error: String) {
        guard let url = URL(string: urlString), url.scheme == "https",
              let host = url.host?.lowercased(),
              allowedHosts.contains(host) || host.hasSuffix(".githubusercontent.com") else {
            return (nil, "更新地址不是受信任的 HTTPS 来源")
        }
        var req = URLRequest(url: url)
        req.timeoutInterval = 12
        req.setValue("ClaudeShield-Updater", forHTTPHeaderField: "User-Agent")
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        var payload: Data?
        var failure = ""
        let sem = DispatchSemaphore(value: 0)
        let task = URLSession.shared.dataTask(with: req) { data, resp, err in
            defer { sem.signal() }
            if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
                failure = http.statusCode == 404 ? "仓库或 Release 不存在"
                    : http.statusCode == 403 || http.statusCode == 429 ? "GitHub 接口被限流"
                    : "更新服务器返回 HTTP \(http.statusCode)"
            } else if err != nil {
                failure = "连不上更新服务器"
            } else if let data = data, data.count <= 4 * 1024 * 1024 {
                payload = data
            } else {
                failure = "更新清单超过大小上限"
            }
        }
        task.resume()
        if sem.wait(timeout: .now() + 15) == .timedOut {
            task.cancel()
            return (nil, "连接更新服务器超时")
        }
        return (payload, failure)
    }

    // MARK: - 版本

    private static func now() -> Double { Date().timeIntervalSince1970 }

    private static func validRepo(_ value: String) -> Bool {
        let pattern = "^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$"
        return value.range(of: pattern, options: .regularExpression) != nil
    }

    private static func normalized(_ value: String) -> String? {
        var text = value.trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("v") { text.removeFirst() }
        return versionTuple(text) == nil ? nil : text
    }

    private static func versionTuple(_ value: String) -> (Int, Int, Int)? {
        var text = value.trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("v") { text.removeFirst() }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let a = Int(parts[0]), let b = Int(parts[1]), let c = Int(parts[2]) else {
            return nil
        }
        return (a, b, c)
    }

    private static func isNewer(_ candidate: String, _ current: String) -> Bool {
        guard let a = versionTuple(candidate) else { return false }
        guard let b = versionTuple(current) else { return true }
        return a > b
    }

    /// macOS 版本可以是 11、11.0、11.0.1；发布版本必须写满三段。
    private static func osTuple(_ value: String) -> (Int, Int, Int)? {
        var text = value.trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("v") { text.removeFirst() }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count),
              let a = Int(parts[0]) else { return nil }
        let b = parts.count > 1 ? Int(parts[1]) : 0
        let c = parts.count > 2 ? Int(parts[2]) : 0
        guard let b = b, let c = c else { return nil }
        return (a, b, c)
    }

    private static func osAtLeast(_ need: (Int, Int, Int)) -> Bool {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion) >= need
    }

    /// 塔装没装、装的是哪版。没装时返回空串；调用方会跳过「塔是否落后」
    /// 这一项，只让哨兵自己的版本参与判断。
    ///
    /// 先看自己所在的那个宿主：哨兵嵌在塔里时，那就是用户实际在用的塔。
    /// 只查 /Applications 会在「塔放在别处、那里还躺着一个旧版」时读错版本。
    private static func installedTowerVersion() -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let host = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let apps = [host,
                    URL(fileURLWithPath: "/Applications/Claude Tower.app"),
                    home.appendingPathComponent("Applications/Claude Tower.app")]
        for app in apps {
            guard app.pathExtension == "app" else { continue }
            let plist = app.appendingPathComponent("Contents/Info.plist")
            guard let data = try? Data(contentsOf: plist),
                  let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  (obj["CFBundleIdentifier"] as? String) == "com.ccclean.app",
                  let value = obj["CFBundleShortVersionString"] as? String,
                  versionTuple(value) != nil else { continue }
            return value
        }
        return ""
    }
}
