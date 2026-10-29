import Cocoa
import UserNotifications
import WebKit

/// Claude Shield —— 塔的哨兵。
///
/// 形态上只有一个菜单栏图标，没有窗口、没有 Dock 图标。UI 用 WKWebView 承载，
/// 复用 Tower 的 CSS 变量与像素风组件——两个程序必须是同一个世界观，
/// 而不是「一个游戏 + 一个系统工具」。
/// 塔在哪。
///
/// 正常安装时哨兵嵌在 `Claude Tower.app/Contents/Resources/` 里，宿主就是
/// 往上三层的那个 .app；必须按路径打开而不是靠 bundle id——LaunchServices
/// 不一定注册过嵌套在别的应用里的 .app，查不到就会误报「没装塔」。
/// 开发时单独跑 Claude Shield.app 才退回按 bundle id 找。
enum TowerHost {
    enum Source: String {
        case host
        case bundle
    }

    static let bundleID = "com.ccclean.app"

    static func hostBundle() -> URL? {
        let host = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        guard host.pathExtension == "app",
              Bundle(path: host.path)?.bundleIdentifier == bundleID else { return nil }
        return host
    }

    static func registeredBundle() -> URL? {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
    }

    /// 面板和 `--tower-path` 自检都走这里，保证「打印的」就是「会打开的那个」。
    static func resolve() -> (url: URL, source: Source)? {
        if let host = hostBundle() { return (host, .host) }
        if let found = registeredBundle() { return (found, .bundle) }
        return nil
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKScriptMessageHandler {

    var statusItem: NSStatusItem!
    var popover: NSPopover!
    var webView: WKWebView!
    var timer: Timer?
    /// 更新检查单独一条线：巡检 30 秒一次，没必要每轮都碰网络
    var updateTimer: Timer?

    var cfg = Store.load()
    var last: Snapshot?
    /// 巡检在后台队列跑，用这个标志防止上一轮没跑完又叠一轮
    var probing = false
    /// 上次动手的时间。L2 用它做冷却，避免杀掉—重启—再杀的循环。
    var lastKill: TimeInterval = 0
    /// 第一次看到「认到了客户端但没接管」的时刻，0 表示现在没这回事。
    /// Probe 拿它算持续了多久；这里只负责记账，判定仍然留在 Probe 里——
    /// 否则会出现「面板说存疑、后台却在杀」这种自相矛盾。
    var takeoverSince: TimeInterval = 0
    /// 当前计时器用的周期。只在周期真的变了才重建计时器。
    var scheduledSecs: TimeInterval = 0
    /// 上一轮是不是处于「TUN 在位但 DNS 没接管」。只为了不重复通知。
    var lastDnsSuspect = false
    /// 同上，UDP 出口不一致。
    var lastStunLeak = false
    /// 这轮启动后是否已经为「没有塔的基线」喊过一次。只喊一次，
    /// 否则每 30 秒一条通知，用户第一件事就是关掉通知权限。
    var notifiedNoTower = false
    /// 开发预览：面板放在普通窗口里而不是 popover
    var previewMode = false
    var previewWindow: NSWindow?

    // MARK: - 启动

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Info.plist 里已经是 LSUIElement，这里再设一次是为了直接从源码跑的开发态也不占 Dock
        NSApplication.shared.setActivationPolicy(.accessory)

        // 开发/截图用：把面板摊在一个普通窗口里。
        // 认命令行参数，也认一个标记文件——`open` 传不进 --args。
        let marker = Store.dir.appendingPathComponent(".show-panel").path
        previewMode = CommandLine.arguments.contains("--show-panel")
            || FileManager.default.fileExists(atPath: marker)

        // 老版本没有 loginIntent。装过启动项就补成「用户想要自启」，
        // 没装过的保持「没选过」，不去替他做一个从没点过的决定。
        if cfg.loginIntent == nil {
            cfg.loginIntent = LoginItem.installed()
        }
        buildStatusItem()
        buildPopover()
        Store.log("shield 启动 level=\(cfg.level) enabled=\(cfg.enabled) preview=\(previewMode) args=\(CommandLine.arguments.dropFirst().joined(separator: " "))")
        // 第一次会弹系统授权框。拒绝也不影响巡检，只是喊不出声。
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        probeNow()
        scheduleTimer()
        Watchdog.start()
        // 启动 20 秒后再查更新，避开首轮巡检；之后每小时问一次「到点了吗」。
        // 到没到点由 UpdateCheck 自己按塔写的 checkHours 判断。
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
            UpdateCheck.startIfDue()
        }
        updateTimer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { _ in
            UpdateCheck.startIfDue()
        }
        RunLoop.main.add(updateTimer!, forMode: .common)
        // 注销/关机时系统会先发这条通知。别让看门狗把正在退出的哨兵当成
        // 崩溃又拉起来——那会让「退出」变成一个关不掉的按钮。
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willPowerOffNotification, object: nil, queue: .main
        ) { _ in
            Watchdog.stop()
        }
        // 启动闸门：Claude 一起来就判一次。用系统通知而不是轮询——
        // 待命时巡检 30 秒一轮，靠轮询最多晚半分钟才反应，那已经不算「拦在启动前」了。
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(appDidLaunch(_:)),
            name: NSWorkspace.didLaunchApplicationNotification, object: nil
        )

        if CommandLine.arguments.contains("--restored") {
            Store.log("watchdog: shield restored after unexpected exit")
            Store.appendHit(&cfg, kind: "restart",
                            note: "看门狗发现哨兵意外退出，已重新拉起")
            Store.save(cfg)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                self?.notify(title: "哨兵已自动恢复",
                             body: "Claude Shield 之前意外退出，看门狗已重新拉起。")
            }
        }

        if previewMode {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                NSApplication.shared.activate(ignoringOtherApps: true)
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
        updateTimer?.invalidate()
        Watchdog.stop()
    }

    /// 关掉面板或预览窗口不等于退出：哨兵要一直留在菜单栏，
    /// 只有面板里的「退出」才是真退出。
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    // MARK: - 菜单栏图标

    func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.imagePosition = .imageOnly
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePopover)
        // 首轮巡检落地前先按「待命」画：这时候什么都还不知道，
        // 先画一个对勾会让人以为已经查过了
        paintIcon(.idle, tooltip: "哨兵")
    }

    /// 图标该画成什么样。
    ///
    /// 映射和面板 `shield.js` 里那段必须完全一致（`idle` + `idleState=ready`
    /// 算正常，`idle` + 其它 idleState 算存疑），否则同一台机器上菜单栏说
    /// 「没事」、点开面板说「先别启动」，用户不知道该信哪个。
    func iconState(_ snap: Snapshot) -> ShieldIconState {
        // 开关关掉、或者暂停中，都是「没在守」——这时候哪怕网络确实有问题，
        // 盾牌也不该红着：用户是主动关的，红色会变成一块擦不掉的噪音。
        if !cfg.enabled { return .idle }
        if paused { return .idle }
        switch snap.verdict {
        case .safe:   return .safe
        case .warn:   return .warn
        case .danger: return .danger
        case .idle:
            // Claude 没在跑。环境没问题就是「就绪」，有问题就是「没过」——
            // 和面板把 verdict 从 idle 改写成 safe / warn 的那两行同一个判断。
            return snap.idleState == .ready ? .safe : .warn
        }
    }

    func applyIcon(_ snap: Snapshot) {
        // 空心盾配一句「出口已断」会自相矛盾：没在守的时候，tooltip 只说没在守
        let tip: String
        if !cfg.enabled { tip = "已关闭" }
        else if paused { tip = "已暂停" }
        else { tip = snap.title }
        paintIcon(iconState(snap), tooltip: tip)
    }

    /// 图标和 tooltip 一起换。分开写迟早会出现「换了图没换字」——
    /// 菜单栏显示红叉、悬停却写着「守护中」。
    func paintIcon(_ state: ShieldIconState, tooltip: String) {
        statusItem.button?.image = ShieldIcon.image(state)
        statusItem.button?.toolTip = "Claude Shield · " + tooltip
    }

    // MARK: - 面板

    func buildPopover() {
        if previewMode {
            buildPreviewWindow()
            return
        }

        popover = NSPopover()
        popover.behavior = .transient
        popover.animates = true

        let vc = NSViewController()
        // 面板要把巡检看到的 12 项都列出来（进程、路由、TUN、系统代理、塔记出口、
        // DNS、UDP、两个时区、上次巡检、自动更新），再加上缺塔时的横幅。554 装不下——
        // 「最近」会被挤成零高。这里的高度要和 shield.css 的 .wrap 一起看：
        // 改一处记得改另一处。
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 340, height: 772))
        let web = makeWebView(NSSize(width: 340, height: 772))
        web.autoresizingMask = [.width, .height]
        root.addSubview(web)
        vc.view = root
        popover.contentViewController = vc

        loadPanel()
    }

    /// 面板本体。popover 和预览窗口共用同一份，避免两处各写一遍导致长得不一样。
    func makeWebView(_ size: NSSize) -> WKWebView {
        let web = WKWebView(frame: NSRect(origin: .zero, size: size))
        // 不设这个，面板会在页面绘制前闪一下白底，暗色主题上特别刺眼
        web.setValue(false, forKey: "drawsBackground")
        web.navigationDelegate = self
        web.configuration.userContentController.add(self, name: "shield")
        webView = web
        return web
    }

    /// 只在开发时用：状态栏项在无 GUI 会话里不会被系统落位，
    /// 把面板放进普通窗口才能截图核对样式。
    func buildPreviewWindow() {
        let size = NSSize(width: 366, height: 798)
        // borderless：标题栏的红绿灯会压在品牌标记上，而生产形态是 popover、
        // 本来就没有标题栏——预览要长得和真的一样。
        let win = NSWindow(contentRect: NSRect(origin: .zero, size: size),
                           styleMask: [.borderless],
                           backing: .buffered, defer: false)
        win.backgroundColor = NSColor(calibratedRed: 0.039, green: 0.047, blue: 0.071, alpha: 1)
        win.isMovableByWindowBackground = true
        win.level = .floating
        win.center()

        let web = makeWebView(size)
        web.autoresizingMask = [.width, .height]
        win.contentView = web
        win.makeKeyAndOrderFront(nil)
        previewWindow = win

        loadPanel()
    }

    /// 打包后从 Resources/web 读；从源码直接跑时退回仓库里的 shield/web。
    func loadPanel() {
        var candidates = [Bundle.main.resourceURL?.appendingPathComponent("web/shield.html")].compactMap { $0 }
        #if DEBUG
        candidates.append(URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("web/shield.html"))
        #endif
        for url in candidates where FileManager.default.fileExists(atPath: url.path) {
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
            return
        }
        webView.loadHTMLString("<body style='background:#0a0c12;color:#e9edf8;font:13px -apple-system;padding:20px'>找不到 shield.html</body>", baseURL: nil)
    }

    @objc func togglePopover() {
        guard let button = statusItem.button else {
            Store.log("toggle: statusItem.button 是 nil")
            return
        }
        if popover.isShown {
            popover.performClose(nil)
            return
        }
        // 打开就先刷新一次，别让人看到上一次的旧结论。
        // forceFresh 会绕开待命时的 5 分钟 DNS/STUN 缓存——用户点开面板，
        // 就是想看「现在」。
        probeNow(forceFresh: true)
        if let win = button.window {
            Store.log("toggle: winFrame=\(win.frame) btnInWin=\(button.convert(button.bounds, to: nil)) screen=\(String(describing: win.screen?.frame))")
        }
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        webView.window?.makeKey()
        Store.log("toggle: shown=\(popover.isShown) buttonWindow=\(button.window != nil)")
        for w in NSApplication.shared.windows {
            Store.log("  win \(w.className) frame=\(w.frame) visible=\(w.isVisible) alpha=\(w.alphaValue)")
        }
    }

    // MARK: - 巡检

    func scheduleTimer(force: Bool = false) {
        let secs = effectiveInterval
        // 周期没变就不重建。apply 每轮都会调这里，无脑重建等于每轮把计时器
        // 推倒重来——巡检会变成「永远等不到下一次」。
        if !force, secs == scheduledSecs, timer != nil { return }
        if secs != scheduledSecs {
            Store.log("interval=\(Int(secs))s level=\(cfg.level) claude=\(last?.claudeRunning ?? false)")
        }
        scheduledSecs = secs
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: secs, repeats: true) { [weak self] _ in
            self?.probeNow()
        }
        RunLoop.main.add(timer!, forMode: .common)
    }

    /// 这一轮该多久跑一次。
    ///
    /// L2 武装时窗口必须更小：30 秒意味着隧道断了最多半分钟才动手，
    /// 而这半分钟里 Claude 发出的每个包都走真实网络。压到 10 秒的代价只是
    /// 每轮多跑 `ps` / `route` / `scutil` 三条只读命令，DNS 与 STUN 仍按
    /// 各自的 TTL 走缓存，不会因此多打一次网络。
    var effectiveInterval: TimeInterval {
        let base = TimeInterval(max(5, cfg.interval))
        guard cfg.enabled, !paused, cfg.level >= 2, last?.claudeRunning == true else { return base }
        return min(base, 10)
    }

    func probeNow(forceStun: Bool = false, forceFresh: Bool = false,
                  forceTransport: Bool = false) {
        guard !probing else { return }
        // 塔可能在上一轮和这一轮之间刚扫过。每轮都重读它写的那几个键，
        // 否则「没有塔的基线」会一直挂到哨兵重启——用户明明已经扫过了。
        // 只读基线，不碰 Shield 自己的开关和命中记录。
        let disk = Store.loadBaseline()
        cfg.baselineTz = disk.baselineTz
        cfg.country = disk.country
        cfg.egressIP = disk.egressIP
        cfg.egressAt = disk.egressAt
        cfg.ruleGuard = disk.ruleGuard
        probing = true
        let baseline = cfg.baselineTz
        let mask = cfg.egressIP
        let guardSpec = cfg.ruleGuard
        // 在进后台队列之前把时间点取下来：后台线程不碰 UI 状态。
        let since = takeoverSince
        // 超过一天的出口不敢拿来比对：换节点、重拨、代理池轮换都会让旧地址失效，
        // 拿它去判「UDP 出口不一致」，除了制造误报没有别的用处。
        let fresh = cfg.egressAt > 0
            && Date().timeIntervalSince1970 - cfg.egressAt < 86400
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let snap = Probe.run(baselineTz: baseline, egressMask: mask,
                                 maskFresh: fresh, ruleGuard: guardSpec,
                                 forceStun: forceStun, forceFresh: forceFresh,
                                 forceTransport: forceTransport,
                                 takeoverSince: since)
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.probing = false
                self.apply(snap)
            }
        }
    }

    var paused: Bool { cfg.pausedUntil > Date().timeIntervalSince1970 }

    func apply(_ snap: Snapshot) {
        let before = last?.verdict
        last = snap
        // 记账：这一轮「客户端在跑但没接管」是不是还在持续，从什么时候开始的。
        // Probe 下一轮拿它算持续时长。客户端一接管或 Claude 退出就清零。
        if snap.takeoverMissing {
            if takeoverSince == 0 { takeoverSince = snap.at.timeIntervalSince1970 }
        } else {
            takeoverSince = 0
        }

        if snap.verdict == .danger || snap.verdict == .warn {
            // DNS / STUN 那两档的 verdict 也是 warn，但原因完全是另一回事。
            // 日志里必须能分开，否则回头翻记录会以为出口断过。
            let kind: String
            if snap.connections.direct > 0 { kind = "connection" }
            else if snap.dnsSuspect { kind = "dns" }
            else if snap.stunLeak { kind = "stun" }
            else if snap.takeoverEscalated { kind = "takeover" }
            else { kind = snap.verdict.rawValue }
            Store.appendHit(&cfg, kind: kind, note: snap.note)
            Store.save(cfg)
        }

        // L2：出口丢失或连接快照出现公网物理路由时请求退出。
        // 原有出口丢失的两条路仍保留：
        // 一是「没 TUN、没系统代理、连代理进程都没看到」；
        // 二是「客户端在跑，但连续 30 秒都没接管」——那一刻流量同样走真实网络。
        // 其余证据不足的状态只提醒。
        var killed: Killer.Outcome?
        if cfg.enabled, !paused, cfg.level >= 2, snap.verdict == .danger {
            let now = Date().timeIntervalSince1970
            // 一分钟内不重复动手：杀完之后 Claude 可能自己重启，别陷入杀掉—重开的循环
            if now - lastKill > 60 {
                let outcome = Killer.stop()
                lastKill = now
                killed = outcome
                // 动过手就必须留痕，而且不能走 5 分钟去重——
                // 杀了三次只剩一条记录，等于没记。
                Store.appendHit(&cfg, kind: "kill",
                                note: "\(snap.title)；\(outcome.note)", force: true)
                Store.save(cfg)
                Store.log("L2 kill: escalated=\(snap.takeoverEscalated) killed=\(outcome.killed) \(outcome.note)")
            }
        }

        applyIcon(snap)

        // 动过手就要说「已经终止」，不能说「还在运行」——上一版这两句共用一个
        // 分支，L2 杀完之后通知还在说 Claude 在跑，正好把最该知道的事说反了。
        if let outcome = killed {
            notify(title: outcome.title, body: "\(snap.title)。\(outcome.note)")
        } else if snap.verdict == .danger, before != .danger {
            notify(title: snap.connections.direct > 0 ? "发现连接路由异常，Claude 还在运行" : "出口已断，Claude 还在运行",
                   body: snap.note)
        }
        // 只在「刚变成危险」时记一行。每 30 秒写一条会把日志刷满。
        if snap.verdict == .danger, before != .danger {
            Store.log("danger: claude=running tun=\(snap.tunUp) proxy=\(snap.sysProxy) clients=\(snap.proxyClients.count) escalated=\(snap.takeoverEscalated)")
        }
        if snap.verdict == .safe, before == .danger {
            Store.log("recovered")
        }

        // 只装了哨兵、没装塔：基线永远接不上，时区和 UDP 都没法比对。
        // 面板里有常驻横幅，但用户可能根本不点开菜单栏——Claude 在跑时喊一次。
        if snap.hasTowerData {
            notifiedNoTower = false
        } else if snap.claudeRunning, cfg.enabled, !paused, !notifiedNoTower {
            notify(title: "哨兵没有塔的基线",
                   body: "时区漂移和 UDP 出口现在比对不了。打开 Claude Tower 扫一次就会接上。")
            Store.appendHit(&cfg, kind: "notower",
                            note: "没有塔的基线，时区与 UDP 出口无法比对")
            Store.save(cfg)
            Store.log("no tower baseline")
            notifiedNoTower = true
        }

        // DNS 那一档单独通知一次。它和「出口存疑」是两回事：
        // 出口存疑是「我们没认出来」，DNS 存疑是「认出来了但规则没做全」——
        // 后者用户能自己去改分流规则，值得打断一次。
        // Claude 没在跑时，网络异常只上面板、不打断：主状态已经是「待命」，
        // 再弹一条「UDP 出口不一致」会让用户以为是 Claude 那边出事了。
        // 等它真的开始工作，第一轮巡检会重新报一次。
        if snap.claudeRunning {
            if snap.dnsSuspect, !lastDnsSuspect {
                notify(title: "TUN 在位，但 DNS 没被接管",
                       body: "claude.ai 解析成了 \(snap.dnsIP)。去客户端看看 DNS 劫持或增强模式是不是没开。")
                Store.log("dns suspect ip=\(snap.dnsIP)")
            }
            lastDnsSuspect = snap.dnsSuspect

            // STUN 泄漏比 DNS 更值得打断：DNS 没接管只是解析绕出去，
            // UDP 出口不一致意味着真实地址已经暴露给对端了。
            if snap.stunLeak, !lastStunLeak {
                notify(title: "UDP 出口不一致，WebRTC 可能泄漏",
                       body: "STUN 探到的地址和塔记的出口对不上。检查客户端是否代理了 UDP。")
                Store.log("stun leak ips=\(snap.stunForeign.map(Probe.maskIP).joined(separator: ",")) mask=\(snap.egressMask)")
            }
            lastStunLeak = snap.stunLeak
        } else {
            lastDnsSuspect = false
            lastStunLeak = false
        }
        // 周期可能刚变过（L2 武装、Claude 起来/退出、暂停）。这里重算一次，
        // 变了才重建计时器，没变就什么都不做。
        scheduleTimer()
        push()
    }

    // MARK: - 启动闸门

    /// 起来之后等多久再判。刚启动的这一两秒里，客户端可能正在切 TUN、
    /// Claude 也还在初始化——立刻下结论会把「正在恢复」当成「没有出口」。
    /// 3 秒足够它露出真面目，又短到 Claude 还没来得及建立会话。
    static let gateDelay: TimeInterval = 3

    @objc func appDidLaunch(_ note: Notification) {
        guard cfg.enabled, !paused, cfg.level >= 2 else { return }
        guard let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
              Killer.isClaude(app) else { return }
        Store.log("gate: claude launched pid=\(app.processIdentifier)")
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.gateDelay) { [weak self] in
            self?.gateCheck()
        }
    }

    /// 闸门自己跑一轮，不复用巡检缓存也不等下一个 tick：
    /// 那一刻要的是「现在到底能不能起来」，缓存描述的是半分钟前。
    func gateCheck() {
        guard cfg.enabled, !paused, cfg.level >= 2 else { return }
        let baseline = cfg.baselineTz
        let mask = cfg.egressIP
        let guardSpec = cfg.ruleGuard
        let fresh = cfg.egressAt > 0
            && Date().timeIntervalSince1970 - cfg.egressAt < 86400
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let snap = Probe.run(baselineTz: baseline, egressMask: mask,
                                 maskFresh: fresh, ruleGuard: guardSpec, forceFresh: true)
            DispatchQueue.main.async { self?.gateDecide(snap) }
        }
    }

    func gateDecide(_ snap: Snapshot) {
        guard cfg.enabled, !paused, cfg.level >= 2 else { return }
        guard snap.claudeRunning else {
            Store.log("gate: claude already gone")
            publish(snap)
            return
        }
        // 只有「确定不能启动」才拦。缺塔基线、基线过期是「我们判不了」，
        // 判不了就不拦——拿自己的无知去阻止用户干活，比漏一次更糟。
        guard snap.idleState == .blocked else {
            Store.log("gate: allow (\(snap.idleState.rawValue))")
            publish(snap)
            return
        }
        let outcome = Killer.stop()
        lastKill = Date().timeIntervalSince1970
        Store.appendHit(&cfg, kind: "gate",
                        note: "\(snap.title)；\(outcome.note)", force: true)
        Store.save(cfg)
        Store.log("gate: blocked reason=\(snap.title) \(outcome.note)")
        notify(title: "Claude 启动检查未通过", body: "\(snap.title)。\(outcome.note)")
        publish(snap)
    }

    /// 只把结论推给界面，不走 `apply()`——apply 会再记一条 danger 命中、
    /// 再发一句「Claude 还在运行」，和闸门刚说的那句正好打架。
    func publish(_ snap: Snapshot) {
        last = snap
        applyIcon(snap)
        push()
    }

    /// 用 UserNotifications 而不是已废弃的 NSUserNotification：
    /// 后者在 macOS 11 之后虽然还能弹，但用户关掉通知权限时不会有任何提示，
    /// 会变成「以为在值守，其实喊不出声」。
    func notify(title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req, withCompletionHandler: nil)
    }

    // MARK: - 打开塔

    /// 面板常驻的「打开塔」，以及横幅上的同一个入口。
    /// 找不到就把原因说清楚——「打开塔」点了没反应比没有按钮更糟。
    func openTower() {
        guard let target = TowerHost.resolve() else {
            Store.log("open tower: host=none bundle=none")
            alertNoTower()
            return
        }
        // 走哪条路必须写进日志：两条分支在开发机上可能指向同一个 .app，
        // 只看「塔起来了」分不清是哪条命中的。
        Store.log("open tower: via=\(target.source.rawValue) path=\(target.url.path)")
        openTower(at: target.url)
    }

    func openTower(at url: URL) {
        let cfgOpen = NSWorkspace.OpenConfiguration()
        cfgOpen.activates = true
        NSWorkspace.shared.openApplication(at: url, configuration: cfgOpen) { [weak self] _, error in
            guard let error = error else { return }
            Store.log("open tower failed: \(error.localizedDescription)")
            DispatchQueue.main.async { self?.alertNoTower(error.localizedDescription) }
        }
    }

    func alertNoTower(_ detail: String? = nil) {
        let alert = NSAlert()
        alert.messageText = "没找到 Claude Tower"
        alert.informativeText = detail
            ?? "塔负责扫描并记下基线，哨兵只读它写的数据。装好并打开塔，扫一次就会自动接上。"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "好")
        NSApplication.shared.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    // MARK: - 推给页面

    func push() {
        let snap = last ?? Snapshot()
        let payload: [String: Any] = [
            "enabled": cfg.enabled,
            "level": cfg.level,
            "verdict": snap.verdict.rawValue,
            "title": snap.title,
            "note": snap.note,
            "claude": snap.claudeRunning,
            "tun": snap.tunUp,
            "tunIface": snap.tunIface,
            "sysProxy": snap.sysProxy,
            "dns": snap.dnsIP,
            "dnsFake": snap.dnsFake,
            "dnsChecked": snap.dnsChecked,
            "dnsSuspect": snap.dnsSuspect,
            "stun": snap.stunAll.map(Probe.maskIP),
            "stunForeign": snap.stunForeign.map(Probe.maskIP),
            "stunChecked": snap.stunChecked,
            "stunLeak": snap.stunLeak,
            // 到 Anthropic 的 HTTPS 有没有走通。这只是那一刻的证据，
            // 不参与主判定——面板要能在没测、只通一条、证书异常时分开显示。
            "connectionsState": snap.connections.state,
            "connectionsDetail": snap.connections.detail,
            "connectionsObserved": snap.connections.observed,
            "connectionsDirect": snap.connections.direct,
            "connectionsUnknown": snap.connections.unknown,
            "transportChecked": snap.transportChecked,
            "transportState": snap.transportState,
            "transportLabel": snap.transportLabel,
            "transportDetail": snap.transportDetail,
            "transportAt": snap.transportAt,
            "egressMask": snap.egressMask,
            "maskFresh": snap.maskFresh,
            // 塔的基线在不在、新不新。缺了就没法判时区漂移和 UDP 出口，
            // 面板要据此挂常驻提醒，而不是只把两行写成「塔还没记过」。
            "towerData": snap.hasTowerData,
            "towerState": snap.towerState,
            "environmentReady": snap.environmentReady,
            "idleState": snap.idleState.rawValue,
            // 塔写基线的时间和国家。面板要显示「多久以前记的」「记的是哪国出口」，
            // 缺了这两个字段就只能说「有基线」，说不清它还值不值得信。
            "egressAt": cfg.egressAt,
            "country": cfg.country,
            "tz": snap.tz,
            "baselineTz": snap.baselineTz,
            "tzDrift": snap.tzDrift,
            // 塔留下的两项设置还成不成立。只上横幅、不改判定：
            // IPv6 被系统重新打开很常见，分流规则也可能被订阅更新冲掉，
            // 但它们要不要修、怎么修，都只有塔能回答。
            "ipv6Checked": snap.ipv6Checked,
            "ipv6Drift": snap.ipv6Drift,
            "ipv6Services": snap.ipv6Services,
            "ruleChecked": snap.guardChecked,
            "ruleDrift": snap.guardDrift,
            "ruleName": snap.guardName,
            "ruleMissing": snap.guardMissing,
            "lastAt": snap.at.timeIntervalSince1970,
            "paused": cfg.pausedUntil > Date().timeIntervalSince1970,
            "loginItem": cfg.loginIntent ?? false,
            // 用户想自启、但启动项已经没了或者还指着旧位置。
            // 只在「他确实开过」的时候才提醒，没开过的人不该看见这条横幅。
            "loginBroken": (cfg.loginIntent ?? false) && !LoginItem.status().ok,
            "version": ShieldVersion.value,
            // 推实际周期，不是配置里的那个：L2 武装时会压到 10 秒，
            // 面板还写「每 30 秒」就是在骗人。
            "interval": Int(effectiveInterval),
            // 自动更新的发现结果。哨兵只查版本，下载与安装都在塔里，
            // 面板据此亮一行并给一个「去塔里更新」按钮。
            "update": UpdateCheck.payload(),
            "hits": cfg.hits.suffix(12).map {
                ["ts": $0.ts, "kind": $0.kind, "note": $0.note]
            },
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else { return }
        webView.evaluateJavaScript("window.SHIELD && window.SHIELD.update(\(json))", completionHandler: nil)
    }

    // MARK: - 页面来的消息

    func userContentController(_ uc: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let action = body["action"] as? String else { return }
        switch action {
        case "toggle":
            cfg.enabled.toggle()
            Store.save(cfg)
            Store.log("enabled=\(cfg.enabled)")
            if cfg.enabled { probeNow() } else { paintIcon(.idle, tooltip: "已关闭") }
            scheduleTimer()
            push()
        case "level":
            if let lv = body["value"] as? Int, lv >= 1, lv <= 2 {
                cfg.level = lv
                Store.save(cfg)
                Store.log("level=\(lv)")
                // 武装的那一刻就该换成 10 秒周期，不用等下一轮巡检回来才生效。
                scheduleTimer()
                push()
            }
        case "pause":
            let mins = (body["minutes"] as? Int) ?? 30
            cfg.pausedUntil = Date().timeIntervalSince1970 + Double(mins * 60)
            Store.save(cfg)
            Store.log("paused \(mins)m")
            scheduleTimer()
            push()
        case "resume":
            cfg.pausedUntil = 0
            Store.save(cfg)
            Store.log("resumed")
            probeNow()
            scheduleTimer()
            push()
        case "now":
            probeNow(forceStun: true, forceFresh: true)
        case "transport":
            // 只强制重测传输。DNS / STUN 该用缓存的还是用缓存——
            // 点这个按钮的人要的是「现在 HTTPS 通不通」。
            probeNow(forceTransport: true)
        case "fixtz":
            let note = TzFix.restore(cfg.baselineTz)
            Store.appendHit(&cfg, kind: "fixtz", note: note)
            Store.save(cfg)
            Store.log("fixtz: \(note)")
            probeNow(forceStun: true, forceFresh: true)
        case "login":
            // 想开但已经失效时，点击是「修」而不是「关」：否则用户看到
            // 一条「自启失效」的横幅，点一下反而把残留的启动项删掉。
            let wanted = cfg.loginIntent ?? LoginItem.installed()
            if wanted, !LoginItem.status().ok {
                LoginItem.install()
                cfg.loginIntent = true
            } else {
                LoginItem.toggle()
                cfg.loginIntent = LoginItem.installed()
            }
            Store.save(cfg)
            push()
        case "log":
            NSWorkspace.shared.open(Store.logURL)
        case "opentower":
            openTower()
        case "update":
            // 只是留个标记让塔把页面滚到更新卡片；确认与安装仍由用户
            // 在塔里点。请求文件写不进去也照样把塔打开。
            if UpdateCheck.writeRequest() {
                Store.log("update requested from panel")
            }
            openTower()
        case "quit":
            Store.log("quit")
            NSApplication.shared.terminate(nil)
        default:
            break
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        push()
    }
}

/// 终止 Claude。先走 `terminate()`——它会经过 App 自己的退出流程（落盘、关窗口），
/// 比 `pkill -9` 温和；只有对方明确拒绝退出才升级到 `forceTerminate()`。
enum Killer {
    /// 找 Claude 的 pid。两条路都要走：
    /// bundle id 是首选（改名、换目录都不影响），但它是唯一的判据时会出事——
    /// 巡检那边按进程路径认人，急停这边只按 bundle id 认人，两边一旦对不上，
    /// 就会出现「面板说出口已断，急停却报没找到进程」这种最坏情况：
    /// 用户以为有人值守，其实那一刀永远落不下去。
    /// 所以 bundle id 落空时，退回按可执行路径兜住。
    /// 这个 NSRunningApplication 是不是 Claude 本体。
    /// bundle id 优先（改名、换目录都不影响），落空再按可执行路径兜底。
    /// 两处都要排除自己的包——Claude Shield.app 的路径里也有 "Claude"。
    static func isClaude(_ app: NSRunningApplication) -> Bool {
        if (app.bundleIdentifier ?? "").lowercased().contains("claudefordesktop") {
            return true
        }
        guard let path = app.bundleURL?.path else { return false }
        return path.contains("/Claude.app") && !path.contains("Claude Shield.app")
    }

    static func pid() -> pid_t? {
        let apps = NSWorkspace.shared.runningApplications
        if let hit = apps.first(where: {
            ($0.bundleIdentifier ?? "").lowercased().contains("claudefordesktop")
        }) {
            return hit.processIdentifier
        }
        return apps.first(where: isClaude)?.processIdentifier
    }

    static func stop() -> Outcome {
        guard let p = pid(), let app = NSRunningApplication(processIdentifier: p) else {
            return .notFound
        }
        if app.terminate() { return .requested(p) }
        if app.forceTerminate() { return .forced(p) }
        return .refused(p)
    }

    /// 动手的结果。做成枚举而不是一句话，是因为调用方要按「到底杀没杀成」
    /// 决定说什么：杀成了说「已终止」，没找到人就说「没找到」。
    /// 混成一句「已请求退出」，等于把失败报成成功——用户以为被保护了。
    enum Outcome {
        case requested(pid_t)
        case forced(pid_t)
        case notFound
        case refused(pid_t)

        var killed: Bool {
            switch self {
            case .requested, .forced: return true
            case .notFound, .refused: return false
            }
        }

        /// 记进命中记录和日志的那句话。带 pid，事后能对上进程。
        var note: String {
            switch self {
            case .requested(let p): return "已请求 Claude 退出（pid \(p)）"
            case .forced(let p):    return "Claude 未响应退出请求，已强制终止（pid \(p)）"
            case .notFound:         return "没找到 Claude 进程"
            case .refused(let p):   return "终止失败，需要手动退出（pid \(p)）"
            }
        }

        /// 通知标题。说的是「我们做了什么」，不是「结果一定如何」——
        /// `terminate()` 返回 true 只代表退出请求被接受，进程可能还要一秒才退。
        /// 报「已终止」而进程还在，比不报更糟。
        var title: String {
            switch self {
            case .requested:          return "已请求 Claude 退出"
            case .forced:             return "已强制终止 Claude"
            case .notFound:           return "该终止 Claude，但没找到进程"
            case .refused:            return "Claude 拒绝退出，请手动关掉"
            }
        }
    }
}

enum ShieldVersion {
    static var value: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "1.0.0-dev"
    }
}

/// 开机自启。用 LaunchAgent 而不是 SMAppService：后者要 macOS 13，
/// 而我们的部署目标是 11.0——不能为了一个开关把整机门槛抬上去。
enum LoginItem {
    static let label = "com.ccclean.shield"
    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static func installed() -> Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    struct Status {
        var installed = false
        var runAtLoad = false
        var pointsHere = false
        /// 文件在、开机加载、而且指向当前这个可执行文件，才算真的有效。
        var ok: Bool { installed && runAtLoad && pointsHere }
    }

    /// 启动项是不是还指向「现在这个 App」。
    ///
    /// 只看 plist 在不在不够：用户把 App 拖到别的目录、或者系统在
    /// 「登录项」里把失效条目清掉之后，文件可能还在，但路径已经对不上了。
    /// 那种情况下 run at login 是静默失败的——正是需要提醒的那一种。
    static func status() -> Status {
        var st = Status()
        guard let data = FileManager.default.contents(atPath: plistURL.path),
              let plist = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? [String: Any] else {
            return st
        }
        st.installed = true
        st.runAtLoad = (plist["RunAtLoad"] as? Bool) ?? false
        let args = plist["ProgramArguments"] as? [String] ?? []
        if let here = Bundle.main.executableURL?.resolvingSymlinksInPath().path,
           let first = args.first {
            let target = URL(fileURLWithPath: first).resolvingSymlinksInPath().path
            st.pointsHere = target == here
        }
        return st
    }

    static func toggle() {
        if installed() { uninstall() } else { install() }
    }

    static func install() {
        guard let exe = Bundle.main.executableURL else { return }
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>\(label)</string>
          <key>ProgramArguments</key>
          <array><string>\(exe.path)</string><string>--background</string></array>
          <key>RunAtLoad</key><true/>
          <!-- 用户主动退出后不要拉起来。哨兵也得能下班。 -->
          <key>KeepAlive</key><false/>
          <key>ProcessType</key><string>Interactive</string>
        </dict>
        </plist>
        """
        let dir = plistURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? xml.data(using: .utf8)?.write(to: plistURL, options: .atomic)
        Store.log("login item installed at \(plistURL.path)")
    }

    static func uninstall() {
        Store.log("login item removed")
        try? FileManager.default.removeItem(at: plistURL)
    }
}

// MARK: - 入口

// 入口放在 main.swift：多文件编译时，只有 main.swift 允许顶层代码。
