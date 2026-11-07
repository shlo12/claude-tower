import Cocoa
import UserNotifications
import WebKit
import Darwin

/// CC Shield —— 塔的哨兵。
///
/// 仅在菜单栏运行，点击图标弹出面板；维护工具与魔塔按需打开。
/// 延续旧面板的状态圈、像素图标和两档强度的视觉区分。
/// 塔在哪。
///
/// 正常安装时哨兵嵌在 `CC Tower.app/Contents/Resources/` 里，宿主就是
/// 往上三层的那个 .app；必须按路径打开而不是靠 bundle id——LaunchServices
/// 不一定注册过嵌套在别的应用里的 .app，查不到就会误报「没装塔」。
/// 开发时单独跑 CC Shield.app 才退回按 bundle id 找。
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

/// 工具引擎（Python）报回来的地址。它是唯一的跨进程入口，所以逐字段校验。
///
/// 端口区间必须和 `app.py::_free_port` 完全一致。以前这里只认到 8800，而
/// Python 会一路试到 8826：8787–8800 被占满时引擎照样起来了，哨兵却认为
/// 地址不合法，空转 25 秒后报「维护工具未能启动」——现象和「引擎崩了」
/// 一模一样，极难查。`tools/check.py` 里有一条断言盯着这两个数字。
enum ToolRuntime {
    /// 校验运行记录，返回引擎地址、引擎 pid、以及拉起它的父进程 pid。
    ///
    /// 父进程 pid 交给调用方去核对「是不是 CC Tower」。这一步不能省，也
    /// 不能换成「等 openApplication 的回调告诉我 pid」——塔本来就在跑的时候
    /// 那个回调不一定回来，界面就会一直停在「正在准备」，而引擎其实早就好了。
    static func endpoint(_ data: Data) -> (url: URL, pid: Int32, parent: Int32)? {
        guard data.count <= 4096,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let parent = obj["parent"] as? Int, parent > 0, parent <= Int(Int32.max),
              let pid = obj["pid"] as? Int, pid > 0, pid <= Int(Int32.max),
              let text = obj["url"] as? String, let url = URL(string: text),
              url.scheme == "http", url.host == "127.0.0.1",
              let port = url.port, (8787...8826).contains(port),
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty || url.path == "/" else { return nil }
        return (url, Int32(pid), Int32(parent))
    }

    /// 指定父进程的版本。测试和「我们自己刚拉起的那一个」用这条。
    static func address(_ data: Data, parent: Int) -> (url: URL, pid: Int32)? {
        guard let e = endpoint(data), Int(e.parent) == parent else { return nil }
        return (e.url, e.pid)
    }
}

/// 菜单栏面板——「现在安不安全」。
///
/// 以前是 `NSPopover`，问题在于 popover 只能是一种尺寸、一种行为。换成
/// 自己控制的 borderless `NSPanel` 之后，圆角、阴影、Esc 收起都能自己定，
/// 但它仍然只是**一个**挂在菜单栏图标下面的瞬态面板：失焦就收起。
///
/// 「去查、去修」那一半不在这里，也不该把这块面板拉宽——面板长成大面板
/// 依然是菜单栏的附属物，手感不会变成窗口。那一半是 `openMainWindow()`
/// 里的独立 `NSWindow`：一个程序、两个界面，不是两个程序。
final class ShieldPanel: NSPanel {
    /// Esc 收起。popover 自带这个行为，换成普通窗口就得自己补。
    /// 用回调而不是直接 orderOut：收起时要顺手摘掉全局监听。
    var onCancel: (() -> Void)?

    /// borderless 的窗口默认不能成为 key，键盘事件会全部丢掉。
    override var canBecomeKey: Bool { true }
    /// 但它不是「主窗口」：⌘W、⌘M 不该作用在它身上。
    override var canBecomeMain: Bool { false }
    override func cancelOperation(_ sender: Any?) { onCancel?() }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate,
                         WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {

    /// 面板的尺寸。它只有这一种形态：仪表盘。
    static let narrowWidth: CGFloat = 340
    /// 面板想要的高度。12 项巡检全列出来要这么高；屏幕放不下时由
    /// `PanelGeometry.fitting` 往下收，所以这里写的是「理想值」不是「定值」。
    static let narrowHeight: CGFloat = 772
    /// 主窗口的初始尺寸。
    ///
    /// 1180 是「体检页两组指标能并排」的下限；再宽，在 1440 宽的笔记本上
    /// 就要贴着屏幕边缘了。窗口可缩放，这只是第一眼的尺寸。
    static let mainSize = NSSize(width: 1180, height: 840)

    /// 引擎（Python 宿主）的状态。
    ///
    /// 单独一个枚举是为了让「拉起中」和「已就绪」分得开：以前用一个
    /// `toolTimer == nil` 兼作两者，于是「还没开始拉」和「已经拉好了」长得一样。
    enum EngineState { case idle, starting, ready, failed }
    /// 引擎从拉起算起最多等这么久。Python 起 HTTP 服务通常在 1 秒内，
    /// 25 秒是给「首次运行、要初始化」留的余量。
    static let engineTimeout: TimeInterval = 25

    var statusItem: NSStatusItem!
    var panel: ShieldPanel!
    /// 最近一次「因为失焦而自动收起」的时刻。
    ///
    /// 点菜单栏图标关面板时，事件顺序是「面板先失焦收起 → 按钮的 action 才
    /// 触发」。不记这个时刻，action 会以为面板本来是关的，于是立刻又打开——
    /// 表现就是「点了没反应」。200 毫秒足够盖住这个窗口，又短到不会吞掉用户
    /// 真正想重开的那一下。
    var panelAutoClosedAt: Date = .distantPast
    /// 「在别的应用里按了鼠标」的监听器。面板可见时才有，收起时立刻摘掉——
    /// 常驻的全局监听会一直唤醒进程，菜单栏应用不该背着这个。
    var outsideClickMonitor: Any?
    var webView: WKWebView!
    /// 主窗口。菜单栏面板是「现在安不安全」，主窗口是「去查、去修」。
    ///
    /// 这是**一个程序的两个界面**，不是两个程序：同一个进程、同一个菜单栏图标、
    /// 同一份状态，主窗口关掉之后哨兵还在值守。以前这两块分属两个 .app，
    /// 于是用户看到两个软件并排站着。
    var mainWindow: NSWindow?
    var mainWebView: WKWebView?
    /// 打开主窗口时想先看哪一页，等引擎起来再跳过去。
    var pendingView = ""
    var engineState = EngineState.idle
    var engineTimer: Timer?
    var engineHost: NSRunningApplication?
    var ownsEngine = false
    var engineOrigin: URL?
    /// 引擎从拉起算起的截止时刻。以前是数 tick（100 × 0.25 秒），
    /// 定时器被 RunLoop 拖慢时数不准，直接记时间才是真「25 秒」。
    var engineDeadline = Date.distantPast
    var timer: Timer?
    /// 更新检查单独一条线：巡检 30 秒一次，没必要每轮都碰网络
    var updateTimer: Timer?

    var cfg = Store.load()
    var last: Snapshot?
    // 准入与精确出口／选择摘要仅留内存；哨兵重启必须重新检查。
    var admittedSession: String?
    var vmRecovery = RuntimeRecovery()
    var sessionMessage = "请先点击检查并启动；缺证据不放行"
    var sessionStarting = false
    var sessionGeneration = 0
    var sessionIssuedAt: TimeInterval = 0
    var sessionLaunchDeadline: TimeInterval = 0

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
    /// 上一轮解析出口是否落在国内解析器。同上，只为了不重复通知。
    var lastDnsResolve = false
    /// 同上，UDP 出口不一致。
    var lastStunLeak = false
    /// 同上，真实地址已经被交给网页（国内节点回了非基线地址）。
    var lastStunExposed = false
    /// 上一次把 live 结论落盘的时刻。
    ///
    /// 每轮都写盘是没必要的：结论没变的时候，唯一会变的就是时间戳。但完全不写
    /// 又不行——塔靠这个时间戳判断「哨兵还活着吗」，五分钟不写就会被当成死了。
    /// 所以「变了就写，没变每两分钟写一次心跳」。
    var commandTimer: Timer?
    var lastLiveSave: TimeInterval = 0
    /// 已经喊过的「出口变了」候选。同一个地址只喊一次，用户确认或改回来就复位。
    var lastEgressSeen = ""
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
        previewMode = CommandLine.arguments.contains("--show-panel")
            || CommandLine.arguments.contains("--show-window")

        // 老版本没有 loginIntent。装过启动项就补成「用户想要自启」，
        // 没装过的保持「没选过」，不去替他做一个从没点过的决定。
        if cfg.loginIntent == nil {
            cfg.loginIntent = LoginItem.installed()
        }
        // 启动项还在、开关没被动过，只是指针断了（App 改名或挪过位置）：
        // 用户既然选过自启就悄悄修好，不挂着「自启待修」等他来点。
        // RunAtLoad 被关掉或整个文件被删都视为用户动作，不替他改回来。
        let loginStatus = LoginItem.status()
        if cfg.loginIntent == true, loginStatus.installed,
           loginStatus.runAtLoad, !loginStatus.pointsHere {
            LoginItem.install()
            Store.log("login item path healed -> \(Bundle.main.executableURL?.path ?? "?")")
        }
        buildStatusItem()
        buildMenu()
        buildPanel()
        Store.log("shield 启动 level=\(cfg.level) enabled=\(cfg.enabled) preview=\(previewMode) args=\(CommandLine.arguments.dropFirst().joined(separator: " "))")
        // 第一次会弹系统授权框。拒绝也不影响巡检，只是喊不出声。
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        probeNow()
        scheduleTimer()
        Watchdog.start()
        commandTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.consumeCommand()
        }
        RunLoop.main.add(commandTimer!, forMode: .common)
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

        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification, object: nil, queue: .main
        ) { [weak self] notification in
            guard let self = self,
                  let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  Killer.isClaude(app) else { return }
            self.admittedSession = nil; self.vmRecovery.reset()
            self.sessionLaunchDeadline = 0
            self.sessionGeneration += 1
            self.sessionMessage = (self.last?.strictFailure.isEmpty == false)
                ? "已结束：" + (self.last?.strictFailure ?? "") + "；下次使用请重新检查"
                : "Claude 已退出，下次使用请重新检查"
            self.push()
        }

        if CommandLine.arguments.contains("--restored") {
            Store.log("watchdog: shield restored after unexpected exit")
            Store.appendHit(&cfg, kind: "restart",
                            note: "看门狗发现哨兵意外退出，已重新拉起")
            Store.save(cfg)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                self?.notify(title: "哨兵已自动恢复",
                             body: "CC Shield 之前意外退出，看门狗已重新拉起。")
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
        stopEngine()
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
        statusItem.button?.action = #selector(togglePanel)
        // 首轮巡检落地前先按「待命」画：这时候什么都还不知道，
        // 先画一个对勾会让人以为已经查过了
        paintIcon(.idle, tooltip: "哨兵")
    }

    /// 主窗口是真窗口，就得有真窗口的快捷键。
    ///
    /// 没有主菜单时 ⌘W / ⌘Q 一律无效——用户第一次想关窗就会按 ⌘W，然后
    /// 发现按了没反应。菜单只在应用被激活（主窗口在前面）时出现，平时
    /// 菜单栏里只有那个盾牌图标，和以前一样。
    func buildMenu() {
        let main = NSMenu()

        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "关于 CC Shield",
                        action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
                        keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "隐藏 CC Shield",
                        action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出 CC Shield",
                        action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        main.addItem(appItem)

        let winItem = NSMenuItem()
        let winMenu = NSMenu(title: "窗口")
        winMenu.addItem(withTitle: "关闭窗口",
                        action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        winMenu.addItem(withTitle: "最小化",
                        action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        winItem.submenu = winMenu
        main.addItem(winItem)

        NSApp.mainMenu = main
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
        if cfg.level >= 2 && admittedSession == nil { return snap.claudeRunning ? .danger : .warn }
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
        statusItem.button?.toolTip = "CC Shield · " + tooltip
    }

    // MARK: - 面板

    func buildPanel() {
        if previewMode {
            buildPreviewWindow()
            // `--show-window`：直接打开主窗口，用来核对窗口本身的样子。
            // 没有它就只能靠点菜单栏图标，而那需要真的 GUI 会话。
            if CommandLine.arguments.contains("--show-window") {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
                    self?.openMainWindow()
                }
            }
            return
        }

        // 面板要把巡检看到的 12 项都列出来（进程、路由、TUN、系统代理、塔记出口、
        // DNS、UDP、两个时区、上次巡检、自动更新），再加上缺塔时的横幅。554 装不下——
        // 「最近」会被挤成零高。这里的高度要和 shield.css 的 .wrap 一起看：
        // 改一处记得改另一处。
        panel = makeShieldPanel(NSSize(width: Self.narrowWidth, height: Self.narrowHeight))
        loadPanel()
    }

    /// 建窗口本体。窄态和预览共用，保证截图看到的就是生产形态。
    func makeShieldPanel(_ size: NSSize) -> ShieldPanel {
        // borderless + 透明底：圆角和阴影都得自己画，否则会看到一个直角白框。
        let panel = ShieldPanel(contentRect: NSRect(origin: .zero, size: size),
                                styleMask: [.borderless, .nonactivatingPanel],
                                backing: .buffered, defer: false)
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        // 压过普通窗口，但不要压过系统弹窗（授权框要能盖在它上面）。
        panel.level = .statusBar
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        // 窄态不该被拖动：它挂在下拉位置，拖走了下次出现还是回原位，只会让人困惑。
        panel.isMovableByWindowBackground = false
        panel.onCancel = { [weak self] in self?.closeByEscape() }
        panel.contentView = makePanelContent(size)
        return panel
    }

    /// 圆角容器 + 网页。`masksToBounds` 必须开，否则网页的直角会盖住圆角。
    func makePanelContent(_ size: NSSize) -> NSView {
        let root = NSView(frame: NSRect(origin: .zero, size: size))
        root.wantsLayer = true
        root.layer?.cornerRadius = 12
        root.layer?.masksToBounds = true
        root.layer?.backgroundColor = NSColor(calibratedRed: 0.039, green: 0.047,
                                              blue: 0.071, alpha: 1).cgColor
        let web = makeWebView(size)
        web.autoresizingMask = [.width, .height]
        root.addSubview(web)
        return root
    }

    // 重复打开应用也只保持菜单栏值守，不创建独立窗口。
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        return true
    }

    /// 面板本体。popover 和预览窗口共用同一份，避免两处各写一遍导致长得不一样。
    func makeWebView(_ size: NSSize) -> WKWebView {
        let web = WKWebView(frame: NSRect(origin: .zero, size: size))
        // 不设这个，面板会在页面绘制前闪一下白底，暗色主题上特别刺眼
        web.setValue(false, forKey: "drawsBackground")
        web.navigationDelegate = self
        web.uiDelegate = self
        web.configuration.userContentController.add(self, name: "shield")
        webView = web
        return web
    }

    /// 只在开发时用：状态栏项在无 GUI 会话里不会被系统落位，
    /// 把面板放进普通窗口才能截图核对样式。
    func buildPreviewWindow() {
        let size = NSSize(width: 366, height: 798)
        // 预览用真正的 ShieldPanel，而不是一个长得像的普通窗口：圆角、阴影、
        // 无标题栏这些正是最容易做错的地方，截图要截到真东西才算数。
        let win = makeShieldPanel(size)
        win.isMovableByWindowBackground = true
        win.center()
        previewWindow = win
        panel = win

        loadPanel()
        // `--show-window` 只关心主窗口。面板照建（`push()` 要往它的 webView
        // 里推状态，没有它就没法跑），但不摆出来——否则截图里会多一扇没人要的窗。
        if !CommandLine.arguments.contains("--show-window") {
            win.orderFrontRegardless()
            win.makeKey()
        }
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

    /// 菜单栏图标被点。开着就关，关着就开。
    ///
    /// 中间那条时间判断是为了「点图标关面板」：面板会先失焦自动收起，按钮的
    /// action 随后才到。没有它，action 看到的是「已经关了」，于是又打开一次，
    /// 用户看到的就是「点了没反应」。
    @objc func togglePanel() {
        guard let panel = panel else { return }
        if panel.isVisible {
            closePanel()
            return
        }
        if Date().timeIntervalSince(panelAutoClosedAt) < 0.2 {
            panelAutoClosedAt = .distantPast
            return
        }
        showPanel()
    }

    func showPanel() {
        guard let panel = panel else { return }
        // 打开就先刷新一次，别让人看到上一次的旧结论。
        // forceFresh 会绕开待命时的 5 分钟 DNS/STUN 缓存——用户点开面板，
        // 就是想看「现在」。
        probeNow(forceFresh: true)
        positionPanel()
        panel.alphaValue = 1
        // 先 orderFrontRegardless 再 makeKey：`.nonactivatingPanel` 在应用没被
        // 激活时不会自己浮上来，只调 makeKeyAndOrderFront 会出现「点一下没反应，
        // 点两下才出来」。
        panel.orderFrontRegardless()
        panel.makeKey()
        webView.window?.makeKey()
        installOutsideClickMonitor()
        Store.log("panel: shown=\(panel.isVisible) frame=\(panel.frame)")
    }

    func closePanel() {
        removeOutsideClickMonitor()
        guard let panel = panel, panel.isVisible else { return }
        panel.orderOut(nil)
        Store.log("panel: closed")
    }

    /// 收进屏幕之后的真实 frame：顶边贴着菜单栏图标、左右不越界。
    ///
    /// `height` 传 nil 表示「铺满可用高度」。面板现在只有一种尺寸（仪表盘），
    /// 这个参数留着是因为 `fitting` 那一步要拿它算上限：屏幕矮的时候先收尺寸
    /// 再算落点，否则光调 origin 只能把面板贴到底边，底栏照样掉在屏幕外。
    func targetFrame(width: CGFloat, height: CGFloat?) -> NSRect? {
        let anchor: NSRect
        let visible: NSRect
        if let button = statusItem.button, let buttonWindow = button.window {
            anchor = buttonWindow.convertToScreen(button.convert(button.bounds, to: nil))
            visible = (buttonWindow.screen ?? NSScreen.main)?.visibleFrame
                ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        } else if let screen = panel?.screen ?? NSScreen.main {
            // 预览/截图模式没有菜单栏图标（无 GUI 会话里 NSStatusItem 不落位）。
            // 用屏幕顶边中点当锚点，这样两种模式看到的是同一个落点算法。
            visible = screen.visibleFrame
            anchor = NSRect(x: visible.midX, y: visible.maxY, width: 1, height: 0)
        } else {
            return nil
        }
        // 先收尺寸再算落点：小屏上 772 点放不下，光靠 origin 只能把面板
        // 贴到底边，底栏照样掉在屏幕外。
        let size = PanelGeometry.fitting(NSSize(width: width, height: height ?? visible.height),
                                         in: visible)
        return NSRect(origin: PanelGeometry.origin(anchor: anchor, size: size, visible: visible),
                      size: size)
    }

    /// 就地把面板摆回菜单栏图标下面，尺寸不变。
    ///
    /// 面板不再有第二种尺寸，所以这里不提供「改成多大」的入口——那正是
    /// 以前「点全部工具就把面板拉宽」留下的口子。
    func positionPanel() {
        guard let panel = panel, let frame = targetFrame(width: panel.frame.width,
                                                         height: panel.frame.height) else { return }
        panel.setFrame(frame, display: true)
        // 尺寸出问题时（「面板被切了」「底栏掉出屏幕」）只有这一行能说明白
        // 到底给了多大，光看代码猜不出来。
        Store.log("panel: frame \(Int(frame.width))x\(Int(frame.height))")
    }

    /// 失焦就收起——这是 popover 的 `.transient` 行为。
    ///
    /// 这里**不用** `windowDidResignKey`。非激活面板从不把应用激活，所以它
    /// 一 `makeKey` 就立刻失焦，按失焦收起的写法会变成「点一下闪一下就没了」。
    /// 真正的信号是「在别的应用里按了鼠标」，用全局监听拿（鼠标事件不需要
    /// 辅助功能授权，键盘才需要）。
    func installOutsideClickMonitor() {
        removeOutsideClickMonitor()
        outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]
        ) { [weak self] _ in
            // 回调不在主线程，切回去再动 UI。
            DispatchQueue.main.async { self?.autoClosePanel() }
        }
    }

    func removeOutsideClickMonitor() {
        if let monitor = outsideClickMonitor {
            NSEvent.removeMonitor(monitor)
            outsideClickMonitor = nil
        }
    }

    /// 因为「点到了别处」而收起。记下时刻，避免紧接着的状态栏点击又把它打开。
    func autoClosePanel() {
        removeOutsideClickMonitor()
        guard let panel = panel, panel.isVisible else { return }
        panelAutoClosedAt = Date()
        panel.orderOut(nil)
        Store.log("panel: auto-closed")
    }

    /// Esc 收起。不记时刻：用户按完 Esc 常常立刻再点图标，那一下该算「打开」。
    /// 主窗口有自己的关闭按钮，Esc 不管它。
    func closeByEscape() {
        removeOutsideClickMonitor()
        guard let panel = panel, panel.isVisible else { return }
        panel.orderOut(nil)
        Store.log("panel: closed by esc")
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
        cfg.egressSeen = disk.egressSeen
        cfg.egressSeenAt = disk.egressSeenAt
        cfg.egressSeenCountry = disk.egressSeenCountry
        cfg.ruleGuard = disk.ruleGuard
        probing = true
        let baseline = cfg.baselineTz
        let mask = cfg.egressIP
        let guardSpec = cfg.ruleGuard
        // 在进后台队列之前把时间点取下来：后台线程不碰 UI 状态。
        let since = takeoverSince
        // 超过一天的出口不敢拿来比对：换节点、重拨、代理池轮换都会让旧地址失效，
        // 拿它去判「UDP 出口不一致」，除了制造误报没有别的用处。
        // 出口变了但还没确认时也不比对：这一刻我们明确知道基线不是现在这条路。
        let pending = !cfg.egressSeen.isEmpty
        let fresh = cfg.egressAt > 0
            && Date().timeIntervalSince1970 - cfg.egressAt < 86400
            && !pending
        let upstream = cfg.upstream
        let retrying = vmRecovery.since != nil
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let snap = Probe.run(baselineTz: baseline, egressMask: mask,
                                 maskFresh: fresh, egressPending: pending,
                                 ruleGuard: guardSpec,
                                 forceStun: forceStun, forceFresh: forceFresh || retrying,
                                 forceTransport: forceTransport || retrying,
                                 takeoverSince: since, upstream: upstream)
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.probing = false
                self.apply(snap)
            }
        }
    }

    var paused: Bool { cfg.pausedUntil > Date().timeIntervalSince1970 }

    func apply(_ input: Snapshot) {
        // 检查并启动之前发出的旧巡检不能撤销一份更新的准入。
        if admittedSession != nil && input.at.timeIntervalSince1970 < sessionIssuedAt { return }
        var snap = input
        if cfg.enabled, !paused, cfg.level >= 2 {
            if snap.claudeRunning {
                if snap.vmManaged || !snap.upstream {
                    let wasRecovering = vmRecovery.since != nil
                    let decision = vmRecovery.evaluate(snap, admitted: admittedSession)
                    if wasRecovering != (vmRecovery.since != nil) || decision.stop != nil {
                        Store.log("network recovery: retry=\(vmRecovery.since != nil) domain=\(snap.domainState) transport=\(snap.transportState) dnsChecked=\(snap.dnsChecked) rootProtected=\(snap.vmNetwork.protected)")
                    }
                    snap.strictNotice = decision.notice
                    if let issue = decision.stop {
                        snap.strictFailure = issue
                        admittedSession = nil; vmRecovery.reset()
                        sessionMessage = issue
                    } else if !decision.notice.isEmpty { sessionMessage = decision.notice }
                    else if wasRecovering { sessionMessage = "网络检查已恢复，继续值守原会话" }
                } else if let stale = StrictSessionPolicy.staleIssue(snap) {
                    // 过期只结束本次使用，不写 strictFailure。
                    // 写了它会一路走到 verdict = .danger 和 Killer.stopSession()：
                    // 探测慢一点就把用户的 Claude 杀掉，而「没看清」不等于「不安全」。
                    admittedSession = nil; vmRecovery.reset()
                    sessionMessage = stale
                } else if let issue = StrictSessionPolicy.runningIssue(snap, admitted: admittedSession) {
                    snap.strictFailure = issue
                    admittedSession = nil; vmRecovery.reset()
                    sessionMessage = issue
                }
            } else if admittedSession != nil && Date().timeIntervalSince1970 > sessionLaunchDeadline {
                admittedSession = nil; vmRecovery.reset()
                sessionMessage = "本次使用已结束；下次使用请重新检查"
            }
        } else {
            admittedSession = nil; vmRecovery.reset()
        }
        let before = last?.verdict
        last = snap
        // 先落基线：下面的提醒和面板都要读更新后的 cfg。
        refreshEgressBaseline(snap)
        reportEgressChange(snap)
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
            else if !snap.stunExposed.isEmpty { kind = "stun-exposed" }
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
                let outcome = Killer.stopSession()
                lastKill = now
                killed = outcome
                // 动过手就必须留痕，而且不能走 5 分钟去重——
                // 杀了三次只剩一条记录，等于没记。
                Store.appendHit(&cfg, kind: "kill",
                                note: "\(snap.strictFailure.isEmpty ? snap.title : snap.strictFailure)；\(outcome.note)", force: true)
                Store.save(cfg)
                Store.log("L2 kill: escalated=\(snap.takeoverEscalated) killed=\(outcome.killed) \(outcome.note)")
            }
        }

        applyIcon(snap)

        // 动过手就要说「已经终止」，不能说「还在运行」——上一版这两句共用一个
        // 分支，L2 杀完之后通知还在说 Claude 在跑，正好把最该知道的事说反了。
        if let outcome = killed {
            notify(title: outcome.title, body: "\(snap.strictFailure.isEmpty ? snap.title : snap.strictFailure)。\(outcome.note)")
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

        // 缺基线：时区只有塔能建，出口哨兵会自己测。
        // 面板里有常驻横幅，但用户可能根本不点开菜单栏——Claude 在跑时喊一次。
        // 用更新后的 cfg 判断：这一轮刚测出出口基线时，不该还喊「没有基线」。
        if !cfg.baselineTz.isEmpty || !cfg.egressIP.isEmpty {
            notifiedNoTower = false
        } else if snap.claudeRunning, cfg.enabled, !paused, !notifiedNoTower {
            notify(title: "哨兵还没有基线",
                   body: "时区基线要打开 CC Tower 扫一次；出口基线哨兵会自己测。")
            Store.appendHit(&cfg, kind: "notower",
                            note: "还没有基线，时区与 UDP 出口无法比对")
            Store.save(cfg)
            Store.log("no baseline")
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

            // 接管没问题、解析却落回国内解析器：这是「名单配错了」，
            // 和「没接管」是两种修法，各报一次。
            if snap.dnsEgressSuspect, !lastDnsResolve {
                let who = snap.dnsResolverOrg.isEmpty ? "国内解析器" : snap.dnsResolverOrg
                notify(title: "DNS 解析出口在国内",
                       body: "TUN 接管了查询，但真正做递归的是 \(who)（\(Probe.maskResolver(snap.dnsResolverIP))）。"
                           + "把客户端的 nameserver 换成境外 DoH。")
                Store.log("dns resolver cn org=\(snap.dnsResolverOrg) country=\(snap.dnsResolverCountry) ip=\(Probe.maskResolver(snap.dnsResolverIP))")
            }
            lastDnsResolve = snap.dnsEgressSuspect

            // STUN 泄漏比 DNS 更值得打断：DNS 没接管只是解析绕出去，
            // UDP 出口不一致意味着真实地址已经暴露给对端了。
            if snap.stunLeak, !lastStunLeak {
                notify(title: "UDP 出口不一致，WebRTC 可能泄漏",
                       body: "STUN 探到的地址和塔记的出口对不上。检查客户端是否代理了 UDP。")
                Store.log("stun leak ips=\(snap.stunForeign.map(Probe.maskIP).joined(separator: ",")) mask=\(snap.egressMask)")
            }
            lastStunLeak = snap.stunLeak

            // 这一条和上面那条可以同时成立：境外节点之间并不分裂，但国内节点
            // 已经把真实地址交出去了。ICE 候选不认「这条是给国内用的」。
            if !snap.stunExposed.isEmpty, !lastStunExposed {
                let who = snap.stunExposed.map(Probe.maskIP).joined(separator: "、")
                notify(title: "WebRTC 在把真实地址交给网页",
                       body: "国内 STUN 节点回了 \(who)，和当前出口不是同一个。"
                           + "浏览器会把它作为 ICE 候选交给任何页面。")
                Store.log("stun exposed ips=\(who) mask=\(snap.egressMask)")
            }
            lastStunExposed = !snap.stunExposed.isEmpty
        } else {
            lastDnsSuspect = false
            lastDnsResolve = false
            lastStunLeak = false
            lastStunExposed = false
        }
        // 周期可能刚变过（L2 武装、Claude 起来/退出、暂停）。这里重算一次，
        // 变了才重建计时器，没变就什么都不做。
        publishLive(snap)
        scheduleTimer()
        push()
    }

    /// 把这一轮结论写进共享状态文件，给塔读。
    ///
    /// 塔只在自己被按下时看一眼世界，两次扫描之间发生的事它一概不知道；
    /// 哨兵每十秒看一次，却只有菜单栏那一小块地方能说话。两边各说各的，
    /// 用户拿到的是两个互不相干的答案。这一份就是让塔在扫描时能顺手带上
    /// 「哨兵刚才看到了什么」——同一个问题只给一个结论。
    ///
    /// 写盘节奏：结论变了立刻写，没变每两分钟补一次心跳。塔靠时间戳判断
    /// 「哨兵还活着吗」，只写变化会让安静的时候看起来像死了。
    func publishLive(_ snap: Snapshot) {
        var next = Config.Live.from(snap)
        if cfg.enabled && !paused && cfg.level >= 2 {
            next.sessionState = sessionStarting ? "checking" : (admittedSession == nil ? "waiting" : "active")
            next.sessionMessage = sessionMessage
        }
        let changed = cfg.live == nil || next.differs(from: cfg.live!)
        cfg.live = next
        let now = Date().timeIntervalSince1970
        if changed || now - lastLiveSave > 20 {
            lastLiveSave = now
            Store.save(cfg)
        }
    }

    /// 把这一轮从 Claude 边缘测到的 HTTP 出口写进基线。
    ///
    /// 这是「不开塔也能每天续期」的那条路：trace 走系统代理 / TUN，
    /// 和 UDP 的 STUN 是两条独立路径，比对仍然有意义。遇到不同的地址
    /// 不直接改基线，只记待确认——见 Store.applyEgress 的注释。
    func refreshEgressBaseline(_ snap: Snapshot) {
        guard !snap.egressCandidateIP.isEmpty else { return }
        let mask = Probe.maskIP(snap.egressCandidateIP)
        let at = snap.domainAt > 0 ? snap.domainAt : snap.at.timeIntervalSince1970
        let update = Store.recordEgress(&cfg, mask: mask,
                                        country: snap.egressCandidateCountry, at: at)
        switch update {
        case .adopted:
            Store.log("egress baseline adopted mask=\(mask) country=\(snap.egressCandidateCountry)")
            lastEgressSeen = ""
        case .refreshed:
            Store.log("egress baseline renewed mask=\(mask)")
            lastEgressSeen = ""
        case .cleared:
            Store.log("egress pending cleared mask=\(mask)")
            lastEgressSeen = ""
        case .pending:
            break
        case .skipped:
            break
        }
    }

    /// 出口对不上时喊一次。同一个候选地址只喊一次；用户确认或改回来就复位，
    /// 否则每 30 秒一条通知，用户第一件事就是关掉通知权限。
    func reportEgressChange(_ snap: Snapshot) {
        guard !cfg.egressSeen.isEmpty else {
            lastEgressSeen = ""
            return
        }
        guard cfg.egressSeen != lastEgressSeen else { return }
        lastEgressSeen = cfg.egressSeen
        let base = [cfg.country, cfg.egressIP].filter { !$0.isEmpty }.joined(separator: " · ")
        let seen = [cfg.egressSeenCountry, cfg.egressSeen].filter { !$0.isEmpty }
            .joined(separator: " · ")
        Store.appendHit(&cfg, kind: "egress",
                        note: "出口从 \(base) 变成 \(seen)，等确认", force: true)
        Store.save(cfg)
        Store.log("egress pending base=\(cfg.egressIP) seen=\(cfg.egressSeen)")
        if snap.claudeRunning, cfg.enabled, !paused {
            notify(title: "出口变了，等你确认",
                   body: "基线是 \(base)，现在测到 \(seen)。是你自己换的节点，就在哨兵面板里确认；"
                       + "不是的话先查代理。")
        }
    }

    func leaveStrictSession(_ reason: String) {
        guard cfg.enabled, !paused, cfg.level >= 2,
              admittedSession != nil || Killer.pid() != nil else { return }
        admittedSession = nil; vmRecovery.reset()
        sessionMessage = reason + "；下次使用需重新检查"
        let outcome = Killer.stopSession()
        Store.appendHit(&cfg, kind: "gate", note: sessionMessage + "；" + outcome.note, force: true)
        Store.save(cfg)
    }

    func startCheckedSession() {
        guard cfg.enabled, !paused, cfg.level >= 2, !sessionStarting else { return }
        guard UserEnvironment.usableHome(UserEnvironment.child["HOME"]) != nil else {
            sessionMessage = "找不到可写的使用者目录，无法安全启动 Claude"
            push()
            return
        }
        guard !NSWorkspace.shared.runningApplications.contains(where: Killer.isClaude) else {
            sessionMessage = "请先退出 Claude，再进行使用前检查"
            push()
            return
        }
        sessionGeneration += 1
        let generation = sessionGeneration
        sessionStarting = true
        sessionMessage = "正在检查环境与代理节点，请稍候"
        admittedSession = nil; vmRecovery.reset()
        push()
        let base = Store.loadBaseline()
        let upstream = cfg.upstream
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let snap = Probe.run(baselineTz: base.baselineTz, egressMask: base.egressIP,
                                 maskFresh: base.egressAt > 0 && Date().timeIntervalSince1970 - base.egressAt < 86400 && base.egressSeen.isEmpty,
                                 egressPending: !base.egressSeen.isEmpty,
                                 ruleGuard: base.ruleGuard, forceFresh: true,
                                 upstream: upstream)
            // 核心探测耗时期间也可能切节点；结束前再读一次运行配置。
            let latest = VMNetworkEvidence.enabled ? VMNetworkEvidence.read().session : SessionController.read()
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.sessionStarting = false
                guard generation == self.sessionGeneration, self.cfg.enabled, !self.paused, self.cfg.level >= 2 else {
                    self.sessionMessage = "检查期间值守设置改变，请重新检查"
                    self.push()
                    return
                }
                if let issue = StrictSessionPolicy.admissionIssue(snap) {
                    self.sessionMessage = issue
                    self.last = snap
                    self.push()
                    return
                }
                // 上游模式没有本机客户端可读，节点复核这一环不适用；
                // 值守期间改靠「上游出口不变」兜底，变化判据在 identity 里。
                guard snap.upstream || (latest.checked && latest.identity == snap.session.identity),
                      !NSWorkspace.shared.runningApplications.contains(where: Killer.isClaude) else {
                    self.sessionMessage = "检查期间节点或客户端状态发生变化，请重新检查"
                    self.push()
                    return
                }
                guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.anthropic.claudefordesktop") else {
                    self.sessionMessage = "未找到已安装的 Claude 桌面端"
                    self.push()
                    return
                }
                self.admittedSession = StrictSessionPolicy.identity(snap)
                self.sessionIssuedAt = Date().timeIntervalSince1970
                self.sessionLaunchDeadline = self.sessionIssuedAt + 15
                self.sessionMessage = "环境检查通过，正在启动 Claude；本次使用期间保持配置和节点不变"
                self.last = snap
                let launch = NSWorkspace.OpenConfiguration()
                launch.environment = UserEnvironment.child
                NSWorkspace.shared.openApplication(at: url, configuration: launch) { [weak self] application, error in
                    DispatchQueue.main.async {
                        guard let self = self else { return }
                        if generation != self.sessionGeneration || !self.cfg.enabled || self.paused || self.cfg.level < 2 {
                            // 启动请求已发出但尚未落地时被取消，不能留下迟到的未监测进程。
                            if let application = application, Killer.isClaude(application) { _ = application.forceTerminate() }
                            self.admittedSession = nil; self.vmRecovery.reset()
                            self.sessionMessage = "检查已取消；延迟启动的 Claude 已请求终止"
                        } else if error != nil || application == nil {
                            self.admittedSession = nil; self.vmRecovery.reset()
                            self.sessionMessage = "Claude 未能启动，请重新检查"
                        } else {
                            self.probeNow(forceFresh: true)
                        }
                        self.push()
                    }
                }
                self.push()
            }
        }
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
        if admittedSession == nil {
            let outcome = Killer.stopSession()
            sessionMessage = "未通过检查并启动；请先退出 Claude，再在哨兵中重新检查"
            Store.appendHit(&cfg, kind: "gate", note: sessionMessage + "；" + outcome.note, force: true)
            Store.save(cfg)
            notify(title: "Claude 本次启动未获准入", body: sessionMessage + "；" + outcome.note)
            probeNow(forceFresh: true)
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.gateDelay) { [weak self] in
            self?.gateCheck()
        }
    }

    /// 闸门自己跑一轮，不复用巡检缓存也不等下一个 tick：
    /// 那一刻要的是「现在到底能不能起来」，缓存描述的是半分钟前。
    func gateCheck() {
        guard cfg.enabled, !paused, cfg.level >= 2 else { return }
        let generation = sessionGeneration
        let baseline = cfg.baselineTz
        let mask = cfg.egressIP
        let guardSpec = cfg.ruleGuard
        let pending = !cfg.egressSeen.isEmpty
        let fresh = cfg.egressAt > 0
            && Date().timeIntervalSince1970 - cfg.egressAt < 86400
            && !pending
        let upstream = cfg.upstream
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let snap = Probe.run(baselineTz: baseline, egressMask: mask,
                                 maskFresh: fresh, egressPending: pending,
                                 ruleGuard: guardSpec, forceFresh: true,
                                 upstream: upstream)
            DispatchQueue.main.async {
                guard let self = self, generation == self.sessionGeneration else { return }
                self.gateDecide(snap)
            }
        }
    }

    func gateDecide(_ input: Snapshot) {
        var snap = input
        guard cfg.enabled, !paused, cfg.level >= 2 else { return }
        guard snap.claudeRunning else {
            Store.log("gate: claude already gone")
            publish(snap)
            return
        }
        let issue: String?
        if snap.vmManaged || !snap.upstream {
            let decision = vmRecovery.evaluate(snap, admitted: admittedSession)
            snap.strictNotice = decision.notice
            issue = decision.stop
        } else { issue = StrictSessionPolicy.runningIssue(snap, admitted: admittedSession) }
        guard let reason = issue else {
            Store.log("gate: admitted session verified")
            publish(snap)
            return
        }
        admittedSession = nil; vmRecovery.reset()
        sessionMessage = reason
        let outcome = Killer.stopSession()
        lastKill = Date().timeIntervalSince1970
        Store.appendHit(&cfg, kind: "gate",
                        note: "\(reason)；\(outcome.note)", force: true)
        Store.save(cfg)
        Store.log("gate: session blocked \(outcome.note)")
        notify(title: "Claude 启动检查未通过", body: "\(reason)。\(outcome.note)")
        var rejected = snap
        rejected.strictFailure = reason
        publish(rejected)
    }

    /// 只把结论推给界面，不走 `apply()`——apply 会再记一条 danger 命中、
    /// 再发一句「Claude 还在运行」，和闸门刚说的那句正好打架。
    func publish(_ snap: Snapshot) {
        publishLive(snap)
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

    // MARK: - 主窗口（体检台）

    /// 主窗口能直接跳到哪一页。
    ///
    /// 名字必须和页面里的页签一一对应：`app.js` 启动时按 `panel-<name>`
    /// 找面板，找不到就停在默认页。以前这里写的是 `dns` / `proxyfix` /
    /// `scanner`，页面里根本没有这三个 id——点「修复 DNS」会静默留在原地。
    ///
    /// 没有 `home`：守护台只在菜单栏面板里有一份。主窗口进来直接是魔塔体检，
    /// 不再把同一块仪表盘摆两遍。
    static let mainViews = ["tower", "privacy", "records", "settings",
                            "settle", "findings", "checklist", "isolation"]

    /// 打开主窗口。
    ///
    /// 这里是「一个程序、两个界面」的第二半：菜单栏面板回答「现在安不安全」，
    /// 主窗口回答「去查、去修」。它是一扇**真正的窗口**——有标题栏、能缩放、
    /// 能最小化，⌘W 关掉之后哨兵还在菜单栏值守。
    ///
    /// 为什么不把面板拉宽：面板是菜单栏的附属物（无标题栏、失焦即收），
    /// 拉宽之后仍然是附属物的手感，而且两块界面得共用一套关闭策略，越改越绕。
    /// 更早的版本是打开 CC Tower 自己的 .app——那等于退回两个软件并排站。
    /// 主窗口在的时候给 Dock 一个图标，关掉就收回。
    ///
    /// 平时它是菜单栏程序（LSUIElement），Dock 里不该常驻一个只有盾牌的程序；
    /// 但主窗口是一扇真窗口——用户会用 ⌘Tab 找它、会点 Dock 图标把它叫回前台，
    /// 没有图标这两件事都做不到。窗口一关就退回 `.accessory`，Dock 保持干净。
    private func setDockPresence(_ on: Bool) {
        let want: NSApplication.ActivationPolicy = on ? .regular : .accessory
        guard NSApp.activationPolicy() != want else { return }
        NSApp.setActivationPolicy(want)
    }

    func openMainWindow(_ view: String = "tower") {
        pendingView = Self.mainViews.contains(view) ? view : "tower"

        // 已经开着就换页，不再开第二扇：同一个进程里两扇窗口指向同一个引擎，
        // 关掉一扇另一扇就白屏了。
        if let win = mainWindow {
            if engineState == .ready, let origin = engineOrigin { showMainPage(origin) }
            NSApp.activate(ignoringOtherApps: true)
            win.makeKeyAndOrderFront(nil)
            return
        }

        // 尺寸也走 `fitting`：1180 在 1080 宽的外接屏上根本放不下，
        // 硬给就会左右各出界一截，标题栏两侧的按钮直接看不见。
        let visible = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1180, height: 840)
        let size = PanelGeometry.fitting(Self.mainSize, in: visible)
        let win = NSWindow(contentRect: NSRect(origin: .zero, size: size),
                           styleMask: [.titled, .closable, .miniaturizable, .resizable],
                           backing: .buffered, defer: false)
        win.title = "CC Shield"
        // 界面本来就是深色的。不锁外观的话，浅色模式下会看到一条白色标题栏
        // 压在一块深色网页上，比没有标题栏还难看。
        win.appearance = NSAppearance(named: .darkAqua)
        win.backgroundColor = NSColor(calibratedRed: 0.039, green: 0.047, blue: 0.071, alpha: 1)
        win.minSize = NSSize(width: 880, height: 620)
        // 关窗只是关窗：不释放窗口对象，也不让 App 跟着退出
        // （`applicationShouldTerminateAfterLastWindowClosed` 已经返回 false）。
        win.isReleasedWhenClosed = false
        win.delegate = self
        let web = makeMainWebView(size)
        win.contentView = web
        win.center()

        mainWindow = win
        mainWebView = web

        // 截图用：菜单栏应用从终端启动时系统不让它抢焦点，窗口会被压在别的
        // 应用后面，`screencapture -R` 截到的就是别人的界面。抬一层就够了，
        // 只影响预览进程，生产路径不碰 `level`。
        if previewMode { win.level = .floating }

        // 面板是瞬态的：主窗口一开它就该收起来，否则两块界面同时说同一件事，
        // 用户不知道该看哪个。
        closePanel()

        // 先要 Dock 图标再上前台：顺序反了会先出现一扇没有图标的窗口，
        // 在 Dock 里找不到它。
        setDockPresence(true)
        NSApp.activate(ignoringOtherApps: true)
        win.makeKeyAndOrderFront(nil)
        // 窗口没出现时（尺寸算错、屏幕换了、被激活策略挡住）只有这一行能说清
        // 到底是「没建」还是「建了但没到前面」。
        Store.log("main: opened \(Int(win.frame.width))x\(Int(win.frame.height)) visible=\(win.isVisible)")

        if previewMode,
           let text = ProcessInfo.processInfo.environment["CC_SHIELD_PREVIEW_URL"],
           let url = URL(string: text) {
            // 截图用：本机已经有一个引擎在跑（比如 `app.py --port 8799`），
            // 预览窗口直接加载它，不用等 `openApplication`——开发机上的沙箱
            // 常常不让哨兵拉起别的 .app，那条路会一直停在「正在准备」。
            // 只在 `--show-window` 下生效；正常路径永远只认 `runtime.json`
            // 里那个由塔自己写下的端口。
            engineOrigin = url
            if let frag = url.fragment, Self.mainViews.contains(frag) { pendingView = frag }
            showMainPage(url)
            return
        }

        if engineState == .ready, let origin = engineOrigin {
            showMainPage(origin)
        } else {
            // 先把等待页放上去再起引擎：起引擎要几百毫秒，空窗口会让人以为
            // 「点了没反应」，然后就会再点一次。
            showEnginePending()
            startEngine()
        }
    }

    /// 主窗口的网页。和面板那个分开：面板加载本地 `shield.html`，主窗口加载
    /// 引擎起的 HTTP 页面，两边的导航策略和落点都不一样。
    func makeMainWebView(_ size: NSSize) -> WKWebView {
        let web = WKWebView(frame: NSRect(origin: .zero, size: size))
        web.setValue(false, forKey: "drawsBackground")
        web.navigationDelegate = self
        web.uiDelegate = self
        // 通道名和面板一致：页面里的 `panel.js` 只会往 `shield` 发消息，
        // 换个名字就得改页面，而那份页面是两个界面共用的。
        web.configuration.userContentController.add(self, name: "shield")
        web.autoresizingMask = [.width, .height]
        return web
    }

    /// 窗口关掉之后把引用清干净。不清的话下次 `openMainWindow` 会以为还开着，
    /// 直接对一扇已经销毁的窗口 makeKeyAndOrderFront。
    func windowWillClose(_ notification: Notification) {
        guard let win = notification.object as? NSWindow, win === mainWindow else { return }
        mainWindow = nil
        mainWebView = nil
        pendingView = ""
        stopEngine()
        // 窗口没了，Dock 图标也一起收：菜单栏程序不该在 Dock 里留个空壳。
        setDockPresence(false)
        Store.log("main: closed")
    }

    /// 拉起 Python 宿主。它是维护页的服务端，也是唯一会被哨兵拉起的子进程。
    func startEngine() {
        guard engineState != .starting else { return }
        guard let target = TowerHost.resolve() else {
            failEngine("没找到 CC Tower，维护页打不开。")
            return
        }
        engineState = .starting
        engineDeadline = Date().addingTimeInterval(Self.engineTimeout)
        // 计时器必须在拉起之前就位。放在 openApplication 的回调里会有一个
        // 死角：回调要是不来（应用已经在跑、LaunchServices 吞掉请求），
        // 就永远没有轮询、也永远到不了超时，界面一直停在「正在准备」。
        engineTimer?.invalidate()
        engineTimer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            self?.pollEngine()
        }
        RunLoop.main.add(engineTimer!, forMode: .common)
        // 塔自己开着就不算我们拉起的，关窗时也不能把它关掉。
        ownsEngine = !NSWorkspace.shared.runningApplications.contains { $0.bundleIdentifier == TowerHost.bundleID }
        let config = NSWorkspace.OpenConfiguration()
        config.environment = UserEnvironment.child
        config.activates = false
        config.arguments = ["--service"]
        NSWorkspace.shared.openApplication(at: target.url, configuration: config) { [weak self] app, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                // 这期间用户可能已经把窗口关了：那就把刚拉起来的引擎收掉，
                // 不要让一个没人看的 Python 进程留在后台。
                guard self.engineState == .starting else {
                    if self.ownsEngine { app?.terminate() }
                    return
                }
                if error != nil { self.failEngine("维护工具没能启动。"); return }
                self.engineHost = app
            }
        }
    }

    /// 每 0.25 秒看一次运行记录。`runtime.json` 是跨进程入口，里面的地址
    /// 带着页面令牌，所以必须逐字段校验（`ToolRuntime.address`），不能
    /// 「读到就用」。
    func pollEngine() {
        guard engineState == .starting else { stopEngineTimer(); return }
        let file = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/CCclean/runtime.json")
        // 父进程必须是 CC Tower 本身：`runtime.json` 里带着页面令牌，
        // 谁写的谁就能拿到，所以「这个文件是塔写的」必须先证明。
        if let data = try? Data(contentsOf: file),
           let endpoint = ToolRuntime.endpoint(data),
           let host = NSRunningApplication(processIdentifier: endpoint.parent),
           host.bundleIdentifier == TowerHost.bundleID,
           kill(endpoint.pid, 0) == 0 {
            stopEngineTimer()
            engineState = .ready
            engineHost = host
            engineOrigin = endpoint.url
            showMainPage(endpoint.url)
            return
        }
        if Date() > engineDeadline { failEngine("维护工具没能启动。") }
    }

    func stopEngineTimer() {
        engineTimer?.invalidate()
        engineTimer = nil
    }

    /// 主动收掉引擎。只关我们自己拉起的那一个。
    func stopEngine() {
        stopEngineTimer()
        engineState = .idle
        engineOrigin = nil
        if ownsEngine { engineHost?.terminate() }
        engineHost = nil
        ownsEngine = false
    }

    /// 在主窗口里加载维护页。fragment 决定先看哪一页。
    ///
    /// 不带 `panel=1`：那个参数是给「嵌在菜单栏面板里」用的，主窗口是完整形态，
    /// 导航、页签、结论灯都按整页排版。
    func showMainPage(_ origin: URL) {
        guard let web = mainWebView else { return }
        var parts = URLComponents(url: origin, resolvingAgainstBaseURL: false)
        parts?.fragment = pendingView.isEmpty ? nil : pendingView
        guard let next = parts?.url else { return }
        engineOrigin = origin
        web.load(URLRequest(url: next))
    }

    /// 引擎还在起：先给一张同样深色的等待页，不要留一块空白。
    func showEnginePending() {
        mainWebView?.loadHTMLString(waitPage("正在准备维护工具…", "后台监测继续运行。"), baseURL: nil)
    }

    func failEngine(_ reason: String) {
        stopEngineTimer()
        engineState = .failed
        Store.log("engine failed: \(reason)")
        mainWebView?.loadHTMLString(waitPage(reason, "后台哨兵仍在值守；关掉这扇窗不影响值守。"),
                                    baseURL: nil)
    }

    /// 等待页/失败页。和主窗口同一套暗色，别在中间闪一块白。
    ///
    /// 不放「返回」按钮：窗口自己有标题栏和关闭按钮，再加一个返回等于给
    /// 用户两条意思一样的路。
    func waitPage(_ title: String, _ note: String) -> String {
        """
        <html><meta charset="utf-8"><body style="margin:0;background:#0a0c12;color:#e9edf8;\
        font:13px/1.6 -apple-system,'PingFang SC',sans-serif;padding:28px">\
        <p style="margin:0 0 6px">\(title)</p>\
        <p style="margin:0;color:#a3adc6">\(note)</p></body></html>
        """
    }

    // 面板收起不再做任何事。以前这里是 `popoverDidClose`，留着是为了说明
    // 「系统授权或确认框也会收起面板，不能中断正在写入的操作」——这条约束现在
    // 由 `windowDidResignKey` 承担，它同样只 orderOut，不碰工具上下文。

    // MARK: - 推给页面

    func push() {
        let snap = last ?? Snapshot()
        publishLive(snap)
        let payload: [String: Any] = [
            "sessionChecked": snap.session.checked,
            "sessionMode": snap.session.mode,
            "sessionMessage": sessionMessage,
            "sessionActive": admittedSession != nil,
            "sessionStarting": sessionStarting,
            "strictIssue": StrictSessionPolicy.admissionIssue(snap) ?? "",
            "enabled": cfg.enabled,
            "level": cfg.level,
            "upstream": cfg.upstream && !snap.vmManaged,
            "vmManaged": snap.vmManaged,
            "vmProtected": snap.vmNetwork.issue == nil,
            "vmIssue": snap.vmNetwork.issue ?? "",
            "vmUDPBlocked": snap.vmNetwork.fresh && snap.vmNetwork.udpBlocked && snap.vmNetwork.pfVerified,
            "isVM": Probe.isVM(),
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
            "dnsResolver": Probe.maskResolver(snap.dnsResolverIP),
            "dnsResolverOrg": snap.dnsResolverOrg,
            "dnsResolverCountry": snap.dnsResolverCountry,
            "dnsResolverChecked": snap.dnsResolverChecked,
            "dnsEgressSuspect": snap.dnsEgressSuspect,
            "stun": snap.stunAll.map(Probe.maskIP),
            "stunForeign": snap.stunForeign.map(Probe.maskIP),
            "stunChecked": snap.stunChecked,
            "stunLeak": snap.stunLeak,
            // 国内节点回的地址里，不属于当前出口的那些。判「真实地址有没有被
            // 交给网页」用的是这一组，不是 stunLeak。
            "stunExposed": snap.stunExposed.map(Probe.maskIP),
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
            // Claude 自己的边缘节点看到的出口。只上屏，不参与 verdict。
            "domainChecked": snap.domainChecked,
            "domainState": snap.domainState,
            "domainLabel": snap.domainLabel,
            "domainDetail": snap.domainDetail,
            "domainAt": snap.domainAt,
            "egressMask": snap.egressMask,
            "maskFresh": snap.maskFresh,
            // 塔的基线在不在、新不新。缺了就没法判时区漂移和 UDP 出口，
            // 面板要据此挂常驻提醒，而不是只把两行写成「塔还没记过」。
            "towerData": snap.hasTowerData,
            "towerState": snap.towerState,
            "environmentReady": snap.environmentReady,
            "idleState": snap.idleState.rawValue,
            // 基线的时间和国家。面板要显示「多久以前测的」「测的是哪国出口」，
            // 缺了这两个字段就只能说「有基线」，说不清它还值不值得信。
            "egressAt": cfg.egressAt,
            "country": cfg.country,
            // 出口变了但还没确认。面板要据此挂横幅、接上确认按钮，
            // 不能让新出口悄悄变成基线。
            "egressSeen": cfg.egressSeen,
            "egressSeenAt": cfg.egressSeenAt,
            "egressSeenCountry": cfg.egressSeenCountry,
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

    /// 消息是从哪个界面来的。
    ///
    /// 两个界面共用一个通道名（页面只认 `shield`），但「返回」的去处不同：
    /// 面板里返回是收起面板，主窗口里返回是回到体检页。
    enum Source { case panel, main }

    func userContentController(_ uc: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame,
              let body = message.body as? [String: Any], let action = body["action"] as? String else { return }
        // 先认「是谁在说话」：面板加载的是本地文件，主窗口加载的是引擎的
        // 127.0.0.1 端口，两者的信任域不一样，不能用同一套判断。
        let fromMain = mainWebView != nil && message.webView === mainWebView
        let current = message.webView?.url
        let resource = Bundle.main.resourceURL?.appendingPathComponent("web").standardizedFileURL.path ?? ""
        let filePage = !fromMain && current?.isFileURL == true && !resource.isEmpty
            && current!.standardizedFileURL.path.hasPrefix(resource + "/")
        // 维护页只认「我们自己加载的那个端口」。令牌在页面里，端口一换
        // 就等于换了信任域，所以三个条件（当前 URL、消息来源、记录的地址）
        // 必须同时对得上。
        let localPage = fromMain && engineOrigin != nil
            && current?.scheme == "http" && current?.host == "127.0.0.1"
            && current?.port == engineOrigin?.port
            && message.frameInfo.securityOrigin.host == "127.0.0.1"
            && message.frameInfo.securityOrigin.port == engineOrigin?.port
        // 等待页/失败页是 `loadHTMLString` 出来的，URL 是 about:blank，
        // 上面那两条都不成立——但「返回」这条动作仍然要能进来。
        let loadingBack = fromMain && action == "back-panel"
            && (current == nil || current?.scheme == "about")
        guard filePage || localPage || loadingBack else { return }
        handleAction(body, from: fromMain ? .main : .panel)
    }

    // 同一用户的私有文件通道。只接受有限动作，不接受路径、脚本或密钥。
    func consumeCommand() {
        let url = Store.dir.appendingPathComponent("shield-command.json")
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              attrs[.type] as? FileAttributeType == .typeRegular,
              (attrs[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let mode = attrs[.posixPermissions] as? NSNumber, mode.intValue & 0o077 == 0,
              let size = attrs[.size] as? NSNumber, size.intValue <= 1024,
              let data = try? Data(contentsOf: url),
              let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = body["id"] as? String, UUID(uuidString: id) != nil,
              let at = body["at"] as? Double,
              abs(Date().timeIntervalSince1970 - at) < 15,
              let action = body["action"] as? String else { return }
        let allowed = ["session-start", "session-end", "watch", "strict", "pause", "resume", "now", "login", "quit", "open-tools", "back-panel"]
        do { try FileManager.default.removeItem(at: url) } catch { return }
        guard allowed.contains(action) else { return }
        var input: [String: Any] = ["action": action]
        if action == "watch" || action == "strict" {
            input = ["action": "level", "value": action == "strict" ? 2 : 1]
        }
        // 回执只表示接收，异步检测是否通过由 live 决定。
        let reply: [String: Any] = ["id": id, "ok": true]
        let result = Store.dir.appendingPathComponent("shield-command-result.json")
        if let output = try? JSONSerialization.data(withJSONObject: reply) {
            try? output.write(to: result, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: result.path)
        }
        handleAction(input)
    }

    func handleAction(_ body: [String: Any], from source: Source = .panel) {
        guard let action = body["action"] as? String else { return }
        if ["fixtz", "confirm-egress"].contains(action), sessionStarting || admittedSession != nil {
            sessionMessage = "请先结束本次使用，再调整基线或时区"
            push()
            return
        }
        if VMNetworkEvidence.enabled && action == "upstream" {
            sessionMessage = "虚拟机使用已有 mihomo 与 pf 固定链路，无需切换上游模式"
            push()
            return
        }
        switch action {
        case "session-start":
            // 与维修请求串行：先发布 checking，再释放锁；维修端持锁读会话状态。
            Store.ensureDir()
            let fd = open(Store.dir.appendingPathComponent("shield-maintenance.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { return }
            defer { close(fd) }
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                sessionMessage = "环境维修尚未完成，请完成后重新检查"
                push()
                return
            }
            defer { flock(fd, LOCK_UN) }
            startCheckedSession()
        case "session-end":
            sessionGeneration += 1
            admittedSession = nil; vmRecovery.reset()
            sessionMessage = "会话已结束；下次使用请重新检查"
            let outcome = Killer.stopSession()
            Store.appendHit(&cfg, kind: "gate", note: sessionMessage + "；" + outcome.note, force: true)
            Store.save(cfg)
            push()
        case "toggle":
            if cfg.enabled { leaveStrictSession("值守已停用，结束本次使用") }
            sessionGeneration += 1
            admittedSession = nil; vmRecovery.reset()
            sessionMessage = "值守设置改变，下次使用需重新检查"
            cfg.enabled.toggle()
            Store.save(cfg)
            Store.log("enabled=\(cfg.enabled)")
            if cfg.enabled { probeNow() } else { paintIcon(.idle, tooltip: "已关闭") }
            scheduleTimer()
            push()
        case "upstream":
            // 两个方向都让现有准入作废：开 = 判据从本机机制换成结果证据，
            // 关 = 重新要求本机代理，而此刻本机可能根本没有。
            leaveStrictSession("上游代理设置改变，结束本次使用")
            sessionGeneration += 1
            admittedSession = nil; vmRecovery.reset()
            cfg.upstream.toggle()
            sessionMessage = cfg.upstream
                ? "上游代理已开：戒严改查边缘出口、传输与 DNS 证据，请检查并启动"
                : "上游代理已关：戒严重新要求本机系统代理与 TUN 同时在位"
            Store.save(cfg)
            Store.log("upstream=\(cfg.upstream)")
            probeNow(forceFresh: true)
            scheduleTimer()
            push()
        case "level":
            if body["value"] as? Int == cfg.level { push(); return }
            if body["value"] as? Int == 1 { leaveStrictSession("已切换为瞭望，结束本次戒严使用") }
            sessionGeneration += 1
            admittedSession = nil; vmRecovery.reset()
            sessionMessage = "值守强度改变，请检查并启动"
            if let lv = body["value"] as? Int, lv >= 1, lv <= 2 {
                cfg.level = lv
                Store.save(cfg)
                Store.log("level=\(lv)")
                probeNow(forceFresh: true)
                // 武装的那一刻就该换成 10 秒周期，不用等下一轮巡检回来才生效。
                scheduleTimer()
                push()
            }
        case "pause":
            leaveStrictSession("值守已暂停，结束本次使用")
            sessionGeneration += 1
            admittedSession = nil; vmRecovery.reset()
            let mins = (body["minutes"] as? Int) ?? 30
            cfg.pausedUntil = Date().timeIntervalSince1970 + Double(mins * 60)
            Store.save(cfg)
            Store.log("paused \(mins)m")
            scheduleTimer()
            push()
        case "resume":
            cfg.enabled = true
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
        case "confirm-egress":
            // 只有用户自己点过这一下，新出口才会替换基线。这一步不要二次确认：
            // 他就是来确认的，再问一遍等于把「是我换的」问成「确定吗」。
            if Store.confirmEgress(&cfg, at: Date().timeIntervalSince1970) {
                Store.appendHit(&cfg, kind: "egress",
                                note: "确认出口变更为 \(cfg.egressIP)", force: true)
                Store.save(cfg)
                Store.log("egress confirmed mask=\(cfg.egressIP) country=\(cfg.country)")
                lastEgressSeen = ""
                probeNow(forceStun: true, forceFresh: true)
            }
            push()
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
            // 「打开主界面」= 开主窗口。以前这里打开的是 CC Tower 自己的
            // 窗口，于是同一个产品裂成两个 .app，用户看到两个软件并排站着。
            openMainWindow()
        case "open-tools":
            NSApp.activate(ignoringOtherApps: true)
            openMainWindow()
        case "tools-ready":
            if mainWindow != nil { Store.log("main page ready"); push() }
        case "back-panel":
            if source == .main {
                // 主窗口里的「返回」是回体检台，不是关窗——窗口自己有标题栏
                // 和关闭按钮，关窗那条路不该藏在页面按钮里。守护台已经只剩
                // 菜单栏那一份，所以这里回的是魔塔体检。
                pendingView = "tower"
                if let origin = engineOrigin { showMainPage(origin) }
            } else {
                closePanel()
            }
        case "repair-dns":
            openMainWindow("privacy")
        case "repair-udp":
            openMainWindow("privacy")
        case "update":
            openMainWindow("settings")
        case "quit":
            let needsExit = cfg.enabled && !paused && cfg.level >= 2 && Killer.pid() != nil
            leaveStrictSession("哨兵将退出，结束本次使用")
            sessionGeneration += 1
            admittedSession = nil; vmRecovery.reset()
            Store.log("quit")
            if needsExit {
                sessionMessage = "正在结束 Claude，完成后退出哨兵"
                push()
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
                    guard let self = self else { return }
                    if Killer.pid() == nil {
                        NSApplication.shared.terminate(nil)
                    } else {
                        self.sessionMessage = "Claude 未能退出，哨兵继续值守；请先手动退出 Claude"
                        self.push()
                        self.probeNow(forceFresh: true)
                    }
                }
            } else {
                NSApplication.shared.terminate(nil)
            }
        default:
            break
        }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = "确认操作"
        alert.informativeText = message
        alert.addButton(withTitle: "继续")
        alert.addButton(withTitle: "取消")
        completionHandler(alert.runModal() == .alertFirstButtonReturn)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }
        let resource = Bundle.main.resourceURL?.appendingPathComponent("web").standardizedFileURL.path ?? ""
        let file = url.isFileURL && !resource.isEmpty && url.standardizedFileURL.path.hasPrefix(resource + "/")
        // 只有主窗口能加载引擎的端口：面板永远只加载本地文件，它要是能跟着
        // 页面跳去 http，等于把「面板里显示什么」交给网络。
        let local = webView === mainWebView && engineOrigin != nil
            && url.scheme == "http" && url.host == "127.0.0.1" && url.port == engineOrigin?.port
        if file || local || url.scheme == "about" { decisionHandler(.allow); return }
        if navigationAction.navigationType == .linkActivated && ["http", "https"].contains(url.scheme ?? "") {
            NSWorkspace.shared.open(url)
        }
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if (error as NSError).domain == NSURLErrorDomain && (error as NSError).code == NSURLErrorCancelled { return }
        if webView === mainWebView { failEngine("维护页没能打开，端口可能已经关了。") }
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
    /// 两处都要排除自己的包——CC Shield.app 的路径里也有 "Claude"。
    static func isClaude(_ app: NSRunningApplication) -> Bool {
        if (app.bundleIdentifier ?? "").lowercased().contains("claudefordesktop") {
            return true
        }
        guard let path = app.bundleURL?.path else { return false }
        return path.contains("/Claude.app") && !path.contains("CC Shield.app")
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

    static func stopSession() -> Outcome {
        let outcome = stop()
        if case .requested(let pid) = outcome,
           let target = NSRunningApplication(processIdentifier: pid), isClaude(target) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                guard !target.isTerminated, isClaude(target) else { return }
                let forced = target.forceTerminate()
                Store.log("session exit escalation success=\(forced)")
            }
        }
        return outcome
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

// Snapshot 到持久化结论的映射放在应用层，Store 可独立编译。
extension Config.Live {
        static func from(_ snap: Snapshot) -> Config.Live {
            Config.Live(
                at: snap.at.timeIntervalSince1970,
                verdict: snap.verdict.rawValue,
                title: snap.title,
                note: snap.note,
                claudeRunning: snap.claudeRunning,
                exitReady: snap.exitReady,
                directConnections: snap.connections.direct,
                takeoverMissing: snap.takeoverMissing,
                tzDrift: snap.tzDrift,
                dnsSuspect: snap.dnsSuspect,
                dnsEgressSuspect: snap.dnsEgressSuspect,
                stunLeak: snap.stunLeak,
                // 打码之后再落盘。塔从不把完整地址交给别人，哨兵也一样。
                stunExposed: snap.stunExposed.map(maskAddress),
                ruleDrift: snap.guardDrift,
                ruleMissing: snap.guardMissing,
                ipv6Drift: snap.ipv6Drift,
                transportState: snap.transportState,
                domainState: snap.domainState,
                domainLabel: snap.domainLabel
            )
        }

}
