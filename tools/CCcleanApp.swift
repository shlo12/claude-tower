import Cocoa
import WebKit

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    var server: Process?
    var timer: Timer?
    var ticks = 0
    var loaded = false

    let runtimePath = NSHomeDirectory() + "/Library/Application Support/CCclean/runtime.json"

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        buildWindow()
        startServer()
        startShieldIfNeeded()
        schedulePoll()
    }

    /// 哨兵是包里的第二个进程，菜单栏常驻；塔关窗退出后它继续守着。
    /// 打开塔时如果没看到它（第一次装、用户手动退过、看门狗也被清掉），
    /// 就在这里补起来——否则「一个应用」会变成「装完只有塔」。
    func startShieldIfNeeded() {
        guard let res = Bundle.main.resourcePath else { return }
        let url = URL(fileURLWithPath: res).appendingPathComponent("Claude Shield.app")
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        let running = NSWorkspace.shared.runningApplications.contains {
            $0.bundleIdentifier == "com.ccclean.shield"
        }
        if running { return }
        let cfg = NSWorkspace.OpenConfiguration()
        // 开塔的人是要看塔，不该把焦点抢到菜单栏去
        cfg.activates = false
        NSWorkspace.shared.openApplication(at: url, configuration: cfg) { _, error in
            if let error = error {
                NSLog("[ccclean] 启动哨兵失败：%@", error.localizedDescription)
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
        if let p = server, p.isRunning {
            p.terminate()
        }
    }

    // MARK: - 菜单

    func buildMenu() {
        let main = NSMenu()

        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "关于 Claude Tower", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "隐藏 Claude Tower", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "退出 Claude Tower", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let editItem = NSMenuItem()
        main.addItem(editItem)
        let edit = NSMenu(title: "编辑")
        edit.addItem(withTitle: "撤销", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "重做", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: "剪切", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "拷贝", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "粘贴", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "全选", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit

        let viewItem = NSMenuItem()
        main.addItem(viewItem)
        let view = NSMenu(title: "视图")
        let reloadItem = NSMenuItem(title: "重新载入", action: #selector(reloadPage), keyEquivalent: "r")
        reloadItem.target = self
        view.addItem(reloadItem)
        viewItem.submenu = view

        NSApp.mainMenu = main
    }

    @objc func reloadPage() {
        webView.reload()
    }

    // MARK: - 窗口

    func buildWindow() {
        let rect = NSRect(x: 0, y: 0, width: 1180, height: 840)
        window = NSWindow(
            contentRect: rect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Claude Tower"
        window.minSize = NSSize(width: 1080, height: 700)
        window.titlebarAppearsTransparent = false
        window.center()

        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "developerExtrasEnabled")
        webView = WKWebView(frame: rect, configuration: config)
        webView.navigationDelegate = self
        webView.autoresizingMask = [.width, .height]

        window.contentView = webView
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - 启动本地服务

    // 光看「文件可执行」不够：没装命令行工具时 /usr/bin/python3 是个只会报错的壳子，
    // 所以每个候选都真跑一次，确认是 Python 3.9+ 才算数。
    func pythonCandidates() -> [String] {
        let home = NSHomeDirectory()
        return [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
            home + "/.pyenv/shims/python3",
            home + "/.local/bin/python3",
            "/usr/bin/python3",
        ]
    }

    func probePython(_ path: String) -> Bool {
        guard FileManager.default.isExecutableFile(atPath: path) else { return false }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
        } catch {
            return false
        }
        return p.terminationStatus == 0
    }

    func pythonPath() -> String? {
        return pythonCandidates().first { probePython($0) }
    }

    // 应用包内自带的解释器。两个架构各带一份，编译时按切片各取各的，
    // 所以同一个通用二进制在 Intel 和 Apple 芯片上都指向对的那份。
    func bundledPython() -> String? {
        guard let res = Bundle.main.resourcePath else { return nil }
        #if arch(arm64)
        let rel = "python/arm64/bin/python3.12"
        #else
        let rel = "python/x86_64/bin/python3.12"
        #endif
        let path = res + "/" + rel
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }
        return probePython(path) ? path : nil
    }

    func startServer() {
        try? FileManager.default.removeItem(atPath: runtimePath)

        // 优先用包里自带的：对方机器上很可能一个 python3 都没有
        // （macOS 12.3 起系统不再自带，/usr/bin/python3 只是个会弹安装提示的壳子）
        let bundled = bundledPython()
        let py = bundled ?? pythonPath()
        guard let py else {
            showError(
                "应用包不完整",
                detail: "内置的 Python 运行时找不到了，系统里也没有可用的 Python 3.9+。"
                    + "请重新解压一份完整的压缩包（不要只拷贝里面的 Claude Tower.app）。"
            )
            return
        }
        if bundled == nil {
            NSLog("[ccclean] 内置运行时不可用，回退到系统 Python：%@", py)
        }
        guard let res = Bundle.main.resourcePath else {
            showError("应用包不完整", detail: "缺少 Resources 目录。")
            return
        }
        let appDir = res + "/app"
        guard FileManager.default.fileExists(atPath: appDir + "/app.py") else {
            showError("应用包不完整", detail: "找不到内置的 app.py。")
            return
        }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: py)
        p.arguments = [appDir + "/app.py", "--app"]
        p.currentDirectoryURL = URL(fileURLWithPath: appDir)
        var env = ProcessInfo.processInfo.environment
        env["PYTHONUNBUFFERED"] = "1"
        // 别往 app 包里写 .pyc：那会破坏代码签名，下次启动可能被拦
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        // 用户 shell 里的这些变量会盖掉内置运行时的搜索路径，一律清掉
        env.removeValue(forKey: "PYTHONPATH")
        env.removeValue(forKey: "PYTHONHOME")
        env["PYTHONNOUSERSITE"] = "1"
        p.environment = env

        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { return }
            if let text = String(data: data, encoding: .utf8) {
                NSLog("[ccclean] %@", text.trimmingCharacters(in: .whitespacesAndNewlines))
            }
        }

        // 「退出游戏」会让后端进程自行结束；子进程一死，应用跟着退出
        p.terminationHandler = { _ in
            DispatchQueue.main.async {
                NSApp.terminate(nil)
            }
        }

        do {
            try p.run()
            server = p
        } catch {
            showError("启动本地服务失败", detail: error.localizedDescription)
        }
    }

    func schedulePoll() {
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            self?.tick()
        }
    }

    func tick() {
        if loaded { return }
        ticks += 1
        if let data = FileManager.default.contents(atPath: runtimePath),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let urlString = obj["url"] as? String,
           let url = URL(string: urlString) {
            loaded = true
            timer?.invalidate()
            webView.load(URLRequest(url: url))
            return
        }
        if ticks > 96 {
            timer?.invalidate()
            showError(
                "本地服务启动超时",
                detail: "Python 可能版本过低或被杀毒软件拦住了。"
                    + "可以在「控制台」里搜索 <code>ccclean</code> 查看具体报错。"
            )
        }
    }

    // MARK: - 兜底页

    func showError(_ title: String, detail: String) {
        let html = """
        <!DOCTYPE html><html><head><meta charset="utf-8"><style>
        body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
        background:#f5f6f8;color:#14161c;font:14px -apple-system,"PingFang SC",sans-serif}
        .box{max-width:520px;padding:32px 36px;background:#fff;border:1px solid #e6e8ee;border-radius:16px;
        box-shadow:0 8px 30px -12px rgba(16,24,40,.18);text-align:center}
        h1{font-size:17px;margin:0 0 10px}
        p{color:#4a5060;line-height:1.7;margin:0 0 8px}
        code{background:#f2f4f7;padding:2px 6px;border-radius:4px;font-family:ui-monospace,Menlo,monospace;font-size:12.5px}
        </style></head><body><div class="box">
        <h1>\(title)</h1><p>\(detail)</p>
        <p style="color:#98a2b3;font-size:12px;margin-top:16px">关掉这个窗口可以退出应用</p>
        </div></body></html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        NSLog("[ccclean] navigation failed: %@", error.localizedDescription)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
