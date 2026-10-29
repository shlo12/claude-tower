import Cocoa

/// 哨兵的进程外看门狗。
///
/// 只负责三件事：每 10 秒写一次心跳、确保看门狗进程活着、用户退出时
/// 通知看门狗一起下班。它不碰巡检，也不决定要不要杀 Claude——那边出问题
/// 时至少还有人来重新拉起它。
enum Watchdog {
    static var child: Process?
    static var beat: Timer?
    static var stopping = false

    static var heartbeatURL: URL { Store.dir.appendingPathComponent("shield-heartbeat.json") }
    static var stopURL: URL { Store.dir.appendingPathComponent("watchdog.stop") }

    static var executable: URL? {
        let bundled = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/ShieldWatchdog")
        if FileManager.default.isExecutableFile(atPath: bundled.path) { return bundled }
        // 从源码直接跑开发态时还没有打包，退回同目录构建产物。
        #if DEBUG
        let dev = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("watchdog/ShieldWatchdog")
        return FileManager.default.isExecutableFile(atPath: dev.path) ? dev : nil
        #else
        return nil
        #endif
    }

    static func start() {
        guard !stopping, let exe = executable else {
            Store.log("watchdog: 没找到 ShieldWatchdog，本次不启用自动拉起")
            return
        }
        Store.ensureDir()
        // 上一次退出留下的停止信号必须先清掉，否则新看门狗一上来就下班。
        try? FileManager.default.removeItem(at: stopURL)
        writeHeartbeat()
        launch(exe)
        beat?.invalidate()
        beat = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { _ in
            writeHeartbeat()
            ensure(exe)
        }
        RunLoop.main.add(beat!, forMode: .common)
        Store.log("watchdog: started \(exe.path)")
    }

    static func stop() {
        guard !stopping else { return }
        stopping = true
        beat?.invalidate()
        beat = nil
        Store.ensureDir()
        // 先落停止信号再发 SIGTERM：即使看门狗刚好在唤醒，也不会误以为
        // 哨兵崩了而把它重新拉起来。
        try? "\(getpid())".write(to: stopURL, atomically: true, encoding: .utf8)
        if let p = child, p.isRunning {
            p.terminate()
            let deadline = Date().addingTimeInterval(1.5)
            while p.isRunning && Date() < deadline {
                usleep(50_000)
            }
        }
        child = nil
        Store.log("watchdog: stopped")
    }

    private static func launch(_ exe: URL) {
        guard !stopping else { return }
        let p = Process()
        p.executableURL = exe
        p.arguments = [
            "--dir", Store.dir.path,
            "--app", Bundle.main.bundleURL.path,
            "--interval", "10",
            "--hang-after", "45",
        ]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            child = p
        } catch {
            Store.log("watchdog: launch failed \(error.localizedDescription)")
        }
    }

    /// 看门狗被系统或别的清理工具杀掉后，下一轮心跳把它补回来。
    /// 若另一个实例正持有锁，新实例会安静退出，10 秒后再试。
    private static func ensure(_ exe: URL) {
        guard !stopping else { return }
        if child?.isRunning == true { return }
        launch(exe)
    }

    private static func writeHeartbeat() {
        guard !stopping else { return }
        Store.ensureDir()
        let payload: [String: Any] = [
            "pid": Int(getpid()),
            // 用系统清醒时长而不是墙上时间：合盖睡眠回来时心跳不会突然
            // 变成「过期 8 小时」，看门狗也就不会误杀一个刚被唤醒的哨兵。
            "uptime": ProcessInfo.processInfo.systemUptime,
            "at": Date().timeIntervalSince1970,
            // 看门狗靠这个认出「这个 pid 还是当初那个进程」。没有它的话，
            // 父进程死后 PID 被系统回收给别的进程时，看门狗会照着号去
            // SIGTERM/SIGKILL，杀的是无关的人。
            "exe": Bundle.main.executableURL?.resolvingSymlinksInPath().path ?? "",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }
        try? data.write(to: heartbeatURL, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: heartbeatURL.path)
    }
}
