import Darwin
import Foundation

// Claude Shield 的进程外看门狗。
//
// 哨兵崩溃或被 kill -9 时，菜单栏图标会一起消失——用户通常要等到下次
// 打开塔才发现「这段时间没人守」。这个进程只做一件事：每 10 秒读一次
// 父进程写的心跳，父进程没了就把它重新拉起来。
//
// 它不是 launchd 常驻服务，也不负责开机自启：生命周期完全跟着 Shield，
// 用户从面板退出时一起退出。

struct Options {
    var dir: URL
    var app: URL?
    var relaunch: String?
    var interval: Double = 10
    var hangAfter: Double = 45
    var notify = true
}

func parseOptions() -> Options {
    let home = FileManager.default.homeDirectoryForCurrentUser
    var opts = Options(dir: home.appendingPathComponent(".ccclean", isDirectory: true))
    let args = CommandLine.arguments
    var i = 1
    while i < args.count {
        let key = args[i]
        let value = i + 1 < args.count ? args[i + 1] : ""
        switch key {
        case "--dir" where !value.isEmpty:
            opts.dir = URL(fileURLWithPath: value)
            i += 1
        case "--app" where !value.isEmpty:
            opts.app = URL(fileURLWithPath: value)
            i += 1
        case "--relaunch" where !value.isEmpty:
            opts.relaunch = value
            i += 1
        case "--interval" where !value.isEmpty:
            opts.interval = max(1, Double(value) ?? 10)
            i += 1
        case "--hang-after" where !value.isEmpty:
            opts.hangAfter = max(15, Double(value) ?? 45)
            i += 1
        case "--no-notify":
            opts.notify = false
        default:
            break
        }
        i += 1
    }
    if opts.app == nil {
        // .../Claude Shield.app/Contents/MacOS/ShieldWatchdog
        let own = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let app = own.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        if app.pathExtension == "app" {
            opts.app = app
        }
    }
    return opts
}

let opts = parseOptions()
let fm = FileManager.default
try? fm.createDirectory(at: opts.dir, withIntermediateDirectories: true,
                        attributes: [.posixPermissions: 0o700])

let heartbeatURL = opts.dir.appendingPathComponent("shield-heartbeat.json")
let stopURL = opts.dir.appendingPathComponent("watchdog.stop")
let lockURL = opts.dir.appendingPathComponent("watchdog.lock")

func log(_ line: String) {
    let url = opts.dir.appendingPathComponent("shield.log")
    let stamp = ISO8601DateFormatter().string(from: Date())
    let text = "\(stamp) watchdog: \(line)\n"
    guard let data = text.data(using: .utf8) else { return }
    // 和 Store.log 一样只留一代，别让看门狗自己写出一个无限长的日志。
    if let attrs = try? fm.attributesOfItem(atPath: url.path),
       let size = attrs[.size] as? Int, size > 256 * 1024 {
        let old = url.appendingPathExtension("1")
        try? fm.removeItem(at: old)
        try? fm.moveItem(at: url, to: old)
    }
    if let fh = try? FileHandle(forWritingTo: url) {
        fh.seekToEndOfFile()
        fh.write(data)
        try? fh.close()
    } else {
        try? data.write(to: url, options: .atomic)
    }
}

// 同一时刻只允许一个看门狗。锁随进程退出自动释放；新哨兵拉起时若旧
// 看门狗还在交接，新实例会安静退出，10 秒后父进程的 ensure() 会再试一次。
let lockFD = open(lockURL.path, O_CREAT | O_RDWR, 0o600)
if lockFD < 0 || flock(lockFD, LOCK_EX | LOCK_NB) != 0 {
    exit(0)
}

struct Heartbeat {
    var pid: pid_t
    var uptime: Double
    /// 父进程自己的可执行文件路径，用来识别 PID 是否已被回收给别的进程。
    /// 老版本心跳没有这个字段，读不到就当空串（不做身份校验）。
    var exe: String
}

func readHeartbeat() -> Heartbeat? {
    guard let data = try? Data(contentsOf: heartbeatURL),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let pid = obj["pid"] as? Int, pid > 0,
          let uptime = obj["uptime"] as? Double else { return nil }
    return Heartbeat(pid: pid_t(pid), uptime: uptime,
                     exe: (obj["exe"] as? String) ?? "")
}

/// 进程当前的可执行文件路径。进程已消失或拿不到权限时返回 nil。
func executablePath(_ pid: pid_t) -> String? {
    var buf = [CChar](repeating: 0, count: Int(4 * MAXPATHLEN))
    let n = proc_pidpath(pid, &buf, UInt32(buf.count))
    guard n > 0 else { return nil }
    return String(cString: buf)
}

/// 这个号现在有没有进程占着。
func pidExists(_ pid: pid_t) -> Bool {
    if pid <= 1 { return false }
    return kill(pid, 0) == 0 || errno == EPERM
}

/// 这个 pid 还是不是当初写心跳的那个进程。
///
/// 只看 kill(pid, 0) 不够：父进程死掉后 PID 会被系统回收，同一个号可能已经
/// 属于一个完全无关的进程，kill 依然返回 0。接下来就是 SIGTERM、3 秒后
/// SIGKILL——杀掉的是别人的进程。所以再拿心跳里记的可执行文件路径核对一次。
///
/// 校验不了的时候一律当「还活着」：少拉起一次只是晚几十秒，错杀别人没法挽回。
func alive(_ pid: pid_t, expecting exe: String = "") -> Bool {
    if !pidExists(pid) { return false }
    guard !exe.isEmpty, let path = executablePath(pid) else { return true }
    return path == exe
}

func stopRequested() -> pid_t? {
    guard let text = try? String(contentsOf: stopURL, encoding: .utf8) else { return nil }
    return pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines))
}

func notify(_ title: String, _ body: String) {
    guard opts.notify else { return }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    p.arguments = ["-e", "display notification \"\(body)\" with title \"\(title)\""]
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    try? p.run()
}

func relaunch() -> Bool {
    if let script = opts.relaunch {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: script)
        p.arguments = ["--restored"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            return true
        } catch {
            log("relaunch helper failed: \(error.localizedDescription)")
            return false
        }
    }
    guard let app = opts.app else {
        log("no app path; cannot relaunch")
        return false
    }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    p.arguments = ["-a", app.path, "--args", "--restored"]
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    do {
        try p.run()
        p.waitUntilExit()
        if p.terminationStatus != 0 {
            log("open \(app.path) exited \(p.terminationStatus)")
            return false
        }
        return true
    } catch {
        log("open failed: \(error.localizedDescription)")
        return false
    }
}

log("start pid=\(getpid()) interval=\(opts.interval) hang=\(opts.hangAfter) app=\(opts.app?.path ?? "-")")

var lostSince: Double?
var lastLaunch: Double = 0
var attempts = 0
var toldCrash = false
var toldFailure = false

while true {
    let now = ProcessInfo.processInfo.systemUptime

    if let stop = stopRequested() {
        let hb = readHeartbeat()
        // 只认「当前这一任父进程」留下的停止信号；上一轮崩溃后残留的
        // 文件不能让新的看门狗提前下班。
        if hb == nil || hb!.pid == stop || !alive(stop) {
            log("stop requested pid=\(stop); exit")
            try? fm.removeItem(at: heartbeatURL)
            exit(0)
        }
        try? fm.removeItem(at: stopURL)
    }

    let hb = readHeartbeat()
    let pidAlive = hb.map { alive($0.pid, expecting: $0.exe) } ?? false
    let fresh = hb.map { now - $0.uptime <= opts.hangAfter } ?? false

    if pidAlive && fresh {
        if lostSince != nil {
            log("parent back pid=\(hb!.pid)")
        }
        lostSince = nil
        attempts = 0
        toldCrash = false
        toldFailure = false
    } else {
        if lostSince == nil {
            lostSince = now
            if let hb = hb, pidAlive {
                log("parent heartbeat stale age=\(Int(now - hb.uptime))s pid=\(hb.pid)")
            } else if let hb = hb, pidExists(hb.pid) && !hb.exe.isEmpty {
                // 号还在，但已经不是当初写心跳的那个进程：PID 被回收给了别人。
                log("pid \(hb.pid) reused by another process; leaving it alone")
            } else if let hb = hb {
                log("parent gone pid=\(hb.pid)")
            } else {
                log("no heartbeat")
            }
        }
        // 给正常退出、应用重启留 3 秒；心跳过期但进程还活着，说明它卡住了，
        // 温和终止后 3 秒还不走再强杀。动手前再核对一次身份：这中间父进程
        // 可能刚好退出，号被别人拿走。
        if now - (lostSince ?? now) >= 3 {
            if let hb = hb, pidAlive, now - hb.uptime > opts.hangAfter,
               alive(hb.pid, expecting: hb.exe) {
                log("parent unresponsive; terminate pid=\(hb.pid)")
                kill(hb.pid, SIGTERM)
                usleep(3_000_000)
                if alive(hb.pid, expecting: hb.exe) {
                    kill(hb.pid, SIGKILL)
                }
            }
            if !toldCrash {
                notify("哨兵意外退出了", "看门狗正在重新拉起 Claude Shield。")
                toldCrash = true
            }
            if now - lastLaunch >= 30 {
                lastLaunch = now
                attempts += 1
                if relaunch() {
                    log("relaunch attempt \(attempts)")
                } else if attempts >= 3 && !toldFailure {
                    notify("哨兵没能重新启动", "请手动打开 Claude Shield。")
                    toldFailure = true
                }
            }
        }
    }

    Thread.sleep(forTimeInterval: opts.interval)
}
