import Foundation

/// 把系统时区改回塔记下的基线。
///
/// 为什么是按钮，不是后台自动：
/// 那要装一个常驻的 root 服务，而我们整个 Shield 的定位是「只读的旁观者」——
/// 为了一个一年遇不到两次的时区漂移去常驻 root，代价和收益完全不成比例。
/// 所以做成你按下按钮、弹一次系统密码框、改一次。看得见，也停得下来。
enum TzFix {
    /// 时区名只允许这些字符。`systemsetup` 的参数会进 osascript 的字符串，
    /// 不校验等于把 shell 注入的口子开在自己的提权路径上。
    static func isSafe(_ tz: String) -> Bool {
        guard !tz.isEmpty, tz.count <= 64, !tz.hasPrefix("-") else { return false }
        let ok = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+-/")
        return tz.unicodeScalars.allSatisfy { ok.contains($0) }
    }

    static func restore(_ tz: String) -> String {
        guard isSafe(tz) else { return "时区名不合法（\(tz)），拒绝执行" }
        let script = "do shell script \"/usr/sbin/systemsetup -settimezone \(tz)\" with administrator privileges"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        do { try p.run() } catch { return "调不起 osascript：\(error.localizedDescription)" }
        // 用户可能在密码框上停很久，这里给足 120 秒
        let sem = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in sem.signal() }
        if sem.wait(timeout: .now() + 120) == .timedOut {
            p.terminate()
            return "等待授权超时，时区没改"
        }
        let text = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if p.terminationStatus == 0 {
            return "已把时区改回 \(tz)"
        }
        // -128 是用户点了取消。这条要单独说，不然会被当成失败重试
        if text.contains("-128") || text.contains("User canceled") {
            return "已取消，时区没改"
        }
        return "改时区失败：\(text.trimmingCharacters(in: .whitespacesAndNewlines))"
    }
}
