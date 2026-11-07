import Cocoa
import CryptoKit
import Darwin

struct TransferFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct VM {
    let id: String
    let name: String
    let running: Bool
}

final class BytesBox {
    private let lock = NSLock()
    private var value = Data()
    func put(_ data: Data) { lock.lock(); value = data; lock.unlock() }
    func get() -> Data { lock.lock(); defer { lock.unlock() }; return value }
}

struct ClosureCheck {
    var host: Int?
    var guest: Int?
    var at = Date()
    var verified: Bool { host == 0 && guest == 0 }
    var text: String {
        if verified { return "本工具傳輸已結束 · 宿主與客機均已核驗" }
        if (host ?? 0) > 0 || (guest ?? 0) > 0 { return "仍偵測到本工具傳輸程序，尚未確認結束" }
        return "結束狀態未確認，請按「核對結束狀態」重試"
    }
}

enum ChannelAudit {
    static func capture(_ executable: String, _ args: [String]) throws -> Data {
        let p = Process(), out = Pipe(), err = Pipe()
        p.executableURL = URL(fileURLWithPath: executable); p.arguments = args
        p.standardInput = FileHandle.nullDevice; p.standardOutput = out; p.standardError = err
        try p.run()
        let group = DispatchGroup(), stdout = BytesBox()
        group.enter()
        DispatchQueue.global().async { stdout.put(out.fileHandleForReading.readDataToEndOfFile()); group.leave() }
        group.enter()
        DispatchQueue.global().async { _ = err.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        let stop = DispatchWorkItem { if p.isRunning { p.terminate() } }
        let kill = DispatchWorkItem { if p.isRunning { Darwin.kill(p.processIdentifier, SIGKILL) } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 10, execute: stop)
        DispatchQueue.global().asyncAfter(deadline: .now() + 12, execute: kill)
        p.waitUntilExit(); group.wait(); stop.cancel(); kill.cancel()
        guard p.terminationStatus == 0 else { throw TransferFailure(message: "傳輸程序核驗未完成") }
        return stdout.get()
    }

    static func hostCount() -> Int? {
        guard let data = try? capture("/bin/ps", ["-ww", "-axo", "uid=,stat=,args="]),
              let text = String(data: data, encoding: .utf8) else { return nil }
        let marker = try! NSRegularExpression(pattern: #"(?:^|\s)--cc-vm-transfer-session=[a-f0-9]{32}(?=\s|$|['"])"#)
        return text.components(separatedBy: "\n").filter { row in
            let parts = row.split(maxSplits: 2, whereSeparator: { $0.isWhitespace })
            guard parts.count == 3, UInt32(parts[0]) == getuid(), !parts[1].contains("Z"),
                  parts[2].contains("/prlctl ") else { return false }
            let args = String(parts[2])
            return marker.firstMatch(in: args, range: NSRange(args.startIndex..., in: args)) != nil
        }.count
    }

    static func run(vm: String, session: String = "all") -> ClosureCheck {
        var result = ClosureCheck()
        // The auditor opens a short-lived read-only exec, with no receiver tag.
        // Check the host again after it exits, so its own process is not counted.
        if let url = Bundle.main.resourceURL?.appendingPathComponent("audit.py"),
           let source = try? Data(contentsOf: url) {
            let code = "exec(__import__('base64').b64decode('" + source.base64EncodedString() + "'))"
            let quoted = "'" + code.replacingOccurrences(of: "'", with: "'\\''") + "'"
            // A read-only retry is safe: it cannot duplicate delivered files.
            for _ in 0..<2 {
                if let data = try? capture(Transfer.prlctl, ["exec", vm, "/usr/bin/python3", "-c", quoted, session]),
                   let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                   json["ok"] as? Bool == true, json["session"] as? String == session,
                   let count = json["active"] as? Int, count >= 0 {
                    result.guest = count
                    break
                }
            }
        }
        result.host = hostCount()
        result.at = Date()
        return result
    }
}

final class SourceFile {
    let name: String
    let handle: FileHandle
    let initial: stat
    init(_ url: URL) throws {
        name = url.lastPathComponent
        guard !name.isEmpty, name != ".", name != "..", name.utf8.count <= 255,
              !name.contains("\\"), !name.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
            throw TransferFailure(message: "檔名含不支援的字元，請重新命名後再傳送。")
        }
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw TransferFailure(message: "無法讀取選中的檔案；請確認權限。符號連結不支援傳送。") }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else {
            Darwin.close(fd)
            throw TransferFailure(message: "只支援一般檔案。資料夾請先壓縮成 ZIP；符號連結與特殊檔案不支援。")
        }
        guard st.st_size >= 0, st.st_size <= 2 * 1024 * 1024 * 1024 else {
            Darwin.close(fd)
            throw TransferFailure(message: "單個檔案上限為 2 GB，請拆分後傳送。")
        }
        handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        initial = st
    }
    func unchanged() -> Bool {
        var st = stat()
        return fstat(handle.fileDescriptor, &st) == 0 && st.st_size == initial.st_size
            && st.st_mtimespec.tv_sec == initial.st_mtimespec.tv_sec
            && st.st_mtimespec.tv_nsec == initial.st_mtimespec.tv_nsec
            && st.st_ctimespec.tv_sec == initial.st_ctimespec.tv_sec
            && st.st_ctimespec.tv_nsec == initial.st_ctimespec.tv_nsec
    }
}

final class Transfer {
    static let prlctl = "/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false
    private var launched = false
    let sessionID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    private(set) var closureCheck: ClosureCheck?

    func cancel() {
        lock.lock(); cancelled = true; let p = process; lock.unlock()
        // Let the writer send a protocol abort before closing Parallels. Killing
        // only its host process can leave guest stdin open until idle timeout.
        if let p = p {
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                if p.isRunning { p.terminate() }
            }
        }
    }

    private func checkCancelled() throws {
        lock.lock(); let value = cancelled; lock.unlock()
        if value { throw TransferFailure(message: "已取消傳送。若在最後確認時取消，請檢查客機收件夾是否已完成收件。") }
    }

    static func availableVMs() throws -> [VM] {
        let p = Process(), out = Pipe(), err = Pipe()
        p.executableURL = URL(fileURLWithPath: prlctl)
        p.arguments = ["list", "-a", "-j"]
        p.standardOutput = out; p.standardError = err; p.standardInput = FileHandle.nullDevice
        try p.run()
        let timeout = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 15, execute: timeout)
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit(); timeout.cancel()
        guard p.terminationStatus == 0,
              let rows = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw TransferFailure(message: "無法取得虛擬機清單。請確認 Parallels Desktop 已安裝，且授權支援 prlctl。")
        }
        return rows.compactMap { row in
            guard let id = row["uuid"] as? String, let name = row["name"] as? String else { return nil }
            return VM(id: id, name: name, running: row["status"] as? String == "running")
        }
    }

    static func receiverCode() throws -> String {
        let url = Bundle.main.resourceURL?.appendingPathComponent("receiver.py")
        guard let url = url, let data = try? Data(contentsOf: url) else {
            throw TransferFailure(message: "接收元件缺失，請重新解壓完整的小工具。")
        }
        return "exec(__import__('base64').b64decode('" + data.base64EncodedString() + "'))"
    }

    func send(vm: String, urls: [URL], progress: @escaping (Double, String) -> Void) throws -> [String: Any] {
        var info: [String: Any]?
        var failure: Error?
        do { info = try sendPayload(vm: vm, urls: urls, progress: progress) }
        catch { failure = error }
        if launched {
            progress(1, "正在核對宿主與客機的傳輸程序是否已結束…")
            closureCheck = ChannelAudit.run(vm: vm, session: sessionID)
        }
        if let failure = failure { throw failure }
        var result = info ?? [:]
        result["closureVerified"] = closureCheck?.verified ?? false
        result["hostActive"] = closureCheck?.host ?? -1
        result["guestActive"] = closureCheck?.guest ?? -1
        return result
    }

    private func sendPayload(vm: String, urls: [URL], progress: @escaping (Double, String) -> Void) throws -> [String: Any] {
        guard UUID(uuidString: vm) != nil else { throw TransferFailure(message: "請選擇清單中的目標虛擬機。") }
        guard !urls.isEmpty, urls.count <= 100 else { throw TransferFailure(message: "每批請選擇 1–100 個檔案。") }
        let sources = try urls.map { try SourceFile($0) }
        let names = sources.map { $0.name.precomposedStringWithCanonicalMapping.lowercased() }
        guard Set(names).count == names.count else { throw TransferFailure(message: "同一批內有同名檔案，請重新命名或分批傳送。") }
        let total = sources.reduce(Int64(0)) { $0 + $1.initial.st_size }
        guard total <= 8 * 1024 * 1024 * 1024 else { throw TransferFailure(message: "每批總量上限為 8 GB，請分批傳送。") }
        try checkCancelled()
        let code = try Self.receiverCode()
        // prlctl joins guest arguments into a shell command. Only fixed program
        // text is shell-quoted; filenames and all file data travel through stdin.
        let quoted = "'" + code.replacingOccurrences(of: "'", with: "'\\''") + "'"
        let p = Process(), input = Pipe(), output = Pipe(), errors = Pipe()
        p.executableURL = URL(fileURLWithPath: Self.prlctl)
        p.arguments = ["exec", vm, "/usr/bin/python3", "-c", quoted, "--cc-vm-transfer-session=" + sessionID]
        p.standardInput = input; p.standardOutput = output; p.standardError = errors
        lock.lock()
        if cancelled { lock.unlock(); try checkCancelled() }
        do { try p.run() } catch {
            lock.unlock()
            throw TransferFailure(message: "無法啟動 Parallels 傳送通道，請確認 Parallels Desktop 已安裝。")
        }
        process = p; launched = true; lock.unlock()
        let reads = DispatchGroup(), stdout = BytesBox(), stderr = BytesBox()
        for (pipe, box) in [(output, stdout), (errors, stderr)] {
            reads.enter()
            DispatchQueue.global().async { box.put(pipe.fileHandleForReading.readDataToEndOfFile()); reads.leave() }
        }
        let timeout = DispatchWorkItem { self.cancel() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 1800, execute: timeout)
        defer {
            timeout.cancel()
            try? input.fileHandleForWriting.close()
            if p.isRunning { p.terminate() }
            lock.lock(); process = nil; lock.unlock()
        }
        func writeRecord(_ record: [String: Any]) throws {
            var data = try JSONSerialization.data(withJSONObject: record)
            data.append(10)
            try input.fileHandleForWriting.write(contentsOf: data)
        }
        var sent: Int64 = 0
        var writingFailed = false
        do {
            try writeRecord(["version": 1, "files": sources.count])
            for (index, source) in sources.enumerated() {
                try checkCancelled()
                try writeRecord(["name": source.name, "size": source.initial.st_size])
                var hash = SHA256(), fileSent: Int64 = 0
                while let data = try source.handle.read(upToCount: 196608), !data.isEmpty {
                    try checkCancelled()
                    fileSent += Int64(data.count)
                    guard fileSent <= source.initial.st_size else { throw TransferFailure(message: "來源檔案在傳送期間有變動，這批傳送已中止。") }
                    hash.update(data: data)
                    var encoded = data.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
                    if !encoded.hasSuffix("\n") { encoded += "\n" }
                    try input.fileHandleForWriting.write(contentsOf: Data(encoded.utf8))
                    sent += Int64(data.count)
                    progress(total > 0 ? Double(sent) / Double(total) : 1,
                             "傳送第 \(index + 1)/\(sources.count) 個檔案 · \(ByteCountFormatter.string(fromByteCount: sent, countStyle: .file)) / \(ByteCountFormatter.string(fromByteCount: total, countStyle: .file))")
                }
                guard fileSent == source.initial.st_size, source.unchanged() else {
                    throw TransferFailure(message: "來源檔案在傳送期間有變動，這批傳送已中止。")
                }
                let digest = hash.finalize().map { String(format: "%02x", $0) }.joined()
                try writeRecord(["end": true, "sha256": digest])
            }
            try checkCancelled()
            try writeRecord(["commit": true])
        } catch let failure as TransferFailure {
            try? writeRecord(["abort": true])
            try? input.fileHandleForWriting.close()
            // A cancelled operation has a three-second process-stop fallback.
            // Other local validation failures need the same bounded cleanup.
            let stop = DispatchWorkItem { if p.isRunning { p.terminate() } }
            DispatchQueue.global().asyncAfter(deadline: .now() + 3, execute: stop)
            p.waitUntilExit(); stop.cancel()
            throw failure
        } catch { writingFailed = true }
        try? input.fileHandleForWriting.close()
        progress(1, "正在核對 SHA256 與收件結果…")
        p.waitUntilExit(); reads.wait()
        try checkCancelled()
        let data = stdout.get()
        let result = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        guard p.terminationStatus == 0, result?["ok"] as? Bool == true,
              (result?["files"] as? Int) == sources.count,
              (result?["bytes"] as? Int64) == total, !writingFailed else {
            let code = result?["error"] as? String ?? ""
            let messages = [
                "no_logged_in_user": "請先登入虛擬機的 macOS 桌面，再重新傳送。",
                "unsafe_destination": "客機的 Downloads 或 VM-Inbox 不是安全的普通資料夾，請檢查後再傳。",
                "checksum_mismatch": "內容校驗不一致，這批檔案未發布到收件夾。",
                "requires_macos": "本工具只支援傳入 macOS 虛擬機。",
                "size_limit": "檔案超過接收上限，請拆分後再傳。"
            ]
            throw TransferFailure(message: messages[code] ?? "傳送未獲成功確認。請確認客機已啟動、Parallels Tools 正常且有 /usr/bin/python3，再重試；不要更改防火牆。")
        }
        return result!
    }
}

enum DropSelection {
    static func files(from pasteboard: NSPasteboard) throws -> [URL] {
        guard let items = pasteboard.pasteboardItems, !items.isEmpty, items.count <= 100 else {
            throw TransferFailure(message: "每批請拖入 1–100 個檔案。")
        }
        var urls: [URL] = [], names = Set<String>(), total: Int64 = 0
        for item in items {
            guard let value = item.string(forType: .fileURL), let url = URL(string: value),
                  url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost" else {
                throw TransferFailure(message: "請從 Finder 拖入本機檔案；不接受網頁連結、文字或尚未下載的附件。")
            }
            var info = stat()
            guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
                throw TransferFailure(message: "只接受普通檔案；資料夾請先壓縮成 ZIP，符號連結不支援。")
            }
            guard info.st_size >= 0, info.st_size <= 2 * 1024 * 1024 * 1024 else {
                throw TransferFailure(message: "單個檔案上限為 2 GB，請拆分後傳送。")
            }
            let name = url.lastPathComponent.precomposedStringWithCanonicalMapping.lowercased()
            guard names.insert(name).inserted else {
                throw TransferFailure(message: "同一批內有同名檔案，請分開傳送或先重新命名。")
            }
            total += info.st_size
            guard total <= 8 * 1024 * 1024 * 1024 else {
                throw TransferFailure(message: "每批總量上限為 8 GB，請分批傳送。")
            }
            urls.append(url)
        }
        return urls
    }
}

final class FileDropView: NSView {
    var canDrop: () -> Bool = { false }
    var onFiles: ([URL]) -> Void = { _ in }
    var onRejected: (String) -> Void = { _ in }
    private let title = NSTextField(labelWithString: "將檔案拖到這裡，即可傳送")
    private let hint = NSTextField(labelWithString: "可拖入多個檔案 · 傳入上方選擇的虛擬機")
    private var highlighted = false { didSet { needsDisplay = true } }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        registerForDraggedTypes([.fileURL])
        title.font = .systemFont(ofSize: 14, weight: .medium)
        hint.font = .systemFont(ofSize: 11); hint.textColor = .secondaryLabelColor
        for label in [title, hint] { label.alignment = .center; label.translatesAutoresizingMaskIntoConstraints = false; addSubview(label) }
        NSLayoutConstraint.activate([
            title.centerXAnchor.constraint(equalTo: centerXAnchor),
            title.widthAnchor.constraint(lessThanOrEqualTo: widthAnchor, constant: -20),
            title.centerYAnchor.constraint(equalTo: centerYAnchor, constant: -10),
            hint.centerXAnchor.constraint(equalTo: centerXAnchor),
            hint.widthAnchor.constraint(lessThanOrEqualTo: widthAnchor, constant: -20),
            hint.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 5)
        ])
        setAccessibilityElement(true); setAccessibilityRole(.group)
        setAccessibilityLabel("檔案拖放區，也可使用下方選擇檔案按鈕")
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }
    override func hitTest(_ point: NSPoint) -> NSView? { bounds.contains(convert(point, from: superview)) ? self : nil }
    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 10, yRadius: 10)
        (highlighted ? NSColor.controlAccentColor.withAlphaComponent(0.10) : NSColor.controlBackgroundColor).setFill(); path.fill()
        (highlighted ? NSColor.controlAccentColor : NSColor.separatorColor).setStroke()
        path.lineWidth = highlighted ? 2 : 1
        path.setLineDash([5, 4], count: 2, phase: 0); path.stroke()
    }
    private func resetAppearance() {
        highlighted = false; title.stringValue = "將檔案拖到這裡，即可傳送"
        hint.stringValue = "可拖入多個檔案 · 傳入上方選擇的虛擬機"; hint.toolTip = nil
    }
    private func inspect(_ sender: NSDraggingInfo) -> NSDragOperation {
        guard canDrop() else {
            highlighted = false; title.stringValue = "目前無法拖入"
            hint.stringValue = "等待傳送或核驗完成；請先確認結束狀態通過"; return []
        }
        guard sender.draggingSourceOperationMask.contains(.copy) else { resetAppearance(); return [] }
        do {
            let urls = try DropSelection.files(from: sender.draggingPasteboard)
            highlighted = true; title.stringValue = "放開即可傳送 \(urls.count) 個檔案"
            hint.stringValue = "傳入上方選擇的虛擬機 · 宿主原檔案會保留"
            return .copy
        } catch {
            highlighted = false; title.stringValue = "無法接收這批內容"
            hint.stringValue = error.localizedDescription; hint.toolTip = error.localizedDescription
            return []
        }
    }
    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation { inspect(sender) }
    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation { inspect(sender) }
    override func draggingExited(_ sender: NSDraggingInfo?) { resetAppearance() }
    override func prepareForDragOperation(_ sender: NSDraggingInfo) -> Bool { !inspect(sender).isEmpty }
    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool { accept(sender.draggingPasteboard) }
    override func concludeDragOperation(_ sender: NSDraggingInfo?) { resetAppearance() }

    @discardableResult func accept(_ pasteboard: NSPasteboard) -> Bool {
        resetAppearance()
        guard canDrop() else { onRejected("請等待傳送或核驗完成，確認狀態通過後再拖入。"); return false }
        do { let urls = try DropSelection.files(from: pasteboard); onFiles(urls); return true }
        catch { onRejected(error.localizedDescription); return false }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var window: NSWindow!
    let vmPicker = NSPopUpButton()
    let choose = NSButton(title: "選擇檔案並傳送…", target: nil, action: nil)
    let refresh = NSButton(title: "重新整理", target: nil, action: nil)
    let cancel = NSButton(title: "取消傳送", target: nil, action: nil)
    let inspect = NSButton(title: "核對結束狀態", target: nil, action: nil)
    let closure = NSTextField(wrappingLabelWithString: "本工具傳輸：尚未核對")
    let hostWatch = NSTextField(wrappingLabelWithString: "僅核驗本工具；不代表 Parallels 全部維護通訊停用。")
    let status = NSTextField(wrappingLabelWithString: "正在讀取虛擬機清單…")
    let progress = NSProgressIndicator()
    let dropZone = FileDropView(frame: .zero)
    let destination = NSTextField(wrappingLabelWithString: "收件位置：客機 ~/Downloads/VM-Inbox\n每批獨立存放，完成 SHA256 校驗後才顯示。")
    var vms: [VM] = []
    var active: Transfer?
    var busy = false
    var lastProgressAt = Date.distantPast
    var checking = false
    var hostScanRunning = false
    var watchTimer: Timer?
    var lastClosure: ClosureCheck?
    var selectingFiles = false
    var canReceiveFiles: Bool {
        !busy && !checking && !selectingFiles && lastClosure?.verified == true
            && vms.indices.contains(vmPicker.indexOfSelectedItem)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let menu = NSMenu(), item = NSMenuItem(), appMenu = NSMenu()
        appMenu.addItem(withTitle: "結束傳入虛擬機", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.submenu = appMenu; menu.addItem(item); NSApp.mainMenu = menu
        buildWindow(); loadVMs()
        watchTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in self?.watchHost() }
    }

    func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 610),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "傳入虛擬機"; window.delegate = self; window.isReleasedWhenClosed = false
        let title = NSTextField(labelWithString: "把檔案傳入 macOS 虛擬機")
        title.font = .systemFont(ofSize: 21, weight: .semibold)
        let detail = NSTextField(wrappingLabelWithString: "只傳你選中的檔案，不開啟共享資料夾。\n不攜帶宿主路徑與檔案系統屬性；檔案內文及內嵌資訊仍會保留。")
        detail.textColor = .secondaryLabelColor
        let targetLabel = NSTextField(labelWithString: "目標虛擬機")
        vmPicker.setAccessibilityLabel("目標虛擬機")
        let targetRow = NSStackView(views: [vmPicker, refresh]); targetRow.spacing = 10
        vmPicker.widthAnchor.constraint(greaterThanOrEqualToConstant: 310).isActive = true
        progress.style = .bar; progress.isIndeterminate = false; progress.minValue = 0; progress.maxValue = 1
        progress.setAccessibilityLabel("傳送進度")
        status.font = .systemFont(ofSize: 13); status.setAccessibilityLabel("傳送狀態")
        destination.font = .systemFont(ofSize: 12); destination.textColor = .secondaryLabelColor
        destination.isSelectable = true
        choose.target = self; choose.action = #selector(selectFiles); choose.bezelStyle = .rounded
        choose.keyEquivalent = "\r"; choose.isEnabled = false
        refresh.target = self; refresh.action = #selector(refreshList); refresh.bezelStyle = .rounded
        cancel.target = self; cancel.action = #selector(cancelTransfer); cancel.bezelStyle = .rounded; cancel.isEnabled = false
        inspect.target = self; inspect.action = #selector(checkChannels); inspect.bezelStyle = .rounded; inspect.isEnabled = false
        vmPicker.target = self; vmPicker.action = #selector(checkChannels)
        closure.font = .systemFont(ofSize: 13, weight: .medium)
        closure.setAccessibilityLabel("本工具傳輸結束核驗")
        hostWatch.font = .systemFont(ofSize: 11); hostWatch.textColor = .secondaryLabelColor
        closure.toolTip = "核驗僅代表所示時間點的本工具傳輸程序狀態。客機核驗是一次短暫的唯讀維護請求；不會關閉 Parallels Tools。"
        let buttons = NSStackView(views: [choose, cancel, inspect]); buttons.spacing = 10
        dropZone.canDrop = { [weak self] in self?.canReceiveFiles == true }
        dropZone.onFiles = { [weak self] urls in
            guard let self = self, self.canReceiveFiles else { return }
            self.start(vm: self.vms[self.vmPicker.indexOfSelectedItem], urls: urls)
        }
        dropZone.onRejected = { [weak self] message in
            guard let self = self, !self.busy, !self.checking else { return }
            self.status.stringValue = message
        }
        let stack = NSStackView(views: [title, detail, targetLabel, targetRow, dropZone, progress, status, destination, closure, hostWatch, buttons])
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 24),
            detail.widthAnchor.constraint(equalTo: stack.widthAnchor),
            dropZone.widthAnchor.constraint(equalTo: stack.widthAnchor),
            dropZone.heightAnchor.constraint(equalToConstant: 76),
            progress.widthAnchor.constraint(equalTo: stack.widthAnchor),
            status.widthAnchor.constraint(equalTo: stack.widthAnchor),
            closure.widthAnchor.constraint(equalTo: stack.widthAnchor),
            hostWatch.widthAnchor.constraint(equalTo: stack.widthAnchor),
            destination.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    @objc func refreshList() { loadVMs() }
    func loadVMs() {
        guard !busy, !checking else { return }
        choose.isEnabled = false; refresh.isEnabled = false; inspect.isEnabled = false
        lastClosure = nil; closure.stringValue = "本工具傳輸：尚未核對"; closure.textColor = .secondaryLabelColor
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try Transfer.availableVMs() }
            DispatchQueue.main.async {
                self.refresh.isEnabled = true; self.vmPicker.removeAllItems()
                switch result {
                case .success(let machines):
                    self.vms = machines.filter { $0.running }
                    self.vmPicker.addItems(withTitles: self.vms.map { $0.name })
                    if let i = self.vms.firstIndex(where: { $0.name == "macOS" }) { self.vmPicker.selectItem(at: i) }
                    self.status.stringValue = self.vms.isEmpty ? "請先啟動 macOS 虛擬機並登入桌面，再按重新整理。" : "支援多選檔案；資料夾請先壓縮成 ZIP。核驗通過後即可選檔。"
                    if !self.vms.isEmpty { self.checkChannels() }
                case .failure(let error): self.status.stringValue = error.localizedDescription
                }
            }
        }
    }

    @objc func selectFiles() {
        guard canReceiveFiles else { return }
        let vm = vms[vmPicker.indexOfSelectedItem]
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = true
        panel.resolvesAliases = false; panel.treatsFilePackagesAsDirectories = true
        panel.prompt = "傳入虛擬機"; panel.message = "僅傳送選中的檔案。資料夾請先壓縮成 ZIP；文件內嵌作者與位置資訊不會自動移除。"
        selectingFiles = true
        panel.beginSheetModal(for: window) { response in
            self.selectingFiles = false
            if response == .OK { self.start(vm: vm, urls: panel.urls) }
        }
    }

    func start(vm: VM, urls: [URL]) {
        guard canReceiveFiles else {
            status.stringValue = "請先核對結束狀態，再重新選檔。"; return
        }
        busy = true; choose.isEnabled = false; refresh.isEnabled = false; vmPicker.isEnabled = false
        inspect.isEnabled = false; closure.stringValue = "傳輸中 · 完成或取消後自動核對結束狀態"; closure.textColor = .secondaryLabelColor
        cancel.isEnabled = true; progress.doubleValue = 0; status.stringValue = "正在建立客機收件通道…"
        let operation = Transfer(); active = operation
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try operation.send(vm: vm.id, urls: urls) { value, message in
                DispatchQueue.main.async {
                    if Date().timeIntervalSince(self.lastProgressAt) > 0.15 || value == 1 {
                        self.lastProgressAt = Date(); self.progress.doubleValue = value; self.status.stringValue = message
                    }
                }
            } }
            DispatchQueue.main.async {
                self.active = nil; self.busy = false; self.cancel.isEnabled = false
                self.refresh.isEnabled = true; self.vmPicker.isEnabled = true; self.inspect.isEnabled = true
                if let checked = operation.closureCheck { self.showClosure(checked) }
                else {
                    self.closure.stringValue = "本次未建立傳輸；保留上次結束核驗結果"
                    self.choose.isEnabled = self.lastClosure?.verified == true
                }
                switch result {
                case .success(let info):
                    self.progress.doubleValue = 1
                    self.status.stringValue = operation.closureCheck?.verified == true
                        ? "已完成：\(urls.count) 個檔案，SHA256 一致，傳輸程序已結束。"
                        : "已收件：\(urls.count) 個檔案，SHA256 一致；結束狀態尚待確認。"
                    self.destination.stringValue = "收件位置：客機 \(info["destination"] as? String ?? "~/Downloads/VM-Inbox")\n在客機 Finder 按 ⇧⌘G，輸入 ~/Downloads/VM-Inbox 即可查看。"
                case .failure(let error):
                    self.status.stringValue = (error as? TransferFailure)?.message ?? "傳送失敗，請檢查選檔權限、客機狀態與可用空間後重試。"
                    self.progress.doubleValue = 0
                }
            }
        }
    }

    @objc func cancelTransfer() {
        cancel.isEnabled = false; status.stringValue = "正在取消傳送…"; active?.cancel()
    }
    func showClosure(_ result: ClosureCheck) {
        lastClosure = result
        let formatter = DateFormatter(); formatter.timeStyle = .medium
        closure.stringValue = result.text + "\n核驗時間：" + formatter.string(from: result.at)
        closure.textColor = result.verified ? .systemGreen : .systemOrange
        choose.isEnabled = result.verified && !busy && !checking
    }
    @objc func checkChannels() {
        guard !busy, !checking, vms.indices.contains(vmPicker.indexOfSelectedItem) else { return }
        let vm = vms[vmPicker.indexOfSelectedItem]
        checking = true; choose.isEnabled = false; inspect.isEnabled = false
        refresh.isEnabled = false; vmPicker.isEnabled = false
        closure.stringValue = "正在核對本工具的宿主與客機傳輸程序…"; closure.textColor = .secondaryLabelColor
        DispatchQueue.global(qos: .utility).async {
            let result = ChannelAudit.run(vm: vm.id)
            DispatchQueue.main.async {
                self.checking = false; self.inspect.isEnabled = true
                self.refresh.isEnabled = true; self.vmPicker.isEnabled = true
                self.showClosure(result)
            }
        }
    }
    func watchHost() {
        guard !busy, !checking, !hostScanRunning else { return }
        hostScanRunning = true
        let started = Date()
        DispatchQueue.global(qos: .utility).async {
            let count = ChannelAudit.hostCount()
            DispatchQueue.main.async {
                self.hostScanRunning = false
                guard !self.busy, !self.checking else { return }
                // An older passive scan must not overwrite a newer dual-end check.
                if let last = self.lastClosure, last.at > started { return }
                if let count = count {
                    let formatter = DateFormatter(); formatter.timeStyle = .medium
                    self.hostWatch.stringValue = "宿主巡檢：\(count == 0 ? "未見本工具傳輸程序" : "偵測到本工具傳輸程序") · \(formatter.string(from: Date()))\n僅核驗本工具；不代表 Parallels 全部維護通訊停用。"
                    if count > 0 {
                        self.lastClosure = nil; self.choose.isEnabled = false
                        self.closure.stringValue = "閒置時偵測到本工具傳輸程序，請核對結束狀態"
                        self.closure.textColor = .systemOrange
                    }
                } else {
                    self.hostWatch.stringValue = "宿主巡檢未成功，請手動核對結束狀態。\n僅核驗本工具；不代表 Parallels 全部維護通訊停用。"
                    self.lastClosure = nil; self.choose.isEnabled = false
                    self.closure.stringValue = "宿主巡檢未完成，結束狀態待確認"; self.closure.textColor = .systemOrange
                }
            }
        }
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if checking { return false }
        if busy { cancelTransfer(); return false }
        return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if checking { return .terminateCancel }
        if busy { cancelTransfer(); return .terminateCancel }
        return .terminateNow
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { watchTimer?.invalidate() }
}

signal(SIGPIPE, SIG_IGN)
if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--audit" {
    let result = ChannelAudit.run(vm: CommandLine.arguments[2])
    let data = try! JSONSerialization.data(withJSONObject: ["closureVerified": result.verified,
        "hostActive": result.host ?? -1, "guestActive": result.guest ?? -1], options: [.sortedKeys])
    print(String(data: data, encoding: .utf8)!); exit(result.verified ? 0 : 2)
}
if CommandLine.arguments.count >= 4 && ["--send", "--check-cancel"].contains(CommandLine.arguments[1]) {
    let operation = Transfer()
    signal(SIGINT, SIG_IGN)
    let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
    interrupt.setEventHandler { operation.cancel() }
    interrupt.resume()
    var cancellationChecked = false
    do {
        let result = try operation.send(vm: CommandLine.arguments[2], urls: CommandLine.arguments.dropFirst(3).map { URL(fileURLWithPath: $0) }) { value, _ in
            // Deterministic developer check: invoke the same cancel action after
            // the first chunk, before the complete-batch commit is possible.
            if CommandLine.arguments[1] == "--check-cancel", value > 0, !cancellationChecked {
                cancellationChecked = true; operation.cancel()
            }
        }
        let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        print(String(data: data, encoding: .utf8)!); exit(result["closureVerified"] as? Bool == true ? 0 : 2)
    } catch {
        fputs((error.localizedDescription + "\n"), stderr)
        if let check = operation.closureCheck { fputs(("結束核驗：" + check.text + "\n"), stderr) }
        exit(1)
    }
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
