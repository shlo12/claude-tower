// 简体→繁体转换器（构建繁中版时用，不参与运行）。
// 走系统自带的 ICU Hans-Hant 变换，不引第三方依赖。
// 用法：
//   hans2hant <文件> [<文件>...]   原地转换文件内容（非 UTF-8 直接跳过）
//   hans2hant --names <根目录>      把目录树里含汉字的文件/目录名也转换
import Foundation

func convert(_ s: String) -> String {
    let m = NSMutableString(string: s)
    CFStringTransform(m, nil, "Hans-Hant" as CFString, false)
    return m as String
}

func convertFile(_ path: String) -> Bool {
    guard let data = FileManager.default.contents(atPath: path),
          var text = String(data: data, encoding: .utf8) else { return false }
    text = convert(text)
    do {
        try text.write(toFile: path, atomically: true, encoding: .utf8)
        return true
    } catch {
        FileHandle.standardError.write("跳过 \(path)：\(error)\n".data(using: .utf8)!)
        return false
    }
}

let args = CommandLine.arguments
if args.count >= 3, args[1] == "--names" {
    // 深目录先改：把含汉字的 basename 逐个转换，最深的路径先处理。
    let root = args[2]
    var paths: [String] = []
    if let e = FileManager.default.enumerator(atPath: root) {
        for case let p as String in e { paths.append(p) }
    }
    for p in paths.sorted(by: { $0.components(separatedBy: "/").count > $1.components(separatedBy: "/").count }) {
        let base = (p as NSString).lastPathComponent
        let dir = (p as NSString).deletingLastPathComponent
        let newBase = convert(base)
        guard newBase != base else { continue }
        let from = dir.isEmpty ? "\(root)/\(base)" : "\(root)/\(dir)/\(base)"
        let to = dir.isEmpty ? "\(root)/\(newBase)" : "\(root)/\(dir)/\(newBase)"
        do { try FileManager.default.moveItem(atPath: from, toPath: to) }
        catch { FileHandle.standardError.write("改名失败 \(from)：\(error)\n".data(using: .utf8)!) }
    }
} else {
    var changed = 0
    for path in args.dropFirst() where convertFile(path) { changed += 1 }
    print("转换 \(changed)/\(args.count - 1) 个文件")
}
