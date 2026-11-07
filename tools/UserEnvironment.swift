import Foundation
import Darwin

/// Repair unusable inherited homes without discarding intentional, writable
/// isolated homes. Read the account fallback from passwd, never from $HOME.
enum UserEnvironment {
    static func usableHome(_ value: String?) -> String? {
        guard let value = value, value.hasPrefix("/"), !value.utf8.contains(0) else { return nil }
        let path = URL(fileURLWithPath: value).standardizedFileURL.path
        var directory: ObjCBool = false
        guard path != "/", FileManager.default.fileExists(atPath: path, isDirectory: &directory),
              directory.boolValue, FileManager.default.isWritableFile(atPath: path) else { return nil }
        return path
    }

    static func resolve(_ inherited: [String: String], accountHome: String) -> [String: String] {
        var result = inherited
        guard let home = usableHome(inherited["CFFIXED_USER_HOME"])
                ?? usableHome(inherited["HOME"]) ?? usableHome(accountHome) else { return result }
        result["HOME"] = home
        if inherited["CFFIXED_USER_HOME"] != nil { result["CFFIXED_USER_HOME"] = home }
        return result
    }

    static var child: [String: String] {
        guard let account = getpwuid(getuid()), let directory = account.pointee.pw_dir else {
            return ProcessInfo.processInfo.environment
        }
        return resolve(ProcessInfo.processInfo.environment, accountHome: String(cString: directory))
    }

    static func normalizeCurrentProcess() {
        let environment = child
        if let home = environment["HOME"] { setenv("HOME", home, 1) }
        if let home = environment["CFFIXED_USER_HOME"] { setenv("CFFIXED_USER_HOME", home, 1) }
    }
}
