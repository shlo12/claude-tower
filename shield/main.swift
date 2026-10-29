import Cocoa

// Claude Shield 的入口。
//
// 多文件编译时只有 main.swift 允许顶层代码——把这三行放进 ShieldApp.swift
// 会直接报 "expressions are not allowed at the top level"。
// 不用 @main：@main 要求类型带静态 main()，而这里的 delegate 需要在
// NSApplication 起来之后才能建 status item，顺序反了会拿到空 statusBar。

// --probe-dump：不建界面，只跑一次巡检把结果打成 JSON。
// 给 tools/test_shield.py 用，也方便在终端里确认「这一刻到底看到了什么」。
if CommandLine.arguments.contains("--probe-dump") {
    // 走真实的配置文件，这样 --probe-dump 就是一次完整的端到端自检，
    // 而不是「用空基线跑一遍」——后者永远看不到 STUN 比对的结果。
    let cfg = Store.load()
    let fresh = cfg.egressAt > 0 && Date().timeIntervalSince1970 - cfg.egressAt < 86400
    let snap = Probe.run(baselineTz: cfg.baselineTz, egressMask: cfg.egressIP,
                         maskFresh: fresh, ruleGuard: cfg.ruleGuard,
                         forceStun: true, forceFresh: true,
                         forceTransport: true)
    let payload: [String: Any] = [
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
        // 和面板一样打码：这个输出常被重定向到文件，落盘的不能是真实地址。
        "stun": snap.stunAll.map(Probe.maskIP),
        "stunForeign": snap.stunForeign.map(Probe.maskIP),
        "stunChecked": snap.stunChecked,
        "stunLeak": snap.stunLeak,
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
        "towerData": snap.hasTowerData,
        "towerState": snap.towerState,
        "environmentReady": snap.environmentReady,
        "idleState": snap.idleState.rawValue,
        "egressAt": cfg.egressAt,
        "country": cfg.country,
        "clients": snap.proxyClients,
        // 「客户端在跑、但没接管」以及它持续够久之后的升级结果。
        // 这两项决定 L2 会不会动手，排查时必须能直接看到。
        "takeover": snap.takeoverMissing,
        "takeoverEscalated": snap.takeoverEscalated,
        "tz": snap.tz,
        "baselineTz": snap.baselineTz,
        "tzDrift": snap.tzDrift,
        "ipv6Checked": snap.ipv6Checked,
        "ipv6Drift": snap.ipv6Drift,
        "ipv6Services": snap.ipv6Services,
        "ruleChecked": snap.guardChecked,
        "ruleDrift": snap.guardDrift,
        "ruleMissing": snap.guardMissing,
        "at": snap.at.timeIntervalSince1970,
        "interval": cfg.interval,
    ]
    if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
       let text = String(data: data, encoding: .utf8) {
        print(text)
    }
    exit(0)
}

// --tower-path：不建界面、不打开任何东西，只打印「打开塔」会走哪条路。
// 两条分支在本机可能指向同一个 .app，光看塔被拉起来分不清是哪条命中的；
// 这个开关让安装好的产物自己把答案说出来。
if CommandLine.arguments.contains("--tower-path") {
    let host = TowerHost.hostBundle()?.path ?? ""
    let bundle = TowerHost.registeredBundle()?.path ?? ""
    let chosen = TowerHost.resolve()
    print("host=\(host)")
    print("bundle=\(bundle)")
    print("chosen=\(chosen?.source.rawValue ?? "none")")
    if let url = chosen?.url { print("path=\(url.path)") }
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
