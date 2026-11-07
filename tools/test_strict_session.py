#!/usr/bin/env python3
"""编译实际 Swift 准入/节点身份判据，使用隔离配置和控制API响应，不连接真实代理、不杀进程。"""
import subprocess
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
HARNESS = r'''
import Foundation
func ok(_ v: Bool, _ why: String) { if !v { fatalError(why) } }
func ready() -> Snapshot {
    var s = Snapshot()
    s.baselineTz = "Etc/UTC"; s.tz = "Etc/UTC"
    s.egressMask = "5.34.*.136"; s.maskFresh = true
    s.sysProxy = true; s.tunUp = true; s.tunIface = "utun9"
    s.session = SessionEvidence(checked: true, mode: "global", identity: "node-a", error: "")
    s.dnsChecked = true; s.dnsFake = true; s.dnsResolverChecked = true; s.dnsResolverCountry = "US"
    s.stunChecked = true
    s.transportChecked = true; s.transportState = "ok"
    s.domainChecked = true; s.domainState = "ok"; s.egressCandidateIP = "5.34.1.136"
    return s
}
ok(Probe.classifyTransportError(URLError(.secureConnectionFailed)) == "connect", "generic TLS failure must retry")
ok(Probe.classifyTransportError(URLError(.serverCertificateUntrusted)) == "tls", "confirmed certificate failure stays hard")
let base = ready()
ok(StrictSessionPolicy.admissionIssue(base) == nil, "healthy admission")
let identity = StrictSessionPolicy.identity(base)
ok(StrictSessionPolicy.runningIssue(base, admitted: identity) == nil, "same session")
ok(StrictSessionPolicy.runningIssue(base, admitted: nil) != nil, "unapproved launch")
var changes: [Snapshot] = []
var s = base; s.maskFresh = false; changes.append(s)
s = base; s.baselineTz = ""; changes.append(s)
s = base; s.dnsChecked = false; changes.append(s)
s = base; s.dnsResolverChecked = false; changes.append(s)
s = base; s.dnsResolverCountry = ""; changes.append(s)
s = base; s.stunChecked = false; changes.append(s)
s = base; s.transportState = "off"; changes.append(s)
s = base; s.domainState = "warn"; changes.append(s)
s = base; s.sysProxy = false; changes.append(s)
s = base; s.tunUp = false; changes.append(s)
s = base; s.session.mode = "rule"; changes.append(s)
s = base; s.session.checked = false; changes.append(s)
s = base; s.egressPending = true; changes.append(s)
s = base; s.guardDrift = true; changes.append(s)
for row in changes { ok(StrictSessionPolicy.runningIssue(row, admitted: identity) != nil, "missing evidence must block") }
// 过期是「这一轮没看清」，不是「用户违规」：准入照样拒绝，但值守中不能
// 记成违规——记了就会走到 verdict = .danger 和杀进程。
var stale = base; stale.at = Date(timeIntervalSinceNow: -90)
ok(StrictSessionPolicy.staleIssue(stale) != nil, "stale must be reported")
ok(StrictSessionPolicy.admissionIssue(stale) != nil, "stale must block admission")
ok(StrictSessionPolicy.runningIssue(stale, admitted: identity) == nil, "stale must not be a violation")
ok(StrictSessionPolicy.contentIssue(stale) == nil, "content itself is fine")
s = base; s.egressCandidateIP = "5.34.99.136"
ok(StrictSessionPolicy.runningIssue(s, admitted: identity) != nil, "same masked prefix is not same exit")
s = base; s.session.identity = "node-b"
ok(StrictSessionPolicy.runningIssue(s, admitted: identity) != nil, "node switch with same IP must stop")
// 上游代理：没有本机接管机制也要探测，结果齐全之前不得显示出口就绪。
var up = ready(); up.upstream = true; up.sysProxy = false; up.tunUp = false
up.session = SessionEvidence()
ok(up.shouldProbeNetwork, "upstream without local proxy must run network probes")
ok(StrictSessionPolicy.admissionIssue(up) == nil && up.exitReady, "verified upstream may admit")
let upstreamID = StrictSessionPolicy.identity(up)
var missingUDP = up; missingUDP.stunChecked = false
ok(StrictSessionPolicy.admissionIssue(missingUDP) != nil && !missingUDP.exitReady, "unknown upstream UDP must block")
var domesticDNS = up; domesticDNS.dnsResolverCountry = "CN"
ok(domesticDNS.dnsEgressSuspect && StrictSessionPolicy.admissionIssue(domesticDNS) != nil, "upstream domestic DNS must block without local TUN")
var missingDNS = up; missingDNS.dnsResolverChecked = false
ok(!missingDNS.exitReady && StrictSessionPolicy.admissionIssue(missingDNS) != nil, "upstream DNS evidence required")
var switchedUpstream = up; switchedUpstream.egressCandidateIP = "5.34.2.136"
ok(StrictSessionPolicy.runningIssue(switchedUpstream, admitted: upstreamID) != nil, "upstream exact exit change ends session")
var noProxy = ready(); noProxy.sysProxy = false; noProxy.tunUp = false
ok(!noProxy.shouldProbeNetwork && !noProxy.exitReady, "ordinary direct path must not start network probes")
// VM 固定链路：纯 TUN、规则模式、主动拒绝 UDP，均以 root 核验为前提。
var vm = ready(); vm.vmManaged = true; vm.sysProxy = false; vm.stunChecked = false
vm.vmNetwork = VMNetworkEvidence(checked: true, protected: true, pfVerified: true,
    udpBlocked: true, identity: String(repeating: "a", count:64),
    policyHash: String(repeating: "b", count:64), at: Date().timeIntervalSince1970)
vm.session = vm.vmNetwork.session
ok(StrictSessionPolicy.admissionIssue(vm) == nil, "verified VM TUN/rule/UDP reject should admit without system proxy")
var vmGeoUnknown=vm; vmGeoUnknown.dnsResolverChecked=false; vmGeoUnknown.dnsResolverCountry=""
ok(StrictSessionPolicy.admissionIssue(vmGeoUnknown) == nil, "VM fixed path and fake DNS do not depend on a geolocation service")
var vmDNSUnknown=vm; vmDNSUnknown.dnsChecked=false
ok(StrictSessionPolicy.admissionIssue(vmDNSUnknown) != nil, "VM DNS query itself must be verified")
var vmBad=vm; vmBad.vmNetwork.pfVerified=false
ok(StrictSessionPolicy.admissionIssue(vmBad) != nil, "unverified VM firewall blocks admission")
vmBad=vm; vmBad.vmNetwork.at=Date().timeIntervalSince1970-30
ok(!vmBad.shouldProbeNetwork && StrictSessionPolicy.admissionIssue(vmBad) != nil, "stale root evidence blocks probes and admission")
vmBad=vm; vmBad.vmNetwork.udpBlocked=false
ok(StrictSessionPolicy.admissionIssue(vmBad) != nil, "UDP timeout alone never admits")
vmBad=vm; vmBad.stunAll=["203.0.113.7"]
ok(StrictSessionPolicy.admissionIssue(vmBad) != nil, "STUN response contradicts VM UDP reject policy")
// 已准入 VM 的短暂故障保留绑定；真实保护失效不能进入宽限期。
let vmBinding = StrictSessionPolicy.identity(vm)
var recovery = RuntimeRecovery()
var flaky = vm; flaky.claudeRunning = true; flaky.domainState = "off"; flaky.egressCandidateIP = ""
var decision = recovery.evaluate(flaky, admitted: vmBinding, now: 100)
ok(decision.stop == nil && !decision.notice.isEmpty, "single timeout retries")
flaky.strictNotice = decision.notice
ok(flaky.verdict == .warn, "retry must warn, never kill or show safe")
ok(recovery.evaluate(flaky, admitted: vmBinding, now: 219).stop == nil, "within grace")
ok(recovery.evaluate(flaky, admitted: vmBinding, now: 220).stop != nil, "continuous failure expires")
_ = recovery.evaluate(flaky, admitted: vmBinding, now: 300)
ok(recovery.evaluate(vm, admitted: vmBinding, now: 310).stop == nil && recovery.since == nil, "recovery resets clock")
var slow = vm; slow.at = Date(timeIntervalSinceNow: -90)
ok(recovery.evaluate(slow, admitted: vmBinding, now: 400).stop == nil && recovery.since != nil, "stale auxiliary sample keeps admission")
ok(recovery.evaluate(vm, admitted: vmBinding, now: 410).stop == nil, "next fresh sample remains admitted")
var healthyTLS = vm; healthyTLS.transportTLSFailure = true
ok(recovery.evaluate(healthyTLS, admitted: vmBinding, now: 450).stop != nil, "TLS failure cannot hide behind healthy auxiliary state")
var hardCases: [Snapshot] = []
var hard = flaky; hard.vmNetwork.pfVerified = false; hardCases.append(hard)
hard = flaky; hard.vmNetwork.at = Date().timeIntervalSince1970 - 30; hardCases.append(hard)
hard = flaky; hard.tunUp = false; hardCases.append(hard)
hard = flaky; hard.session.identity = "changed"; hardCases.append(hard)
hard = flaky; hard.egressCandidateIP = "5.34.99.136"; hardCases.append(hard)
hard = flaky; hard.domainConflict = true; hardCases.append(hard)
hard = flaky; hard.transportTLSFailure = true; hardCases.append(hard)
hard = flaky; hard.dnsChecked = true; hard.dnsFake = false; hardCases.append(hard)
hard = flaky; hard.stunAll = ["203.0.113.7"]; hardCases.append(hard)
for hard in hardCases { ok(recovery.evaluate(hard, admitted: vmBinding, now: 500).stop != nil, "real protection failure must stop immediately") }
ok(recovery.evaluate(flaky, admitted: nil, now: 600).stop != nil, "no grace for unapproved launch")
ok(StrictSessionPolicy.admissionIssue(flaky) != nil, "initial admission stays strict")
var missingDNSVM = vm; missingDNSVM.dnsChecked = false
ok(recovery.evaluate(missingDNSVM, admitted: vmBinding, now: 700).stop == nil && recovery.since != nil, "missing DNS query may retry behind verified PF")
ok(recovery.evaluate(changes[0], admitted: identity, now: 710).stop != nil && recovery.since == nil, "desktop baseline failure stays hard")
// 普通 Mac 只宽限 HTTPS/边缘探测，仍依赖新鲜的系统代理、TUN、节点、DNS 和 UDP。
var desktop = ready(); desktop.vmManaged = false; desktop.claudeRunning = true
let desktopID = StrictSessionPolicy.identity(desktop)
var desktopRecovery = RuntimeRecovery()
var desktopFlaky = desktop; desktopFlaky.transportState = "warn"
var retry = desktopRecovery.evaluate(desktopFlaky, admitted: desktopID, now: 10)
ok(retry.stop == nil && !retry.notice.isEmpty, "desktop transport outage retries")
desktopFlaky.strictNotice = retry.notice
ok(desktopFlaky.verdict == .warn, "desktop retry remains warning")
ok(desktopRecovery.evaluate(desktopFlaky, admitted: desktopID, now: 129).stop == nil, "desktop within grace")
ok(desktopRecovery.evaluate(desktopFlaky, admitted: desktopID, now: 130).stop != nil, "desktop continuous outage expires")
_ = desktopRecovery.evaluate(desktopFlaky, admitted: desktopID, now: 200)
ok(desktopRecovery.evaluate(desktop, admitted: desktopID, now: 210).stop == nil && desktopRecovery.since == nil, "desktop recovery resets")
var desktopDomain = desktop; desktopDomain.domainState = "off"; desktopDomain.egressCandidateIP = ""
ok(desktopRecovery.evaluate(desktopDomain, admitted: desktopID, now: 220).stop == nil, "unknown edge IP does not replace admission")
var desktopHard: [Snapshot] = []
var d = desktopFlaky; d.tunUp = false; desktopHard.append(d)
d = desktopFlaky; d.sysProxy = false; desktopHard.append(d)
d = desktopFlaky; d.session.checked = false; desktopHard.append(d)
d = desktopFlaky; d.session.mode = "rule"; desktopHard.append(d)
d = desktopFlaky; d.session.identity = "changed"; desktopHard.append(d)
d = desktopFlaky; d.egressCandidateIP = "5.34.99.136"; desktopHard.append(d)
d = desktopFlaky; d.dnsChecked = false; desktopHard.append(d)
d = desktopFlaky; d.dnsResolverCountry = ""; desktopHard.append(d)
d = desktopFlaky; d.stunChecked = false; desktopHard.append(d)
d = desktopFlaky; d.connections.direct = 1; desktopHard.append(d)
d = desktopFlaky; d.transportTLSFailure = true; desktopHard.append(d)
d = desktopFlaky; d.domainConflict = true; desktopHard.append(d)
d = desktopFlaky; d.at = Date(timeIntervalSinceNow: -90); desktopHard.append(d)
for row in desktopHard { ok(desktopRecovery.evaluate(row, admitted: desktopID, now: 240).stop != nil, "desktop must not soften loss of protection evidence") }
ok(desktopRecovery.evaluate(desktopFlaky, admitted: nil, now: 250).stop != nil, "desktop unapproved launch gets no grace")
ok(StrictSessionPolicy.admissionIssue(desktopFlaky) != nil, "desktop preflight stays strict")
let direct: [String: Any] = ["GLOBAL": ["type": "Selector", "now": "DIRECT"], "DIRECT": ["type": "Direct"]]
ok(SessionController.selection(direct) == nil, "global DIRECT rejected")
let proxies: [String: Any] = ["GLOBAL": ["type": "Selector", "now": "Auto", "all": ["Auto"]],
                            "Auto": ["type": "URLTest", "now": "NodeA", "all": ["NodeA", "NodeB"]],
                            "NodeA": ["type": "Shadowsocks"], "NodeB": ["type": "Shadowsocks"]]
ok(SessionController.selection(proxies)?["__terminal"] == "NodeA", "actual auto choice is resolved")
var switched = proxies; switched["Auto"] = ["type": "URLTest", "now": "NodeB", "all": ["NodeA", "NodeB"]]
ok(SessionController.selection(switched) != SessionController.selection(proxies), "auto failover identity changes")
var unusedChange = proxies
unusedChange["Unused"] = ["type": "URLTest", "now": "NodeB", "all": ["NodeA", "NodeB"]]
ok(SessionController.selection(unusedChange) == SessionController.selection(proxies), "unused group change must not end the active session")
let unknown: [String: Any] = ["GLOBAL": ["type": "LoadBalance", "all": ["NodeA"]]]
ok(SessionController.selection(unknown) == nil, "unresolved balancing rejected")
let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
defer { try? FileManager.default.removeItem(at: dir) }
let root = dir.appendingPathComponent("Library/Application Support/com.follow.clash")
try! FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
let file = root.appendingPathComponent("config.yaml")
func write(_ controller: String) { try! "external-controller: \"\(controller)\"\nsecret: \"test-local-only\"\n".write(to: file, atomically: true, encoding: .utf8) }
write("127.0.0.1:9090")
var apiCalls = 0
let fetch: (URL, String, String) -> [String: Any]? = { url, path, secret in
    apiCalls += 1
    ok(url.host == "127.0.0.1" && secret == "test-local-only", "credential stays local")
    return path == "configs" ? ["mode": "global", "tun": ["enable": true]] : ["proxies": proxies]
}
let result = SessionController.read(commands: "flclash", home: dir, fetch: fetch, proxyDescription: { "local-proxy" })
ok(result.checked && !result.identity.isEmpty && result.mode == "global", "loopback controller evidence")
write("outside.invalid:9090"); apiCalls = 0
let remote = SessionController.read(commands: "flclash", home: dir, fetch: fetch, proxyDescription: { "local-proxy" })
ok(!remote.checked && apiCalls == 0, "remote API must never receive secret")
write("127.0.0.1:9090")
let failed = SessionController.read(commands: "flclash", home: dir, fetch: { _,_,_ in nil }, proxyDescription: { "local" })
ok(!failed.checked, "failed API stays unconfirmed")
print("strict session admission, exact exit, node identity, and local-only controller checks passed")
'''
class StrictSessionTests(unittest.TestCase):
    def test_actual_swift_policy(self):
        with tempfile.TemporaryDirectory() as d:
            main = Path(d)/'main.swift'; main.write_text(HARNESS)
            binary = Path(d)/'test'
            result = subprocess.run(['swiftc', str(ROOT/'shield/Probe.swift'), str(main), '-o', str(binary)], capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
if __name__ == '__main__': unittest.main(verbosity=2)
