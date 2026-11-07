#!/usr/bin/env python3
"""VM 专用 pf 白名单与只读状态；由 root LaunchDaemon 执行，不依赖应用界面。

策略由安装器从已审核的 mihomo 配置及回环 API 建立。配置或节点链变化时
封住物理出口；不切节点，不提供 DIRECT 备用路径，不记录 API 密钥。
"""
import ast
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request

PROFILE = Path('/usr/local/etc/ccclean-vm-network.json')
STATUS = Path('/var/run/ccclean-vm-network.json')
CONFIG = Path('/usr/local/etc/mihomo/config.yaml')
ANCHOR = 'com.vmproxy'


def run(args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=6,
                       env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    if r.returncode:
        raise RuntimeError('network command failed')
    return r.stdout


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def scalar(text, key):
    for line in text.splitlines():
        if line.startswith(key + ':'):
            value = line.split(':', 1)[1].strip()
            if value.startswith(('"', "'")):
                try:
                    return str(ast.literal_eval(value))
                except (ValueError, SyntaxError):
                    raise ValueError('invalid quoted configuration field') from None
            return value.split(' #', 1)[0].strip()
    return ''


def api(text, path):
    address = scalar(text, 'external-controller')
    if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', address):
        raise ValueError('controller must bind to IPv4 loopback')
    secret = scalar(text, 'secret')
    req = urllib.request.Request('http://' + address + '/' + path)
    if secret:
        req.add_header('Authorization', 'Bearer ' + secret)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=3) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('controller response too large')
    return json.loads(raw)


def selection(proxies, root='PROXY'):
    chain = []
    current = root
    for _ in range(32):
        if current.upper() in ('DIRECT', 'REJECT', 'PASS', 'COMPATIBLE', 'REJECT-DROP'):
            raise ValueError('non-proxy selection')
        if any(row[0] == current for row in chain):
            raise ValueError('selection cycle')
        row = proxies.get(current) or {}
        kind = str(row.get('type', ''))
        if not kind:
            raise ValueError('unknown node')
        chain.append([current, kind])
        if row.get('now'):
            members = row.get('all')
            if not isinstance(members, list) or members != [row['now']]:
                raise ValueError('each selected group must contain exactly its approved node; alternatives are not allowed')
            current = row['now']
        elif 'all' not in row and kind.lower() not in (
                'direct', 'reject', 'selector', 'fallback', 'urltest', 'loadbalance'):
            return digest(chain)
        else:
            raise ValueError('unresolved selection')
    raise ValueError('selection too deep')


def rules_valid(rules):
    # 使用实际内核规则，不把配置文件里的一行文字当成已经生效。
    rejected_udp = False
    for row in rules:
        kind = str(row.get('type', '')).lower()
        payload = str(row.get('payload', '')).lower()
        target = str(row.get('proxy', '')).upper()
        if kind == 'network' and payload == 'udp' and target in ('REJECT', 'REJECT-DROP'):
            rejected_udp = True
        if target not in ('PROXY', 'DIRECT', 'REJECT', 'REJECT-DROP'):
            return False
        if kind == 'match':
            return rejected_udp and target == 'PROXY'
        # 仅允许必要的本地直连例外，拒绝任何其他公网 DIRECT 分流。
        if target == 'DIRECT':
            try:
                net = ipaddress.ip_network(payload, strict=False)
            except ValueError:
                return False
            if not any(net.subnet_of(ipaddress.ip_network(n)) for n in (
                    ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16')
                    if net.version == 4 else ('::1/128', 'fe80::/10', 'fc00::/7'))):
                return False
    return False


def rules_identity(rules):
    # 内核附带命中计数和时间戳，不能把这些变化当成规则被改写。
    return digest([{k: row.get(k, '') for k in ('type', 'payload', 'proxy')} |
                   {'disabled': (row.get('extra') or {}).get('disabled', False)} for row in rules])


def runtime(text):
    config = api(text, 'configs')
    rules = api(text, 'rules').get('rules') or []
    proxies = api(text, 'proxies').get('proxies') or {}
    if config.get('mode') != 'rule' or (config.get('tun') or {}).get('enable') is not True:
        raise ValueError('rule mode and TUN required')
    if not rules_valid(rules):
        raise ValueError('UDP reject and final PROXY rules required')
    chains = {'PROXY': selection(proxies)}
    if 'SS-AUTO' in proxies:
        chains['SS-AUTO'] = selection(proxies, 'SS-AUTO')
    return {'mode': 'rule', 'identity': digest(chains), 'rulesHash': rules_identity(rules),
            'udpBlocked': True}


def valid_profile(p):
    if p.get('version') != 1 or not re.fullmatch(r'en[0-9]+', p.get('interface', '')):
        raise ValueError('invalid physical interface')
    if not re.fullmatch(r'utun[0-9]+', p.get('tunInterface', '')):
        raise ValueError('invalid TUN interface')
    port = p.get('port')
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('explicit upstream TCP port required')
    ips = p.get('allowedIPs')
    if not isinstance(ips, list) or not 1 <= len(ips) <= 8:
        raise ValueError('explicit proxy IP whitelist required')
    for ip in ips:
        if not isinstance(ip, str) or not ipaddress.IPv4Address(ip).is_global:
            raise ValueError('only explicit public IPv4 proxy addresses are supported')
    for key in ('configHash', 'identity', 'rulesHash'):
        if not re.fullmatch(r'[0-9a-f]{64}', p.get(key, '')):
            raise ValueError('invalid policy fingerprint')
    if p.get('dhcpServer'):
        server = ipaddress.IPv4Address(p['dhcpServer'])
        if not server.is_private or server.is_loopback or server.is_unspecified:
            raise ValueError('DHCP server must be a private IPv4 address')
    return p


def pf_rules(profile, sealed=False):
    p = valid_profile(profile)
    lines = ['pass quick on lo0 all no state',
             'pass quick on ' + p['tunInterface'] + ' all no state']
    if not sealed:
        lines.append('pass out quick on ' + p['interface'] +
                     ' inet proto tcp to { ' + ', '.join(p['allowedIPs']) + ' } port ' + str(p['port']))
    dhcp = ['255.255.255.255'] + ([p['dhcpServer']] if p.get('dhcpServer') else [])
    lines += ['pass out quick on ' + p['interface'] +
              ' inet proto udp from any port 68 to { ' + ', '.join(dhcp) + ' } port 67',
              'block drop out quick all']
    return '\n'.join(lines) + '\n'


def normalize_pf(text):
    # pfctl 的计数/警告不应混入规则身份；规则顺序和动作保持严格比对。
    return [' '.join(line.split()) for line in text.splitlines() if line.strip()]


def atomic(path, data, mode=0o644):
    fd, temporary = tempfile.mkstemp(prefix='.ccclean-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, sort_keys=True)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def secure_file(path):
    st = path.lstat()
    if not path.is_file() or path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError('policy and configuration must be root-owned and not writable by others')
    return path.read_text()


def audit():
    if os.geteuid() != 0:
        raise PermissionError('root required')
    p = valid_profile(json.loads(secure_file(PROFILE)))
    healthy = False
    message = 'Network policy not verified'
    evidence = {}
    try:
        text = secure_file(CONFIG)
        if hashlib.sha256(text.encode()).hexdigest() != p['configHash']:
            raise ValueError('approved proxy configuration changed')
        evidence = runtime(text)
        if any(evidence[k] != p[k] for k in ('identity', 'rulesHash')):
            raise ValueError('approved node chain or rules changed')
        route = run(['/sbin/route', '-n', 'get', '-inet', '1.1.1.1'])
        match = re.search(r'interface:\s*(\S+)', route)
        if not match or match[1] != p['tunInterface']:
            raise ValueError('approved TUN route unavailable')
        healthy = True
        message = 'Approved proxy chain and firewall verified'
    except Exception:
        # 不将异常原文（可能包含代理配置或认证信息）写进状态或日志。
        message = 'Approved proxy chain unavailable or changed; physical egress sealed'

    expected = pf_rules(p, sealed=not healthy)
    with tempfile.TemporaryDirectory(prefix='ccclean-pf-') as directory:
        candidate = Path(directory) / 'rules'
        candidate.write_text(expected)
        # 让 pfctl 自己给出标准格式，随后与真正加载的规则精确比对。
        canonical = run(['/sbin/pfctl', '-o', 'none', '-n', '-v', '-f', str(candidate)])
        active = run(['/sbin/pfctl', '-a', ANCHOR, '-sr'])
        info = run(['/sbin/pfctl', '-s', 'info'])
        main = run(['/sbin/pfctl', '-sr'])
        interfaces = run(['/sbin/pfctl', '-s', 'Interfaces', '-v'])
        skipped = [line.split()[0] for line in interfaces.splitlines() if '(skip)' in line]
        if not interfaces.strip() or any(name != 'lo0' for name in skipped):
            raise RuntimeError('physical interface firewall bypass detected')
        first = next((x.strip() for x in main.splitlines()
                      if x.strip().startswith(('anchor ', 'pass ', 'block ', 'match '))), '')
        if not first.startswith('anchor "' + ANCHOR + '"'):
            raise RuntimeError('primary firewall anchor missing or not first')
        enabled = 'Status: Enabled' in info
        changed = normalize_pf(canonical) != normalize_pf(active)
        if changed:
            run(['/sbin/pfctl', '-o', 'none', '-a', ANCHOR, '-f', str(candidate)])
        if not enabled:
            run(['/sbin/pfctl', '-e'])
        if changed or not enabled:
            # 已建立的旧直连状态也必须清除；只影响当前客机。
            run(['/sbin/pfctl', '-F', 'states'])
        loaded = run(['/sbin/pfctl', '-a', ANCHOR, '-sr'])
        if normalize_pf(canonical) != normalize_pf(loaded):
            raise RuntimeError('firewall verification failed')
    result = {'version': 1, 'at': time.time(), 'protected': healthy,
              'pfVerified': True, 'udpBlocked': healthy and evidence.get('udpBlocked') is True,
              'mode': evidence.get('mode', ''), 'identity': p['identity'] if healthy else '',
              'policyHash': digest(p), 'interface': p['interface'],
              'tunInterface': p['tunInterface'], 'message': message}
    atomic(STATUS, result)
    return result


if __name__ == '__main__':
    # 防止维护脚本被误用于宿主机。
    try:
        is_guest = run(['/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present']).strip() == '1'
    except Exception:
        is_guest = False
    if not is_guest:
        raise SystemExit('macOS virtual machine required')
    try:
        audit()
    except Exception:
        if os.geteuid() == 0:
            # 策略损坏或核验失败时也不能沿用旧的放行状态。
            try:
                with tempfile.TemporaryDirectory(prefix='vm-emergency-') as d:
                    p = Path(d) / 'rules'
                    p.write_text('pass out quick on lo0 all\nblock drop out quick all\n')
                    run(['/sbin/pfctl', '-a', ANCHOR, '-f', str(p)])
                    if 'Status: Enabled' not in run(['/sbin/pfctl', '-s', 'info']):
                        run(['/sbin/pfctl', '-e'])
                    run(['/sbin/pfctl', '-F', 'states'])
            except Exception:
                pass
            atomic(STATUS, {'version': 1, 'at': time.time(), 'protected': False,
                            'pfVerified': False, 'udpBlocked': False,
                            'message': 'Network protection could not be verified'})
        raise SystemExit(1)
