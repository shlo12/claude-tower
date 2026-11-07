#!/usr/bin/env python3
"""仅在 macOS 客机安装网络保护。先预览，--apply 才写入。

--allow-ip 可重复指定，必须是用户批准的代理端点；不会猜测或下载节点。
不会修改 mihomo 配置、认证、节点、DNS、输入法或宿主机设置。
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import time

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('vmguard', ROOT / 'vm-network-guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def prepare(args):
    if guard.run(['/usr/sbin/sysctl', '-n', 'kern.hv_vmm_present']).strip() != '1':
        raise ValueError('This installer only supports a macOS virtual machine')
    text = guard.secure_file(guard.CONFIG)
    evidence = guard.runtime(text)
    profile = dict(version=1, interface=args.interface, tunInterface=args.tun,
                   allowedIPs=sorted(set(args.allow_ip)), port=args.port,
                   configHash=hashlib.sha256(text.encode()).hexdigest(),
                   identity=evidence['identity'], rulesHash=evidence['rulesHash'])
    try:
        profile['dhcpServer'] = guard.run(['/usr/sbin/ipconfig', 'getoption', args.interface, 'server_identifier']).strip()
    except Exception:
        profile['dhcpServer'] = ''
    return guard.valid_profile(profile)


def install(profile):
    if os.geteuid() != 0:
        raise PermissionError('Run the installer as root inside the virtual machine')
    pf_conf = Path('/etc/pf.conf')
    pf_anchor = Path('/etc/pf.anchors/com.vmproxy')
    original = guard.secure_file(pf_conf)
    lines = [x for x in original.splitlines() if not x.strip().startswith('set skip on ')
             if not (x.strip().startswith(('anchor "com.vmproxy"',
                                          'load anchor "com.vmproxy"')))]
    # anchor 必须位于过滤规则最前；pf 要求选项、scrub、NAT 在过滤规则之前。
    position = next((i for i, line in enumerate(lines)
                     if line.strip().startswith(('anchor ', 'pass ', 'block '))), len(lines))
    lines[position:position] = ['anchor "com.vmproxy" quick']
    lines += ['load anchor "com.vmproxy" from "/etc/pf.anchors/com.vmproxy"']
    candidate = 'set skip on lo0\n' + '\n'.join(lines) + '\n'
    # 先持久化封闭规则；代理运行证据明确通过后才由 guard 打开已批准端点。
    sealed = guard.pf_rules(profile, sealed=True)
    backup = Path('/var/root') / ('ccclean-vm-network-backup-' + str(time.time_ns()))
    backup.mkdir(mode=0o700)
    for path in (pf_conf, pf_anchor, guard.PROFILE):
        if path.exists():
            shutil.copyfile(path, backup / path.name)
            os.chmod(backup / path.name, 0o600)
    helper = Path('/usr/local/libexec/ccclean-vm-network-guard.py')
    helper.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    # 安装目标链不允许用户可写目录或符号链接。
    directories = (helper.parent, guard.CONFIG.parent, guard.PROFILE.parent, Path('/Library/LaunchDaemons'))
    for path in {ancestor for directory in directories for ancestor in (directory, *directory.parents)}:
        st = path.lstat()
        if path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('Installation parent must be root-owned and not writable by others')
    with tempfile.TemporaryDirectory(prefix='vm-pf-install-') as directory:
        f = Path(directory) / 'anchor'; f.write_text(sealed)
        guard.run(['/sbin/pfctl', '-n', '-f', str(f)])
        pf_anchor.write_text(sealed); os.chmod(pf_anchor, 0o600)
        f.write_text(candidate)
        try:
            guard.run(['/sbin/pfctl', '-n', '-f', str(f)])
        except Exception:
            old = backup / pf_anchor.name
            if old.exists(): shutil.copyfile(old, pf_anchor)
            raise
        pf_conf.write_text(candidate); os.chmod(pf_conf, 0o644)
        guard.PROFILE.parent.mkdir(parents=True, exist_ok=True)
        guard.atomic(guard.PROFILE, profile, 0o600)
        shutil.copyfile(ROOT / 'vm-network-guard.py', helper)
        os.chown(helper, 0, 0); os.chmod(helper, 0o700)
        job = Path('/Library/LaunchDaemons/com.ccclean.vm-network.plist')
        job.write_bytes(plistlib.dumps({
            'Label': 'com.ccclean.vm-network',
            'ProgramArguments': ['/usr/bin/python3', '-I', str(helper)],
            'RunAtLoad': True, 'StartInterval': 10,
            'StandardOutPath': '/dev/null', 'StandardErrorPath': '/dev/null',
        }))
        os.chown(job, 0, 0); os.chmod(job, 0o644)
        guard.run(['/sbin/pfctl', '-f', str(pf_conf)])
        if 'Status: Enabled' not in guard.run(['/sbin/pfctl', '-s', 'info']):
            guard.run(['/sbin/pfctl', '-e'])
        guard.run(['/sbin/pfctl', '-F', 'states'])
        result = guard.audit()
        # 已有任务仅卸载本工具自身，不碰 mihomo 和原 kill-switch。
        import subprocess
        subprocess.run(['/bin/launchctl', 'bootout', 'system/com.ccclean.vm-network'],
                       capture_output=True, timeout=8)
        guard.run(['/bin/launchctl', 'bootstrap', 'system', str(job)])
    print(json.dumps({'installed': True, 'protected': result['protected'],
                      'backup': str(backup)}, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--interface', required=True)
    ap.add_argument('--tun', required=True)
    ap.add_argument('--allow-ip', action='append', required=True)
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--apply', action='store_true')
    args = ap.parse_args()
    profile = prepare(args)
    if args.apply:
        install(profile)
    else:
        print(json.dumps({'preview': True, 'interface': profile['interface'],
                          'tun': profile['tunInterface'], 'endpointCount': len(profile['allowedIPs']),
                          'rules': guard.pf_rules(profile)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
