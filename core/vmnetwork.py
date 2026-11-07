"""VM 构建专用：读取 root 网络保护任务的实时证明，不从用户偏好推定安全。"""
import json
from pathlib import Path
import stat
import re
import time

MARKER = Path(__file__).resolve().parent.parent / 'vm-profile.json'
STATUS = Path('/var/run/ccclean-vm-network.json')


def enabled():
    return MARKER.is_file()


def read():
    out = {'managed': enabled(), 'checked': False, 'protected': False,
           'pfVerified': False, 'udpBlocked': False,
           'message': '未配置或未取得虚拟机网络保护状态'}
    if not out['managed']:
        return out
    try:
        st = STATUS.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                or st.st_size > 16384):
            return out
        raw = json.loads(STATUS.read_text())
        at = raw.get('at')
        if (raw.get('version') != 1 or isinstance(at, bool) or not isinstance(at, (float, int))
                or not -2 <= time.time() - at <= 25):
            return out
        for key in ('protected', 'pfVerified', 'udpBlocked'):
            if not isinstance(raw.get(key), bool):
                return out
        if raw['protected'] and any(not re.fullmatch(r'[0-9a-f]{64}', str(raw.get(k, ''))) for k in ('identity', 'policyHash')):
            return out
        out.update(checked=True, **{k: raw[k] for k in ('protected', 'pfVerified', 'udpBlocked')})
        out['message'] = ('固定代理与断网保护已核验' if out['protected'] and out['pfVerified']
                          else '固定代理不可用或策略变化，禁止启动 Claude')
    except (OSError, ValueError, TypeError):
        pass
    return out
