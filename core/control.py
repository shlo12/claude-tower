"""本机控制通道向独立哨兵发送有限指令；不执行命令行，不保存网络身份。"""
from __future__ import annotations
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from . import shield, compat

LOCK = threading.Lock()
ACTIONS = frozenset(('session-start', 'session-end', 'watch', 'strict', 'pause', 'resume', 'now', 'login', 'quit', 'open-tools', 'back-panel'))


MAINTENANCE_PATHS = frozenset(("/api/privacy", "/api/ipv6", "/api/proxyfix", "/api/region",
    "/api/align", "/api/location", "/api/shellproxy", "/api/shellenv", "/api/sessionapi",
    "/api/timezone", "/api/clean", "/api/backups/restore", "/api/uninstall", "/api/profiles", "/api/netcfg"))


def begin_maintenance():
    if sys.platform != 'darwin':
        return None
    import fcntl
    shield.STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(shield.STATE_DIR / 'shield-maintenance.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if maintenance_blocked():
            raise RuntimeError('请先结束戒严会话，再修复设置')
        return fd
    except BaseException:
        os.close(fd)
        raise


def status() -> dict:
    data = shield.read()
    alive = sys.platform == 'darwin' and shield.running()
    live = shield.live()
    fresh = alive and live['available'] and live['age'] is not None and live['age'] <= 45
    paused = shield._int(data.get('pausedUntil')) > time.time()
    enabled = bool(data.get('enabled', True))
    level = 2 if data.get('level') in (2, 3) else 1
    state = live['sessionState'] if fresh else 'unknown'
    if alive and (paused or not enabled):
        state = 'paused' if paused else 'off'
    elif fresh and level == 1:
        state = 'watch'
    return {'supported': sys.platform == 'darwin', 'running': alive, 'fresh': fresh,
            'enabled': enabled, 'paused': paused, 'level': level, 'state': state,
            'login': shield.launch_agent_state(),
            'message': live['sessionMessage'] if fresh else '尚未收到哨兵的新鲜巡检结果，请等待或打开菜单栏检查',
            'live': live, 'hits': [{'at': x.get('ts', x.get('at')), 'kind': str(x.get('kind', ''))[:32],
                                  'note': str(x.get('note', ''))[:400]}
                                 for x in (data.get('hits') if isinstance(data.get('hits'), list) else [])[-30:] if isinstance(x, dict)]}


def maintenance_blocked() -> bool:
    data = shield.read()
    # 戒严无法确认会话状态时也不允许维修；先由哨兵结束使用或切到瞭望。
    if not (sys.platform == 'darwin' and shield.running() and data.get('enabled', True)
            and data.get('level') in (2, 3)
            and not shield._int(data.get('pausedUntil')) > time.time()):
        return False
    live = data.get('live') if isinstance(data.get('live'), dict) else {}
    return (not status()['fresh'] or live.get('sessionState') in ('active', 'checking', 'ending')
            or bool(compat.claude_processes()))


def send(action: str) -> dict:
    if not isinstance(action, str) or action not in ACTIONS:
        raise ValueError('未知哨兵操作')
    if sys.platform != 'darwin' or not shield.running():
        raise RuntimeError('哨兵未运行；请从完整 macOS 应用打开主窗口')
    if not LOCK.acquire(blocking=False):
        raise RuntimeError('另一项哨兵操作正在处理中')
    request = shield.STATE_DIR / 'shield-command.json'
    reply = shield.STATE_DIR / 'shield-command-result.json'
    temp = None
    command_fd = None
    ident = None
    try:
        shield.STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(shield.STATE_DIR, 0o700)
        import fcntl
        command_fd = os.open(shield.STATE_DIR / 'shield-command.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(command_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if request.exists():
            # 不覆盖其他窗口/进程的有效指令。
            if time.time() - request.stat().st_mtime < 15:
                raise RuntimeError('哨兵尚未处理上一项操作')
            request.unlink()
        ident = str(uuid.uuid4())
        fd, temp = tempfile.mkstemp(prefix='.command-', dir=shield.STATE_DIR)
        with os.fdopen(fd, 'w') as f:
            json.dump({'id': ident, 'at': time.time(), 'action': action}, f)
        os.replace(temp, request)
        temp = None
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            try:
                result = json.loads(reply.read_text())
                if result.get('id') == ident:
                    if not result.get('ok'):
                        raise RuntimeError('哨兵拒绝了这项操作')
                    return {'ok': True, 'accepted': True, 'message': '哨兵已接收；实际结果以哨兵面板状态为准'}
            except (OSError, ValueError):
                pass
            time.sleep(.1)
        raise RuntimeError('哨兵未确认操作；请检查菜单栏，勿重复启动 Claude')
    finally:
        # 超时撤销尚未被消费的本次请求，避免稍后意外启动。
        if ident:
            try:
                if json.loads(request.read_text()).get('id') == ident:
                    request.unlink()
            except (OSError, ValueError, AttributeError):
                pass
        if command_fd is not None:
            os.close(command_fd)
        if temp:
            try: os.unlink(temp)
            except OSError: pass
        LOCK.release()
