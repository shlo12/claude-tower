"""按用户确认给 FlClash 增加本机只读监测入口；不自动更改代理模式或节点。
控制接口本身有写能力，所以仅监听回环地址并启用随机密钥；工具只发 GET。
恢复记录不含密钥或节点配置，卸载前先撤销本工具创建的入口。
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import secrets
import socket
import tempfile
from pathlib import Path
from . import compat, history, proxyfix

STATE = Path.home() / '.ccclean/session-api.json'
_DISCARDED = '接口已被其他操作改回，只清理了本工具的记录，未改动 FlClash 设置'


def _state():
    try:
        data = json.loads(STATE.read_text())
    except FileNotFoundError:
        return None
    if not isinstance(data, dict) or data.get('version') != 1:
        raise ValueError('本机监测接口恢复记录无效')
    return data


def _save(data):
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.session-api-', dir=STATE.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
        os.replace(name, STATE)
    finally:
        if os.path.exists(name): os.unlink(name)


def status():
    saved = _state()
    cfg, error = proxyfix._flclash_settings() if compat.IS_MAC else (None, '仅支持 macOS FlClash 的自动设置')
    patch = (cfg or {}).get('patchClashConfig')
    patch = patch if isinstance(patch, dict) else {}
    existing = bool(patch.get('external-controller'))
    return {'supported': compat.IS_MAC and isinstance((cfg or {}).get('patchClashConfig'), dict),
            'applied': bool(saved), 'canUndo': bool(saved),
            'canApply': not saved and not existing and not error and isinstance((cfg or {}).get('patchClashConfig'), dict),
            'message': error or ('本工具已配置本机监测接口，可恢复' if saved else
                                '已有控制接口，请在哨兵中检查；工具不会覆盖' if existing else
                                '可为 FlClash 配置本机接口；将重启客户端并短暂断网，不更改节点或模式')}


def apply(action):
    if not compat.IS_MAC: raise ValueError('仅支持 macOS')
    if action not in ('apply', 'undo'): raise ValueError('未知操作')
    if compat.claude_processes(): raise ValueError('请先退出 Claude 桌面端和 CLI，再修改本机监测接口')
    with proxyfix.LOCK:
        if STATE.is_symlink() or STATE.parent.is_symlink(): raise ValueError('恢复记录路径不能是符号链接')
        saved = _state()
        if action == 'apply' and saved: raise ValueError('已有本工具记录，请先恢复')
        if action == 'undo' and not saved: raise ValueError('没有可恢复的监测接口记录')
        if action == 'undo':
            # 先看一眼再决定要不要折腾客户端：退出再启动会断网几秒，而「接口
            # 早就不在了」这种最常见的情况根本不需要动 FlClash。
            pre, pre_error = proxyfix._flclash_settings()
            pre_patch = (pre or {}).get('patchClashConfig')
            if (not pre_error and isinstance(pre_patch, dict)
                    and pre_patch.get('external-controller') != saved.get('endpoint')):
                STATE.unlink()
                history.log('sessionapi.undo', ok=True)
                return {'ok': True, 'message': _DISCARDED}
        was_running = proxyfix._proc_alive(proxyfix.FLCLASH_PROC)
        if not proxyfix._quit(): raise RuntimeError('FlClash 未退出，设置未修改')
        old = None
        try:
            cfg, error = proxyfix._flclash_settings()
            if error: raise ValueError(error)
            old = copy.deepcopy(cfg)
            patch = cfg.get('patchClashConfig')
            if not isinstance(patch, dict): raise ValueError('未找到 FlClash 扩展配置')
            if action == 'apply':
                if patch.get('external-controller') or patch.get('external-controller-unix'):
                    raise ValueError('已有控制接口，未覆盖')
                # 端口占用变化会使客户端启动失败；准入会保持拒绝，不会回落放行。
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                endpoint = f'127.0.0.1:{port}'
                token = secrets.token_urlsafe(32)
                record = {'version': 1, 'endpoint': endpoint,
                          'before': {k: patch.get(k) for k in ('external-controller', 'secret') if k in patch and not patch[k]},
                          'present': [k for k in ('external-controller', 'secret') if k in patch],
                          'secretCreated': not bool(patch.get('secret'))}
                if record['secretCreated']: patch['secret'] = token
                record['secretHash'] = hashlib.sha256(str(patch['secret']).encode()).hexdigest()
                patch['external-controller'] = endpoint
                _save(record)
            else:
                if patch.get('external-controller') != saved.get('endpoint'):
                    # 我们写进去的那条已经不在了：用户在客户端界面里改回去了、
                    # 换了客户端，或者上次写到一半就崩了。这时候没有可恢复的
                    # 东西——继续报「接口已被其他操作修改」会让面板永远显示
                    # 「可恢复」，点下去永远失败，而用户没有任何出口能摆脱它。
                    # 清掉记录、不动 FlClash，是唯一说得通的处理。
                    STATE.unlink()
                    history.log('sessionapi.undo', ok=True)
                    return {'ok': True, 'message': _DISCARDED}
                secret_ours = hashlib.sha256(
                    str(patch.get('secret', '')).encode()).hexdigest() == saved.get('secretHash')
                for key in ('external-controller', 'secret'):
                    if key == 'secret' and (not saved.get('secretCreated') or not secret_ours):
                        # 密钥被别处换过了：那不是我们设的那个，不能替用户删。
                        continue
                    if key in saved.get('present', []): patch[key] = saved.get('before', {}).get(key, '')
                    else: patch.pop(key, None)
            if not proxyfix._write_settings(cfg): raise RuntimeError('写入本机接口失败')
            back, error = proxyfix._flclash_settings()
            if error or back.get('patchClashConfig') != patch: raise RuntimeError('写入后回读不一致')
            if action == 'undo': STATE.unlink()
        except Exception:
            # 即使 defaults 部分写入后报错，也尽力恢复；回滚失败时保留恢复记录。
            restored = old is not None and proxyfix._write_settings(old)
            if restored and action == 'apply': STATE.unlink(missing_ok=True)
            history.log('sessionapi.' + action, ok=False)
            raise
        finally:
            if was_running: proxyfix._launch()
        history.log('sessionapi.' + action, ok=True)
        return {'ok': True, 'message': '已配置本机监测接口，请确认 TUN、系统代理与全局模式开启，再到哨兵检查并启动' if action == 'apply' else '已恢复本工具创建接口前的设置'}
