"""macOS 持久隐私设置：用户配置 + hosts 管理块，无常驻进程。"""
import json
import os
import shlex
import subprocess
import threading
import time
from pathlib import Path

from . import compat, telemetry

CONFIG = Path.home() / ".claude/settings.json"
STATE = Path.home() / ".ccclean/privacy-state.json"
HOSTS = Path("/private/etc/hosts")
BEGIN = "# BEGIN CCLEAN TELEMETRY PRIVACY V1"
END = "# END CCLEAN TELEMETRY PRIVACY V1"
HOST_NAMES = telemetry.DATADOG_HOSTS + telemetry.LEGACY_HOSTS
KEYS = tuple(key for _, _, key in telemetry.CHANNELS)
LOCK = threading.Lock()

# 只移除自己的完整块；遇到嵌套/残缺标记拒绝修改，保留其他工具的规则。
STRIP_AWK = '''
$0 == "# BEGIN CCLEAN TELEMETRY PRIVACY V1" { if (inside || seen) bad=1; inside=1; seen=1; next }
$0 == "# END CCLEAN TELEMETRY PRIVACY V1" { if (!inside) bad=1; inside=0; next }
!inside { print }
END { if (inside || bad) exit 42 }
'''


def block():
    return "\n".join([BEGIN, *[f"{ip} {host}" for host in HOST_NAMES
                               for ip in ("0.0.0.0", "::1")], END]) + "\n"


def _config():
    try:
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
        raise ValueError("settings.json 根节点和 env 必须为对象，未修改")
    return data


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # 独占临时文件，避免覆盖同名文件或跟随符号链接。
    import tempfile
    fd, name = tempfile.mkstemp(prefix=".privacy-", dir=str(path.parent))
    try:
        os.fchmod(fd, path.stat().st_mode & 0o777 if path.exists() else 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _hosts_script(enable):
    # 高权限操作只执行此固定脚本；不接收前端的路径、主机名或 shell 文本。
    append = "printf '%s' " + shlex.quote(block()) + ' >> "$out"' if enable else ":"
    return '''set -eu
hosts=/private/etc/hosts
[ -f "$hosts" ] && [ ! -L "$hosts" ] || exit 41
snapshot=$(/usr/bin/mktemp /private/etc/.ccclean-original.XXXXXX)
out=$(/usr/bin/mktemp /private/etc/.ccclean-hosts.XXXXXX)
trap '/bin/rm -f "$snapshot" "$out"' EXIT
/bin/cp -p "$hosts" "$snapshot"
/usr/bin/awk ''' + shlex.quote(STRIP_AWK) + ''' "$snapshot" > "$out"
''' + append + '''
/usr/bin/cmp -s "$snapshot" "$hosts" || exit 43
if [ ! -e /private/etc/hosts.ccclean-before-privacy ]; then
  /bin/cp -p "$snapshot" /private/etc/hosts.ccclean-before-privacy
fi
/usr/sbin/chown root:wheel "$out"
/bin/chmod 644 "$out"
/bin/mv -f "$out" "$hosts"
/usr/bin/dscacheutil -flushcache || true
/usr/bin/killall -HUP mDNSResponder || true
'''


def _authorize_hosts(enable):
    # 密码由 macOS 原生授权窗口处理，应用不收集密码。
    script = "do shell script " + json.dumps(_hosts_script(enable), ensure_ascii=False) + " with administrator privileges"
    result = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError("系统未完成 hosts 修改（可能取消授权、规则标记损坏或文件被其他程序改动）。可重试或恢复。")


def status():
    try:
        data = _config()
        config_error = ""
    except (OSError, ValueError) as exc:
        data, config_error = {}, str(exc)
    try:
        hosts = HOSTS.read_text(encoding="utf-8")
        managed = hosts.count(BEGIN) == 1 and hosts.count(END) == 1 and BEGIN in hosts and END in hosts
        exact = managed and block() in hosts
    except OSError:
        managed = exact = False
    env = data.get("env", {})
    return {"supported": compat.IS_MAC, "configPath": str(CONFIG),
            "settingsConfigured": all(env.get(k) == "1" for k in KEYS) and not config_error,
            "configError": config_error, "hostsConfigured": exact, "hostsManaged": managed,
            "restoreAvailable": STATE.exists() or managed, "domains": list(HOST_NAMES),
            "scope": "默认 Claude Code 用户配置 + 全系统 hosts；自定义配置目录、项目/组织覆盖需另查。",
            "limits": "退出本应用后设置保留。需重启 Claude；hosts 仅覆盖列出的主机，不是通配或进程防火墙，"
                      "可能被自带 DNS、代理远端解析绕过；不验证实际流量。规则也影响其他应用对同名主机的访问。"}


def apply(enable):
    if not compat.IS_MAC:
        raise ValueError("此持久设置入口仅支持 macOS")
    with LOCK:
        # 拒绝跟随用户配置或状态的符号链接，避免写入意外位置。
        if CONFIG.is_symlink() or CONFIG.parent.is_symlink() or STATE.is_symlink() or STATE.parent.is_symlink():
            raise ValueError("配置或状态路径是符号链接，未修改")
        data = _config()  # 在请求管理员权限之前检查 JSON，失败不碰 hosts。
        existed = CONFIG.exists()
        before = CONFIG.read_bytes() if existed else None
        saved = json.loads(STATE.read_text()) if STATE.exists() else None
        if saved is not None and (not isinstance(saved, dict)
                or not isinstance(saved.get("original"), dict)
                or set(saved["original"]) != set(KEYS)
                or any(not isinstance(v, dict) or not isinstance(v.get("present"), bool)
                       or "value" not in v for v in saved["original"].values())
                or not isinstance(saved.get("existed"), bool)
                or not isinstance(saved.get("envExisted"), bool)):
            raise ValueError("恢复记录损坏，未修改设置或 hosts；请先检查本地恢复记录")
        if saved and saved.get("configPath") != str(CONFIG):
            raise ValueError("原备份的配置位置不同，请先恢复原设置")
        if enable and saved is None:
            env = data.get("env", {})
            saved = {"configPath": str(CONFIG), "existed": existed, "envExisted": "env" in data,
                     "original": {k: {"present": k in env, "value": env.get(k)} for k in KEYS},
                     "createdAt": time.time()}
            # 提前持久化恢复信息，授权取消或后续写入失败也有恢复依据。
            _write(STATE, saved)
        _authorize_hosts(enable)
        # 授权过程中用户可能编辑了配置；不覆盖新修改，hosts 状态保留并提供恢复。
        if (CONFIG.read_bytes() if CONFIG.exists() else None) != before:
            raise RuntimeError("hosts 已处理，但配置同时被其他程序改动；未覆盖配置，请刷新状态后重试或恢复")
        if enable:
            data.setdefault("env", {}).update({k: "1" for k in KEYS})
            _write(CONFIG, data)
        elif saved:
            env = data.get("env", {})
            for key, old in saved["original"].items():
                if env.get(key) != "1":  # 保留用户后来作出的不同修改。
                    continue
                if old["present"]:
                    env[key] = old["value"]
                else:
                    env.pop(key, None)
            if not env and not saved["envExisted"]:
                data.pop("env", None)
            if not data and not saved["existed"]:
                CONFIG.unlink(missing_ok=True)
            elif CONFIG.exists() or data:
                _write(CONFIG, data)
            STATE.unlink()
        return status()
