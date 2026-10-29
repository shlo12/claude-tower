"""跨平台兼容层：macOS 与 Windows 的系统调用差异都收在这里。

约定：每个函数在自身平台上返回对应结果；拿不到的返回空值而不是抛异常。
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform == "win32"
HOME = Path.home()


def run(cmd: list, timeout: int = 6, shell: bool = False) -> str:
    """统一子进程出口：静默失败返回空串。"""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            check=False, shell=shell,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (r.stdout or "").strip()
    except Exception:
        return ""


# ---------------------------------------------------------------- 身份/主机名


def computer_name() -> str:
    if IS_MAC:
        return run(["scutil", "--get", "ComputerName"]) or socket.gethostname()
    return os.environ.get("COMPUTERNAME") or socket.gethostname()


# ---------------------------------------------------------------- 时区

# Windows 时区名 → IANA（只列跟 Claude 风控判断相关的常见档）
WIN_TZ_MAP = {
    "China Standard Time": "Asia/Shanghai",
    "Taipei Standard Time": "Asia/Taipei",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "Singapore Standard Time": "Asia/Singapore",
    "Pacific Standard Time": "America/Los_Angeles",
    "Mountain Standard Time": "America/Denver",
    "Central Standard Time": "America/Chicago",
    "Eastern Standard Time": "America/New_York",
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest",
    "Russian Standard Time": "Europe/Moscow",
    "India Standard Time": "Asia/Kolkata",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "UTC": "UTC",
    "Coordinated Universal Time": "UTC",
}


def timezone_name() -> str:
    """IANA 风格时区名（尽量），拿不到就返回原始名。"""
    if IS_MAC:
        tz = run(["readlink", "/etc/localtime"])
        if tz and "/" in tz:
            return tz.split("zoneinfo/", 1)[-1]
        out = run(["systemsetup", "-gettimezone"], 4)
        m = re.search(r"Time Zone:\s*(\S+)", out)
        return m.group(1) if m else ""
    out = run(["tzutil", "/g"], 4)
    if out:
        return WIN_TZ_MAP.get(out, out)
    return time.tzname[0] if time.tzname else ""


def set_timezone_command(tz: str) -> str:
    if IS_MAC:
        return f"sudo systemsetup -settimezone {tz}"
    # Windows 需要把 IANA 名换回 Windows 名
    rev = {v: k for k, v in WIN_TZ_MAP.items()}
    return f"tzutil /s \"{rev.get(tz, tz)}\""


IANA_TZ = re.compile(r"^[A-Za-z_]+/[A-Za-z_\-+]+$|^UTC$")


def apply_timezone(tz: str) -> tuple[bool, str]:
    """授权改系统时区。密码只出现在系统原生授权窗口，本应用不接触。"""
    if not IANA_TZ.match(tz or ""):
        return False, "时区名格式不合法"
    if IS_MAC:
        script = (f'do shell script "/usr/sbin/systemsetup -settimezone {tz}" '
                  "with administrator privileges")
        r = subprocess.run(["/usr/bin/osascript", "-e", script],
                           capture_output=True, text=True, timeout=180, check=False)
        if r.returncode:
            return False, "系统未完成修改（可能取消授权）"
        return (timezone_name() == tz), ("已生效" if timezone_name() == tz else "修改后校验未通过")
    if IS_WIN:
        rev = {v: k for k, v in WIN_TZ_MAP.items()}
        win_tz = rev.get(tz)
        if not win_tz:
            return False, f"暂不支持映射 {tz}，请用控制面板手动改"
        ps = f"Start-Process tzutil -ArgumentList '/s','\"{win_tz}\"' -Verb RunAs -Wait"
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=120, check=False,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode:
            return False, (r.stderr or "授权被取消")[:160]
        return (timezone_name() == tz), ("已生效" if timezone_name() == tz else "修改后校验未通过")
    return False, "当前平台不支持"


# ---------------------------------------------------------------- 父进程链


def ancestor_names(limit: int = 12) -> list[str]:
    """父进程链上的进程名（小写）。拿不到的平台返回 []。"""
    if IS_WIN:
        return []
    names, pid, seen = [], os.getppid(), set()
    for _ in range(limit):
        if pid in seen or pid <= 1:
            break
        seen.add(pid)
        out = run(["ps", "-p", str(pid), "-o", "ppid=,comm="], 3)
        parts = out.split(None, 1)
        if len(parts) < 2:
            break
        names.append(Path(parts[1]).name.lower())
        try:
            pid = int(parts[0])
        except ValueError:
            break
    return names


# ---------------------------------------------------------------- hosts


def hosts_path() -> Path:
    if IS_WIN:
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


# ---------------------------------------------------------------- 系统代理


def system_proxy() -> dict:
    """{enabled, server, pac} — macOS scutil / Windows 注册表。"""
    if IS_MAC:
        out = run(["scutil", "--proxy"], 5)
        schemes = (
            ("HTTPS", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
            ("HTTP", "HTTPEnable", "HTTPProxy", "HTTPPort"),
            ("SOCKS", "SOCKSEnable", "SOCKSProxy", "SOCKSPort"),
        )
        active = [(name, host, port) for name, flag, host, port in schemes
                  if re.search(rf"{flag}\s*:\s*1", out)]
        server = ""
        for name, host, port in active:
            h = re.search(rf"{host}\s*:\s*(\S+)", out)
            p = re.search(rf"{port}\s*:\s*(\d+)", out)
            if h:
                server = f"{h.group(1)}:{p.group(1) if p else '?'}"
                break
        pac = re.search(r"ProxyAutoConfigURLString\s*:\s*(\S+)", out)
        return {"enabled": bool(active), "server": server, "pac": pac.group(1) if pac else "", "raw": out,
                "schemes": [name for name, _, _ in active]}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            get = lambda n, d="": winreg.QueryValueEx(k, n)[0] if _has_val(k, n) else d
            return {
                "enabled": bool(get("ProxyEnable", 0)),
                "server": get("ProxyServer", "") or "",
                "pac": get("AutoConfigURL", "") or "",
                "raw": "",
                "schemes": ["HTTP"] if get("ProxyEnable", 0) else [],
            }
    except Exception:
        return {"enabled": False, "server": "", "pac": "", "raw": "", "schemes": []}


def _has_val(key, name) -> bool:
    import winreg
    try:
        winreg.QueryValueEx(key, name)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- DNS


def system_dns() -> list[str]:
    if IS_MAC:
        out = run(["scutil", "--dns"], 5)
        return sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*([\d.]+)", out)))
    out = run(["ipconfig", "/all"], 6)
    ips = re.findall(r"(?:IPv4 )?[Dd][Nn][Ss] [Ss]ervers?[^\n]*?:\s*([\d.]+)", out)
    ips += re.findall(r"^\s{20,}([\d.]+)\s*$", out, re.M)
    return sorted(set(ips))


# ---------------------------------------------------------------- 进程


def claude_processes() -> list[dict]:
    """正在运行的 claude 进程（CLI 与桌面端）。"""
    if IS_MAC:
        procs, seen = [], set()
        for pat in ("claude", "Claude.app/Contents/MacOS"):
            out = run(["pgrep", "-fl", pat], 4)
            for ln in out.splitlines():
                parts = ln.strip().split(None, 1)
                if len(parts) != 2:
                    continue
                try:
                    pid = int(parts[0])
                except ValueError:
                    continue
                low = parts[1].lower()
                if (Path(low).name == "claude" or "/claude.app/contents/macos/" in low) and pid not in seen:
                    seen.add(pid)
                    procs.append({"pid": pid, "name": parts[1][:90]})
        return procs
    out = run(["tasklist", "/FO", "CSV", "/NH"], 6)
    procs = []
    for ln in out.splitlines():
        m = re.match(r'"([^"]+)"\s*,\s*"(\d+)"', ln)
        if not m:
            continue
        name, pid = m.group(1), int(m.group(2))
        if name.lower() in ("claude.exe", "claude") or (name.lower().startswith("claude") and "helper" not in name.lower()):
            procs.append({"pid": pid, "name": name})
    return procs


def quit_processes(procs: list[dict]) -> int:
    """按 pid 退出；返回剩余数量。"""
    if IS_MAC:
        run(["osascript", "-e", 'tell application "Claude" to quit'], 8)
        run(["pkill", "-x", "claude"], 4)
        time.sleep(0.8)
        left = claude_processes()
        if left:
            run(["pkill", "-9", "-x", "claude"], 4)
            run(["pkill", "-9", "-f", "Claude.app/Contents/MacOS"], 4)
            time.sleep(0.5)
            left = claude_processes()
        return len(left)
    for p in procs:
        run(["taskkill", "/PID", str(p["pid"])], 4)
    time.sleep(0.8)
    left = claude_processes()
    for p in left:
        run(["taskkill", "/F", "/PID", str(p["pid"])], 4)
    return len(claude_processes())


# ---------------------------------------------------------------- 打开目标（设置面板 / 文件 / 站点）

SETTINGS_PANES_MAC = {
    "general": "x-apple.systempreferences:com.apple.settings.General",
    "datetime": "x-apple.systempreferences:com.apple.Date-Time-Settings.extension",
    "language": "x-apple.systempreferences:com.apple.Localization-Settings.extension",
    "region": "x-apple.systempreferences:com.apple.Localization-Settings.extension",
    "sharing": "x-apple.systempreferences:com.apple.Sharing-Settings.extension",
    "network": "x-apple.systempreferences:com.apple.Network-Settings.extension",
    "keychain": "open -a 'Keychain Access'",
}
SETTINGS_PANES_WIN = {
    "general": "ms-settings:about",
    "datetime": "ms-settings:dateandtime",
    "language": "ms-settings:regionlanguage",
    "region": "ms-settings:regionlanguage",
    "sharing": "ms-settings:about",            # 改电脑名的面板
    "network": "ms-settings:network-proxy",
    "keychain": "certmgr.msc",
}
ALLOWED_SITES = {"ip.net.coffee"}


def open_pane(pane: str) -> str:
    """返回启动命令；不可用时返回空串。"""
    if IS_MAC:
        uri = SETTINGS_PANES_MAC.get(pane)
        if not uri:
            return ""
        if uri.startswith("open "):
            return uri
        return f'open "{uri}"'
    uri = SETTINGS_PANES_WIN.get(pane)
    if not uri:
        return ""
    if pane == "keychain":
        return f'start "" "{uri}"'
    return f'start "" "{uri}"'


def open_file_cmd(path: str) -> str:
    if IS_MAC:
        return f'open -t "{path}"'
    return f'notepad "{path}"'


def open_url_cmd(url: str) -> str:
    if IS_MAC:
        return f'open "{url}"'
    return f'start "" "{url}"'


def run_shell(cmd: str) -> tuple[int, str]:
    """执行 shell 命令（open/start/notepad 这类）；返回 (rc, stderr)。"""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=8, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return r.returncode, (r.stderr or "")[:200]
    except Exception as exc:
        return 1, str(exc)[:200]


# ---------------------------------------------------------------- 废纸篓 / 隔离区


def trash_root() -> Path:
    """能进系统废纸篓最好；不行就退回本地隔离区。"""
    if IS_MAC:
        return HOME / ".Trash"
    return HOME / ".ccclean" / "quarantine"


def send_to_trash(path: Path) -> tuple[bool, str]:
    """单个文件/目录进废纸篓。Windows 用 PowerShell VisualBasic Recycle。

    返回 (是否进了系统废纸篓, 说明)。
    """
    if IS_MAC:
        # macOS 直接 mv 到 ~/.Trash 即废纸篓
        dest = path.parent / ".Trash" if False else trash_root() / path.name
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                dest = dest.parent / f"{path.stem}-{int(time.time())}{path.suffix}"
            path.rename(dest)
            return True, str(dest)
        except OSError:
            return False, ""
    ps = (
        "Add-Type -AssemblyName Microsoft.VisualBasic; "
        f"$p='{str(path).replace(chr(39), chr(39)+chr(39))}'; "
        "if (Test-Path -LiteralPath $p -PathType Container) "
        "{ [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p,'OnlyErrorDialogs','SendToRecycleBin') } "
        "else { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p,'OnlyErrorDialogs','SendToRecycleBin') }"
    )
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=15, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if r.returncode == 0:
        return True, "回收站"
    return False, (r.stderr or "")[:160]


# ---------------------------------------------------------------- 环境变量（持久层）

_ENV_VARS_SENSITIVE = re.compile(
    r"(anthropic|claude|openai|api_key|token|secret|proxy|base_url|telemetry|statsig)", re.I
)


def persistent_env() -> list[dict]:
    """持久化的可疑环境变量：macOS launchd getenv / Windows 用户+机器注册表。"""
    if IS_MAC:
        out = run(["launchctl", "print", f"gui/{os.getuid()}"], 6)
        hits = []
        for m in re.finditer(r"environment\s*=>\s*\{([^}]*)\}", out):
            for line in m.group(1).splitlines():
                kv = re.match(r"\s*\"?([A-Za-z_][\w]*)\"?\s*=\s*\"?([^\"]*)\"?", line)
                if kv and _ENV_VARS_SENSITIVE.search(kv.group(1)):
                    hits.append({"name": kv.group(1), "value": kv.group(2)[:80], "scope": "launchd"})
        # 还有常见直接 getenv 的
        for var in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                    "http_proxy", "https_proxy", "HTTPS_PROXY"):
            v = run(["launchctl", "getenv", var], 2)
            if v and not any(h["name"] == var for h in hits):
                hits.append({"name": var, "value": v[:80], "scope": "launchd"})
        return hits
    hits = []
    try:
        import winreg
        for scope, root, sub in (
            ("用户", winreg.HKEY_CURRENT_USER, r"Environment"),
            ("系统", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        ):
            try:
                with winreg.OpenKey(root, sub) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        if _ENV_VARS_SENSITIVE.search(name):
                            hits.append({"name": name, "value": str(val)[:80], "scope": scope})
            except OSError:
                continue
    except Exception:
        pass
    return hits


def unset_env(var: str, scope: str = "用户") -> tuple[bool, str]:
    """删除一个持久环境变量。"""
    if IS_MAC:
        r = subprocess.run(["launchctl", "unsetenv", var], capture_output=True, text=True, timeout=6, check=False)
        return r.returncode == 0, (r.stderr or "")[:160]
    ps_scope = "User" if scope == "用户" else "Machine"
    ps = f"[Environment]::SetEnvironmentVariable('{var}',$null,'{ps_scope}')"
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=8, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return r.returncode == 0, (r.stderr or "")[:160]


# ---------------------------------------------------------------- 启动项 / 后台


def startup_items() -> list[dict]:
    """常驻启动项：macOS LaunchAgents / Windows Run 键 + 启动文件夹 + 计划任务。"""
    items = []
    if IS_MAC:
        for base in (HOME / "Library" / "LaunchAgents", Path("/Library/LaunchAgents")):
            if not base.exists():
                continue
            for p in sorted(base.glob("*.plist")):
                items.append({"name": p.stem, "path": str(p), "kind": "launchagent"})
        return items
    try:
        import winreg
        for scope, root in (("用户", winreg.HKEY_CURRENT_USER), ("系统", winreg.HKEY_LOCAL_MACHINE)):
            for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
                try:
                    with winreg.OpenKey(root, sub) as k:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(k, i)
                            except OSError:
                                break
                            i += 1
                            items.append({
                                "name": name,
                                "path": f"{scope} Run 键 · {str(val)[:90]}",
                                "kind": "registry",
                                "hive": "HKCU" if scope == "用户" else "HKLM",
                                "sub": sub,
                            })
                except OSError:
                    continue
    except Exception:
        pass
    startup = Path(os.environ.get("APPDATA", str(HOME))) / "Microsoft/Windows/Start Menu/Programs/Startup"
    if startup.exists():
        for p in sorted(startup.iterdir()):
            items.append({"name": p.stem, "path": str(p), "kind": "startup-folder"})
    return items


def remove_startup_item(item: dict) -> tuple[bool, str]:
    """卸载/删除一个启动项。item 来自 startup_items()。"""
    name = item.get("name", "")
    if IS_MAC:
        # 先试 bootout（未加载也无妨），再把 plist 移进废纸篓
        run(["launchctl", "bootout", f"gui/{os.getuid()}/{name}"], 4)
        p = Path(item.get("path", ""))
        if p.exists():
            if item.get("noCopy"):
                p.unlink()
                return True, "已卸载并直接删除含凭据的启动项；不留副本，不可还原"
            ok, note = send_to_trash(p)
            return ok, note or str(p)
        return True, "已卸载（plist 已不存在）"
    if item.get("kind") == "registry":
        try:
            import winreg
            hive = winreg.HKEY_CURRENT_USER if item.get("hive") == "HKCU" else winreg.HKEY_LOCAL_MACHINE
            with winreg.OpenKey(hive, item.get("sub", ""), 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
            return True, "已从注册表删除"
        except OSError as exc:
            return False, str(exc)[:160]
    p = Path(item.get("path", ""))
    if p.exists():
        return send_to_trash(p)
    return True, "目标已不存在"


# ---------------------------------------------------------------- 证书（MITM 根证书）


def mitm_cert_names(keywords: tuple) -> list[str]:
    """在系统根证书存储里找名字含关键词的证书。"""
    if IS_MAC:
        hits = []
        for kc in (Path("/Library/Keychains/System.keychain"),
                   HOME / "Library/Keychains/login.keychain-db"):
            if not kc.exists():
                continue
            out = run(["security", "find-certificate", "-a", "-Z", str(kc)], 10)
            for label in re.findall(r'"labl"<blob>="([^"]+)"', out):
                if any(k in label.lower() for k in keywords):
                    hits.append(f"{label}（{kc.name.replace('.keychain-db','')}）")
        return hits
    hits = []
    for store in ("Root", "CA"):
        for scope_flag in (["-user"], []):
            out = run(["certutil", *scope_flag, "-store", store], 15)
            for m in re.finditer(r"(?:序列号|Serial Number)[:\s]+\S+", out):
                pass
            # certutil 输出里有 "颁发给:" / "Issued to:" 行
            for m in re.finditer(r"(?:颁发给|Issued to)[:：]\s*(.+)", out):
                label = m.group(1).strip()
                if any(k in label.lower() for k in keywords):
                    scope = "用户" if scope_flag else "系统"
                    hits.append(f"{label}（{scope} {store}）")
    return sorted(set(hits))


# ---------------------------------------------------------------- 路由 / 接口


def default_route_iface() -> str:
    if IS_MAC:
        m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get", "default"], 3))
        return m.group(1) if m else ""
    out = run(["route", "print", "0.0.0.0"], 4)
    m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+\S+\s+\S+\s+(\d+)", out)
    if m:
        iface = run(["netsh", "interface", "ipv4", "show", "interfaces"], 4)
        mm = re.search(rf"^\s*{m.group(1)}\s+\S+\s+\S+\s+(.*)$", iface, re.M)
        if mm:
            return mm.group(1).strip()[:40]
    return ""


def tunnel_interfaces() -> int:
    """TUN/隧道接口数量。"""
    if IS_MAC:
        return len(re.findall(r"^utun\d+:", run(["ifconfig"], 4), re.M))
    out = run(["netsh", "interface", "show", "interface"], 5)
    n = 0
    for ln in out.splitlines():
        if re.search(r"TAP|TUN|WireGuard|Wintun|OpenVPN|Mullvad|NordLynx|Tailscale|ZeroTier|Radmin|Hamachi", ln, re.I):
            n += 1
    return n


def proxy_processes(keywords: tuple) -> list[str]:
    """监听中的代理类进程名。"""
    if IS_MAC:
        out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], 6)
        return sorted({ln.split()[0] for ln in out.splitlines()
                       if ln.split() and any(k in ln.split()[0].lower() for k in keywords)})
    out = run(["netstat", "-ano", "-p", "tcp"], 8)
    listen_pids = {ln.split()[-1] for ln in out.splitlines() if "LISTENING" in ln and len(ln.split()) >= 5}
    tl = run(["tasklist", "/FO", "CSV", "/NH"], 6)
    names = set()
    for ln in tl.splitlines():
        m = re.match(r'"([^"]+)"\s*,\s*"(\d+)"', ln)
        if m and m.group(2) in listen_pids and any(k in m.group(1).lower() for k in keywords):
            names.add(m.group(1))
    return sorted(names)


# macOS 上 Shadowrocket / Surge 一类客户端通过 Network Extension 接管，
# 不一定监听本地 TCP 端口，lsof 看不到。它们的连接状态记在 scutil --nc list。
_VPN_PROXY_KEYS = (
    "shadowrocket", "surge", "clash", "sing-box", "stash", "quantumult",
    "loon", "v2ray", "xray", "trojan", "outline",
)


def proxy_vpn_connections() -> list[str]:
    """已连接的代理型 VPN 服务名。只认已知代理客户端，不把公司 VPN 当链路。"""
    if not IS_MAC:
        return []
    out = run(["scutil", "--nc", "list"], 5)
    names: list[str] = []
    for line in out.splitlines():
        if "(Connected)" not in line:
            continue
        low = line.lower()
        if not any(key in low for key in _VPN_PROXY_KEYS):
            continue
        quoted = re.search(r'"([^"]+)"', line)
        if quoted:
            name = quoted.group(1)
        else:
            name = line.split("com.")[-1].split()[0] if "com." in line else "VPN"
        if name not in names:
            names.append(name)
    return sorted(names)


def listening_ports() -> list[dict]:
    """本地监听端口（代理遗留检查用）。"""
    ports = []
    if IS_MAC:
        out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], 6)
        for ln in out.splitlines()[1:]:
            p = ln.split()
            if len(p) >= 9 and ":" in p[8]:
                m = re.search(r":(\d+)$", p[8])
                if m:
                    ports.append({"pid": p[1], "name": p[0], "port": int(m.group(1))})
        return ports
    out = run(["netstat", "-ano", "-p", "tcp"], 8)
    tl = {m.group(2): m.group(1) for m in
          re.finditer(r'"([^"]+)"\s*,\s*"(\d+)"', run(["tasklist", "/FO", "CSV", "/NH"], 6))}
    for ln in out.splitlines():
        if "LISTENING" not in ln:
            continue
        p = ln.split()
        if len(p) >= 5:
            m = re.search(r":(\d+)$", p[1])
            if m:
                ports.append({"pid": p[-1], "name": tl.get(p[-1], "?"), "port": int(m.group(1))})
    return ports


# ---------------------------------------------------------------- IPv6


def ipv6_exposure() -> dict:
    """{has_global_v6, has_default_v6_route, default_v6_iface, interfaces}"""
    if IS_MAC:
        conf = run(["ifconfig"], 4)
        interfaces: dict[str, list[str]] = {}
        current = ""
        for line in conf.splitlines():
            head = re.match(r"^([A-Za-z0-9_.-]+):", line)
            if head:
                current = head.group(1)
                continue
            addr = re.search(r"inet6\s+(?!fe80)(?!::1)([0-9a-fA-F:]+)", line)
            if current and addr:
                interfaces.setdefault(current, []).append(addr.group(1))
        g6 = [ip for ips in interfaces.values() for ip in ips]
        r6 = run(["route", "-n", "get", "-inet6", "default"], 3)
        iface = re.search(r"interface:\s*(\S+)", r6)
        return {
            "has_global_v6": bool(g6),
            "has_default_v6_route": "gateway" in r6,
            "default_v6_iface": iface.group(1) if iface else "",
            "interfaces": interfaces,
            "sample": g6[:2],
        }
    out = run(["ipconfig"], 4)
    g6 = re.findall(r"IPv6 Address[\. ]*:\s*([0-9a-fA-F:]+)", out)
    r6 = run(["route", "print", "-6"], 5)
    has_def = bool(re.search(r"::/0\s", r6))
    return {"has_global_v6": bool(g6), "has_default_v6_route": has_def,
            "default_v6_iface": "", "interfaces": {}, "sample": g6[:2]}


def wifi_device() -> str:
    """Wi-Fi 服务对应的网卡名（macOS，如 en0）。"""
    if not IS_MAC:
        return ""
    out = run(["/usr/sbin/networksetup", "-listallhardwareports"], 5)
    for block in re.split(r"\n\s*\n", out):
        if not re.search(r"Hardware Port:\s*(?:Wi-?Fi|AirPort)", block, re.I):
            continue
        dev = re.search(r"Device:\s*(\S+)", block)
        if dev:
            return dev.group(1)
    return ""


# ---------------------------------------------------------------- Claude 安装位置


def which_claude() -> list[str]:
    if IS_MAC:
        out = run(["sh", "-lc", "which -a claude 2>/dev/null; ls ~/.claude/local 2>/dev/null"], 4)
    else:
        out = run(["cmd", "/c", "where claude 2>nul"], 4)
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


# ---------------------------------------------------------------- 配置文件目录（代理工具）

CLASH_ROOTS_MAC = [
    ".config/clash", ".config/mihomo",
    "Library/Application Support/ClashX", "Library/Application Support/ClashX Pro",
    "Library/Application Support/Clash Verge", "Library/Application Support/clash-verge",
    "Library/Application Support/mihomo-party", "Library/Application Support/Stash",
    "Library/Application Support/sing-box", "Library/Application Support/com.follow.clash",
]
CLASH_ROOTS_WIN = [
    "AppData/Roaming/clash-verge", "AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev",
    "AppData/Roaming/mihomo-party", "AppData/Roaming/ClashX",
    ".config/clash", ".config/mihomo",
]


def clash_roots() -> list[Path]:
    names = CLASH_ROOTS_MAC if IS_MAC else CLASH_ROOTS_WIN
    return [HOME / n for n in names]


# ---------------------------------------------------------------- rc 启动文件


def rc_files() -> list[Path]:
    """shell 启动脚本（放代理变量/标记的地方）。"""
    if IS_MAC:
        return [HOME / n for n in (".zshrc", ".bashrc", ".bash_profile", ".zprofile", ".profile", ".zshenv")]
    docs = HOME / "Documents" / "PowerShell"
    docs7 = HOME / "Documents" / "WindowsPowerShell"
    return [
        docs7 / "Microsoft.PowerShell_profile.ps1",
        docs / "Microsoft.PowerShell_profile.ps1",
        docs7 / "profile.ps1",
        docs / "profile.ps1",
    ]


# ---------------------------------------------------------------- 浏览器数据目录


def browser_dirs() -> dict:
    """{浏览器名: [根目录]}。"""
    if IS_MAC:
        return {
            "Chrome": [HOME / "Library/Application Support/Google/Chrome"],
            "Edge": [HOME / "Library/Application Support/Microsoft Edge"],
            "Arc": [HOME / "Library/Application Support/Arc/User Data"],
            "Brave": [HOME / "Library/Application Support/BraveSoftware/Brave-Browser"],
            "Firefox": [HOME / "Library/Application Support/Firefox/Profiles"],
        }
    la = Path(os.environ.get("LOCALAPPDATA", str(HOME)))
    ra = Path(os.environ.get("APPDATA", str(HOME)))
    return {
        "Chrome": [la / "Google/Chrome/User Data"],
        "Edge": [la / "Microsoft/Edge/User Data"],
        "Firefox": [ra / "Mozilla/Firefox/Profiles"],
        "Brave": [la / "BraveSoftware/Brave-Browser/User Data"],
    }


# ---------------------------------------------------------------- 钥匙串 / 凭据


def keychain_services() -> list[str]:
    """与 claude 相关的钥匙串条目名。"""
    if IS_MAC:
        out = run(["security", "dump-keychain"], 15)
        svcs = sorted(set(re.findall(r'"svce"<blob>="([^"]*)"', out)))
        return [s for s in svcs if re.search(r"claude|anthropic", s, re.I)]
    # Windows Credential Manager
    out = run(["cmdkey", "/list"], 6)
    hits = []
    for m in re.finditer(r"(?:目标|Target)[:：]\s*(\S*?(?:claude|anthropic)\S*)", out, re.I):
        hits.append(m.group(1))
    return sorted(set(hits))


def delete_keychain(service: str) -> tuple[bool, str]:
    if IS_MAC:
        r = subprocess.run(["security", "delete-generic-password", "-s", service],
                           capture_output=True, text=True, timeout=10, check=False)
        if r.returncode == 0 or "could not be found" in (r.stderr or "").lower() or r.returncode == 44:
            return True, ""
        return False, (r.stderr or "")[:160]
    r = subprocess.run(["cmdkey", f"/delete:{service}"], capture_output=True, text=True, timeout=10, check=False)
    return r.returncode == 0, (r.stderr or r.stdout or "")[:160]


# ---------------------------------------------------------------- 键盘/语言


def os_language() -> str:
    if IS_MAC:
        out = run(["defaults", "read", "-g", "AppleLanguages"], 4)
        m = re.search(r'"([a-zA-Z-]+)"', out)
        return m.group(1) if m else ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\International") as k:
            v, _ = winreg.QueryValueEx(k, "LocaleName")
            return str(v)
    except Exception:
        import locale
        loc = locale.getlocale()[0] or ""
        return loc.replace("_", "-")


# ---------------------------------------------------------------- 杂项


def platform_tag() -> str:
    return "macOS" if IS_MAC else "Windows"


def platform_version() -> str:
    if IS_MAC:
        return run(["sw_vers", "-productVersion"], 3)
    return f"{sys.getwindowsversion().major}.{sys.getwindowsversion().minor}" if IS_WIN else sys.platform
