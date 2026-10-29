"""自动更新：从 GitHub Releases 取新版，校验、暂存，用户确认后安装。

三件事分开做，任何一步失败都不往下走：

1. **检查**只读 release 元数据和 manifest，不动磁盘上的应用。
2. **下载**把两个 zip 落到 `~/.ccclean/update-staging/`，逐个核对
   manifest 里的体积与 SHA256，再解开、读 Info.plist、跑 `codesign
   --verify`。没有一样对得上就不算「可以安装」。
3. **安装**必须带 `confirm=True`。这一步会退出塔与哨兵、把当前两个
   `.app` 备份到 `~/.ccclean/update-backup/`，换上新包，再重新拉起。
   新包起不来或者签名/版本不对，脚本自己回滚旧包——用户确认过一次，
   不代表允许他们把两个应用换成打不开的东西。

更新源是用户自己填的 `owner/repo`，默认空。空的时候整条链路不联网，
界面显示「未配置更新源」。仓库是公开的 GitHub 仓库，不需要 token，
也就没有凭据可以泄漏。

安装脚本用 `/bin/sh` 而不是 Python：塔自己被替换时，正在运行的 Python
解释器就在被挪走的那个 bundle 里，继续 import 标准库并不安全。脚本
先完成所有文件操作，成功或回滚后才拉起新进程。
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
CONFIG_FILE = STATE_DIR / "update.json"
REQUEST_FILE = STATE_DIR / "update-request.json"
STAGING_DIR = STATE_DIR / "update-staging"
BACKUP_DIR = STATE_DIR / "update-backup"
RUN_DIR = STATE_DIR / "update-run"
LOCK_FILE = STATE_DIR / "update.lock"
LOG_FILE = STATE_DIR / "update.log"

DEFAULT_CHECK_HOURS = 12
MIN_CHECK_HOURS = 1
MAX_CHECK_HOURS = 168
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ASSET_BYTES = 300 * 1024 * 1024
MAX_EXTRACT_BYTES = 900 * 1024 * 1024
MAX_ZIP_ENTRIES = 6000
MANIFEST_NAME = "update-manifest.json"
USER_AGENT = "ClaudeTower-Updater"
GITHUB_API = "https://api.github.com"

TOWER_BUNDLE_ID = "com.ccclean.app"
SHIELD_BUNDLE_ID = "com.ccclean.shield"

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_VER_RE = re.compile(r"^v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")
_OS_VER_RE = re.compile(r"^v?(\d{1,4})(?:\.(\d{1,4}))?(?:\.(\d{1,4}))?$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# 只有这些主机可以出现在下载地址里。manifest 里的 URL 不直接用——
# 真正的下载地址从 GitHub API 的 assets 里按名字取，这里再拦一道。
_ALLOWED_HOSTS = (
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)

_BUSY = threading.Lock()
_NET = threading.Lock()
_DL = threading.Lock()
_AUTO = {"thread": None, "phase": ""}


class UpdateError(RuntimeError):
    pass


# ------------------------------------------------------------------ 配置


def _now() -> int:
    return int(time.time())


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict) -> bool:
    """原子写 0600。更新配置里有仓库名和安装记录，没有凭据，但仍不该
    让别人读到「这台机器准备装哪个版本」。"""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(STATE_DIR, 0o700)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".update-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except (OSError, ValueError):
        return False
    return True


def load() -> dict:
    return _read_json(CONFIG_FILE)


def _save(patch: dict) -> dict:
    data = load()
    data.update(patch)
    data["schema"] = 1
    _write_json(CONFIG_FILE, data)
    return data


def _events(data: dict, event: dict) -> list:
    rows = [e for e in (data.get("events") or []) if isinstance(e, dict)]
    rows.append(event)
    return rows[-20:]


def repo() -> str:
    return str(load().get("repo") or "").strip()


def _clean_repo(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if not _REPO_RE.match(text):
        raise UpdateError("仓库格式应为主持人/仓库名，例如 owner/claude-tower")
    return text


def _check_hours(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = DEFAULT_CHECK_HOURS
    return max(MIN_CHECK_HOURS, min(MAX_CHECK_HOURS, n))


def configure(repo_value: str, auto_check=None, check_hours=None) -> dict:
    if _installing():
        raise UpdateError("正在安装更新，等重启完成后再改设置")
    patch: dict = {"repo": _clean_repo(repo_value)}
    if auto_check is not None:
        patch["autoCheck"] = bool(auto_check)
    if check_hours is not None:
        patch["checkHours"] = _check_hours(check_hours)
    if patch.get("repo") != repo():
        # 换了仓库，上一次的检查结论和暂存包都不再可信
        patch.update({"latest": None, "staged": None, "lastError": "", "lastCheck": 0})
        _discard_staging()
    with _BUSY:
        _save(patch)
    return {"repo": patch.get("repo", repo()), "autoCheck": patch.get("autoCheck"),
            "checkHours": patch.get("checkHours")}


# ------------------------------------------------------------------ 版本


def _ver(text: str):
    m = _VER_RE.match((text or "").strip())
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def _os_ver(text: str):
    """macOS 版本，允许 11、11.0、11.0.1 三种写法。"""
    m = _OS_VER_RE.match((text or "").strip())
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def _newer(candidate: str, current: str) -> bool:
    a, b = _ver(candidate), _ver(current)
    if a is None:
        return False
    if b is None:
        return True
    return a > b


def _valid_version(value: str) -> str:
    text = (value or "").strip()
    if not _ver(text):
        raise UpdateError("版本号不是 x.y.z 形式")
    return text[1:] if text.startswith("v") else text


def nested_shield(tower_app: Path) -> Path:
    """哨兵的位置由宿主决定：塔的 Resources 里，只有一个 .app。"""
    return Path(tower_app) / "Contents" / "Resources" / "Claude Shield.app"


def installed_shield_version(tower_app: Path | None = None) -> str:
    apps = []
    if tower_app:
        apps.append(nested_shield(tower_app))
    else:
        running = _running_app("Claude Tower.app")
        if running:
            apps.append(nested_shield(running))
        for root in (Path("/Applications"), HOME / "Applications"):
            apps.append(nested_shield(root / "Claude Tower.app"))
    for app in apps:
        if not app.exists():
            continue
        try:
            plist = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
        except (OSError, ValueError):
            continue
        value = str(plist.get("CFBundleShortVersionString") or "")
        if _ver(value):
            return value
    return ""


# ------------------------------------------------------------------ 网络


def _url_ok(url: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(url or "")
    if parsed.scheme == "https":
        host = (parsed.hostname or "").lower()
        return host in _ALLOWED_HOSTS or host.endswith(".githubusercontent.com")
    # 测试用本地假 GitHub。公网地址必须是 HTTPS。
    if parsed.scheme == "http":
        return (parsed.hostname or "") in ("127.0.0.1", "localhost", "::1")
    return False


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """每一次跳转都重新过主机白名单。

    `urlopen` 默认会跟着 3xx 走到底；只检查第一跳，等于把「只从 GitHub
    下载」写成了口号。GitHub 的资产会跳到 objects.githubusercontent.com，
    这在白名单里，不受影响。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _url_ok(newurl):
            raise UpdateError("更新地址重定向到了不受信任的来源")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect)


def _fetch(url: str, limit: int, timeout: float = 12.0) -> bytes:
    if not _url_ok(url):
        raise UpdateError("更新地址不是受信任的 HTTPS 来源")
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    })
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                raise UpdateError(f"更新服务器返回 HTTP {resp.status}")
            data = resp.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateError("仓库或 Release 不存在") from exc
        if exc.code in (403, 429):
            raise UpdateError("GitHub 接口被限流，过一会儿再试") from exc
        raise UpdateError(f"更新服务器返回 HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"连不上更新服务器：{getattr(exc, 'reason', exc)}") from exc
    if len(data) > limit:
        raise UpdateError("更新文件超过大小上限")
    return data


def _release(repo_value: str) -> dict:
    if not repo_value:
        raise UpdateError("未配置更新源")
    url = f"{GITHUB_API}/repos/{repo_value}/releases/latest"
    try:
        raw = _fetch(url, 4 * 1024 * 1024)
    except UpdateError:
        raise
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise UpdateError("更新服务器返回的不是合法 JSON") from exc
    if not isinstance(data, dict) or data.get("draft") or data.get("prerelease"):
        raise UpdateError("最新 Release 不可用")
    version = _valid_version(str(data.get("tag_name") or ""))
    assets = {}
    for item in data.get("assets") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        url = str(item.get("browser_download_url") or "")
        if not name or not _url_ok(url):
            continue
        try:
            size = int(item.get("size") or 0)
        except (TypeError, ValueError):
            continue
        assets[name] = {"name": name, "url": url, "size": size}
    if MANIFEST_NAME not in assets:
        raise UpdateError(f"Release 缺少 {MANIFEST_NAME}")
    notes = str(data.get("body") or "")[:4000]
    html = str(data.get("html_url") or "")
    return {
        "version": version,
        "assets": assets,
        "notes": notes,
        "htmlUrl": html if html.startswith("https://github.com/") else "",
    }


def _manifest(release: dict) -> dict:
    asset = release["assets"][MANIFEST_NAME]
    if asset["size"] > MAX_MANIFEST_BYTES:
        raise UpdateError("更新清单超过大小上限")
    raw = _fetch(asset["url"], MAX_MANIFEST_BYTES)
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise UpdateError("更新清单不是合法 JSON") from exc
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise UpdateError("更新清单格式不认识")
    if _valid_version(str(data.get("version") or "")) != release["version"]:
        raise UpdateError("更新清单与 Release 版本不一致")
    shield_version = _valid_version(str(data.get("shieldVersion") or ""))
    min_os = str(data.get("minMacOS") or "11.0")
    if _os_ver(min_os) is None:
        raise UpdateError("更新清单里的最低系统版本无效")
    assets = {}
    for key in ("tower",):
        item = (data.get("assets") or {}).get(key)
        if not isinstance(item, dict):
            raise UpdateError(f"更新清单缺少 {key} 包")
        name = str(item.get("name") or "")
        sha = str(item.get("sha256") or "").lower()
        size = item.get("bytes")
        if not name or "/" in name or "\\" in name or name.startswith("."):
            raise UpdateError(f"{key} 包名无效")
        if name not in release["assets"]:
            raise UpdateError(f"Release 里找不到 {name}")
        if not _HEX_RE.match(sha):
            raise UpdateError(f"{key} 包的 SHA256 无效")
        try:
            size = int(size)
        except (TypeError, ValueError):
            raise UpdateError(f"{key} 包的体积无效") from None
        if size <= 0 or size > MAX_ASSET_BYTES:
            raise UpdateError(f"{key} 包的体积超出上限")
        known = release["assets"][name]["size"]
        if known and known != size:
            raise UpdateError(f"{key} 包的体积与 Release 记录不一致")
        assets[key] = {"name": name, "sha256": sha, "bytes": size}
    return {
        "version": release["version"],
        "shieldVersion": shield_version,
        "minMacOS": min_os,
        "notes": str(data.get("notes") or release.get("notes") or "")[:4000],
        "assets": assets,
    }


def _os_ok(min_os: str) -> bool:
    if sys.platform != "darwin":
        return False
    current = platform.mac_ver()[0] or "0"
    a, b = _os_ver(min_os), _os_ver(current)
    return bool(a and b and b >= a)


# ------------------------------------------------------------------ 检查


def _cached_check(data: dict) -> bool:
    if not data.get("repo") or not data.get("latest"):
        return False
    last = int(data.get("lastCheck") or 0)
    hours = _check_hours(data.get("checkHours"))
    return bool(last) and _now() - last < hours * 3600


def check(force: bool = False, current_tower: str = "", current_shield: str = "") -> dict:
    data = load()
    repo_value = str(data.get("repo") or "")
    if not repo_value:
        return {"ok": True, "status": "unconfigured", "configured": False}
    if not force and _cached_check(data):
        return {"ok": True, **_verdict(data, current_tower, current_shield), "cached": True}

    with _NET:
        return _check_network(repo_value, data, current_tower, current_shield)


def _check_network(repo_value: str, data: dict, current_tower: str, current_shield: str) -> dict:
    try:
        release = _release(repo_value)
        latest_version = release["version"]
        patch: dict = {"lastCheck": _now(), "lastError": ""}
        if not _newer(latest_version, current_tower) and latest_version != current_tower:
            patch.update({"latest": None, "staged": None})
            _discard_staging()
            with _BUSY:
                saved = _save(patch)
            return {"ok": True, **_verdict(saved, current_tower, current_shield)}
        manifest = _manifest(release)
        if not _newer(latest_version, current_tower):
            patch.update({"latest": None, "staged": None})
            _discard_staging()
            with _BUSY:
                saved = _save(patch)
            return {"ok": True, **_verdict(saved, current_tower, current_shield)}
        if not _os_ok(manifest["minMacOS"]):
            raise UpdateError(f"新版要求 macOS {manifest['minMacOS']} 或更高")
        latest = {
            "version": latest_version,
            "shieldVersion": manifest["shieldVersion"],
            "minMacOS": manifest["minMacOS"],
            "notes": manifest["notes"],
            "checkedAt": _now(),
            "assets": manifest["assets"],
            "htmlUrl": release.get("htmlUrl") or "",
        }
        stale = data.get("staged") if isinstance(data.get("staged"), dict) else None
        if stale and stale.get("version") != latest_version:
            patch["staged"] = None
        patch["latest"] = latest
        patch["events"] = _events(data, {
            "at": _now(), "kind": "check",
            "note": f"发现新版 {latest_version}（哨兵 {manifest['shieldVersion']}）",
        })
        with _BUSY:
            saved = _save(patch)
        if patch.get("staged") is None and stale:
            _discard_staging()
        return {"ok": True, **_verdict(saved, current_tower, current_shield)}
    except UpdateError as exc:
        with _BUSY:
            saved = _save({
                "lastCheck": _now(), "lastError": str(exc),
                "events": _events(data, {"at": _now(), "kind": "error", "note": str(exc)}),
            })
        return {"ok": False, "error": str(exc), **_verdict(saved, current_tower, current_shield)}


def _verdict(data: dict, current_tower: str, current_shield: str) -> dict:
    latest = data.get("latest") if isinstance(data.get("latest"), dict) else None
    version = str((latest or {}).get("version") or "")
    # 哨兵跟着塔一起发：塔的版本就是整个包的版本，不再单独比哨兵。
    # shieldVersion 只用于展示「包里是哪个哨兵」。
    newer = bool(version and _newer(version, current_tower))
    return {
        "configured": bool(data.get("repo")),
        "latest": latest,
        "newer": newer,
        "status": "update" if newer else ("current" if data.get("lastCheck") else "idle"),
        "lastError": str(data.get("lastError") or ""),
    }


# ------------------------------------------------------------------ 下载与校验


def _copy_stream(src, dest: Path, sha_expected: str, size_expected: int) -> None:
    digest = hashlib.sha256()
    written = 0
    with open(dest, "wb") as fh:
        while True:
            chunk = src.read(256 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > size_expected or written > MAX_ASSET_BYTES:
                raise UpdateError("更新文件超过清单记录的体积")
            digest.update(chunk)
            fh.write(chunk)
    if written != size_expected:
        raise UpdateError("更新文件体积与清单不一致")
    if digest.hexdigest() != sha_expected:
        raise UpdateError("更新文件 SHA256 与清单不一致")


def _download_asset(asset: dict, dest: Path) -> None:
    if not _url_ok(asset.get("url") or ""):
        raise UpdateError("下载地址不是受信任的 HTTPS 来源")
    req = urllib.request.Request(asset["url"], headers={"User-Agent": USER_AGENT})
    try:
        with _OPENER.open(req, timeout=30) as resp:
            if getattr(resp, "status", 200) != 200:
                raise UpdateError(f"下载失败：HTTP {resp.status}")
            length = resp.headers.get("Content-Length")
            if length and int(length) > asset["bytes"]:
                raise UpdateError("下载体积超过清单记录")
            _copy_stream(resp, dest, asset["sha256"], asset["bytes"])
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"下载失败：HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"下载失败：{getattr(exc, 'reason', exc)}") from exc


def _safe_extract(zip_path: Path, dest: Path, app_name: str) -> None:
    """只接受「根目录下恰好一个 .app」的压缩包。

    路径穿越、符号链接、解压炸弹都在这里拦住。更新包是外部输入，
    不能因为对方是 GitHub 就免检。
    """
    try:
        zf = zipfile.ZipFile(zip_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise UpdateError("更新包不是合法的 zip") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise UpdateError("更新包里的文件数超过上限")
        total = 0
        roots = set()
        for info in infos:
            name = info.filename
            if name.startswith(("/", "\\")) or "\\" in name or "\x00" in name:
                raise UpdateError("更新包里有非法路径")
            parts = [p for p in name.split("/") if p]
            if not parts:
                continue
            if parts[0] == "__MACOSX":
                continue
            if any(p in (".", "..") for p in parts):
                raise UpdateError("更新包里有越界路径")
            roots.add(parts[0])
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise UpdateError("更新包里不允许符号链接")
            total += max(0, int(info.file_size))
            if total > MAX_EXTRACT_BYTES:
                raise UpdateError("解压后体积超过上限")
        if roots != {app_name}:
            raise UpdateError(f"更新包根目录必须是 {app_name}")
        try:
            zf.extractall(dest)
        except (OSError, zipfile.BadZipFile) as exc:
            raise UpdateError("解压更新包失败") from exc
        # zipfile 不恢复 Unix 权限位。不补这一步，主可执行文件解出来是
        # 0644——签名能过，`open` 却起不来，安装自检会失败并回滚。
        for info in infos:
            parts = [p for p in info.filename.split("/") if p]
            if not parts or parts[0] == "__MACOSX" or any(p in (".", "..") for p in parts):
                continue
            target = dest.joinpath(*parts)
            if not target.exists() or target.is_symlink():
                continue
            mode = (info.external_attr >> 16) & 0o777
            if not mode:
                mode = 0o755 if info.is_dir() else 0o644
            try:
                os.chmod(target, mode)
            except OSError:
                pass
        exe = dest / app_name / "Contents" / "MacOS"
        for name in ("CCclean", "Shield", "ShieldWatchdog"):
            path = exe / name
            if path.is_file():
                try:
                    os.chmod(path, 0o755)
                except OSError:
                    pass


def _verify_bundle(app: Path, app_name: str, version: str, bundle_id: str) -> None:
    if not app.is_dir():
        raise UpdateError(f"更新包里没有 {app_name}")
    try:
        plist = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    except (OSError, ValueError) as exc:
        raise UpdateError(f"{app_name} 的 Info.plist 读不了") from exc
    if str(plist.get("CFBundleIdentifier") or "") != bundle_id:
        raise UpdateError(f"{app_name} 的 bundle id 不对")
    if str(plist.get("CFBundleShortVersionString") or "") != version:
        raise UpdateError(f"{app_name} 的版本与清单不一致")
    exe = app / "Contents" / "MacOS" / ("CCclean" if bundle_id == TOWER_BUNDLE_ID else "Shield")
    if not exe.is_file() or not os.access(exe, os.X_OK):
        raise UpdateError(f"{app_name} 里没有可执行文件")
    try:
        r = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)],
                           capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateError(f"{app_name} 签名校验跑不起来") from exc
    if r.returncode != 0:
        raise UpdateError(f"{app_name} 签名校验失败")


def download(current_tower: str = "", current_shield: str = "") -> dict:
    """下载并校验新版。不安装，不退出任何进程。"""
    data = load()
    repo_value = str(data.get("repo") or "")
    latest = data.get("latest") if isinstance(data.get("latest"), dict) else {}
    version = str(latest.get("version") or "")
    if not repo_value:
        raise UpdateError("未配置更新源")
    if not version:
        raise UpdateError("还没有检查到新版")

    # 暂存目录里已经有同一版本且校验过，就不再下载
    staged = data.get("staged") if isinstance(data.get("staged"), dict) else None
    if staged and staged.get("version") == version and _staged_path(version).exists():
        return {"ok": True, "staged": staged}

    if not _DL.acquire(blocking=False):
        raise UpdateError("已经在下载了")
    try:
        if not _NET.acquire(blocking=False):
            raise UpdateError("正在检查更新，请稍后再试")
        try:
            _AUTO["phase"] = "download"
            return _download_network(repo_value, version, current_tower, current_shield)
        finally:
            _NET.release()
            _AUTO["phase"] = ""
    finally:
        _DL.release()


def _download_network(repo_value: str, version: str,
                      current_tower: str, current_shield: str) -> dict:
    release = _release(repo_value)
    if release["version"] != version:
        raise UpdateError("Release 内容已经变化，请重新检查")
    manifest = _manifest(release)
    if manifest["version"] != version:
        raise UpdateError("更新清单与已检查的版本不一致")
    shield_version = manifest["shieldVersion"]
    if not _newer(version, current_tower):
        raise UpdateError("新版并不比当前版本新")
    if not _os_ok(manifest["minMacOS"]):
        raise UpdateError(f"新版要求 macOS {manifest['minMacOS']} 或更高")

    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STAGING_DIR, 0o700)
    tmp = Path(tempfile.mkdtemp(dir=str(STAGING_DIR), prefix=f".{version}-"))
    try:
        asset = manifest["assets"]["tower"]
        app_name = "Claude Tower.app"
        zip_path = tmp / "tower.zip"
        src = release["assets"].get(asset["name"])
        if not src:
            raise UpdateError(f"Release 里找不到 {asset['name']}")
        _download_asset({**asset, "url": src["url"]}, zip_path)
        zdir = tmp / "tower"
        zdir.mkdir()
        _safe_extract(zip_path, zdir, app_name)
        zip_path.unlink(missing_ok=True)
        tower_new = zdir / app_name
        _verify_bundle(tower_new, app_name, version, TOWER_BUNDLE_ID)
        # 哨兵不单独下载了，但它必须在包里、版本跟清单对得上：
        # 只验塔等于放过「塔更新了、哨兵还是旧的」这种半截包。
        _verify_bundle(nested_shield(tower_new), "Claude Shield.app",
                       shield_version, SHIELD_BUNDLE_ID)

        # 下载期间用户可能改了仓库；那些字节来自旧仓库，不能当新仓库的暂存包
        if repo() != repo_value:
            raise UpdateError("更新源已经变化，请重新检查")
        final = _staged_path(version)
        if final.exists():
            # 只删我们自己生成的暂存目录
            shutil.rmtree(final)
        os.replace(tmp, final)
        staged = {
            "version": version,
            "shieldVersion": shield_version,
            "at": _now(),
            "dir": str(final.relative_to(STATE_DIR)),
        }
        _save({
            "staged": staged,
            "lastError": "",
            "events": _events(load(), {
                "at": _now(), "kind": "download",
                "note": f"{version} 已下载并通过 SHA256、版本与签名校验",
            }),
        })
        return {"ok": True, "staged": staged}
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def download_async(current_tower: str, current_shield: str = "") -> bool:
    """后台下载。页面轮询 status 看 stagedReady，不靠这个线程的返回值。"""
    thread = _AUTO.get("thread")
    if thread and thread.is_alive():
        return False
    if _DL.locked():
        return False

    def run():
        try:
            download(current_tower=current_tower, current_shield=current_shield)
        except UpdateError as exc:
            data = load()
            with _BUSY:
                _save({
                    "lastError": str(exc),
                    "events": _events(data, {
                        "at": _now(), "kind": "error", "note": str(exc),
                    }),
                })
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True, name="ccclean-download")
    _AUTO["thread"] = t
    t.start()
    return True


def _staged_path(version: str) -> Path:
    return STAGING_DIR / version


def _discard_staging() -> None:
    """清掉自己生成的暂存目录。名字必须是版本号或临时前缀，别碰别的东西。"""
    try:
        if not STAGING_DIR.exists():
            return
        for child in STAGING_DIR.iterdir():
            name = child.name
            if name.startswith(".") or _ver(name):
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
    except OSError:
        pass


def discard() -> dict:
    if _installing():
        raise UpdateError("正在安装更新，暂存包不能丢")
    with _BUSY:
        _save({"staged": None})
        _discard_staging()
    return {"ok": True}


# ------------------------------------------------------------------ 安装


def _running_app(suffix: str) -> Path | None:
    try:
        exe = Path(sys.executable).resolve()
    except OSError:
        return None
    for parent in exe.parents:
        if parent.suffix == ".app" and parent.name == suffix:
            return parent
    return None


def _shield_running() -> bool:
    try:
        r = subprocess.run(["/bin/ps", "-axo", "comm="], capture_output=True, text=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        return False
    return any("Claude Shield.app/Contents/MacOS/Shield" in line
               for line in (r.stdout or "").splitlines())


def _writable_target(target: Path) -> bool:
    parent = target.parent
    if not parent.is_dir() or not os.access(parent, os.W_OK):
        return False
    if target.exists() and not os.access(target, os.W_OK):
        return False
    return True


def _installing() -> bool:
    active = _read_json(RUN_DIR / "active.json")
    if not active:
        return False
    try:
        pid = int(active.get("pid") or 0)
    except (TypeError, ValueError):
        return False
    if not pid or _now() - int(active.get("at") or 0) > 3600:
        return False
    if (_read_json(RUN_DIR / "result.json")):
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _sh(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def _write_script(script: Path, plan: dict) -> None:
    paths = {k: _sh(v) for k, v in plan.items() if isinstance(v, str)}
    text = f"""#!/bin/sh
# Claude Tower 更新安装脚本。由 ~/.ccclean/update-run/<版本>/ 生成，
# 安装结束后可以连同这个目录一起删掉。
set -u

LOG={paths['log']}
RESULT={paths['result']}
ACTIVE={paths['active']}
STAMP={paths['stamp']}
TOWER={paths['tower_target']}
TOWER_NEW={paths['tower_new']}
BACKUP={paths['backup']}
HEARTBEAT={paths['heartbeat']}
RUNTIME={paths['runtime']}
STOP_MARKER={paths['stop_marker']}
TOWER_VER={paths['tower_version']}
SHIELD_VER={paths['shield_version']}
TOWER_OLD_VER={paths['tower_from']}
SHIELD_OLD_VER={paths['shield_from']}
SHIELD_WAS_RUNNING={paths['shield_was_running']}
LAUNCH={paths['launch']}
SHIELD_PID={paths['shield_pid']}
# 哨兵跟着塔一起换：它就在塔的 Resources 里，没有单独的目标路径
SHIELD="$TOWER/Contents/Resources/Claude Shield.app"
DONE=0
TOWER_SWAPPED=0
TOWER_BACKED=0

say() {{ printf '%s %s\\n' "$(/bin/date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }}
write_result() {{
  /bin/cat > "$RESULT" <<EOF
{{"ok":$1,"at":$(/bin/date +%s),"from":"$TOWER_OLD_VER","to":"$TOWER_VER","shieldFrom":"$SHIELD_OLD_VER","shieldTo":"$SHIELD_VER","reason":"$2"}}
EOF
}}
stop_identity() {{
  want="$1"
  /bin/ps -axo pid=,comm= | while read -r pid comm; do
    if [ "$comm" = "$want" ]; then /bin/kill -TERM "$pid" 2>/dev/null || true; fi
  done
}}
wait_gone() {{
  want="$1"; n=0
  while [ "$n" -lt 40 ]; do
    if ! /bin/ps -axo comm= | /usr/bin/grep -qx "$want"; then return 0; fi
    /bin/sleep 0.25; n=$((n+1))
  done
  return 1
}}
# 塔的宿主进程只是壳，真正跑 HTTP 的是 bundle 里内嵌的 Python。
# 只杀 CCclean 不够：宿主一死 Python 进程要 2 秒才自行退出，而这段窗口
# 里旧 bundle 正在被挪走，进程还占着里面的文件和端口。
stop_under() {{
  root="$1"
  /bin/ps -axo pid=,comm= | while read -r pid comm; do
    case "$comm" in
      "$root"/*) /bin/kill -TERM "$pid" 2>/dev/null || true ;;
    esac
  done
}}
wait_gone_under() {{
  root="$1"; n=0
  while [ "$n" -lt 40 ]; do
    if ! /bin/ps -axo comm= | /usr/bin/awk -v r="$root/" 'index($0, r) == 1 {{ found=1 }} END {{ exit found ? 0 : 1 }}'; then
      return 0
    fi
    /bin/sleep 0.25; n=$((n+1))
  done
  return 1
}}
restore_app() {{
  src="$1"; dst="$2"
  if [ -d "$src" ]; then
    /bin/mkdir -p "$(dirname "$dst")"
    /usr/bin/ditto "$src" "$dst" || return 1
  fi
}}
rollback() {{
  reason="$1"; [ "$DONE" = 1 ] && return 0
  say "ROLLBACK: $reason"
  stop_identity "$SHIELD/Contents/MacOS/ShieldWatchdog"
  stop_identity "$SHIELD/Contents/MacOS/Shield"
  stop_identity "$TOWER/Contents/MacOS/CCclean"
  stop_under "$TOWER/Contents/Resources/python"
  /bin/sleep 1
  if [ "$TOWER_SWAPPED" = 1 ] && [ -d "$TOWER" ]; then
    /bin/mv "$TOWER" "$BACKUP/failed-tower-$$" 2>/dev/null || true
  fi
  if [ "$TOWER_BACKED" = 1 ]; then restore_app "$BACKUP/Claude Tower.app.new" "$TOWER" || true; fi
  /bin/rm -rf "$TOWER.ccclean-new-$$" "$TOWER.ccclean-old-$$" 2>/dev/null || true
  /bin/rm -f "$STOP_MARKER" "$HEARTBEAT" "$RUNTIME"
  # 旧塔如果是嵌哨兵的版本，open 之后它会自己把哨兵带起来
  if [ "$LAUNCH" = 1 ] && [ -d "$TOWER" ]; then
    /usr/bin/open "$TOWER" >/dev/null 2>&1 || true
  fi
  write_result 0 "$reason"
  /bin/rm -f "$ACTIVE"
  DONE=1
  exit 1
}}
trap 'if [ "$DONE" = 0 ]; then rollback unexpected; fi' EXIT INT TERM HUP

say "install $TOWER_OLD_VER -> $TOWER_VER (shield $SHIELD_OLD_VER -> $SHIELD_VER)"
# 塔在第 2 秒就会被停掉，用它 pid 写的「安装中」标记随之失效；
# 由脚本自己接管，新塔启动后到结果落盘前的几秒才不会被当成「没在装」。
if [ -n "$ACTIVE" ]; then
  printf '{{"pid":%s,"at":%s,"version":"%s"}}\n' "$$" "$(/bin/date +%s)" "$TOWER_VER" > "$ACTIVE" 2>/dev/null || true
fi
# 给发起安装的塔一点时间把 HTTP 响应发回页面，再动手
/bin/sleep 2

say "stop watchdog and apps"
if [ -n "$SHIELD_PID" ]; then
  printf '%s' "$SHIELD_PID" > "$STOP_MARKER"
  # 直接按 pid 停：过渡期里的哨兵可能还在旧的独立路径上，
  # 只按 path 匹配会漏掉它，新塔再把包内哨兵拉起来就是两个。
  /bin/kill -TERM "$SHIELD_PID" 2>/dev/null || true
fi
stop_identity "$SHIELD/Contents/MacOS/ShieldWatchdog"
/bin/sleep 0.5
stop_identity "$SHIELD/Contents/MacOS/Shield"
stop_identity "$TOWER/Contents/MacOS/CCclean"
stop_under "$TOWER/Contents/Resources/python"
wait_gone "$TOWER/Contents/MacOS/CCclean" || say "warning: old tower still running"
wait_gone "$SHIELD/Contents/MacOS/Shield" || say "warning: old shield still running"
wait_gone_under "$TOWER/Contents/Resources/python" || say "warning: old tower python still running"
/bin/rm -f "$STOP_MARKER" "$HEARTBEAT" "$RUNTIME"

/bin/mkdir -p "$BACKUP"
say "backup current app to $BACKUP"
if [ -d "$TOWER" ]; then
  /usr/bin/ditto "$TOWER" "$BACKUP/Claude Tower.app.new" || rollback backup-tower
  TOWER_BACKED=1
fi

say "swap in new tower"
NEW="$TOWER.ccclean-new-$$"; OLD="$TOWER.ccclean-old-$$"
/bin/rm -rf "$NEW"
/usr/bin/ditto "$TOWER_NEW" "$NEW" || rollback stage-tower
if ! /bin/mv "$TOWER" "$OLD" 2>/dev/null; then rollback move-old-tower; fi
if /bin/mv "$NEW" "$TOWER"; then TOWER_SWAPPED=1; else rollback swap-tower; fi

say "verify codesign and versions"
# 嵌套签名会被 --deep 一并校验；下面再单独核一遍包内哨兵是否存在、版本对不对
/usr/bin/codesign --verify --deep --strict "$TOWER" >>"$LOG" 2>&1 || rollback codesign-tower
v=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$TOWER/Contents/Info.plist" 2>/dev/null || true)
[ "$v" = "$TOWER_VER" ] || rollback version-tower
[ -d "$SHIELD" ] || rollback missing-shield
v=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$SHIELD/Contents/Info.plist" 2>/dev/null || true)
[ "$v" = "$SHIELD_VER" ] || rollback version-shield
say "codesign ok"

/bin/mv "$TOWER.ccclean-old-$$" "$BACKUP/old-tower-$$" 2>/dev/null || true

if [ "$LAUNCH" = 1 ]; then
  say "launch new tower"
  /usr/bin/open "$TOWER" >/dev/null 2>&1 || rollback launch-tower
  n=0
  while [ "$n" -lt 30 ]; do
    if [ -f "$RUNTIME" ]; then
      url=$(/usr/bin/sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' "$RUNTIME" | /usr/bin/head -n 1)
      if [ -n "$url" ] && /usr/bin/curl -fsS -o /dev/null --max-time 2 "$url"; then break; fi
    fi
    /bin/sleep 1; n=$((n+1))
  done
  [ "$n" -lt 30 ] || rollback tower-not-starting
  say "tower runtime ok"

  # 哨兵由塔启动（一个应用、两个进程），这里只等它的心跳。
  # 之前它就没在跑（用户手动退过）就不强求，塔起来后也会带它。
  if [ "$SHIELD_WAS_RUNNING" = 1 ]; then
    n=0
    while [ "$n" -lt 30 ]; do
      if [ -f "$HEARTBEAT" ] && [ "$HEARTBEAT" -nt "$STAMP" ]; then break; fi
      /bin/sleep 1; n=$((n+1))
    done
    [ "$n" -lt 30 ] || rollback shield-not-starting
    say "shield heartbeat ok"
  fi
fi

say "install ok"
/bin/rm -rf "$TOWER.ccclean-new-$$" "$TOWER.ccclean-old-$$" 2>/dev/null || true
write_result 1 ""
/bin/rm -f "$ACTIVE"
DONE=1
exit 0
"""
    try:
        script.write_text(text, encoding="utf-8")
        os.chmod(script, 0o700)
        r = subprocess.run(["/bin/sh", "-n", str(script)], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateError("安装脚本写入失败") from exc
    if r.returncode != 0:
        raise UpdateError("安装脚本语法检查失败：" + (r.stderr or "").strip()[:200])


def install(*, confirm: bool, current_tower: str, current_shield: str = "",
            tower_app: Path | None = None, launch: bool = True) -> dict:
    """把已校验的暂存包换上去。只应由用户点击触发。"""
    if not confirm:
        raise UpdateError("更新会重启塔与哨兵，需要确认后才会安装")
    if sys.platform != "darwin":
        raise UpdateError("自动安装只支持 macOS")
    with _BUSY:
        data = load()
        staged = data.get("staged") if isinstance(data.get("staged"), dict) else None
        if not staged:
            raise UpdateError("还没有下载并校验新版")
        version = str(staged.get("version") or "")
        if not _newer(version, current_tower):
            raise UpdateError("当前已经是最新版本")
        staged_dir = _staged_path(version)
        if not staged_dir.exists():
            raise UpdateError("暂存包不在了，请重新下载")
        if _installing():
            raise UpdateError("上一次安装还没有结束")

        target = Path(tower_app) if tower_app else _running_app("Claude Tower.app")
        if not target or not target.exists():
            raise UpdateError("塔不是从应用包运行的，无法自动替换；请先构建并安装 Claude Tower.app")
        if not _writable_target(target):
            raise UpdateError(f"没有写入 {target.parent} 的权限，请手动安装新版")

        RUN_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(RUN_DIR, 0o700)
        # 只清自己生成的旧 run 目录，保留最近一次的安装脚本便于排查
        for child in RUN_DIR.iterdir():
            if child.is_dir() and _ver(child.name) and child.name != version:
                shutil.rmtree(child, ignore_errors=True)
        run = RUN_DIR / version
        run.mkdir(parents=True, exist_ok=True)
        os.chmod(run, 0o700)
        backup = BACKUP_DIR / f"{time.strftime('%Y%m%d-%H%M%S')}-{current_tower}"
        backup.mkdir(parents=True, exist_ok=True)
        os.chmod(backup, 0o700)

        stamp = run / "stamp"
        stamp.touch()
        shield_from = current_shield or installed_shield_version(target)
        plan = {
            "log": str(LOG_FILE),
            "result": str(RUN_DIR / "result.json"),
            "active": str(RUN_DIR / "active.json"),
            "stamp": str(stamp),
            "tower_target": str(target),
            "tower_new": str(staged_dir / "tower" / "Claude Tower.app"),
            "backup": str(backup),
            "heartbeat": str(STATE_DIR / "shield-heartbeat.json"),
            "runtime": str(HOME / "Library" / "Application Support" / "CCclean" / "runtime.json"),
            "stop_marker": str(STATE_DIR / "watchdog.stop"),
            "tower_version": version,
            "shield_version": str(staged.get("shieldVersion") or ""),
            "tower_from": current_tower,
            "shield_from": shield_from,
            "shield_was_running": "1" if _shield_running() else "0",
            "launch": "1" if launch else "0",
            "shield_pid": str(_shield_pid() or ""),
        }
        script = run / "install.sh"
        _write_script(script, plan)

        active = {"pid": os.getpid(), "at": _now(), "version": version}
        _write_json(RUN_DIR / "active.json", active)
        _save({
            "events": _events(data, {
                "at": _now(), "kind": "install",
                "note": f"开始安装 {version}，塔与哨兵将重启",
            }),
        })
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as log:
                log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} spawn {script}\n")
            subprocess.Popen(
                ["/bin/sh", str(script)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            (RUN_DIR / "active.json").unlink(missing_ok=True)
            raise UpdateError("安装脚本启动失败") from exc
        return {"ok": True, "started": True, "version": version,
                "shieldVersion": plan["shield_version"], "shield": True}


def _shield_pid() -> int | None:
    try:
        r = subprocess.run(["/bin/ps", "-axo", "pid=,comm="], capture_output=True,
                           text=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (r.stdout or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        if parts[1].endswith("Claude Shield.app/Contents/MacOS/Shield"):
            try:
                return int(parts[0])
            except ValueError:
                continue
    return None


# ------------------------------------------------------------------ 结果与状态

_REASONS = {
    "unexpected": "安装脚本意外退出",
    "backup-tower": "备份当前塔失败",
    "stage-tower": "展开新版塔失败",
    "move-old-tower": "挪走旧塔失败",
    "swap-tower": "替换塔失败",
    "codesign-tower": "新塔签名校验失败",
    "version-tower": "新塔版本号不符",
    "missing-shield": "新塔里没有哨兵",
    "version-shield": "包内哨兵版本号不符",
    "launch-tower": "新塔无法启动",
    "tower-not-starting": "新塔启动后没有响应",
    "shield-not-starting": "哨兵启动后没有心跳",
}


def _consume_result() -> dict | None:
    """安装脚本结束后把结果并进 update.json，并清掉 active 标记。

    脚本是独立进程，不能直接改 JSON（并发写会互相覆盖），所以把结果
    落在自己的 run 目录里，由塔下次读状态时收编。
    """
    result = _read_json(RUN_DIR / "result.json")
    if not result:
        return None
    data = load()
    last = data.get("lastInstall") if isinstance(data.get("lastInstall"), dict) else {}
    if last.get("at") == result.get("at") and last.get("to") == result.get("to"):
        return result
    ok = bool(result.get("ok"))
    reason = str(result.get("reason") or "")
    result["reasonText"] = "" if ok else _REASONS.get(reason, "安装失败，已回滚")
    patch = {"lastInstall": result}
    if ok:
        patch["staged"] = None
        patch["latest"] = None
        patch["lastCheck"] = _now()
        _discard_staging()
    patch["events"] = _events(data, {
        "at": _now(), "kind": "installed" if ok else "rollback",
        "note": (f"已更新到 {result.get('to')}" if ok
                 else f"更新失败（{result['reasonText']}），已回滚到 {result.get('from')}"),
    })
    with _BUSY:
        _save(patch)
    (RUN_DIR / "active.json").unlink(missing_ok=True)
    if ok:
        _prune_backups()
    return result


def _prune_backups(keep: int = 2) -> None:
    """只留最近几份旧版备份。每份是两个完整的 .app，不收拾会一直长。"""
    try:
        dirs = sorted((p for p in BACKUP_DIR.iterdir() if p.is_dir()), key=lambda p: p.name)
    except OSError:
        return
    for old in dirs[:-keep] if len(dirs) > keep else []:
        shutil.rmtree(old, ignore_errors=True)


def status(current_tower: str, current_shield: str = "") -> dict:
    _consume_result()
    data = load()
    verdict = _verdict(data, current_tower, current_shield)
    staged = data.get("staged") if isinstance(data.get("staged"), dict) else None
    staged_ready = bool(staged and staged.get("version") == str((verdict.get("latest") or {}).get("version") or "")
                        and _staged_path(str(staged.get("version"))).exists())
    installing = _installing()
    if not verdict["configured"]:
        state = "unconfigured"
    elif installing:
        state = "installing"
    elif verdict["newer"]:
        state = "update"
    elif verdict["lastError"] and not verdict["latest"]:
        state = "error"
    else:
        state = "current" if data.get("lastCheck") else "idle"
    return {
        "ok": True,
        "state": state,
        "configured": verdict["configured"],
        "repo": str(data.get("repo") or ""),
        "autoCheck": bool(data.get("autoCheck", True)),
        "checkHours": _check_hours(data.get("checkHours")),
        "current": {"tower": current_tower, "shield": current_shield},
        "latest": verdict["latest"],
        "newer": verdict["newer"],
        "staged": staged if staged_ready else None,
        "stagedReady": staged_ready,
        "installing": installing,
        "phase": _AUTO.get("phase") or "",
        "lastCheck": int(data.get("lastCheck") or 0),
        "lastError": verdict["lastError"],
        "lastInstall": data.get("lastInstall") or None,
        "events": (data.get("events") or [])[-8:],
        "requested": _take_request(),
    }


def _take_request() -> bool:
    """哨兵面板点了「去塔里更新」会留一个请求标记。塔读一次就消掉，
    只用来把页面滚到更新卡片，不触发安装。"""
    if not REQUEST_FILE.exists():
        return False
    try:
        REQUEST_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    return True


def auto_maybe(current_tower: str, current_shield: str = "") -> bool:
    """到点了就后台检查并下载。返回是否真的启动了后台任务。"""
    data = load()
    if not data.get("repo") or not bool(data.get("autoCheck", True)):
        return False
    thread = _AUTO.get("thread")
    if thread and thread.is_alive():
        return False
    last = int(data.get("lastCheck") or 0)
    if last and _now() - last < _check_hours(data.get("checkHours")) * 3600:
        return False

    def run():
        try:
            _AUTO["phase"] = "check"
            result = check(force=True, current_tower=current_tower,
                           current_shield=current_shield)
            _AUTO["phase"] = ""
            if result.get("newer"):
                download(current_tower=current_tower, current_shield=current_shield)
        except Exception:
            pass
        finally:
            _AUTO["phase"] = ""

    t = threading.Thread(target=run, daemon=True, name="ccclean-updater")
    _AUTO["thread"] = t
    t.start()
    return True
