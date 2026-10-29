#!/usr/bin/env python3
"""CCclean · Claude 环境洁净度检测与清理工具（本地服务）"""

from __future__ import annotations

import ast
import atexit
import json
import mimetypes
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# PyInstaller 打包后资源在 sys._MEIPASS；源码运行取脚本所在目录
ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))

from core import (  # noqa: E402
    align, browserwebrtc, checklist, cleaner, compat, deep, ipcheck, ipv6cfg,
    isolation, leaderboard, netcfg, privacy, proxyfix, proxydiag, regioncfg,
    rules, scanner, shield, tower, uninstall, updater, watch, wizard,
)

WEB = ROOT / "web"
VERSION = "2.19.5"
PRIVACY_TOKEN = secrets.token_urlsafe(32)
# 每次启动重新生成的会话令牌。所有 /api/ 请求都要带上它（X-CClean-Token）。
# 用自定义头而不是 cookie，是因为自定义头会强制浏览器先发 OPTIONS 预检，
# 而本服务根本不响应 OPTIONS —— 于是任何跨站页面都发不出带这个头的请求，
# 连「悄悄替你点一下清理」都做不到。cookie 做不到这一点：跨站表单照样能带。
SESSION_TOKEN = secrets.token_urlsafe(32)
STATE: dict = {"scan": None, "lock": threading.Lock()}
RUNTIME_DIR = (Path.home() / "Library" / "Application Support" / "CCclean") if compat.IS_MAC else \
    Path.home() / ".ccclean" / "runtime"
# 免责声明的「已读」记在这里：localStorage 按 origin（含端口）隔离，
# 端口一变就会重弹，所以真正的标记放在本机文件里。
NOTICE_FILE = Path.home() / ".ccclean" / "notice.json"


def _notice_state() -> dict:
    try:
        data = json.loads(NOTICE_FILE.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    acked_version = data.get("version") or ""
    # 只认「当前这一版」的确认记录。免责声明改了内容就该重读一次，
    # 否则老用户永远看不到新增的那几条（比如「钥匙串条目删了回不来」）。
    return {
        "acked": bool(data.get("acked")) and acked_version == VERSION,
        "at": data.get("at") or 0,
        "version": acked_version,
        "current": VERSION,
    }


def _notice_ack() -> dict:
    state = {"acked": True, "at": time.time(), "version": VERSION}
    try:
        NOTICE_FILE.parent.mkdir(parents=True, exist_ok=True)
        NOTICE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    return state


def _json_default(obj):
    return str(obj)


def _scan_cached(force: bool = False) -> dict:
    with STATE["lock"]:
        scan = STATE.get("scan")
        if scan is None or force:
            scan = scanner.scan(with_network=True)
            STATE["scan"] = scan
            # 顺手把基线写给哨兵：塔是唯一知道「出口该在哪个国家」的一方，
            # Shield 自己扫不出这个结论，只能读。
            shield.write_baseline(scan)
    return scan


def _egress_baseline() -> tuple[str, int | None]:
    """塔记录的出口（打码后）与它的年龄。

    浏览器侧 WebRTC 的判定需要一个「出口应该是什么」的参照，
    这份参照和哨兵用的是同一个来源——shield.json 里的 egressIP。
    自己另存一份就会出现「塔说 A、哨兵说 B」的分裂。
    """
    data = shield.read()
    mask = str(data.get("egressIP") or "")
    at = int(data.get("egressAt") or 0)
    return mask, (max(0, int(time.time()) - at) if at else None)


def _tower_payload(force_scan: bool = False, with_scan: bool = False) -> dict:
    scan = _scan_cached(force_scan)
    data = tower.build(scan, ipcheck.check())
    out = {
        "ok": True,
        **data,
        "score": scan.get("score"),
        "grade": scan.get("grade"),
        "board": {"entries": leaderboard.list_entries()[:20], "stats": leaderboard.stats()},
    }
    if with_scan:
        out["scan"] = scan
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = f"CCclean/{VERSION}"
    protocol_version = "HTTP/1.1"

    # ---------------------------------------------------------- 基础
    def log_message(self, fmt, *args):
        pass

    def _send(self, status: int, body: bytes, ctype: str = "application/json; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status: int = 200):
        self._send(status, json.dumps(data, ensure_ascii=False, default=_json_default).encode("utf-8"))

    def _err(self, msg: str, status: int = 400):
        self._json({"ok": False, "error": msg}, status)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    # ---------------------------------------------------------- 路由
    def _local_request(self) -> bool:
        """Host / Origin 双重校验，挡 DNS 重绑定与跨站发起的请求。

        攻击者可以让 evil.com 解析到 127.0.0.1，但浏览器发来的 Host 会是
        evil.com，这里直接不认；同源页面发的请求 Origin 与本机 Host 一致，
        或者干脆没有 Origin（地址栏直接访问、curl）。
        """
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        return host in allowed and (not origin or origin == "http://" + host)

    def _session_ok(self) -> bool:
        """本机来源 + 会话令牌。两样都得对，缺一不可。"""
        return self._local_request() and secrets.compare_digest(
            self.headers.get("X-CClean-Token", ""), SESSION_TOKEN
        )

    def _guard(self) -> bool:
        """统一的接口闸门：放行返回 True，否则已经写好 403 响应并返回 False。"""
        if self._session_ok():
            return True
        self._err("请求来源无效，请重新打开本应用页面", 403)
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/api/privacy", "/api/ipv6", "/api/proxyfix",
                           "/api/region", "/api/align"):
            # 这几个接口自己用 PRIVACY_TOKEN，而且要先把令牌发给页面，不能走统一闸门
            if not self._local_request():
                return self._err("只允许本地应用页面访问", 403)
            if parsed.path == "/api/proxyfix":
                # 端口策略是用户在预览前选的，覆盖统计得按他选的那种算，
                # 否则预览里写的规则和实际会写下去的不是一回事。
                mode = (parse_qs(parsed.query).get("port") or [""])[0]
                return self._json({"ok": True, "token": PRIVACY_TOKEN,
                                   **proxyfix.status(mode)})
            module = {"privacy": privacy, "ipv6": ipv6cfg,
                      "region": regioncfg, "align": align}[
                          parsed.path.rsplit("/", 1)[-1]]
            return self._json({"ok": True, "token": PRIVACY_TOKEN, **module.status()})
        if parsed.path.startswith("/api/"):
            if not self._guard():
                return
            return self._api_get(parsed.path, parse_qs(parsed.query))
        return self._static(parsed.path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 先过闸门再读 body：没通过校验的请求连 4KB 的 JSON 都不必解析
        if path not in ("/api/privacy", "/api/ipv6", "/api/proxyfix",
                        "/api/region", "/api/align") \
                and path.startswith("/api/") and not self._guard():
            return

        body = self._body()

        if path == "/api/privacy":
            if not self._local_request() or not secrets.compare_digest(
                self.headers.get("X-CClean-Privacy-Token", ""), PRIVACY_TOKEN
            ):
                return self._err("请求来源无效，请重新打开本应用页面", 403)
            if not isinstance(body, dict) or body.get("action") not in ("enable", "restore") or body.get("confirm") is not True:
                return self._err("请先预览并确认要执行的操作")
            try:
                result = privacy.apply(body["action"] == "enable")
                STATE["scan"] = None
                return self._json({"ok": True, **result})
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                return self._err(str(exc), 400)

        if path == "/api/ipv6":
            if not self._local_request() or not secrets.compare_digest(
                self.headers.get("X-CClean-Privacy-Token", ""), PRIVACY_TOKEN
            ):
                return self._err("请求来源无效，请重新打开本应用页面", 403)
            if not isinstance(body, dict) or body.get("action") not in ("off", "restore") or body.get("confirm") is not True:
                return self._err("请先预览并确认要执行的操作")
            try:
                result = ipv6cfg.apply(body["action"])
                STATE["scan"] = None
                return self._json({"ok": True, **result})
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                return self._err(str(exc), 400)

        if path == "/api/proxyfix":
            if not self._local_request() or not secrets.compare_digest(
                self.headers.get("X-CClean-Privacy-Token", ""), PRIVACY_TOKEN
            ):
                return self._err("请求来源无效，请重新打开本应用页面", 403)
            if not isinstance(body, dict) or body.get("action") not in ("apply", "undo") \
                    or body.get("confirm") is not True:
                return self._err("请先预览并确认要执行的操作")
            try:
                result = proxyfix.apply(body["action"], body.get("portMode") or "proxy")
                STATE["scan"] = None
                return self._json({"ok": True, **result})
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                return self._err(str(exc), 400)

        if path == "/api/region":
            if not self._local_request() or not secrets.compare_digest(
                self.headers.get("X-CClean-Privacy-Token", ""), PRIVACY_TOKEN
            ):
                return self._err("请求来源无效，请重新打开本应用页面", 403)
            if not isinstance(body, dict) or body.get("action") not in ("apply", "restore") \
                    or body.get("confirm") is not True:
                return self._err("请先预览并确认要执行的操作")
            try:
                if body["action"] == "restore":
                    result = regioncfg.restore()
                else:
                    result = regioncfg.apply(body.get("region") or "",
                                             body.get("locale") or "")
                STATE["scan"] = None
                return self._json({"ok": True, **result})
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                return self._err(str(exc), 400)

        if path == "/api/align":
            if not self._local_request() or not secrets.compare_digest(
                self.headers.get("X-CClean-Privacy-Token", ""), PRIVACY_TOKEN
            ):
                return self._err("请求来源无效，请重新打开本应用页面", 403)
            if not isinstance(body, dict) or body.get("action") not in ("apply", "restore") \
                    or body.get("confirm") is not True:
                return self._err("请先预览并确认要执行的操作")
            try:
                if body["action"] == "restore":
                    result = align.restore()
                else:
                    keys = body.get("keys")
                    if not isinstance(keys, list):
                        return self._err("请先勾选要对齐的项目")
                    result = align.apply(keys,
                                         str(body.get("country") or ""),
                                         str(body.get("timezone") or ""),
                                         str(body.get("locale") or ""),
                                         str(body.get("language") or ""))
                STATE["scan"] = None
                return self._json({"ok": True, **result})
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                return self._err(str(exc), 400)

        if path == "/api/update":
            return self._update(body)

        if path == "/api/notice":
            return self._json({"ok": True, **_notice_ack()})

        if path == "/api/netcfg":
            try:
                state = netcfg.set_country((body.get("country") or "").strip())
            except ValueError as exc:
                return self._err(str(exc), 400)
            STATE["scan"] = None
            return self._json({"ok": True, **state})

        if path == "/api/scan":
            net = bool(body.get("net", True))
            with STATE["lock"]:
                data = scanner.scan(with_network=net)
                STATE["scan"] = data
            shield.write_baseline(data)
            # net=False 是「这次别碰网」。ipcheck 要访问外部接口，
            # 不能在这个开关下面偷偷跑——测试里正是靠它避免真实网络。
            if net:
                ipcheck.check(force=True)
            return self._json({"ok": True, **data})

        if path == "/api/preview":
            scan = STATE.get("scan")
            if not scan:
                return self._err("请先执行一次扫描", 409)
            plan = cleaner.build_plan(scan["items"], body.get("ids") or [])
            return self._json({"ok": True, "plan": plan, "running": cleaner.running_claude()})

        if path == "/api/kill-claude":
            return self._json({"ok": True, **cleaner.quit_claude()})

        if path == "/api/snapshot":
            try:
                return self._json(cleaner.full_snapshot())
            except cleaner.CleanError as exc:
                return self._err(str(exc), 400)

        if path == "/api/probe/webrtc":
            # 候选地址只能由浏览器给：ICE 是浏览器自己的栈，Python 那边
            # 发的 STUN 包走的是本机 UDP，两者不是一回事。
            # 先校验形状再谈基线：形状不对就没必要为它跑一次完整扫描。
            if not isinstance(body, dict) or not isinstance(body.get("candidates"), list):
                return self._err("缺少 candidates 字段", 400)
            mask, age = _egress_baseline()
            if not mask:
                # 还没有基线就先扫一次，否则这一项永远只能回「无法比对」
                _scan_cached(force=True)
                mask, age = _egress_baseline()
            try:
                verdict = browserwebrtc.save(body, mask=mask, age=age)
            except ValueError as exc:
                return self._err(str(exc), 400)
            # 结论变了，缓存作废；下一次取塔数据会重新算分
            STATE["scan"] = None
            return self._json({"ok": True, "verdict": verdict})

        if path == "/api/timezone":
            if not body.get("confirm"):
                return self._err("需要确认后才会请求系统授权", 400)
            ok, note = compat.apply_timezone((body.get("tz") or "").strip())
            return self._json({"ok": ok, "message": note, "tz": compat.timezone_name()})

        if path == "/api/uninstall":
            try:
                result = uninstall.execute(body.get("ids") or [], body.get("confirm") or "")
            except ValueError as exc:
                return self._err(str(exc), 400)
            # 状态目录可能已经被清掉，缓存必须作废；否则下一次读塔会拿到
            # 一份指向已删除文件的旧结果。
            STATE["scan"] = None
            self._json({"ok": True, **result, "left": uninstall.leftovers()})
            if result.get("quit"):
                # 应用包已经进废纸篓了。留一点时间把结果发回页面再退出，
                # 否则用户看到的是一个「连接被重置」。
                threading.Timer(2.0, _quit_process).start()
            return

        if path == "/api/clean":
            scan = STATE.get("scan")
            if not scan:
                return self._err("请先执行一次扫描", 409)
            try:
                result = cleaner.execute(scan["items"], body.get("ids") or [], body.get("confirm", ""))
            except cleaner.CleanError as exc:
                return self._err(str(exc), 400)
            STATE["scan"] = None
            return self._json({"ok": True, "result": result})

        if path == "/api/backups/restore":
            bid = (body.get("id") or "").strip()
            try:
                result = cleaner.restore(bid, body.get("confirm") or "")
            except cleaner.CleanError as exc:
                return self._err(str(exc), 400)
            STATE["scan"] = None
            return self._json({"ok": True, "result": result, "backups": cleaner.list_backups()})

        if path == "/api/profiles":
            name = (body.get("name") or "").strip()
            if not name:
                return self._err("请填写配置档名称")
            info = isolation.create_profile(
                name,
                (body.get("tz") or "UTC").strip(),
                (body.get("baseUrl") or "").strip(),
                bool(body.get("docker")),
            )
            return self._json({"ok": True, **info})

        if path == "/api/wizard/progress":
            progress = wizard.load_progress()
            if "checklist" in body and isinstance(body["checklist"], list):
                progress["checklist"] = [str(x) for x in body["checklist"]]
            if "ack" in body and isinstance(body["ack"], list):
                progress["ack"] = [str(x) for x in body["ack"]]
            wizard.save_progress(progress)
            return self._json({"ok": True})

        if path == "/api/wizard/mark":
            progress = wizard.load_progress()
            key = body.get("key")
            if key == "ip":
                progress["ip"] = {"opened": True, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
            elif key == "report":
                progress["report"] = time.strftime("%Y-%m-%d %H:%M")
            wizard.save_progress(progress)
            return self._json({"ok": True})

        if path == "/api/wizard/ack":
            progress = wizard.load_progress()
            level_id = (body.get("id") or "").strip()
            ack = set(progress.get("ack") or [])
            if body.get("on") is False:
                ack.discard(level_id)
            else:
                ack.add(level_id)
            progress["ack"] = sorted(ack)
            wizard.save_progress(progress)
            return self._json({"ok": True, "ack": progress["ack"]})

        if path == "/api/open":
            pane = (body.get("pane") or "").strip()
            if pane:
                cmd = compat.open_pane(pane)
                if not cmd:
                    return self._err("未知的设置面板", 400)
                compat.run_shell(cmd)
                return self._json({"ok": True})
            file = (body.get("file") or "").strip()
            if file:
                hosts = str(compat.hosts_path())
                kc = "/Library/Keychains/System.keychain" if compat.IS_MAC else "certmgr"
                allowed = {
                    hosts, "/etc/hosts",
                    str(Path.home() / ".claude" / "settings.json"),
                    str(Path.home() / ".claude" / "settings.local.json"),
                    str(Path.home() / ".claude.json"),
                    kc, "/Library/Keychains/System.keychain", "certmgr",
                }
                if file not in allowed:
                    return self._err("该文件不在允许列表内", 400)
                if file in ("certmgr", "/Library/Keychains/System.keychain") and compat.IS_WIN:
                    compat.run_shell('start "" "certmgr.msc"')
                    return self._json({"ok": True})
                target = hosts if file == "/etc/hosts" else file
                if not Path(target).exists() and file != "/etc/hosts":
                    return self._err("目标文件不存在", 404)
                compat.run_shell(compat.open_file_cmd(target))
                return self._json({"ok": True})
            url = (body.get("url") or "").strip()
            if not url.startswith("https://"):
                return self._err("只允许打开 https 地址")
            host = urlparse(url).hostname or ""
            if host not in ("ip.net.coffee", "www.ip.net.coffee"):
                return self._err("该地址不在允许列表内")
            compat.run_shell(compat.open_url_cmd(url))
            progress = wizard.load_progress()
            if url.rstrip("/").endswith("/claude"):
                progress["ip"] = {"opened": True, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
                wizard.save_progress(progress)
            return self._json({"ok": True})

        # ------------------------------------------------------ 魔塔
        if path == "/api/tower/fight":
            lid = (body.get("id") or "").strip()
            if not lid:
                return self._err("缺少关卡 id")
            res = tower.fight(_scan_cached(), lid, ipcheck.check())
            if not res.get("ok"):
                return self._err(res.get("error") or "出招失败", 409)
            return self._json({"ok": True, "battle": res["battle"], "state": res["state"]})

        if path == "/api/tower/sweep":
            fid = (body.get("floor") or "").strip()
            res = tower.sweep(_scan_cached(), fid, ipcheck.check())
            if not res.get("ok"):
                return self._err(res.get("error") or "扫荡失败", 409)
            return self._json({"ok": True, "ids": res["ids"], "state": res["state"]})

        if path == "/api/tower/retry":
            fid = (body.get("floor") or "").strip()
            res = tower.retry_floor(_scan_cached(), fid, ipcheck.check())
            if not res.get("ok"):
                return self._err(res.get("error") or "重闯失败", 409)
            return self._json({"ok": True, "state": res["state"]})

        if path == "/api/tower/boss":
            bid = (body.get("id") or "").strip()
            res = tower.fight_boss(_scan_cached(), bid, ipcheck.check())
            if not res.get("ok"):
                return self._err(res.get("error") or "守卫还没现身", 409)
            return self._json({"ok": True, "battle": res["battle"], "state": res["state"]})

        if path == "/api/tower/final":
            res = tower.fight_final(_scan_cached(), ipcheck.check())
            if not res.get("ok"):
                return self._err(res.get("error") or "塔顶还锁着", 409)
            return self._json({"ok": True, "battle": res["battle"], "state": res["state"]})

        if path == "/api/tower/heal":
            res = tower.heal(_scan_cached(), ipcheck.check())
            return self._json({"ok": True, "state": res["state"]})

        if path == "/api/tower/history":
            summary = body.get("summary")
            if not isinstance(summary, dict) or not summary.get("tour"):
                return self._err("不是一次完整的挑战结算")
            try:
                record = tower.record_tour(summary, skipped=bool(body.get("skipped")))
            except OSError as exc:
                return self._err(f"挑战历史写入失败：{exc}", 500)
            return self._json({"ok": True, "record": record, **tower.history_payload()})

        if path == "/api/tower/reset":
            tower.reset()
            return self._json({"ok": True, "state": _tower_payload()})

        if path == "/api/quit":
            self._json({"ok": True})
            threading.Timer(0.35, _quit_process).start()
            return

        # ------------------------------------------------------ 勇士榜
        if path == "/api/leaderboard":
            days = body.get("days")
            try:
                days = int(days) if days not in (None, "") else None
            except (TypeError, ValueError):
                days = None
            entry = leaderboard.add(
                body.get("name") or "",
                days=days,
                hp=body.get("hp") or 0,
                level=body.get("level") or 1,
                exp=body.get("exp") or 0,
                duration_sec=body.get("durationSec") or 0,
                title=body.get("title") or "",
                note=body.get("note") or "",
            )
            return self._json({
                "ok": True,
                "entry": entry,
                "entries": leaderboard.list_entries(),
                "stats": leaderboard.stats(),
            })

        if path == "/api/leaderboard/delete":
            ok = leaderboard.remove(body.get("ts") or 0)
            return self._json({"ok": ok, "entries": leaderboard.list_entries(), "stats": leaderboard.stats()})

        if path == "/api/leaderboard/export":
            entry = body.get("entry") if isinstance(body.get("entry"), dict) else None
            dest = _save_md(
                f"ccclean-勇士榜-{time.strftime('%Y%m%d-%H%M')}.md",
                leaderboard.export_md(entry),
            )
            return self._json({
                "ok": True,
                "path": str(dest).replace(str(Path.home()), "~"),
                "absolute": str(dest),
            })

        if path == "/api/watch/start":
            port = int(body.get("port") or 0)
            r = watch.start(port)
            if r.get("error"):
                return self._err(r["error"], 500)
            return self._json({"ok": True, **r})
        if path == "/api/watch/stop":
            return self._json({"ok": True, **watch.stop()})

        if path == "/api/checklist/toggle":
            progress = wizard.load_progress()
            cid = (body.get("id") or "").strip()
            cur = set(progress.get("checklist") or [])
            if body.get("on") is False:
                cur.discard(cid)
            else:
                cur.add(cid)
            progress["checklist"] = sorted(cur)
            wizard.save_progress(progress)
            return self._json({"ok": True, "done": progress["checklist"]})


        if path == "/api/tower/tour-report":
            tid = body.get("id")
            if not tid:
                return self._err("缺少挑战记录 id", 400)
            rec = tower.tour_record(tid)
            if not rec:
                return self._err("这条挑战记录不存在（可能已被滚动清理）", 404)
            no = rec.get("no") or 0
            tag = time.strftime("%Y%m%d-%H%M", time.localtime(rec.get("ts") or time.time()))
            dest = _save_md(f"ccclean-挑战战报-{no:03d}-{tag}.md", _redact(_tour_report_md(rec)))
            return self._json({"ok": True, "path": str(dest).replace(str(Path.home()), "~"), "absolute": str(dest)})

        if path == "/api/report":
            return self._api_get(path, {})

        return self._err("未知接口", 404)

    def _update(self, body: dict):
        if not isinstance(body, dict):
            return self._err("请求内容无效")
        action = str(body.get("action") or "")
        current_shield = updater.installed_shield_version()
        try:
            if action == "configure":
                config = updater.configure(
                    str(body.get("repo") or ""),
                    auto_check=body.get("autoCheck"),
                    check_hours=body.get("checkHours"),
                )
                return self._json({"ok": True, "config": config})
            if action == "check":
                updater.check(force=True, current_tower=VERSION, current_shield=current_shield)
                return self._json(updater.status(VERSION, current_shield))
            if action == "download":
                started = updater.download_async(VERSION, current_shield)
                return self._json({"ok": True, "started": started,
                                   **updater.status(VERSION, current_shield)})
            if action == "install":
                # 换掉两个应用、重启两个进程，必须由用户点确认按钮触发
                if body.get("confirm") is not True:
                    return self._err("安装会重启塔与哨兵，需要确认")
                return self._json(updater.install(
                    confirm=True, current_tower=VERSION,
                    current_shield=current_shield, launch=True))
            if action == "discard":
                return self._json({"ok": True, **updater.discard()})
            return self._err("未知操作")
        except updater.UpdateError as exc:
            return self._err(str(exc), 409)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            return self._err(str(exc), 400)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/") and not self._guard():
            return
        if parsed.path == "/api/profiles":
            q = parse_qs(parsed.query)
            return self._json({"ok": True, **isolation.delete_profile((q.get("slug") or [""])[0])})
        return self._err("未知接口", 404)

    # ---------------------------------------------------------- API
    def _api_get(self, path: str, query: dict):
        if path == "/api/meta":
            return self._json(
                {
                    "version": VERSION,
                    "home": str(Path.home()),
                    "platform": sys.platform,
                    "python": sys.version.split()[0],
                    "claudeDir": str(Path.home() / ".claude"),
                    "categories": rules.CATEGORY_META,
                    "severityLabel": rules.SEVERITY_LABEL,
                    "disclaimer": rules.DISCLAIMER,
                    "app": "--app" in sys.argv,
                }
            )
        if path == "/api/notice":
            return self._json({"ok": True, **_notice_state()})
        if path == "/api/netcfg":
            return self._json({"ok": True, **netcfg.status()})
        if path == "/api/timezone":
            return self._json({"ok": True, "tz": compat.timezone_name(),
                               "supported": compat.IS_MAC or compat.IS_WIN})
        if path == "/api/shield":
            return self._json({"ok": True, **shield.status()})
        if path == "/api/egress":
            limit = 40
            try:
                limit = max(1, min(60, int((query.get("limit") or [limit])[0])))
            except (TypeError, ValueError):
                pass
            return self._json({
                "ok": True,
                "history": ipcheck.history(limit),
                "drift": ipcheck.drift(),
                "file": str(ipcheck.EGRESS_FILE).replace(str(Path.home()), "~"),
            })
        if path == "/api/tower":
            force = (query.get("rescan") or ["0"])[0] == "1"
            return self._json(_tower_payload(force_scan=force, with_scan=True))
        if path == "/api/tower/preview":
            force = (query.get("rescan") or ["0"])[0] == "1"
            return self._json(tower.preview(_scan_cached(force), ipcheck.check()))
        if path == "/api/tower/history":
            return self._json({"ok": True, **tower.history_payload()})
        if path == "/api/leaderboard":
            return self._json({
                "ok": True,
                "entries": leaderboard.list_entries(),
                "stats": leaderboard.stats(),
            })
        if path == "/api/ipcheck":
            force = (query.get("force") or ["0"])[0] == "1"
            return self._json({"ok": True, "ip": ipcheck.check(force=force)})
        if path == "/api/scan":
            net = (query.get("net") or ["1"])[0] != "0"
            with STATE["lock"]:
                data = scanner.scan(with_network=net)
                STATE["scan"] = data
            return self._json({"ok": True, **data})
        if path == "/api/checklist":
            progress = wizard.load_progress()
            return self._json(
                {
                    "ok": True,
                    "groups": checklist.GROUPS,
                    "total": checklist.TOTAL,
                    "done": progress.get("checklist") or [],
                }
            )
        if path == "/api/backups":
            return self._json({"ok": True, "backups": cleaner.list_backups()})
        if path == "/api/profiles":
            return self._json({"ok": True, "profiles": isolation.list_profiles()})
        if path == "/api/watch":
            return self._json({"ok": True, **watch.status()})
        if path == "/api/uninstall":
            return self._json({"ok": True, **uninstall.plan()})
        if path == "/api/update":
            current_shield = updater.installed_shield_version()
            updater.auto_maybe(VERSION, current_shield)
            return self._json(updater.status(VERSION, current_shield))
        if path == "/api/tool/hosts-block":
            dest = _save_md(
                f"ccclean-遥测封缄-{time.strftime('%Y%m%d-%H%M')}.txt",
                deep.telemetry_block_text() + "\n",
            )
            return self._json({"ok": True, "path": str(dest).replace(str(Path.home()), "~")})
        if path == "/api/report":
            scan = STATE.get("scan")
            if not scan:
                return self._err("请先执行一次扫描", 409)
            dest = _save_md(f"ccclean-环境报告-{time.strftime('%Y%m%d-%H%M')}.md", _redact(_report_md(scan)))
            return self._json({"ok": True, "path": str(dest).replace(str(Path.home()), "~"), "absolute": str(dest)})

        return self._err("未知接口", 404)

    # ---------------------------------------------------------- 静态
    def _static(self, path: str):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (WEB / rel).resolve()
        if not str(target).startswith(str(WEB.resolve())) or not target.exists() or target.is_dir():
            return self._send(404, b"Not Found", "text/plain; charset=utf-8")
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        data = target.read_bytes()
        if target.name == "index.html":
            # 会话令牌与版本号直接写进页面，而不是让前端再请求一次：否则页面
            # 已经渲染、令牌还没取回来的那几百毫秒里，点任何按钮都会 403；
            # 版本号同理——前端要拿它判断免责声明是不是「这一版」的。
            marker = b'<meta charset="utf-8">'
            inject = (
                marker
                + b'\n<meta name="cc-token" content="' + SESSION_TOKEN.encode() + b'">'
                + b'\n<meta name="cc-version" content="' + VERSION.encode() + b'">'
            )
            if marker in data:
                data = data.replace(marker, inject, 1)
        return self._send(200, data, ctype)


def _redact(text: str) -> str:
    """战报脱敏：主机名、用户名、公网 IP 换成稳定占位符，方便分享。"""
    import hashlib

    def token(prefix: str, raw: str) -> str:
        return f"[{prefix}-{hashlib.sha1(raw.encode()).hexdigest()[:6]}]"

    out = text
    secrets: list[tuple[str, str]] = []
    hostnames = [compat.computer_name(), _run(["hostname"])]
    if compat.IS_MAC:
        hostnames.append(_run(["scutil", "--get", "LocalHostName"]))
    for hn in hostnames:
        if hn and len(hn) > 2 and hn not in ("-", "localhost"):
            secrets.append((hn, token("host", hn)))
    user = Path.home().name
    if user:
        secrets.append((user, token("user", user)))
    # 公网 IP：把战报里出现的 IPv4 都换掉（公共 DNS 除外）
    public_dns = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "114.114.114.114", "223.5.5.5", "9.9.9.9", "0.0.0.0", "127.0.0.1"}
    for m in sorted(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", out)), key=len, reverse=True):
        if m in public_dns or m.startswith("192.168.") or m.startswith("10.") or m.startswith("172.16.") or m.startswith("169.254."):
            continue
        secrets.append((m, token("ip", m)))
    for raw, tok in secrets:
        out = out.replace(raw, tok)
    return out


def _run(cmd) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=4, check=False)
        return (r.stdout or "").strip()
    except Exception:
        return ""


def _save_md(name: str, content: str) -> Path:
    """把报告写到下载目录，并在访达里定位。避免 WKWebView 走下载流程把界面顶掉。"""
    dest_dir = Path.home() / "Downloads"
    if not dest_dir.exists():
        dest_dir = Path.home() / "Desktop"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / name
    stem, _, ext = name.rpartition(".")
    i = 2
    while dest.exists():
        dest = dest_dir / f"{stem}-{i}.{ext}"
        i += 1
    dest.write_text(content, encoding="utf-8")
    try:
        if compat.IS_MAC:
            subprocess.Popen(["open", "-R", str(dest)])
        else:
            os.startfile(str(dest.parent))  # type: ignore[attr-defined]
    except Exception:
        pass
    return dest


def _report_md(scan: dict) -> str:
    lines = [
        "# CCclean · Claude 环境洁净度报告",
        "",
        f"- 扫描时间：{scan['scannedAt']}",
        f"- 洁净度评分：**{scan['score']} / 100**（{scan['grade']} 级 · {scan['verdict']}）",
        f"- 系统时区：{scan['system']['timezone']}",
        f"- 出口：{scan['network'].get('country') or '-'} / {scan['network'].get('city') or '-'}"
        f" · {scan['network'].get('org') or '-'}"
        f" · {scan['network'].get('asn_type') or ('机房（推断）' if scan['network'].get('hosting') else '未知类型')}",
        "",
        f"> {scan['verdictText']}",
        "",
        "## 统计",
        "",
        "| 级别 | 数量 |",
        "| --- | --- |",
    ]
    for sev in rules.SEVERITY_ORDER:
        lines.append(f"| {rules.SEVERITY_LABEL[sev]} | {scan['counts'].get(sev, 0)} |")

    lines += ["", "## 检测明细", ""]
    current = None
    for item in scan["items"]:
        cat = rules.CATEGORY_META.get(item["category"], {}).get("label", item["category"])
        if cat != current:
            lines += ["", f"### {cat}", ""]
            current = cat
        badge = rules.SEVERITY_LABEL[item["severity"]]
        lines.append(f"- **[{badge}] {item['title']}**")
        if item["detail"]:
            lines.append(f"  - {item['detail']}")
        for ev in item["evidence"]:
            lines.append(f"  - `{ev['label']}`: `{ev['value']}`")
        if item["advice"]:
            lines.append(f"  - 建议：{item['advice']}")

    lines += ["", "---", "", rules.DISCLAIMER, ""]
    return "\n".join(lines)


def _tour_report_md(rec: dict) -> str:
    """一次全塔挑战的战报：按存档里的快照导出，随时可重导。"""
    no = rec.get("no")
    total = rec.get("total") or 0
    defeated = rec.get("defeated") or 0
    failed = rec.get("failed") or []
    floors = rec.get("floors") or []
    gear = rec.get("gear") or []
    lines = [
        "# Claude Tower · 全塔挑战战报",
        "",
        f"- 挑战编号：**#{no}**",
        f"- 挑战时间：{rec.get('at') or '-'}",
        f"- 结果：**{'全塔通关' if rec.get('cleared') else f'{len(failed)} 项检测未通过'}**"
        + (" · 跳过演出" if rec.get("skipped") else ""),
        f"- 击杀：{defeated} / {total} · 阵亡 {rec.get('deaths') or 0} 次"
        f" · 通关楼层 {rec.get('clearedFloors') or 0} / 4 · 层主 {rec.get('bosses') or 0} / 4",
        "",
    ]
    if floors:
        lines += ["## 楼层进度", "", "| 层 | 击杀 | 状态 |", "| --- | --- | --- |"]
        for f in floors:
            lines.append(f"| {f.get('no')} {f.get('name')} | {f.get('defeated')}/{f.get('count')} | {'通关' if f.get('cleared') else '未通关'} |")
        lines.append(f"| 05 塔顶 | {1 if rec.get('cleared') else 0}/1 | {'通关' if rec.get('cleared') else '未通关'} |")
        lines.append("")
    if gear:
        lines += ["## 拾取装备", ""]
        for g in gear:
            lines.append(f"- {g.get('name')}（{g.get('label')} +{g.get('value')}）")
        lines.append("")
    if failed:
        lines += ["## 未通过检测明细", ""]
        for x in failed:
            mon = x.get("monster") or {}
            sev = rules.SEVERITY_LABEL.get(x.get("sev"), x.get("sev") or "info")
            lines.append(f"### [{sev}] {x.get('id')} {x.get('title')}")
            lines.append(f"- 位置：第 {x.get('floorNo')} 层 · {x.get('floorName')} · {mon.get('name') or '?'}")
            if x.get("value"):
                lines.append(f"- 结论：{x['value']}")
            if x.get("detail"):
                lines.append(f"- 说明：{x['detail']}")
            if x.get("advice"):
                lines.append(f"- 建议：{x['advice']}")
            how = x.get("how")
            if isinstance(how, str) and how.startswith("["):
                try:
                    how = ast.literal_eval(how)
                except Exception:
                    pass
            if how:
                for step in (how if isinstance(how, list) else [how]):
                    lines.append(f"  - {step}")
            if x.get("fixIds"):
                lines.append(f"- 可自动清理项：`{'`、`'.join(x['fixIds'])}`")
            lines.append("")
    else:
        lines += ["## 未通过检测明细", "", "全部检测通过，塔顶的灯灭了。", ""]
    lines += ["---", "", "挑战是只读推演：这份快照记录的是那一趟的检测结论，",
              "真实闯关进度、阵亡记录与装备都没有被改写。", "", rules.DISCLAIMER, ""]
    return "\n".join(lines)


def _quit_process() -> None:
    """「退出游戏」走这里：先让响应发出去，再清掉 runtime.json 并结束进程。"""
    try:
        (RUNTIME_DIR / "runtime.json").unlink(missing_ok=True)
    except Exception:
        pass
    os._exit(0)


def _free_port(start: int = 8787) -> int:
    for port in range(start, start + 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("找不到可用端口")


def _write_runtime(url: str, port: int) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    target = RUNTIME_DIR / "runtime.json"
    target.write_text(
        json.dumps({"pid": os.getpid(), "url": url, "port": port, "at": time.time()}), encoding="utf-8"
    )

    def _cleanup():
        try:
            if target.exists():
                target.unlink()
        except Exception:
            pass

    atexit.register(_cleanup)


def _watch_parent(server) -> None:
    """宿主被强杀时子进程会变成孤儿并继续占着端口，这里主动退出。

    宿主正常退出会先 terminate 子进程；但 kill -9 宿主、或从终端直接 Ctrl+C
    时，Python 子进程会被 launchd 收养（ppid 变 1），端口就一直被占着。
    """
    ppid0 = os.getppid()
    while True:
        time.sleep(2.0)
        if os.getppid() != ppid0:
            try:
                server.server_close()
            finally:
                os._exit(0)


def _install_signal_handlers() -> None:
    """收到 SIGTERM/SIGINT 时直接退出，避免 serve_forever 卡住不退。"""

    def _bye(signum, frame):
        os._exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _bye)
        except (ValueError, OSError):
            pass


def main():
    # 独立诊断走命令行：不启服务、不读系统设置，测完就退（退出码给脚本用）
    if any(a in ("--diagnose-proxy", "--proxy", "-p") or a.startswith(("--diagnose-proxy=", "--proxy=")) for a in sys.argv[1:]):
        sys.exit(proxydiag.main(sys.argv[1:]))
    app_mode = "--app" in sys.argv
    port_arg = None
    for i, a in enumerate(sys.argv):
        if a == "--port" and i + 1 < len(sys.argv):
            port_arg = int(sys.argv[i + 1])
    port = port_arg or _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"

    if app_mode:
        _write_runtime(url, port)
        _install_signal_handlers()
        threading.Thread(target=_watch_parent, args=(server,), daemon=True).start()
    else:
        print(f"\n  CCclean v{VERSION}")
        print(f"  Claude 环境洁净度检测 · {url}")
        print("  按 Ctrl+C 退出\n")

    if not app_mode and "--no-open" not in sys.argv:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    # 启动后隔几秒再查更新，别和首屏扫描抢网络；未配置更新源时直接返回
    def _auto_update():
        time.sleep(6)
        try:
            updater.auto_maybe(VERSION, updater.installed_shield_version())
        except Exception:
            pass

    threading.Thread(target=_auto_update, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if not app_mode:
            print("\n  已退出。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
