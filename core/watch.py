"""观察哨：本地请求观察代理。

把 Claude 的 HTTP(S) 代理指到 127.0.0.1:<port>，它会把 CONNECT/HTTP 请求的
目标主机与时间记下来，原样转发到上游——只记录元数据，不解密 TLS。
不写任何配置，不进系统设置，关掉即停。
"""

from __future__ import annotations

import select
import socket
import socketserver
import threading
import time
from pathlib import Path

from .telemetry import target_label

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
LOG_FILE = STATE_DIR / "watch.log"

_BUF = 64 * 1024

_state = {"server": None, "thread": None, "port": 0, "started": None, "hits": 0}
# start() 内记录启动日志时会再次获取同一把锁。
_lock = threading.RLock()


def _log(line: str):
    line = line.rstrip("\n")
    with _lock:
        _state["hits"] += 1
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')}  {line}\n")
    except OSError:
        pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 16384:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                head += chunk
            first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = first.split(" ")
            method = parts[0].upper() if parts else ""
            if method == "CONNECT" and len(parts) >= 2:
                host_port = parts[1]
                host, _, port = host_port.rpartition(":")
                _log(f"CONNECT  {host}:{port or '443'}  [{target_label(host)}]")
                self._tunnel(host, int(port or 443))
            elif method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH") and len(parts) >= 2:
                host_hdr = next(
                    (ln.split(":", 1)[1].strip() for ln in head.decode("latin-1", "replace").split("\r\n")[1:]
                     if ln.lower().startswith("host:")),
                    "",
                )
                _log(f"{method:<7} {host_hdr}  [{target_label(host_hdr.split(':')[0])}]")
                self._plain_http(parts[1], host_hdr, head)
            else:
                _log(f"未知请求：{first[:80]}")
        except Exception:
            return

    def _tunnel(self, host, port):
        try:
            up = socket.create_connection((host, port), timeout=10)
        except OSError as e:
            try:
                self.request.sendall(f"HTTP/1.1 502 {e}\r\n\r\n".encode())
            except OSError:
                pass
            return
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            up.close()
            return
        self._relay(up)

    def _plain_http(self, url, host_hdr, head):
        host, _, port = (host_hdr or "").partition(":")
        if not host:
            _log("HTTP 请求缺少 Host 头")
            return
        try:
            up = socket.create_connection((host, int(port or 80)), timeout=10)
        except OSError:
            return
        try:
            up.sendall(head)
            self._relay(up)
        except OSError:
            up.close()

    def _relay(self, up: socket.socket):
        try:
            with up:
                while True:
                    r, _w, _x = select.select([self.request, up], [], [], 60)
                    if not r:
                        break
                    for s in r:
                        data = s.recv(_BUF)
                        if not data:
                            return
                        (up if s is self.request else self.request).sendall(data)
        except OSError:
            pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(port: int = 0) -> dict:
    with _lock:
        if _state["server"]:
            return {"running": True, "port": _state["port"], "already": True}
        try:
            LOG_FILE.write_text(f"# 观察哨日志 · 启动于 {time.strftime('%Y-%m-%d %H:%M:%S')}\n", encoding="utf-8")
        except OSError:
            pass
        try:
            srv = _Server(("127.0.0.1", port or 0), _Handler)
        except OSError as e:
            return {"running": False, "error": str(e)}
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.4}, daemon=True)
        t.start()
        _state.update({"server": srv, "thread": t, "port": srv.server_address[1], "started": time.time(), "hits": 0})
        _log(f"观察哨上线，监听 127.0.0.1:{_state['port']}")
        return {"running": True, "port": _state["port"], "already": False}


def stop() -> dict:
    with _lock:
        srv = _state["server"]
        _state.update({"server": None, "thread": None, "port": 0, "started": None})
    if srv:
        _log("观察哨收哨")
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    return {"running": False}


def status() -> dict:
    lines = []
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            pass
    with _lock:
        running = bool(_state["server"])
        port = _state["port"]
        hits = _state["hits"]
    return {
        "running": running,
        "port": port,
        "hits": hits,
        "log": lines[-40:],
    }
