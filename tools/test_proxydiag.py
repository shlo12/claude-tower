#!/usr/bin/env python3
"""独立代理诊断：地址解析、CONNECT / SOCKS5 握手、退出码。

握手部分对着本地假代理跑，不联网、不碰真实节点。

    python3 tools/test_proxydiag.py
"""

from __future__ import annotations

import io
import json
import socket
import sys
import threading
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import proxydiag


def _recv_exact(conn, size):
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise AssertionError("对端提前关闭")
        buf += chunk
    return buf


class FakeProxy(threading.Thread):
    """一次性的假代理：按脚本应答，并把收到的字节记下来。"""

    def __init__(self, steps):
        super().__init__(daemon=True)
        self.steps = steps
        self.got = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.error = None

    def run(self):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(3)
            try:
                for read, reply in self.steps:
                    self.got.append(read(conn) if callable(read) else read)
                    if reply:
                        conn.sendall(reply)
                time.sleep(0.15)      # 让客户端先把 socket 用起来
            finally:
                conn.close()
        except Exception as exc:      # 让断言看到原因，而不是静默超时
            self.error = exc
        finally:
            self.sock.close()


def _http_steps(status_line=b"HTTP/1.1 200 Connection established\r\n\r\n"):
    def read_head(conn):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf
    return [(read_head, status_line)]


def _socks_steps(rep=0x00):
    def reply(code):
        return b"\x05" + bytes([code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"

    def read_greet(conn):
        return _recv_exact(conn, 3)

    def read_connect(conn):
        head = _recv_exact(conn, 4)
        alen = _recv_exact(conn, 1)[0]
        host = _recv_exact(conn, alen)
        port = _recv_exact(conn, 2)
        return (host.decode(), int.from_bytes(port, "big"))

    return [(read_greet, b"\x05\x00"), (read_connect, reply(rep))]


class ParseTests(unittest.TestCase):
    def test_accepts_the_three_real_schemes(self):
        self.assertEqual(proxydiag.parse_proxy("http://127.0.0.1:7890")["port"], 7890)
        self.assertEqual(proxydiag.parse_proxy("socks5://127.0.0.1:1080")["scheme"],
                         "socks5")
        self.assertEqual(proxydiag.parse_proxy("socks5h://localhost:1080")["host"],
                         "localhost")

    def test_bare_host_port_defaults_to_http(self):
        out = proxydiag.parse_proxy("127.0.0.1:7890")
        self.assertEqual(out["scheme"], "http")

    def test_rejects_what_it_cannot_do(self):
        cases = {
            "": "缺少代理地址",
            "ftp://127.0.0.1:21": "不支持",
            "http://127.0.0.1": "要带端口",
            "http://user:pass@127.0.0.1:7890": "用户名密码",
            "http://127.0.0.1:7890/path": "路径",
            "https://127.0.0.1:7890": "https://",
        }
        for url, needle in cases.items():
            with self.assertRaises(proxydiag.ProxyError) as ctx:
                proxydiag.parse_proxy(url)
            self.assertIn(needle, str(ctx.exception), url)


class HandshakeTests(unittest.TestCase):
    def test_http_connect_sends_the_right_request(self):
        server = FakeProxy(_http_steps())
        server.start()
        sock = proxydiag._connect_http(
            {"host": "127.0.0.1", "port": server.port}, "api.anthropic.com", 443, 3)
        sock.close()
        server.join(3)
        self.assertIsNone(server.error)
        self.assertIn(b"CONNECT api.anthropic.com:443 HTTP/1.1",
                      server.got[0])

    def test_http_connect_refusal_is_reported(self):
        server = FakeProxy(_http_steps(b"HTTP/1.1 403 Forbidden\r\n\r\n"))
        server.start()
        with self.assertRaises(OSError) as ctx:
            proxydiag._connect_http(
                {"host": "127.0.0.1", "port": server.port}, "claude.ai", 443, 3)
        server.join(3)
        self.assertIn("403", str(ctx.exception))

    def test_socks5_asks_the_proxy_to_resolve_the_name(self):
        """发域名而不是本地解析——socks5h 的语义，也避开本地 DNS 泄漏。"""
        server = FakeProxy(_socks_steps())
        server.start()
        sock = proxydiag._connect_socks5(
            {"host": "127.0.0.1", "port": server.port}, "api.anthropic.com", 443, 3)
        sock.close()
        server.join(3)
        self.assertIsNone(server.error)
        self.assertEqual(server.got[1], ("api.anthropic.com", 443))

    def test_socks5_refusal_is_reported(self):
        server = FakeProxy(_socks_steps(rep=0x05))
        server.start()
        with self.assertRaises(OSError) as ctx:
            proxydiag._connect_socks5(
                {"host": "127.0.0.1", "port": server.port}, "claude.ai", 443, 3)
        server.join(3)
        self.assertIn("连接被拒绝", str(ctx.exception))


class ProbeTests(unittest.TestCase):
    def fake_head(self, ok_flags):
        rows = iter(ok_flags)

        def _head(host, path, proxy, timeout):
            ok = next(rows)
            return {"host": host, "path": path, "ok": ok,
                    "status": 401 if ok else 0, "ms": 12, "note": "", "error": ""}
        return _head

    def test_both_reachable(self):
        with patch.object(proxydiag, "_head", self.fake_head([True, True])):
            out = proxydiag.probe("http://127.0.0.1:7890")
        self.assertTrue(out["ok"])
        self.assertIn("两条都到达", out["summary"])
        self.assertEqual(len(out["targets"]), 2)

    def test_one_reachable(self):
        with patch.object(proxydiag, "_head", self.fake_head([True, False])):
            out = proxydiag.probe("http://127.0.0.1:7890")
        self.assertFalse(out["ok"])
        self.assertIn("只有一条到达", out["summary"])

    def test_none_reachable(self):
        with patch.object(proxydiag, "_head", self.fake_head([False, False])):
            out = proxydiag.probe("socks5://127.0.0.1:1080")
        self.assertFalse(out["ok"])
        self.assertIn("都没到达", out["summary"])


class CliTests(unittest.TestCase):
    def test_invalid_timeouts_and_unknown_flags_are_rejected(self):
        for args in (["--proxy", "http://127.0.0.1:7890", "--timeout", "nan"],
                     ["--proxy", "http://127.0.0.1:7890", "--timeout", "inf"], ["--unknown"]):
            code, _, _ = self.run_main(args)
            self.assertEqual(code, 2)

    def run_main(self, argv, result=None):
        out, err = io.StringIO(), io.StringIO()
        patches = [redirect_stdout(out), redirect_stderr(err)]
        if result is not None:
            patches.append(patch.object(proxydiag, "probe", lambda *a, **k: result))
        for p in patches:
            p.__enter__()
        try:
            code = proxydiag.main(argv)
        finally:
            for p in reversed(patches):
                p.__exit__(None, None, None)
        return code, out.getvalue(), err.getvalue()

    def test_exit_0_when_both_reachable(self):
        code, out, _ = self.run_main(
            ["--diagnose-proxy", "http://127.0.0.1:7890"],
            {"ok": True, "summary": "两条都到达", "targets": []})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"], "两条都到达")

    def test_exit_1_when_not_reachable(self):
        code, _, _ = self.run_main(
            ["--diagnose-proxy", "http://127.0.0.1:7890"],
            {"ok": False, "summary": "两条都没到达", "targets": []})
        self.assertEqual(code, 1)

    def test_exit_2_on_bad_address(self):
        code, _, err = self.run_main(["--diagnose-proxy", "https://127.0.0.1:7890"])
        self.assertEqual(code, 2)
        self.assertIn("https://", err)

    def test_exit_2_without_proxy(self):
        code, _, err = self.run_main(["--diagnose-proxy"])
        self.assertEqual(code, 2)
        self.assertIn("缺少代理地址", err)

    def test_help_exits_0(self):
        code, out, _ = self.run_main(["--diagnose-proxy", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("退出码", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
