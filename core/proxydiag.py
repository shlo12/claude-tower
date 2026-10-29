"""独立代理诊断：给一条代理地址，测它能不能把 Claude 送出去。

和 App 里那一行「传输」的区别：那一行测的是**当前系统路径**（TUN / 系统
代理 / 直连，由系统决定），这里测的是**你指定的那一条**，不改系统设置、
不读客户端配置。换节点之前先验一遍，比切过去发现不通再切回来强——切来
切去本身就是一次出口漂移。

只发 `HEAD`，不带任何凭据，证书照常校验。到达即算通过：`401` / `403` 是
预期结果（这一测本来就没有身份），不算失败。

退出码：`0` 两条都到达；`1` 至少一条没到达；`2` 代理地址或参数不合法。
"""
from __future__ import annotations

import json
import math
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

TIMEOUT = 8.0
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
TARGETS = (
    ("api.anthropic.com", "/v1/models"),
    ("claude.ai", "/"),
)
SCHEMES = ("http", "https", "socks5", "socks5h")
SOCKS_ERRORS = {
    1: "代理内部错误", 2: "规则不允许", 3: "网络不可达",
    4: "主机不可达", 5: "连接被拒绝", 6: "TTL 过期",
    7: "不支持的命令", 8: "不支持的地址类型",
}


class ProxyError(ValueError):
    """地址或参数不合法（退出码 2），不是「代理不通」。"""


# ---------------------------------------------------------------- 地址

def parse_proxy(url: str) -> dict:
    """`http://127.0.0.1:7890` / `socks5://127.0.0.1:1080` → 结构化。

    https:// 代理（对代理本身加密）不做：要在一个 TLS 连接里再 CONNECT，
    标准库的 http.client 干不了，自己写又容易写成一个「看起来测了」的东西。
    遇到就明说，不假装支持。
    """
    raw = (url or "").strip()
    if not raw:
        raise ProxyError("缺少代理地址，例如 http://127.0.0.1:7890")
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise ProxyError(f"代理地址解析失败：{exc}") from exc
    scheme = (parts.scheme or "").lower()
    if scheme not in SCHEMES:
        raise ProxyError(f"不支持的代理类型 {scheme or '空'}；支持 "
                         "http / socks5 / socks5h")
    if scheme == "https":
        raise ProxyError("不支持 https:// 代理（对代理本身加密）。"
                         "Clash 系的 mixed-port 同时接受明文 CONNECT，"
                         "把地址写成 http://127.0.0.1:<端口> 即可")
    host = (parts.hostname or "").strip()
    if not host:
        raise ProxyError("代理地址里没有主机名")
    try:
        port = parts.port
    except ValueError as exc:
        raise ProxyError(f"端口不合法：{exc}") from exc
    if not port:
        raise ProxyError("代理地址要带端口，例如 http://127.0.0.1:7890")
    if parts.username or parts.password:
        # 带认证的代理要把凭据塞进 CONNECT，本工具不处理——也不该把密码
        # 出现在命令行历史和日志里
        raise ProxyError("不支持带用户名密码的代理地址")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ProxyError("代理地址不该带路径或参数")
    return {"scheme": scheme, "host": host, "port": port, "url": raw}


# ---------------------------------------------------------------- 传输

def _recv_exact(sock, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("连接被对端关闭")
        buf += chunk
    return buf


def _read_until(sock, marker: bytes, limit: int) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise OSError("响应头过长")
    return buf


def _connect_http(proxy: dict, host: str, port: int, timeout: float):
    sock = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\n"
                      f"Host: {host}:{port}\r\n\r\n").encode())
        head = _read_until(sock, b"\r\n\r\n", 8192)
        line = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if " 200" not in line:
            raise OSError(f"代理拒绝 CONNECT：{line[:60] or '无响应'}")
        return sock
    except Exception:
        sock.close()
        raise


def _connect_socks5(proxy: dict, host: str, port: int, timeout: float):
    sock = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("代理不接受免认证的 SOCKS5 连接")
        name = host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name
                     + port.to_bytes(2, "big"))
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError("SOCKS5 连接失败：" + SOCKS_ERRORS.get(head[1], str(head[1])))
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 4:
            _recv_exact(sock, 16)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _open(proxy: dict, host: str, port: int, timeout: float):
    if proxy["scheme"] in ("socks5", "socks5h"):
        return _connect_socks5(proxy, host, port, timeout)
    return _connect_http(proxy, host, port, timeout)


def _head(host: str, path: str, proxy: dict, timeout: float) -> dict:
    started = time.time()
    out = {"host": host, "path": path, "ok": False, "status": 0,
           "ms": 0, "note": "", "error": ""}
    sock = None
    tls = None
    try:
        sock = _open(proxy, host, 443, timeout)
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock = None  # 交给 tls 管了
        tls.settimeout(timeout)
        tls.sendall((f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\n"
                     f"User-Agent: {UA}\r\nAccept: */*\r\n"
                     "Connection: close\r\n\r\n").encode())
        head = _read_until(tls, b"\r\n\r\n", 16384)
        line = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        bits = line.split()
        status = int(bits[1]) if len(bits) >= 2 and bits[1].isdigit() else 0
        out["status"] = status
        out["ok"] = status > 0
        if status in (401, 403):
            out["note"] = "unauthenticated" if status == 401 else "access_restricted"
        elif status >= 500:
            out["note"] = "服务端错误，但路是通的"
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"证书校验失败：{exc.verify_message or exc}"
        out["note"] = "证书异常——中间人代理最想要的就是这个状态"
    except (ssl.SSLError, OSError, ValueError) as exc:
        out["error"] = str(exc)[:200] or type(exc).__name__
    finally:
        for s in (tls, sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        out["ms"] = int((time.time() - started) * 1000)
    return out


def probe(url: str, targets=TARGETS, timeout: float = TIMEOUT) -> dict:
    """跑完所有目标，返回一份可以原样打印的结论。"""
    proxy = parse_proxy(url)
    results = [_head(host, path, proxy, timeout) for host, path in targets]
    ok = all(r["ok"] for r in results)
    if ok:
        summary = "两条都到达"
    elif any(r["ok"] for r in results):
        summary = "只有一条到达——多半是分流规则漏了其中一个域名"
    else:
        summary = "两条都没到达"
    return {"proxy": proxy["url"], "scheme": proxy["scheme"], "ok": ok,
            "summary": summary, "targets": results}


# ---------------------------------------------------------------- 命令行

def main(argv) -> int:
    url = ""
    timeout = TIMEOUT
    rest = list(argv)
    if any(a in ("--help", "-h") for a in rest):
        print("用法：python3 app.py --proxy <http://主机:端口|socks5://主机:端口> [--timeout 秒]\n"
              "也支持 --diagnose-proxy；输出 JSON。退出码：0 两条都到达 / 1 至少一条没到达 / 2 参数不合法")
        return 0
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in ("--diagnose-proxy", "--proxy", "-p") and i + 1 < len(rest) and not rest[i + 1].startswith("-"):
            url = rest[i + 1]
            i += 2
            continue
        if arg.startswith(("--diagnose-proxy=", "--proxy=")):
            url = arg.split("=", 1)[1]
            i += 1
            continue
        if arg in ("--timeout", "-t") and i + 1 < len(rest):
            try:
                value = float(rest[i + 1])
                if not math.isfinite(value) or not 1 <= value <= 30:
                    raise ValueError("timeout out of range")
                timeout = value
            except ValueError:
                print("✗ --timeout 要 1 到 30 之间的有限数字（秒）", file=sys.stderr)
                return 2
            i += 2
            continue
        if arg in ("--help", "-h"):
            print("用法：python3 app.py --diagnose-proxy <代理地址> [--timeout 秒]\n"
                  "      python3 app.py --diagnose-proxy http://127.0.0.1:7890\n"
                  "      python3 app.py --diagnose-proxy socks5://127.0.0.1:1080\n"
                  "退出码：0 都到达 / 1 至少一条没到达 / 2 参数不合法")
            return 0
        if arg in ("--diagnose-proxy", "--proxy", "-p"):
            print("✗ 缺少代理地址", file=sys.stderr)
            return 2
        print(f"✗ 参数不合法：{arg}", file=sys.stderr)
        return 2

    if not url:
        print("✗ 缺少代理地址，例如 --diagnose-proxy http://127.0.0.1:7890",
              file=sys.stderr)
        return 2
    try:
        result = probe(url, timeout=timeout)
    except ProxyError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1
