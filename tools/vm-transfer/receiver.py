"""Receive explicitly selected file bytes over Parallels exec stdin.

No host folder mounting, archive extraction, or automatic file execution.
"""
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import sys
import tempfile
import time
import uuid

MAX_FILE = 2 * 1024**3
MAX_TOTAL = 8 * 1024**3
MAX_FILES = 100
READ_TIMEOUT = 0
LAST_ALARM = 0.0


class TransferError(Exception):
    pass


def line(stream, limit=16384):
    global LAST_ALARM
    now = time.monotonic()
    if READ_TIMEOUT and now - LAST_ALARM >= 5:
        signal.alarm(READ_TIMEOUT)
        LAST_ALARM = now
    value = stream.readline(limit + 1)
    if not value or len(value) > limit or not value.endswith(b"\n"):
        raise TransferError("incomplete_stream")
    return value


def record(stream):
    try:
        data = json.loads(line(stream))
    except (ValueError, UnicodeError):
        raise TransferError("invalid_protocol") from None
    if not isinstance(data, dict):
        raise TransferError("invalid_protocol")
    return data


def valid_name(name):
    return (isinstance(name, str) and name not in ("", ".", "..")
            and not any(c in name for c in "/\\")
            and not any(ord(c) < 32 or ord(c) == 127 for c in name)
            and len(name.encode("utf-8")) <= 255)


def receive(stream, home):
    """Publish one batch only after every size/hash and final commit match."""
    home = Path(home)
    downloads = home / "Downloads"
    if downloads.is_symlink() or (downloads.exists() and not downloads.is_dir()):
        raise TransferError("unsafe_destination")
    downloads.mkdir(mode=0o700, exist_ok=True)
    inbox = downloads / "VM-Inbox"
    try:
        inbox.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = inbox.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise TransferError("unsafe_destination")
    os.chmod(inbox, 0o700)
    header = record(stream)
    count = header.get("files")
    if header.get("version") != 1 or type(count) is not int or not 1 <= count <= MAX_FILES:
        raise TransferError("invalid_protocol")
    staging = Path(tempfile.mkdtemp(prefix=".incoming-", dir=inbox))
    seen = set()
    total = 0
    try:
        for _ in range(count):
            meta = record(stream)
            name, size = meta.get("name"), meta.get("size")
            if not valid_name(name) or name in seen:
                raise TransferError("invalid_filename")
            if type(size) is not int or not 0 <= size <= MAX_FILE or total + size > MAX_TOTAL:
                raise TransferError("size_limit")
            seen.add(name)
            digest, received = hashlib.sha256(), 0
            fd = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as dest:
                while True:
                    raw = line(stream, 1024)
                    if raw.startswith(b"{"):
                        try:
                            end = json.loads(raw)
                        except ValueError:
                            raise TransferError("invalid_protocol") from None
                        if (not isinstance(end, dict) or end.get("end") is not True
                                or end.get("sha256") != digest.hexdigest() or received != size):
                            raise TransferError("checksum_mismatch")
                        break
                    try:
                        chunk = base64.b64decode(raw.rstrip(b"\r\n"), validate=True)
                    except binascii.Error:
                        raise TransferError("invalid_protocol") from None
                    received += len(chunk)
                    if received > size:
                        raise TransferError("size_mismatch")
                    dest.write(chunk)
                    digest.update(chunk)
                dest.flush()
                os.fsync(dest.fileno())
            total += received
        if record(stream).get("commit") is not True:
            raise TransferError("incomplete_stream")
        batch = time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + uuid.uuid4().hex[:12]
        final = inbox / batch
        staging.rename(final)
        return {"ok": True, "files": count, "bytes": total,
                "destination": "~/Downloads/VM-Inbox/" + batch}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    global READ_TIMEOUT
    def interrupted(_sig, _frame):
        raise TransferError("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    # Parallels may keep guest stdin open after its host process disconnects.
    # Bound inactivity instead of relying on EOF delivery through that channel.
    READ_TIMEOUT = 60
    signal.alarm(READ_TIMEOUT)
    try:
        if sys.platform != "darwin":
            raise TransferError("requires_macos")
        if (len(sys.argv) != 2 or not re.fullmatch(
                r"--cc-vm-transfer-session=[a-f0-9]{32}", sys.argv[1])):
            raise TransferError("invalid_session")
        user = pwd.getpwuid(os.stat("/dev/console").st_uid)
        if user.pw_uid == 0 or user.pw_uid < 500:
            raise TransferError("no_logged_in_user")
        if os.geteuid() == 0:
            os.initgroups(user.pw_name, user.pw_gid)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
        if os.geteuid() != user.pw_uid:
            raise TransferError("wrong_user")
        os.umask(0o077)
        result = receive(sys.stdin.buffer, user.pw_dir)
    except TransferError as error:
        result = {"ok": False, "error": str(error)}
    except Exception:
        # Do not print paths, content, or raw system diagnostics.
        result = {"ok": False, "error": "receiver_failed"}
    signal.alarm(0)
    print(json.dumps(result), flush=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
