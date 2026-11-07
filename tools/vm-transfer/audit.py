"""One-shot inspection of this tool's tagged guest receivers, not all VM channels."""
import json
import os
import re
import subprocess
import sys
import time

MARKER = re.compile(r"(?:^|\s)--cc-vm-transfer-session=([a-f0-9]{32})(?=\s|$|['\"])")


def sessions(text, exclude=0):
    found = {}
    for row in text.splitlines():
        parts = row.strip().split(None, 2)
        if len(parts) != 3 or not parts[0].isdigit() or "Z" in parts[1]:
            continue
        pid = int(parts[0])
        match = MARKER.search(parts[2])
        if pid != exclude and match:
            found[pid] = match.group(1)
    return found


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    if target != "all" and not re.fullmatch(r"[a-f0-9]{32}", target):
        raise ValueError("invalid_session")
    deadline = time.monotonic() + 2
    while True:
        text = subprocess.check_output(["/bin/ps", "-ww", "-axo", "pid=,stat=,args="],
                                       text=True, timeout=3)
        active = sessions(text, os.getpid())
        if not active or time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    print(json.dumps({"ok": True, "active": len(active),
                      "current": sum(x == target for x in active.values()),
                      "session": target}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"ok": False, "error": "inspection_failed"}), flush=True)
        raise SystemExit(1)
