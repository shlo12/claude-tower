"""隔离环境生成器：为不同账号/用途创建互不污染的 CLAUDE_CONFIG_DIR 与启动器。"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path

from . import compat

HOME = Path.home()
STATE_DIR = HOME / ".ccclean"
PROFILE_DIR = STATE_DIR / "profiles"


def _slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", name.strip()).strip("-").lower()
    return s or "profile"


def list_profiles() -> list[dict]:
    if not PROFILE_DIR.exists():
        return []
    out = []
    for d in sorted(PROFILE_DIR.iterdir()):
        meta = d / "env.json"
        if not meta.exists():
            continue
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except Exception:
            continue
        data["slug"] = d.name
        script_name = "run.bat" if compat.IS_WIN else "run.sh"
        data["script"] = str(d / script_name).replace(str(HOME), "~")
        out.append(data)
    return out


def create_profile(name: str, tz: str, base_url: str = "", with_docker: bool = False) -> dict:
    slug = _slug(name)
    root = PROFILE_DIR / slug
    cfg = root / "claude"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "settings.json").write_text("{}\n", encoding="utf-8")

    # shell 启动器（macOS/Linux）
    script = root / "run.sh"
    base_line = f'export ANTHROPIC_BASE_URL="{base_url}"' if base_url else "unset ANTHROPIC_BASE_URL"
    script.write_text(
        f"""#!/bin/sh
# CCclean 隔离启动器 · {name}
# 配置目录、时区、代理变量都与主环境完全隔离
set -eu

export CLAUDE_CONFIG_DIR="{cfg}"
export TZ="{tz}"
{base_line}

# 不继承主环境里的密钥，避免串号
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN

exec claude "$@"
""",
        encoding="utf-8",
    )
    os.chmod(script, 0o755)

    # Windows 批处理启动器（两平台都生成，换系统也能用）
    bat = root / "run.bat"
    bat_base = f'set "ANTHROPIC_BASE_URL={base_url}"' if base_url else 'set "ANTHROPIC_BASE_URL="'
    bat.write_text(
        f"""@echo off
rem CCclean 隔离启动器 · {name}
set "CLAUDE_CONFIG_DIR={cfg}"
set "TZ={tz}"
{bat_base}
set "ANTHROPIC_API_KEY="
set "ANTHROPIC_AUTH_TOKEN="
claude %*
""",
        encoding="utf-8",
    )
    ps1 = root / "run.ps1"
    ps1_base = f'$env:ANTHROPIC_BASE_URL = "{base_url}"' if base_url else 'Remove-Item Env:ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue'
    ps1.write_text(
        f"""# CCclean 隔离启动器 · {name}
$env:CLAUDE_CONFIG_DIR = "{cfg}"
$env:TZ = "{tz}"
{ps1_base}
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue
claude @args
""",
        encoding="utf-8",
    )

    meta = {
        "name": name,
        "slug": slug,
        "timezone": tz,
        "baseUrl": base_url,
        "configDir": str(cfg).replace(str(HOME), "~"),
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "docker": with_docker,
    }
    (root / "env.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    if with_docker:
        _write_docker(root, name)

    if compat.IS_WIN:
        run_cmd = str(bat).replace(str(HOME), "~")
        abs_path = str(bat)
    else:
        run_cmd = f"sh {str(script).replace(str(HOME), '~')}"
        abs_path = str(script)
    return {
        "profile": meta,
        "runCommand": run_cmd,
        "absolute": abs_path,
        "dockerCommand": f"sh {str(root / 'run-docker.sh').replace(str(HOME), '~')}" if with_docker else None,
    }


def _write_docker(root: Path, name: str) -> None:
    dockerfile = root / "Dockerfile"
    dockerfile.write_text(
        """FROM node:22-slim
RUN npm install -g @anthropic-ai/claude-code \\
 && useradd -m -u 1000 claude
USER claude
WORKDIR /home/claude
ENV CLAUDE_CONFIG_DIR=/home/claude/.claude
ENTRYPOINT ["claude"]
""",
        encoding="utf-8",
    )
    runner = root / "run-docker.sh"
    runner.write_text(
        f"""#!/bin/sh
# 容器化运行：不接触主机任何配置文件
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
TAG="ccclean-{_slug(name)}"
docker build -q -t "$TAG" "$DIR" >/dev/null
mkdir -p "$DIR/container-claude"
exec docker run --rm -it \\
  -v "$DIR/container-claude:/home/claude/.claude" \\
  -v "$PWD:/work" -w /work \\
  -e TZ="${{TZ:-UTC}}" \\
  "$TAG" "$@"
""",
        encoding="utf-8",
    )
    os.chmod(runner, 0o755)
    (root / "run-docker.bat").write_text(
        f"""@echo off
rem 容器化运行：不接触主机任何配置文件
set "DIR=%~dp0"
set "TAG=ccclean-{_slug(name)}"
docker build -q -t %TAG% "%DIR%" >nul
if not exist "%DIR%container-claude" mkdir "%DIR%container-claude"
docker run --rm -it -v "%DIR%container-claude:/home/claude/.claude" -v "%CD%:/work" -w /work -e "TZ=%TZ%" %TAG% %*
""",
        encoding="utf-8",
    )


def delete_profile(slug: str) -> dict:
    root = PROFILE_DIR / _slug(slug)
    if not root.exists():
        return {"ok": False, "message": "配置档不存在"}
    # 配置档可包含独立令牌和运行日志，删除时不能整体保留在废纸篓。
    if root.is_symlink():
        root.unlink()
    else:
        shutil.rmtree(root)
    return {"ok": True, "message": "已删除配置档；不留副本，不可还原"}
