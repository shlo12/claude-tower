#!/usr/bin/env python3
"""交叉编译 Windows .NET Framework 哨兵。需要自行准备微软 SDK 和 net48 引用程序集。"""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser()
p.add_argument('--dotnet', required=True, type=Path)
p.add_argument('--references', required=True, type=Path)
a = p.parse_args()
sdk = sorted((a.dotnet.parent / 'sdk').glob('*/Roslyn/bincore/csc.dll'))[-1]
out = ROOT / 'build/windows'
out.mkdir(parents=True, exist_ok=True)
refs = ['mscorlib', 'System', 'System.Core', 'System.Windows.Forms', 'System.Drawing', 'System.Web.Extensions', 'System.Security']
args = [str(a.dotnet), str(sdk), '/nologo', '/target:winexe', '/win32manifest:windows/shield/app.manifest', '/platform:anycpu', '/optimize+', '/deterministic+', '/nostdlib+', '/out:' + str(out / 'WindowsShield.exe'), '/resource:windows/shield/Probe.ps1,WindowsShield.Probe.ps1']
args += ['/r:' + str(a.references / (r + '.dll')) for r in refs]
args += ['windows/shield/' + r for r in ['WindowsShield.cs', 'Policy.cs', 'PolicyTests.cs', 'Installer.cs']]
subprocess.run(args, cwd=ROOT, check=True, env=dict(os.environ, DOTNET_CLI_HOME=str(out / '.dotnet'), DOTNET_NOLOGO='1'))
from windows_shield_artifact import record
record(out / 'WindowsShield.exe', 'cross-compile')
print('Compiled WindowsShield.exe (cross compile; Windows runtime validation still required)')
