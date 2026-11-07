#!/usr/bin/env python3
"""Bind a Windows binary to its source revision; reject stale packaging inputs."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ['WindowsShield.cs', 'Policy.cs', 'PolicyTests.cs', 'Installer.cs', 'Probe.ps1', 'app.manifest']

def fingerprint():
    return {name: hashlib.sha256((ROOT / 'windows/shield' / name).read_bytes()).hexdigest() for name in FILES}

def verify(binary):
    receipt = json.loads(binary.with_suffix('.build.json').read_text())
    if receipt['sources'] != fingerprint():
        raise ValueError('Windows Shield source changed: rebuild the EXE before packaging')
    if receipt['binary_sha256'] != hashlib.sha256(binary.read_bytes()).hexdigest():
        raise ValueError('Windows Shield EXE hash mismatch')
    data = binary.read_bytes()
    offset = int.from_bytes(data[60:64], 'little')
    if data[:2] != b'MZ' or data[offset:offset+4] != b'PE\0\0':
        raise ValueError('Not a Windows PE executable')
    return receipt

def record(binary, method):
    binary.with_suffix('.build.json').write_text(json.dumps({
        'sources': fingerprint(), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'build_method': method, 'windows_runtime_validation': 'not recorded; see test reports'
    }, indent=2) + '\n')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('binary', type=Path)
    p.add_argument('--record', choices=['cross-compile', 'windows-csc'])
    a = p.parse_args()
    if a.record:
        record(a.binary, a.record)
    verify(a.binary)
    print('Windows Shield source/binary receipt verified')
