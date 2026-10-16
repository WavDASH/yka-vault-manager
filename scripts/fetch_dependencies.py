"""Fetch pinned external runtime packages; never install or run a driver."""
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def fetch(url, digest, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        with target.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() == digest: return
        raise SystemExit(f'Existing dependency does not match its pin: {target.name}')
    partial = target.with_suffix(target.suffix + '.download')
    with urllib.request.urlopen(url, timeout=60) as source, partial.open('wb') as output:
        while chunk := source.read(1024*1024): output.write(chunk)
    with partial.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
            raise SystemExit('Dependency SHA-256 mismatch; nothing was installed.')
    partial.rename(target)


def main():
    deps = json.loads((ROOT/'vendor/dependencies.json').read_text(encoding='utf-8'))
    securefs = next(d for d in deps if d['name'] == 'securefs')
    package = ROOT/'vendor/downloads/securefs-2.0.0.zip'
    fetch(securefs['url'], securefs['sha256'], package)
    target = ROOT/'vendor/securefs/securefs.exe'; target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(package) as archive:
        matches = [n for n in archive.namelist() if Path(n).name == 'securefs.exe']
        if len(matches) != 1: raise SystemExit('Unexpected SecureFS package layout.')
        content = archive.read(matches[0])
    if hashlib.sha256(content).hexdigest() != securefs['executable_sha256']['securefs.exe']:
        raise SystemExit('SecureFS executable hash mismatch.')
    if target.exists() and target.read_bytes() != content: raise SystemExit('Refusing to replace a different SecureFS executable.')
    if not target.exists(): target.write_bytes(content)
    winfsp = next(d for d in deps if d['name'] == 'winfsp')
    fetch(winfsp['url'], winfsp['sha256'], ROOT/'vendor/installers/winfsp-2.1.25156.msi')
    print('Pinned SecureFS and WinFsp packages verified. No driver was installed.')


if __name__ == '__main__': main()
