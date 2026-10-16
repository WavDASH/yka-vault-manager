"""Create a clean, verified source copy without changing the development tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def source_files(root=ROOT):
    files = ['README.md', 'LICENSE', '.gitignore', 'requirements.lock.txt', 'app.py', 'start.bat',
        'native/Cargo.toml', 'native/Cargo.lock', 'vendor/dependencies.json',
        'docs/THIRD_PARTY.md', 'docs/dependency-inventory.json', 'vendor/age-plugin-yubikey.patch']
    scripts = ['environment.ps1', 'build.ps1', 'package.ps1', 'installer.ps1',
        'fetch_dependencies.py', 'build_icons.py', 'collect_licenses.py', 'export_source.py', 'release_sources.py']
    files += ['scripts/'+name for name in scripts]
    plugin = 'vendor/age-plugin-yubikey-source/'
    files += [plugin+name for name in ('Cargo.toml', 'Cargo.lock', 'i18n.toml', 'README.md',
        'LICENSE-MIT', 'LICENSE-APACHE', 'YKA_CHANGES.md')]
    for folder in ['src', 'native/src', 'assets', 'installer', 'docs/licenses', plugin+'src', plugin+'i18n']:
        files += [p.relative_to(root).as_posix() for p in (root/folder).rglob('*')
            if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo')]
    result = sorted(set(files))
    for name in result:
        path = root/name
        if not path.is_file() or path.is_symlink(): raise RuntimeError('Missing/unsafe source input: '+name)
    return result


def export(destination):
    destination = Path(destination).absolute()
    if destination.exists(): raise SystemExit('Destination already exists; no files were changed.')
    files = source_files()  # Validate all inputs before creating the destination.
    destination.mkdir()
    manifest = {}
    for name in files:
        source = ROOT/name; target = destination/name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected: raise RuntimeError('Copy verification failed: '+name)
        manifest[name] = expected
    (destination/'SOURCE_SHA256.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    print(f'Clean source created and verified: {len(files)} files.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination'); export(parser.parse_args().destination)
