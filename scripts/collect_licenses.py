import importlib.metadata
import json
from pathlib import Path
import subprocess
import tomli

root = Path(__file__).resolve().parents[1]
output = root / 'docs/licenses'
output.mkdir(exist_ok=True)
entries = []
for dist in importlib.metadata.distributions():
    name = dist.metadata['Name']
    entries.append({'kind': 'python', 'name': name, 'version': dist.version,
                    'license': dist.metadata.get('License-Expression') or dist.metadata.get('License', '')})
    for file in dist.files or []:
        if any(word in str(file).upper() for word in ('LICENSE', 'COPYING', 'NOTICE')) and file.name.lower().endswith(('.txt', '.md', '.rst', 'license', 'copying', 'notice')):
            path = Path(dist.locate_file(file))
            if path.is_file(): (output / (name + '-' + file.name)).write_bytes(path.read_bytes())
# Cargo metadata returns the exact locked source locations; copy notices for compiled transitive crates.
seen = set()
for manifest in ('native/Cargo.toml', 'vendor/age-plugin-yubikey-source/Cargo.toml'):
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version', '1',
                                                   '--manifest-path', str(root / manifest)], cwd=root))
    for package in metadata['packages']:
        identity = (package['name'], package['version'])
        if identity in seen: continue
        seen.add(identity)
        entries.append({'kind': 'rust', 'name': package['name'], 'version': package['version'], 'license': package['license']})
        source = Path(package['manifest_path']).parent
        for path in source.iterdir():
            if path.is_file() and any(path.name.upper().startswith(word) for word in ('LICENSE', 'COPYING', 'NOTICE')):
                (output / (package['name'] + '-' + package['version'] + '-' + path.name)).write_bytes(path.read_bytes())
(root / 'docs/dependency-inventory.json').write_text(json.dumps(entries, indent=2), encoding='utf-8')
python_notice = Path(__import__('sys').prefix) / 'LICENSE.txt'
if python_notice.is_file():
    (output / ('Python-' + __import__('platform').python_version() + '-LICENSE.txt')).write_bytes(python_notice.read_bytes())
print(f'Collected notices for {len(entries)} locked dependency records.')
