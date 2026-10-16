"""Keep matching application/plugin sources and a release integrity manifest."""
from pathlib import Path
import hashlib
import json
import os
import re
import zipfile
import sys

root=Path(__file__).resolve().parents[1]
version=re.search(r"__version__ = '([^']+)'",(root/'src/yka/__init__.py').read_text()).group(1)
output=root/'dist'/f'YkaVaultManager-Source-{version}.zip'
sys.path.insert(0, str(Path(__file__).resolve().parent))
from export_source import source_files
files=[root/name for name in source_files(root)]
manifest={}
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
    for path in sorted(set(files)):
        if not path.is_file() or path.is_symlink(): continue
        name=path.relative_to(root).as_posix(); archive.write(path,name)
        with path.open('rb') as stream: manifest[name]=hashlib.file_digest(stream,'sha256').hexdigest()
    archive.writestr('SOURCE_SHA256.json',json.dumps(manifest,indent=2))
with zipfile.ZipFile(output) as archive:
    for name,digest in manifest.items():
        with archive.open(name) as stream: assert hashlib.file_digest(stream,'sha256').hexdigest()==digest
artifacts={}
for path in [output,root/'dist'/f'YkaVaultManager-Setup-{version}.exe',*sorted((root/'dist'/f'portable-{version}').rglob('*'))]:
    if path.is_file():
        with path.open('rb') as stream: artifacts[path.relative_to(root/'dist').as_posix()]=hashlib.file_digest(stream,'sha256').hexdigest()
(root/'dist'/f'release-{version}-sha256.json').write_text(json.dumps(artifacts,indent=2),encoding='utf-8')
print(f'Matching source: {len(manifest)} files verified; release manifest: {len(artifacts)} artifacts.')
