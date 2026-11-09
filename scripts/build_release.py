"""Reproducible ZIP + file manifest + SHA-256 release proof; does not read credentials."""
from __future__ import annotations

import hashlib
import json
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE_DIRS = ('src/', 'tests/', 'examples/', 'docs/', 'scripts/', '.github/')
INCLUDE_FILES = {'.gitignore', 'README.md', 'README.en.md', 'LICENSE', 'SECURITY.md',
                 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md', 'pyproject.toml'}
IGNORE = {'.git', '.pytest_cache', '__pycache__', '.venv', 'venv', 'dist', 'build', '.mypy_cache'}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT).as_posix()
    return (path.is_file() and not path.is_symlink() and not
            any(x in IGNORE or x.endswith('.egg-info') or x.endswith('.pyc') or x.endswith('.pyo') for x in path.parts)
            and (relative in INCLUDE_FILES or relative.startswith(INCLUDE_DIRS)))


def build(directory: Path) -> tuple[Path, Path, Path]:
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    directory.mkdir(parents=True, exist_ok=True)
    prefix = f'netpol-contract-guard-v{version}'
    paths = sorted((p for p in ROOT.rglob('*') if included(p)), key=lambda p: p.relative_to(ROOT).as_posix())
    names = [p.relative_to(ROOT).as_posix() for p in paths]
    if not paths or 'README.md' not in names or '.github/workflows/ci.yml' not in names:
        raise ValueError('mandatory distributable files are missing')
    manifest = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    manifest_file = directory / f'{prefix}-manifest.json'
    manifest_file.write_text(json.dumps({'version': version, 'sha256': manifest}, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    zip_file = directory / f'{prefix}-source.zip'
    with zipfile.ZipFile(zip_file, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in paths:
            name = prefix + '/' + path.relative_to(ROOT).as_posix()
            entry = zipfile.ZipInfo(name, date_time=(2026, 11, 9, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    checksum_file = directory / f'{prefix}-SHA256SUMS.txt'
    checksum_file.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                                     for p in (zip_file, manifest_file)), encoding='utf-8')
    return zip_file, manifest_file, checksum_file


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'dist'
    for file in build(target):
        print(file)
