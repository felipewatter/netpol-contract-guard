"""Dynamic-version source artifact tests: never hardcode an old release tag."""
from __future__ import annotations
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from netpol_contract_guard import __version__
from scripts.build_release import build

PREFIX=f'netpol-contract-guard-v{__version__}'

class Packaging(unittest.TestCase):
    def test_reproducible(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first=build(Path(a)); second=build(Path(b))
            self.assertEqual([hashlib.sha256(x.read_bytes()).hexdigest() for x in first],
                             [hashlib.sha256(x.read_bytes()).hexdigest() for x in second])

    def test_manifest_and_checksums(self):
        with tempfile.TemporaryDirectory() as t:
            archive,manifest,checksums=build(Path(t))
            proof=json.loads(manifest.read_text())
            self.assertEqual(proof['version'],__version__)
            with zipfile.ZipFile(archive) as files:
                names=files.namelist()
                self.assertEqual(len(names),len(proof['sha256']))
                for name in names:
                    rel=name.split('/',1)[1]
                    self.assertEqual(hashlib.sha256(files.read(name)).hexdigest(),proof['sha256'][rel])
                    self.assertTrue(name.startswith(PREFIX+'/'))
                    self.assertNotIn('../',name)
            data=dict(line.split('  ',1) for line in checksums.read_text().splitlines())
            self.assertEqual(set(data.values()),{archive.name,manifest.name})
            for checksum,file in data.items():
                self.assertEqual(hashlib.sha256((Path(t)/file).read_bytes()).hexdigest(),checksum)

    def test_no_build_artifacts_or_secrets(self):
        with tempfile.TemporaryDirectory() as t:
            archive,*_=build(Path(t))
            with zipfile.ZipFile(archive) as files:
                paths=files.namelist()
                for forbidden in ('.git/', '__pycache__','/dist/', '.env', '.egg-info','.pyc','.venv'):
                    self.assertFalse(any(forbidden in path for path in paths),forbidden)
                for required in ('README.md','README.en.md','LICENSE','SECURITY.md','docs/THREAT_MODEL.md',
                                 'tests/test_release.py','.github/workflows/ci.yml','.github/workflows/release.yml',
                                 'pyproject.toml','examples/contracts.json'):
                    self.assertIn(PREFIX+'/'+required,paths)

if __name__=='__main__':unittest.main()
