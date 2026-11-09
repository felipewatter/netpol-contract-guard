"""CLI subprocess and output safety tests."""
from __future__ import annotations
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from netpol_contract_guard import __version__
from netpol_contract_guard.cli import main, write_atomic
from netpol_contract_guard.model import InputError

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / 'examples'

def command(*args):
    return [sys.executable,'-m','netpol_contract_guard',*args]

def args_audit(snap='baseline.json'):
    return ['audit','--snapshot',str(EXAMPLES/snap),'--contracts',str(EXAMPLES/'contracts.json')]

def args_compare():
    return ['compare','--before',str(EXAMPLES/'baseline.json'),'--after',str(EXAMPLES/'candidate-risky.json'),
            '--contracts',str(EXAMPLES/'contracts.json')]

class CLI(unittest.TestCase):
    def subprocess(self,*args):
        return subprocess.run(command(*args),capture_output=True,text=True,check=False,cwd=ROOT)

    def test_version(self):
        result=self.subprocess('--version')
        self.assertEqual(result.returncode,0)
        self.assertIn(__version__,result.stdout)

    def test_clean_audit(self):
        result=self.subprocess(*args_audit())
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('violations=0',result.stdout)

    def test_bad_audit(self):
        result=self.subprocess(*args_audit('candidate-risky.json'))
        self.assertEqual(result.returncode,2)
        self.assertIn('ROGUE_TO_DB_DENY',result.stdout)

    def test_compare_block(self):
        result=self.subprocess(*args_compare())
        self.assertEqual(result.returncode,2)
        self.assertIn('drift=new-exposure',result.stdout)

    def test_bypass_threshold(self):
        result=self.subprocess(*args_compare(),'--fail-on','none')
        self.assertEqual(result.returncode,0)

    def test_json_and_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'report.json';b=Path(tmp)/'report.sarif'
            result=self.subprocess(*args_compare(),'--format','json','--output',str(a),'--sarif',str(b))
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertEqual(json.loads(a.read_text())['summary']['newExposures'],1)
            self.assertEqual(json.loads(b.read_text())['version'],'2.1.0')
            self.assertEqual(len(json.loads(b.read_text())['runs'][0]['results']),1)

    def test_invalid_json_returns_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.json';p.write_text('{')
            result=self.subprocess('audit','--snapshot',str(p),'--contracts',str(EXAMPLES/'contracts.json'))
            self.assertEqual(result.returncode,3)
            self.assertIn('input error:',result.stderr)

    def test_unwritable_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=self.subprocess(*args_audit(),'--output',str(Path(tmp)/'missing'/'out.json'))
            self.assertEqual(result.returncode,3)

    def test_equal_output_paths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=str(Path(tmp)/'out.json')
            result=self.subprocess(*args_audit(),'--output',p,'--sarif',p)
            self.assertEqual(result.returncode,3)

    def test_symlink_output_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            original=Path(tmp)/'original.json';original.write_text('immutable')
            link=Path(tmp)/'link.json'
            try:link.symlink_to(original)
            except OSError:self.skipTest('symlinks unavailable')
            with self.assertRaises(InputError):write_atomic(str(link),'unsafe')
            self.assertEqual(original.read_text(),'immutable')

    def test_write_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'result.json'
            write_atomic(str(path),'first')
            write_atomic(str(path),'updated')
            self.assertEqual(path.read_text(),'updated')

if __name__=='__main__':unittest.main()
