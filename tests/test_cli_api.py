"""In-process CLI control flow and output coverage, independent of shell tools."""
from __future__ import annotations
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from netpol_contract_guard import __version__
from netpol_contract_guard.cli import main

ROOT=Path(__file__).resolve().parents[1]
EX=ROOT/'examples'
COMMON=['--contracts',str(EX/'contracts.json')]

class CliAPI(unittest.TestCase):
    def run_cli(self, args):
        output=io.StringIO();errors=io.StringIO()
        with redirect_stdout(output),redirect_stderr(errors):
            status=main(args)
        return status,output.getvalue(),errors.getvalue()

    def test_audit_in_process(self):
        rc,out,err=self.run_cli(['audit','--snapshot',str(EX/'baseline.json'),*COMMON])
        self.assertEqual((rc,err),(0,''))
        self.assertIn('gate=passed',out)

    def test_audit_json_output(self):
        rc,out,err=self.run_cli(['audit','--snapshot',str(EX/'candidate-risky.json'),*COMMON,'--format','json'])
        self.assertEqual(rc,2)
        result=json.loads(out)
        self.assertEqual(result['gate'],'blocked')
        self.assertEqual(result['summary']['violations'],1)

    def test_compare_direct(self):
        rc,out,err=self.run_cli(['compare','--before',str(EX/'baseline.json'),
                                 '--after',str(EX/'candidate-risky.json'),*COMMON])
        self.assertEqual(rc,2)
        self.assertIn('new-exposure',out)

    def test_invalid_input(self):
        rc,out,err=self.run_cli(['audit','--snapshot','does-not-exist.json',*COMMON])
        self.assertEqual(rc,3)
        self.assertIn('input error',err)

    def test_output_file_in_process(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'result.json';sarif=Path(t)/'out.sarif'
            rc,out,err=self.run_cli(['audit','--snapshot',str(EX/'baseline.json'),*COMMON,
                                     '--output',str(path),'--sarif',str(sarif),'--format','json'])
            self.assertEqual(rc,0)
            self.assertEqual(out,'')
            self.assertEqual(json.loads(path.read_text())['summary']['violations'],0)
            self.assertEqual(json.loads(sarif.read_text())['version'],'2.1.0')

    def test_invalid_same_output_path(self):
        with tempfile.TemporaryDirectory() as t:
            path=str(Path(t)/'collision.json')
            rc,out,err=self.run_cli(['audit','--snapshot',str(EX/'baseline.json'),*COMMON,
                                     '--output',path,'--sarif',path])
            self.assertEqual(rc,3)
            self.assertIn('paths must be different',err)
            self.assertFalse(Path(path).exists())

    def test_write_failure_is_error_not_traceback(self):
        rc,out,err=self.run_cli(['audit','--snapshot',str(EX/'baseline.json'),*COMMON,
                                 '--output','invalid-parent/output.json'])
        self.assertEqual(rc,3)
        self.assertIn('unsafe output',err)

    def test_sarif_failure_status_3(self):
        rc,out,err=self.run_cli(['audit','--snapshot',str(EX/'baseline.json'),*COMMON,
                                 '--sarif','invalid-parent/output.sarif'])
        self.assertEqual(rc,3)
        self.assertIn('unsafe output',err)

    def test_never_overwrite_input_contracts(self):
        before=(EX/'contracts.json').read_bytes()
        rc,out,err=self.run_cli(['audit','--snapshot',str(EX/'baseline.json'),*COMMON,
                                 '--output',str(EX/'contracts.json')])
        self.assertEqual(rc,3)
        self.assertIn('refusing to overwrite',err)
        self.assertEqual((EX/'contracts.json').read_bytes(),before)

    def test_version(self):
        with redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as caught:
                main(['--version'])
        self.assertEqual(caught.exception.code,0)
        self.assertIn(__version__,output.getvalue())

if __name__=='__main__':unittest.main()
