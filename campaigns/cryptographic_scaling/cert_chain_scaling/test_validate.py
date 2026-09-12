"""Host path regression; no Docker process or TLS connection is launched."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import validate


class ValidatePathsTests(unittest.TestCase):
 def test_relative_fixture_path_uses_absolute_readonly_mount(self):
  with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
   base=Path(tmp);fixture=base/'fixtures/profile/depth-2';fixture.mkdir(parents=True)
   for name in ('root.pem','root.key','server.pem','server.key','intermediates.pem','root.der','server.der'):
    (fixture/name).write_text(name)
   (fixture/'server-chain.pem').write_text('-----BEGIN CERTIFICATE-----\nserver\n')
   (fixture/'manifest.json').write_text(json.dumps({'depth_including_root':2,'profile':'test','files_sha256':{},'certificate_checks':{}}))
   relative=(base/'fixtures').relative_to(Path.cwd());output=base/'validation.json'
   def verify(cmd,**kwargs):
    self.assertEqual(cmd[cmd.index('-v')+1],f'{fixture.resolve()}:/fixture:ro')
    return SimpleNamespace(returncode=0,stderr='')
   with patch('sys.argv',['validate.py',str(relative),'--output',str(output)]), \
        patch.object(validate.subprocess,'run',side_effect=verify) as run, \
        patch.object(validate,'PROFILES',['test']*0), contextlib.redirect_stdout(io.StringIO()):
    # Only one minimal fixture is needed to exercise the Docker boundary.
    with self.assertRaises(SystemExit):validate.main()
   run.assert_called_once()
   report=json.loads(output.read_text())
   self.assertTrue(report['checks'][0]['chain_valid'])
   self.assertEqual(len(report['failures']),1)
   original=output.read_bytes()
   with patch('sys.argv',['validate.py',str(relative),'--output',str(output)]), \
        patch.object(validate.subprocess,'run') as run,contextlib.redirect_stderr(io.StringIO()):
    with self.assertRaises(SystemExit):validate.main()
   run.assert_not_called();self.assertEqual(output.read_bytes(),original)

if __name__=='__main__':unittest.main()
