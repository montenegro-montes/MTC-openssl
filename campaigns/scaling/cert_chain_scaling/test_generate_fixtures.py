"""Host-ownership regression tests; no Docker process is launched."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate_fixtures


class GenerateFixtureOwnershipTests(unittest.TestCase):
 def invoke(self, output, create_manifest):
  commands=[]
  def check_output(command, **kwargs):
   if command[:3] == ["docker", "image", "inspect"]:
    return json.dumps([{"Id": "sha256:test"}])
   return "test-commit\n"
  def run(command, **kwargs):
   commands.append(command)
   if create_manifest:
    manifest=output/"ecdsa-p256"/"depth-3"/"manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{}")
  with patch("sys.argv", ["generate_fixtures.py", "--output", str(output),
                           "--profile", "ecdsa-p256", "--depth", "3"]), \
       patch.object(generate_fixtures.os, "getuid", return_value=1234), \
       patch.object(generate_fixtures.os, "getgid", return_value=5678), \
       patch.object(generate_fixtures.subprocess, "check_output", side_effect=check_output), \
       patch.object(generate_fixtures.subprocess, "run", side_effect=run), \
       contextlib.redirect_stdout(io.StringIO()):
   generate_fixtures.main()
  return commands

 def test_container_writes_as_host_user(self):
  with tempfile.TemporaryDirectory() as temporary:
   output=Path(temporary)/"fixtures"
   commands=self.invoke(output, create_manifest=True)
  self.assertEqual(len(commands), 1)
  command=commands[0]
  self.assertEqual(command[command.index("--user")+1], "1234:5678")

 def test_missing_or_unreadable_manifest_is_not_reported_as_success(self):
  with tempfile.TemporaryDirectory() as temporary:
   output=Path(temporary)/"fixtures"
   with self.assertRaisesRegex(SystemExit, "manifest is not host-readable"):
    self.invoke(output, create_manifest=False)


if __name__ == "__main__":unittest.main()
