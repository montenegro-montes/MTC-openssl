"""The original C demos use nonuniform exit conventions; verify their outputs.
codigoOriginal/C/mtc_tests.c returns 1 on success and 0 on failure. Preserve this behavior.
"""
import subprocess,re
for command,expected,marker in [
    (['/opt/mt/bin/merkle_tests'],0,'Verification: VALID'),
    (['/opt/mt/bin/mtc_tests','/work/certs/classic/server.pem'],1,'Certificate loaded successfully'),
    (['/opt/mt/bin/merkle_mtc_tests','/work/certs/classic'],0,'Verification: VALID')]:
    r=subprocess.run(command,text=True,capture_output=True,timeout=30)
    print(r.stdout,end='');print(r.stderr,end='')
    assert r.returncode==expected and marker in r.stdout and 'INVALID' not in r.stdout,command
    if command[0].endswith('/mtc_tests'):assert re.search(r'Merkle leaf hash:\n0x[0-9a-f]{64}',r.stdout)
print('Original C demos: expected status/output PASS')
