#!/bin/sh
set -eu
printf 'Original C, wire, TLS, compact, profile and MTC suites\n'
python3 /opt/measurement/test_legacy.py
/opt/mt/bin/test_wire
python3 /opt/mt/tests/test_tls.py
/opt/compact/test_parser /work/compact/batch16/pq/bundle-0000.bin
python3 /opt/compact/test_tls.py
PROFILE_DETAIL=1 python3 /opt/profiling/test_tls.py
sh /opt/profiling/test_timer.sh
sh /opt/mtc/test_verifier.sh
python3 /opt/mtc/test_tls.py
printf 'Saved security suites on the measurement-only executable\n'
python3 /opt/measurement/test_saved.py compact
PROFILE_DETAIL=1 python3 /opt/measurement/test_saved.py profile
python3 /opt/measurement/test_saved.py mtc
printf 'ALL REGRESSION AND NEGATIVE TESTS PASS\n'
