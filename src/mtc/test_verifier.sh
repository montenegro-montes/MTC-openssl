#!/bin/sh
set -eu
: "${MTC_BATCH:?MTC_BATCH must point to the verifier fixture batch}"
cc -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I/opt/openssl-mtc/include -I/opt/openssl-profile/include -I/opt/mtc /opt/mtc/check.c \
  -L/opt/openssl-mtc/lib -Wl,-rpath,/opt/openssl-mtc/lib -lssl -lcrypto -o /tmp/mtc-check
python3 /opt/mtc/test_core.py
python3 /opt/mtc/test_verifier.py
cc -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I/opt/openssl-profile/include -I/opt/mtc /opt/mtc/fuzz.c \
  -L/opt/openssl-mtc/lib -Wl,-rpath,/opt/openssl-mtc/lib -lssl -lcrypto -o /tmp/mtc-fuzz
/tmp/mtc-fuzz "$MTC_BATCH/pq/authority.bin" "$MTC_BATCH/pq/standalone-0000.der"
