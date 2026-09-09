#!/bin/sh
set -eu
cc -g -fsanitize=address,undefined -I/opt/openssl-profile/include -I/opt/profiling \
  /opt/profiling/test_profile.c /opt/profiling/profile.c \
  -L/opt/openssl-profile/lib -Wl,-rpath,/opt/openssl-profile/lib \
  -lssl -lcrypto -o /tmp/profile-timer-test
/tmp/profile-timer-test
