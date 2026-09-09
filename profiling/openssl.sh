#!/bin/sh
# The older executables retain their original library search path.
export LD_LIBRARY_PATH=/opt/openssl-profile/lib:/opt/oqs/lib
exec /opt/openssl-profile/bin/openssl "$@"
