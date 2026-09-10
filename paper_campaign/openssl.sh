#!/bin/sh
export LD_LIBRARY_PATH=/opt/openssl-mtc/lib:/opt/oqs/lib
exec /opt/openssl-paper/bin/openssl "$@"
