#!/bin/sh
set -eu

delay="${NETWORK_HALF_DELAY_MS:-0}"

if [ "${VALIDATION_NETWORK_FAMILY:-latency}" = "combined" ]; then
    if [ "${1:-}" = "probe" ]; then
        exec /opt/network-combined/client.sh probe
    fi
    python3 /opt/network-combined/apply_network.py
elif [ "$delay" != "0" ]; then
    tc qdisc add dev eth0 root netem delay "${delay}ms"
fi

case "${1:-}" in
probe)
    echo QDISC_CLIENT_BEGIN
    tc -s qdisc show dev eth0
    echo QDISC_CLIENT_END
    ping -n -c 20 -i 0.05 -W 2 server
    ;;
measure)
    shift
    echo QDISC_CLIENT_BEFORE_BEGIN
    tc qdisc show dev eth0
    echo QDISC_CLIENT_BEFORE_END
    python3 /opt/native-pcap-validation/measure.py "$@"
    echo QDISC_CLIENT_AFTER_BEGIN
    tc -s qdisc show dev eth0
    echo QDISC_CLIENT_AFTER_END
    ;;
*)
    echo "usage: client.sh probe|measure" >&2
    exit 2
    ;;
esac
