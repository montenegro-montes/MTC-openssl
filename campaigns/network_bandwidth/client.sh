#!/bin/sh
set -eu

rate="${NETWORK_RATE_MBIT}mbit"
burst="${NETWORK_BURST_BYTES}b"
queue_latency="${NETWORK_QUEUE_LATENCY_MS}ms"
delay="${NETWORK_HALF_DELAY_MS}ms"

# One TBF rate per direction. The child netem adds only deterministic delay.
tc qdisc add dev eth0 root handle 1: tbf rate "$rate" burst "$burst" latency "$queue_latency"
tc qdisc add dev eth0 parent 1:1 handle 10: netem delay "$delay"

show_qdisc() {
    tc -s qdisc show dev eth0
}

case "${1:-}" in
probe)
    echo QDISC_CLIENT_BEGIN
    show_qdisc
    echo QDISC_CLIENT_END
    ping -n -c 20 -i 0.05 -W 3 server
    echo IPERF_FORWARD_BEGIN
    iperf3 -c server -t 4 -O 1 -J
    echo IPERF_FORWARD_END
    # Allow the shaped control connection and queued packets to close before
    # opening the reverse-direction iperf session.
    sleep 2
    echo IPERF_REVERSE_BEGIN
    iperf3 -c server -t 4 -O 1 -R -J
    echo IPERF_REVERSE_END
    echo QDISC_CLIENT_PROBE_AFTER_BEGIN
    show_qdisc
    echo QDISC_CLIENT_PROBE_AFTER_END
    ;;
measure)
    shift
    echo QDISC_CLIENT_BEFORE_BEGIN
    show_qdisc
    echo QDISC_CLIENT_BEFORE_END
    python3 /opt/measurement/measure.py "$@"
    echo QDISC_CLIENT_AFTER_BEGIN
    show_qdisc
    echo QDISC_CLIENT_AFTER_END
    ;;
*)
    echo "usage: client.sh probe|measure" >&2
    exit 2
    ;;
esac
