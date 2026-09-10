#!/bin/sh
set -eu

loss="${LOSS_TARGET_PERCENT}%"
tc qdisc replace dev eth0 root netem delay 25ms loss "$loss"

qdisc() { tc -s qdisc show dev eth0; }
counters() { nstat -az TcpRetransSegs TcpOutSegs TcpInSegs; }

case "${1:-}" in
probe)
    echo QDISC_CLIENT_BEGIN
    qdisc
    echo QDISC_CLIENT_END
    # ping returns non-zero when loss is observed; the runner parses all output.
    ping -n -c "$LOSS_PROBE_PACKETS" -i 0.01 -W 2 server || true
    echo QDISC_CLIENT_PROBE_AFTER_BEGIN
    qdisc
    echo QDISC_CLIENT_PROBE_AFTER_END
    ;;
measure)
    shift
    echo QDISC_CLIENT_BEFORE_BEGIN
    qdisc
    echo TCP_CLIENT_BEFORE_BEGIN
    counters
    echo TCP_CLIENT_BEFORE_END
    python3 /opt/network-loss/measure.py "$@"
    echo TCP_CLIENT_AFTER_BEGIN
    counters
    echo TCP_CLIENT_AFTER_END
    echo QDISC_CLIENT_AFTER_BEGIN
    qdisc
    echo QDISC_CLIENT_AFTER_END
    ;;
*)
    echo "usage: client.sh probe|measure" >&2
    exit 2
    ;;
esac
