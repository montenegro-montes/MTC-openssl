#!/bin/sh
set -eu
python3 /opt/network-combined/apply_network.py
qdisc() { tc -s qdisc show dev eth0; }
counters() { nstat -az TcpRetransSegs TcpOutSegs TcpInSegs; }
case "${1:-}" in
probe)
  echo QDISC_CLIENT_BEGIN; qdisc; echo QDISC_CLIENT_END
  ping -n -c "$PROBE_PACKETS" -i 0.01 -W 2 server || true
  iperf3 -c server -t 2 || true
  iperf3 -c server -R -t 2 || true
  ;;
measure)
  shift
  echo QDISC_CLIENT_BEFORE_BEGIN; qdisc; echo QDISC_CLIENT_BEFORE_END
  echo TCP_CLIENT_BEFORE_BEGIN; counters; echo TCP_CLIENT_BEFORE_END
  python3 /opt/measurement/measure.py "$@"
  echo TCP_CLIENT_AFTER_BEGIN; counters; echo TCP_CLIENT_AFTER_END
  echo QDISC_CLIENT_AFTER_BEGIN; qdisc; echo QDISC_CLIENT_AFTER_END
  ;;
*) echo 'usage: client.sh probe|measure' >&2; exit 2;;
esac
