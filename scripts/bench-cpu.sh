#!/usr/bin/env bash
# Server CPU cost and client round-trip latency at a fixed offered packet rate,
# with the DCID filter on or off.
#
# One run = start the server, bring a paced blast up to steady state, then time
# 400 client pings. CPU is sampled from /proc/<server-pid>/stat across exactly
# the interval the pings were measured in, so the CPU and latency columns
# describe the same moment. Only the server process is measured.
#
# Usage: scripts/bench-cpu.sh <on|off> <pps|0>
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/common.sh

MODE=${1:?usage: bench-cpu.sh <on|off> <pps>}
RATE=${2:?usage: bench-cpu.sh <on|off> <pps>}
THREADS="${THREADS:-8}"   # enough headroom for 1M pps; keeps the pacing smooth
PINGS="${PINGS:-400}"; INTERVAL="${INTERVAL:-10}"; SETTLE="${SETTLE:-2}"; HZ=100

wait_for_port_free || exit 1
rm -f server_cert.der
EXTRA=""; [ "$MODE" = off ] && EXTRA="--no-dcid-validation"
taskset -c "$SRV_CPUS" "$BIN/server" --listen "$LISTEN" $EXTRA > /tmp/bench-srv.log 2>&1 &
SPID=$!
BPID=""
cleanup() { [ -n "$BPID" ] && kill -9 "$BPID" 2>/dev/null; stop_server; }
trap cleanup EXIT
wait_for_server /tmp/bench-srv.log || exit 1

if [ "$RATE" != 0 ]; then
  taskset -c "$BL_CPUS" "$BIN/blaster" --target "$LISTEN" --threads "$THREADS" \
    --duration 40 --pps "$RATE" > /tmp/bench-blaster.log 2>&1 &
  BPID=$!
  disown $BPID      # we kill it ourselves; skip the job-control "Killed" notice
  sleep "$SETTLE"
fi

# --- measurement window ---
t0=$(uptime_s); c0=$(cputime $SPID); i0=$(udp_in)
taskset -c "$CLI_CPUS" timeout 60 "$BIN/client" --server "$LISTEN" --count "$PINGS" \
  --interval-ms "$INTERVAL" --size 64 > /tmp/bench-cli.log 2>&1
crc=$?
t1=$(uptime_s); c1=$(cputime $SPID); i1=$(udp_in)
# --- window closed ---

awk -v t0="$t0" -v t1="$t1" -v c0="$c0" -v c1="$c1" -v i0="$i0" -v i1="$i1" -v hz=$HZ \
    -v mode="$MODE" -v rate="$RATE" -v crc="$crc" \
    -v rtt="$(grep -oP 'rtt min/avg/max = \K[0-9./]+' /tmp/bench-cli.log)" \
    -v ok="$(grep -oP 'sent, \K[0-9]+(?= echoed)' /tmp/bench-cli.log)" \
    -v sent="$(grep -oP '^\K[0-9]+(?= sent,)' /tmp/bench-cli.log)" 'BEGIN{
  w=t1-t0; cores=(c1-c0)/hz/w; deliv=(i1-i0)/w
  printf "mode=%s offered=%s window=%.2fs deliv_pps=%.0f srv_cores=%.3f us_per_pkt=%.2f pings=%s/%s rtt=%s conn=%s\n",
    mode, rate, w, deliv, cores, (deliv>1000 ? cores*1e6/deliv : 0), (ok==""?0:ok), (sent==""?0:sent),
    (rtt==""?"connect-failed":rtt), (crc==0?"ok":"FAILED")
}'
